#!/usr/bin/env python3
"""promote_quality.py —— 实测质量 tier 覆盖的离线晋升器（模式 C 的生产端）。

输入：evaluate_quality.py 产出的 reports/quality.json（不可信工件，可能来自任意
上游配置的评测结果，按敌对输入处理），产出 quality/tier-overrides.json。

设计原则（与 promote_discovery.py / publish_discovery.py 同源）：
- 严格 JSON（拒 NaN/Infinity/重复键/控制字符）、深度/节点/大小预算；
- 决策规则只依赖报告自身，不访问网络、不执行任何第三方代码；
- 全量自测试（--test），输出可被 --validate 复核；
- 与上一版 overrides 比对做增量阀（promote 方向每轮最多 MAX_PROMOTE_DELTA 条，
  demote 方向不受限——变差要快、升档要慢）。

身份/指纹口径必须与 evaluate_quality.py 逐字节一致：
  sourceId         = sha256_json([factoryId, name, searchUrl])[:24]
  configFingerprint = sha256_json(item)         # 64 hex
消费端（update_sources.py）持有同一套复刻实现并二次校验。
"""
from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import re
import sys
import tempfile

SCHEMA_VERSION = 1
OVERRIDES_SCHEMA_VERSION = 1
MAX_REPORT_SIZE = 10 * 1024 * 1024
MAX_PREVIOUS_SIZE = 256 * 1024
MAX_OUTPUT_SIZE = 256 * 1024
MAX_SUMMARIES = 2000
MAX_OVERRIDES = 64
MAX_PROMOTE_DELTA = 8
MAX_TIER_DELTA = 2
VALID_DAYS = 14
MAX_TIER = 6
BASELINE_UNTIERED = 2  # 与 update_sources.py 的 tier_sort_value(None) 语义一致

_SOURCE_ID_RE = re.compile(r"[0-9a-f]{24}\Z")
_FINGERPRINT_RE = re.compile(r"[0-9a-f]{64}\Z")
_FACTORY_ID_RE = re.compile(r"[A-Za-z0-9_-]{1,64}\Z")
_DATE_RE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}\Z")
DIRECTIONS = ("promote", "demote")


class PromoteError(ValueError):
    pass


# ---------------------------------------------------------------- strict JSON

def _reject_json_constant(value):
    raise PromoteError(f"JSON 含非法常量: {value!r}")


def _strict_json_object(pairs):
    obj = {}
    for key, value in pairs:
        if key in obj:
            raise PromoteError(f"JSON 含重复键: {key!r}")
        obj[key] = value
    return obj


def strict_json(data: bytes):
    try:
        return json.loads(data.decode("utf-8-sig"), parse_constant=_reject_json_constant,
                          object_pairs_hook=_strict_json_object)
    except UnicodeDecodeError as exc:
        raise PromoteError("文件不是合法 UTF-8") from exc
    except json.JSONDecodeError as exc:
        raise PromoteError(f"JSON 解析失败: {exc}") from exc


def has_control(value: str) -> bool:
    return any(ord(ch) < 32 or ord(ch) == 127 for ch in value)


def validate_tree(value, depth=0, nodes=None):
    """深度/节点预算 + 基础类型检查。"""
    if nodes is None:
        nodes = [0]
    nodes[0] += 1
    if nodes[0] > 300_000:
        raise PromoteError("JSON 节点数超限")
    if depth > 24:
        raise PromoteError("JSON 嵌套过深")
    if isinstance(value, str):
        if has_control(value):
            raise PromoteError("JSON 字符串含控制字符")
    elif isinstance(value, list):
        for item in value:
            validate_tree(item, depth + 1, nodes)
    elif isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str) or has_control(key):
                raise PromoteError("JSON 键非法")
            validate_tree(item, depth + 1, nodes)
    elif isinstance(value, (bool, int)) or value is None:
        pass
    elif isinstance(value, float):
        if value != value or value in (float("inf"), float("-inf")):
            raise PromoteError("JSON 含非法浮点数")
    else:
        raise PromoteError(f"JSON 含不支持的类型: {type(value).__name__}")


def regular_file_bytes(path: str, maximum: int) -> bytes:
    if not os.path.exists(path):
        raise PromoteError(f"文件缺失: {path}")
    if os.path.islink(path) or not os.path.isfile(path):
        raise PromoteError(f"文件类型非法（须常规文件）: {path}")
    size = os.path.getsize(path)
    if size == 0 or size > maximum:
        raise PromoteError(f"文件为空或超过 {maximum} 字节: {path}")
    with open(path, "rb") as handle:
        data = handle.read(maximum + 1)
    if len(data) > maximum:
        raise PromoteError(f"文件读取超限: {path}")
    return data


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _bounded_str(value, limit: int) -> bool:
    return isinstance(value, str) and value and not has_control(value) and len(value) <= limit


def _bounded_int(value, minimum: int, maximum: int) -> bool:
    return (not isinstance(value, bool) and isinstance(value, int)
            and minimum <= value <= maximum)


def _bounded_number(value, minimum: float, maximum: float) -> bool:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return False
    return minimum <= value <= maximum


# ---------------------------------------------------------------- report 校验

def validate_recommendation(rec) -> None:
    if not isinstance(rec, dict):
        raise PromoteError("recommendation 必须是对象")
    if not isinstance(rec.get("ready"), bool):
        raise PromoteError("recommendation.ready 非法")
    recommended = rec.get("recommendedTier")
    if recommended is not None and not _bounded_int(recommended, 0, MAX_TIER):
        raise PromoteError("recommendation.recommendedTier 非法")
    for field in ("observations", "distinctDays", "highAdObservations"):
        value = rec.get(field)
        if value is not None and not _bounded_int(value, 0, 100_000):
            raise PromoteError(f"recommendation.{field} 非法")
    for field in ("transportSuccessRate", "medianScore"):
        value = rec.get(field)
        if value is not None and not _bounded_number(value, 0.0, 1000.0):
            raise PromoteError(f"recommendation.{field} 非法")
    value = rec.get("medianDurationMs")
    if value is not None and not _bounded_number(value, 0.0, 3600_000.0):
        raise PromoteError("recommendation.medianDurationMs 非法")


def validate_summary(item) -> None:
    if not isinstance(item, dict):
        raise PromoteError("sources 条目必须是对象")
    source_id = item.get("sourceId")
    if not isinstance(source_id, str) or not _SOURCE_ID_RE.fullmatch(source_id):
        raise PromoteError(f"sourceId 非法: {source_id!r}")
    if not _bounded_str(item.get("name"), 200):
        raise PromoteError(f"name 非法: {item.get('name')!r}")
    factory_id = item.get("factoryId")
    if not isinstance(factory_id, str) or not _FACTORY_ID_RE.fullmatch(factory_id):
        raise PromoteError(f"factoryId 非法: {factory_id!r}")
    official = item.get("officialTier")
    if official is not None and not _bounded_int(official, 0, MAX_TIER):
        raise PromoteError(f"officialTier 非法: {official!r}")
    if not isinstance(item.get("tierDisagreement"), bool):
        raise PromoteError("tierDisagreement 必须是 bool")
    validate_recommendation(item.get("recommendation"))
    latest = item.get("latest")
    if latest is not None:
        if not isinstance(latest, dict):
            raise PromoteError("latest 必须是对象或 null")
        fingerprint = latest.get("configFingerprint")
        if not isinstance(fingerprint, str) or not _FINGERPRINT_RE.fullmatch(fingerprint):
            raise PromoteError(f"latest.configFingerprint 非法: {fingerprint!r}")


def parse_report(report_bytes: bytes) -> dict:
    document = strict_json(report_bytes)
    if not isinstance(document, dict):
        raise PromoteError("报告必须是 JSON 对象")
    if document.get("schemaVersion") != SCHEMA_VERSION:
        raise PromoteError("报告 schemaVersion 非法")
    generated = document.get("generatedAt")
    if not isinstance(generated, str) or not _valid_timestamp(generated):
        raise PromoteError("报告 generatedAt 非法")
    summaries = document.get("sources")
    if not isinstance(summaries, list) or len(summaries) > MAX_SUMMARIES:
        raise PromoteError("sources 非法或超限")
    validate_tree(document)
    for summary in summaries:
        validate_summary(summary)
    return {"generatedAt": generated, "sources": summaries}


def _valid_timestamp(value: str) -> bool:
    if not isinstance(value, str) or len(value) > 40 or has_control(value):
        return False
    candidate = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        moment = dt.datetime.fromisoformat(candidate)
    except ValueError:
        return False
    return moment.tzinfo is not None


def _report_date(generated_at: str) -> str:
    return generated_at[:10]


# ---------------------------------------------------------------- 决策

def decide_overrides(summaries: list) -> list:
    """从报告 summaries 中筛出应生成 override 的条目（未做限量与增量阀）。"""
    chosen = []
    for summary in summaries:
        rec = summary["recommendation"]
        if not rec.get("ready") or not summary.get("tierDisagreement"):
            continue
        if summary["factoryId"] == "rss":
            continue
        recommended = rec.get("recommendedTier")
        latest = summary.get("latest")
        if recommended is None or latest is None:
            continue
        baseline = summary["officialTier"]
        baseline = baseline if baseline is not None else BASELINE_UNTIERED
        delta = recommended - baseline
        if delta == 0 or abs(delta) > MAX_TIER_DELTA:
            continue
        chosen.append({
            "sourceId": summary["sourceId"],
            "configFingerprint": latest["configFingerprint"],
            "officialTier": summary["officialTier"],
            "tier": recommended,
            "direction": "demote" if delta > 0 else "promote",
            "evidenceCount": rec.get("observations") or 0,
            "medianScore": rec.get("medianScore"),
            "transportSuccessRate": rec.get("transportSuccessRate"),
        })
    return chosen


def _prev_key(entry: dict):
    return entry["sourceId"]


def apply_caps(chosen: list, previous: list) -> tuple[list, dict]:
    """增量阀：demote 全部放行；promote 相对上一版的新增/变更 ≤ MAX_PROMOTE_DELTA。

    总量 ≤ MAX_OVERRIDES：demote 优先（按 medianScore 升序，即最差的先录入），
    promote 按证据强度排序（成功率、分位分降序，sourceId 字典序兜底保证确定性）。
    """
    previous_index = {entry["sourceId"]: entry for entry in previous}
    demotes = [entry for entry in chosen if entry["direction"] == "demote"]
    promotes = [entry for entry in chosen if entry["direction"] == "promote"]

    def promote_changed(entry) -> bool:
        old = previous_index.get(entry["sourceId"])
        return (old is None or old.get("direction") != "promote"
                or old.get("tier") != entry["tier"]
                or old.get("configFingerprint") != entry["configFingerprint"])

    fresh_promotes = [entry for entry in promotes if promote_changed(entry)]
    kept_promotes = list(promotes)
    trimmed_promotes = 0
    if len(fresh_promotes) > MAX_PROMOTE_DELTA:
        ranked_new = sorted(fresh_promotes, key=lambda e: (
            -(e["transportSuccessRate"] or 0.0), -(e["medianScore"] or 0.0), e["sourceId"]))
        keep_ids = {entry["sourceId"] for entry in ranked_new[:MAX_PROMOTE_DELTA]}
        kept_ids = {entry["sourceId"] for entry in promotes} - {
            entry["sourceId"] for entry in fresh_promotes}
        kept_promotes = [entry for entry in promotes
                         if entry["sourceId"] in keep_ids or entry["sourceId"] in kept_ids]
        trimmed_promotes = len(fresh_promotes) - MAX_PROMOTE_DELTA
        # 仍未变化的旧 promote 也可能把总量推高；统一走下面的总量阀再截一次。

    demotes.sort(key=lambda e: ((e["medianScore"] if e["medianScore"] is not None else 101.0),
                                e["sourceId"]))
    kept_promotes.sort(key=lambda e: (
        -(e["transportSuccessRate"] or 0.0), -(e["medianScore"] or 0.0), e["sourceId"]))
    kept = demotes + kept_promotes
    trimmed_total = 0
    if len(kept) > MAX_OVERRIDES:
        trimmed_total = len(kept) - MAX_OVERRIDES
        kept = kept[:MAX_OVERRIDES]
    kept.sort(key=lambda e: e["sourceId"])  # 稳定 diff
    stats = {
        "decided": len(chosen),
        "demote": len(demotes),
        "promote": len(promotes),
        "trimmedPromoteDelta": trimmed_promotes,
        "trimmedTotal": trimmed_total,
        "kept": len(kept),
    }
    return kept, stats


# ---------------------------------------------------------------- overrides 校验（自身输出 → --validate 复用）

def validate_overrides_document(document) -> dict:
    if not isinstance(document, dict):
        raise PromoteError("overrides 必须是 JSON 对象")
    if document.get("schemaVersion") != OVERRIDES_SCHEMA_VERSION:
        raise PromoteError("overrides schemaVersion 非法")
    generated = document.get("generatedAt")
    valid_until = document.get("validUntil")
    if (not isinstance(generated, str) or not _valid_timestamp(generated)
            or not isinstance(valid_until, str) or not _DATE_RE.fullmatch(valid_until)):
        raise PromoteError("overrides 时间字段非法")
    if valid_until < _report_date(generated):
        raise PromoteError("validUntil 早于 generatedAt")
    evidence = document.get("evidence")
    if (not isinstance(evidence, dict)
            or not _bounded_str(evidence.get("reportSha256") or "", 64)
            or not _FINGERPRINT_RE.fullmatch(evidence.get("reportSha256") or "")
            or not isinstance(evidence.get("reportGeneratedAt"), str)
            or not _valid_timestamp(evidence["reportGeneratedAt"])):
        raise PromoteError("overrides evidence 非法")
    overrides = document.get("overrides")
    if not isinstance(overrides, list) or len(overrides) > MAX_OVERRIDES:
        raise PromoteError("overrides 列表非法或超限")
    seen = set()
    for entry in overrides:
        if not isinstance(entry, dict):
            raise PromoteError("override 条目必须是对象")
        allowed = {"sourceId", "configFingerprint", "officialTier", "tier", "direction",
                   "evidenceCount", "medianScore", "transportSuccessRate", "note"}
        if set(entry) - allowed:
            raise PromoteError(f"override 含未知字段: {sorted(set(entry) - allowed)!r}")
        if not _SOURCE_ID_RE.fullmatch(entry.get("sourceId") or ""):
            raise PromoteError("override sourceId 非法")
        if entry["sourceId"] in seen:
            raise PromoteError("override sourceId 重复")
        seen.add(entry["sourceId"])
        if not _FINGERPRINT_RE.fullmatch(entry.get("configFingerprint") or ""):
            raise PromoteError("override configFingerprint 非法")
        if not _bounded_int(entry.get("tier"), 0, MAX_TIER):
            raise PromoteError("override tier 非法")
        official = entry.get("officialTier")
        if official is not None and not _bounded_int(official, 0, MAX_TIER):
            raise PromoteError("override officialTier 非法")
        if entry.get("direction") not in DIRECTIONS:
            raise PromoteError("override direction 非法")
        if not _bounded_int(entry.get("evidenceCount"), 0, 100_000):
            raise PromoteError("override evidenceCount 非法")
        if entry.get("medianScore") is not None and not _bounded_number(entry["medianScore"], 0.0, 100.0):
            raise PromoteError("override medianScore 非法")
        tsr = entry.get("transportSuccessRate")
        if tsr is not None and not _bounded_number(tsr, 0.0, 1.0):
            raise PromoteError("override transportSuccessRate 非法")
    return document


def load_previous(path: str | None) -> list:
    if not path or not os.path.exists(path):
        return []
    data = regular_file_bytes(path, MAX_PREVIOUS_SIZE)
    document = strict_json(data)
    validate_tree(document)
    return validate_overrides_document(document)["overrides"]


def build_document(report_bytes: bytes, previous: list, now: dt.datetime | None = None) -> tuple[dict, dict]:
    report = parse_report(report_bytes)
    chosen = decide_overrides(report["sources"])
    kept, stats = apply_caps(chosen, previous)
    now = now or dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
    today = now.date().isoformat()
    report_date = _report_date(report["generatedAt"])
    base_date = max(today, report_date)
    valid_until = (dt.date.fromisoformat(base_date) + dt.timedelta(days=VALID_DAYS)).isoformat()
    document = {
        "schemaVersion": OVERRIDES_SCHEMA_VERSION,
        "generatedAt": now.isoformat().replace("+00:00", "Z"),
        "validUntil": valid_until,
        "evidence": {
            "reportSha256": sha256_bytes(report_bytes),
            "reportGeneratedAt": report["generatedAt"],
        },
        "overrides": kept,
    }
    stats["validUntil"] = valid_until
    return document, stats


def write_output_atomic(path: str, document: dict) -> str:
    payload = json.dumps(document, ensure_ascii=False, indent=2, sort_keys=False).encode("utf-8")
    if len(payload) > MAX_OUTPUT_SIZE:
        raise PromoteError("overrides 输出超限")
    parent = os.path.dirname(os.path.realpath(path))
    os.makedirs(parent, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".tier-overrides.tmp-", dir=parent)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(payload)
            handle.write(b"\n")
        os.chmod(tmp, 0o644)
        os.replace(tmp, path)
    finally:
        try:
            os.unlink(tmp)
        except OSError:
            pass
    return sha256_bytes(payload + b"\n")


# ---------------------------------------------------------------- selftests

def run_selftests():
    import unittest

    FP_A = "a" * 64
    FP_B = "b" * 64
    FP_C = "c" * 64

    def make_summary(source_id, name="X", factory="web-selector", official=1,
                     recommended=None, ready=True, disagreement=True,
                     fp=FP_A, latest=True, tsr=1.0, med=95.0):
        return {
            "sourceId": source_id,
            "name": name,
            "factoryId": factory,
            "officialTier": official,
            "recommendation": {
                "ready": ready,
                "observations": 3,
                "distinctDays": 3,
                "transportSuccessRate": tsr,
                "medianScore": med,
                "medianDurationMs": 1000,
                "highAdObservations": 0,
                "recommendedTier": recommended,
            },
            "tierDisagreement": disagreement,
            "testedThisRun": True,
            "latest": {"configFingerprint": fp} if latest else None,
        }

    def make_report(summaries, generated="2026-08-26T04:30:00+00:00"):
        return json.dumps({
            "schemaVersion": 1,
            "generatedAt": generated,
            "method": {},
            "run": {"totalSources": len(summaries), "testedSources": len(summaries),
                    "transportPassed": 0, "transportPassRate": 0},
            "observations": [],
            "sources": summaries,
        }, ensure_ascii=False).encode("utf-8")

    class T(unittest.TestCase):
        def test_valid_report_yields_override(self):
            doc, stats = build_document(make_report([make_summary("a" * 24, recommended=3)]),
                                        [], now=dt.datetime(2026, 8, 26, tzinfo=dt.timezone.utc))
            self.assertEqual(len(doc["overrides"]), 1)
            entry = doc["overrides"][0]
            self.assertEqual(entry["direction"], "demote")
            self.assertEqual(entry["tier"], 3)
            self.assertEqual(stats["kept"], 1)

        def test_not_ready_skipped(self):
            doc, _ = build_document(make_report([make_summary("a" * 24, recommended=3,
                                                              ready=False)]), [])
            self.assertEqual(doc["overrides"], [])

        def test_no_disagreement_skipped(self):
            doc, _ = build_document(make_report([make_summary("a" * 24, recommended=3,
                                                              disagreement=False)]), [])
            self.assertEqual(doc["overrides"], [])

        def test_rss_factory_skipped(self):
            doc, _ = build_document(make_report([make_summary("a" * 24, factory="rss",
                                                              recommended=4)]), [])
            self.assertEqual(doc["overrides"], [])

        def test_missing_latest_skipped(self):
            doc, _ = build_document(make_report([make_summary("a" * 24, recommended=3,
                                                              latest=False)]), [])
            self.assertEqual(doc["overrides"], [])

        def test_tier_delta_gt2_skipped(self):
            doc, _ = build_document(make_report([make_summary("a" * 24, official=0,
                                                              recommended=3)]), [])
            self.assertEqual(doc["overrides"], [])

        def test_untiered_baseline_uses_2(self):
            doc, _ = build_document(make_report([make_summary("a" * 24, official=None,
                                                              recommended=0)]), [])
            entry = doc["overrides"][0]
            self.assertEqual(entry["direction"], "promote")
            self.assertEqual(entry["officialTier"], None)
            self.assertEqual(entry["tier"], 0)

        def test_promote_delta_capped_at_8(self):
            items = [make_summary(f"{i:024x}", recommended=0, official=2,
                                  tsr=1.0 - i * 0.01) for i in range(12)]
            doc, stats = build_document(make_report(items), [])
            promotes = [e for e in doc["overrides"] if e["direction"] == "promote"]
            self.assertEqual(len(promotes), 8)
            self.assertEqual(stats["trimmedPromoteDelta"], 4)

        def test_demote_not_capped_by_delta(self):
            items = [make_summary(f"{i:024x}", recommended=3, official=1,
                                  med=50.0 - i) for i in range(10)]
            doc, stats = build_document(make_report(items), [])
            self.assertEqual(len(doc["overrides"]), 10)
            self.assertEqual(stats["demote"], 10)

        def test_total_cap_64(self):
            items = [make_summary(f"{i:024x}", recommended=4, official=2,
                                  med=10.0) for i in range(70)]
            doc, stats = build_document(make_report(items), [])
            self.assertEqual(len(doc["overrides"]), 64)
            self.assertEqual(stats["trimmedTotal"], 6)

        def test_unchanged_promotes_exempt_from_delta_budget(self):
            previous = [{"sourceId": "a" * 24, "configFingerprint": "a" * 64,
                         "officialTier": 2, "tier": 0, "direction": "promote",
                         "evidenceCount": 3, "medianScore": 95.0, "transportSuccessRate": 1.0}]
            chosen_doc, stats = build_document(
                make_report([make_summary("a" * 24, recommended=0, official=2)] + [
                    make_summary(f"{i:024x}", recommended=0, official=2) for i in range(7)]),
                previous)
            self.assertEqual(len(chosen_doc["overrides"]), 8)
            self.assertEqual(stats["trimmedPromoteDelta"], 0)

        def test_strict_json_rejects_duplicate_keys(self):
            data = (b'{"schemaVersion":1,"generatedAt":"2026-08-26T00:00:00Z",'
                    b'"sources":[],"sources":[]}')
            with self.assertRaises(PromoteError):
                parse_report(data)

        def test_strict_json_rejects_nan(self):
            data = make_report([make_summary("a" * 24, recommended=3)])
            data = data.replace(b'"medianScore": 95.0', b'"medianScore": NaN')
            with self.assertRaises(PromoteError):
                parse_report(data)

        def test_validate_own_output(self):
            with tempfile.TemporaryDirectory() as td:
                out = os.path.join(td, "tier-overrides.json")
                doc, _ = build_document(make_report([make_summary("a" * 24, recommended=3)]), [])
                write_output_atomic(out, doc)
                reread = validate_overrides_document(
                    strict_json(regular_file_bytes(out, MAX_OUTPUT_SIZE)))
                self.assertEqual(len(reread["overrides"]), 1)

        def test_invalid_baseline_aborts(self):
            with tempfile.TemporaryDirectory() as td:
                path = os.path.join(td, "bad.json")
                with open(path, "w", encoding="utf-8") as fh:
                    fh.write('{"schemaVersion": 2, "overrides": []}')
                with self.assertRaises(PromoteError):
                    load_previous(path)

        def test_report_schema_version_rejected(self):
            data = json.dumps({"schemaVersion": 2, "generatedAt": "2026-08-26T00:00:00Z",
                               "sources": []}).encode()
            with self.assertRaises(PromoteError):
                parse_report(data)

        def test_valid_until_extends_14_days(self):
            doc, _ = build_document(make_report([make_summary("a" * 24, recommended=3)]), [],
                                    now=dt.datetime(2026, 8, 26, tzinfo=dt.timezone.utc))
            self.assertEqual(doc["validUntil"], "2026-09-09")

        def test_oversize_report_rejected(self):
            with tempfile.TemporaryDirectory() as td:
                path = os.path.join(td, "big.json")
                with open(path, "wb") as fh:
                    fh.write(b" " * (MAX_REPORT_SIZE + 1))
                with self.assertRaises(PromoteError):
                    regular_file_bytes(path, MAX_REPORT_SIZE)

        def test_symlink_report_rejected(self):
            with tempfile.TemporaryDirectory() as td:
                real = os.path.join(td, "real.json")
                with open(real, "wb") as fh:
                    fh.write(make_report([]))
                link = os.path.join(td, "link.json")
                os.symlink(real, link)
                with self.assertRaises(PromoteError):
                    regular_file_bytes(link, MAX_REPORT_SIZE)

    suite = unittest.TestLoader().loadTestsFromTestCase(T)
    result = unittest.TextTestRunner(verbosity=1).run(suite)
    total = result.testsRun
    if not result.wasSuccessful():
        raise SystemExit(1)
    print(f"selftests: {total}")


# ---------------------------------------------------------------- main

def main(argv=None):
    args = list(sys.argv[1:] if argv is None else argv)
    if "--test" in args:
        run_selftests()
        return 0
    if "--validate" in args:
        index = args.index("--validate")
        try:
            target = args[index + 1]
            document = validate_overrides_document(
                strict_json(regular_file_bytes(target, MAX_OUTPUT_SIZE)))
        except PromoteError as exc:
            print(f"overrides 校验失败: {exc}", file=sys.stderr)
            return 1
        print(f"overrides 校验通过（{len(document['overrides'])} 条）")
        return 0
    try:
        report_path = args[args.index("--report") + 1] if "--report" in args else "reports/quality.json"
        out_path = args[args.index("--out") + 1] if "--out" in args else "quality/tier-overrides.json"
        previous_path = (args[args.index("--previous") + 1]
                         if "--previous" in args else "quality/tier-overrides.json")
        report_bytes = regular_file_bytes(report_path, MAX_REPORT_SIZE)
        previous = load_previous(previous_path)
        document, stats = build_document(report_bytes, previous)
        manifest = write_output_atomic(out_path, document)
        print(f"overrides 产出: {out_path}（决定 {stats['decided']}，录入 {stats['kept']}；"
              f"demote {stats['demote']} / promote {stats['promote']}，"
              f"promote阀裁 {stats['trimmedPromoteDelta']}，总量阀裁 {stats['trimmedTotal']}，"
              f"有效期至 {stats['validUntil']}）")
        print(f"manifest SHA-256: {manifest}")
        return 0
    except PromoteError as exc:
        print(f"overrides 晋升失败: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
