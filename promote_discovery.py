#!/usr/bin/env python3

from __future__ import annotations

import argparse
import copy
import datetime as dt
import hashlib
import importlib.util
import json
import math
import os
import re
import shutil
import stat
import tempfile
from pathlib import Path


def _load_url_policy():
    path = Path(__file__).resolve().with_name("animeko_url_policy.py")
    if not path.is_file():
        raise RuntimeError("缺少同目录 animeko_url_policy.py")
    spec = importlib.util.spec_from_file_location("animeko_promoter_url_policy", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("无法加载animeko URL policy")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_URL_POLICY = _load_url_policy()
canonicalize_url = _URL_POLICY.canonicalize_url
repository_key_for_url = _URL_POLICY.repository_key_for_url
resource_key_for_url = _URL_POLICY.resource_key_for_url
is_repository_seed = _URL_POLICY.is_repository_seed
UrlPolicyError = _URL_POLICY.UrlPolicyError

STATE_VERSION = 2
MAX_ARTIFACT_FILE = 5 * 1024 * 1024
MAX_POLICY_FILE = 64 * 1024
MAX_LINK_FILE_SIZE = 1024 * 1024
MAX_LINKS = 5000
MAX_LINK_ADDITIONS = 50
MAX_CANDIDATES = 5000
MAX_PROGRAMS = 500
MAX_EVIDENCE = 20
MAX_POLICY_LINES = 1000
PROBATION_MIN_RUNS = 3
PROBATION_MIN_DAYS = 2
PROBATION_MIN_STABLE_RUNS = 3
RAW_FILES = frozenset({
    "latest.json", "programs.json", "candidates.json", "redundant.json", "rejected.json",
})
OUTPUT_FILES = (
    "all_animeko_links.txt",
    "discovery/state.json",
    "discovery/programs.json",
    "discovery/candidates.json",
    "discovery/redundant.json",
    "discovery/rejected.json",
    "discovery/latest.json",
    "discovery/promotion.json",
)
SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
TRUST_KEY_RE = re.compile(r"(?:github|gitlab|gitee|codeberg):[a-z0-9_.-]+(?:/[a-z0-9_.-]+)+\Z")
REPOSITORY_RE = re.compile(r"[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)+\Z")
SAFE_CODE_RE = re.compile(r"[-A-Za-z0-9_.:]{1,128}\Z")
SAFE_SIGNAL_RE = re.compile(r"[A-Za-z0-9_.:/-]{1,80}\Z")
SAFE_REF_RE = re.compile(r"[A-Za-z0-9_./-]{1,255}\Z")
RUN_ID_RE = re.compile(r"(?:github:[0-9]+:[0-9]+|local:[A-Za-z0-9_.:-]{1,80}|legacy:[0-9T:+Z-]{1,40})\Z")
ALLOWED_CATEGORIES = frozenset({
    "aggregator", "generator", "converter", "validator", "workflow-bot", "mirror-sync",
    "editor-or-service", "subscription",
})
LEGACY_STATE_FIELDS = frozenset({
    "first_seen", "last_seen", "observed_dates", "successful_runs", "consecutive_successes",
    "stable_successes", "last_sha256", "status", "evidence", "observed_by",
    "max_program_score", "trusted_evidence", "trusted_provenance", "redundant", "last_error",
    "last_items", "last_new_items", "last_overlap_items", "last_latency", "promoted_on",
})
SECRET_PATTERNS = (
    re.compile(r"gh[pousr]_[A-Za-z0-9_]{12,}"),
    re.compile(r"github_pat_[A-Za-z0-9_]{20,}"),
    re.compile(r"glpat-[A-Za-z0-9_-]{12,}"),
    re.compile(r"Bearer\s+[A-Za-z0-9._~+/=-]{8,}", re.IGNORECASE),
    re.compile(r"sk-[A-Za-z0-9_-]{12,}"),
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"),
    re.compile(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"),
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    re.compile(r"(?:access_token|api[_-]?key|token|authorization|password|secret)=[^&\s\"']{8,}", re.IGNORECASE),
)


def json_bytes(obj) -> bytes:
    return (json.dumps(obj, ensure_ascii=False, sort_keys=True, indent=2, allow_nan=False) + "\n").encode("utf-8")


def reject_json_constant(value):
    raise ValueError(f"非法JSON常量: {value}")


def strict_json_object(pairs):
    obj = {}
    for key, value in pairs:
        if key in obj:
            raise ValueError(f"JSON重复键: {key}")
        obj[key] = value
    return obj


def has_control(value: str) -> bool:
    return any(ord(ch) < 32 or ord(ch) == 127 for ch in value)


def safe_json_tree(value, depth=0, nodes=None):
    if nodes is None:
        nodes = [0]
    nodes[0] += 1
    if depth > 30 or nodes[0] > 100000:
        raise RuntimeError("JSON结构过深或节点过多")
    if isinstance(value, str):
        if len(value) > 10000 or has_control(value):
            raise RuntimeError("JSON含超长字符串或控制字符")
    elif isinstance(value, list):
        for item in value:
            safe_json_tree(item, depth + 1, nodes)
    elif isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str) or has_control(key):
                raise RuntimeError("JSON字段名非法")
            if len(key) > 200:
                try:
                    is_canonical_url_key = len(key) <= 8192 and canonicalize_url(key) == key
                except (UrlPolicyError, TypeError):
                    is_canonical_url_key = False
                if not is_canonical_url_key:
                    raise RuntimeError("超长JSON键必须是canonical URL")
            safe_json_tree(item, depth + 1, nodes)
    elif value is not None and not isinstance(value, (bool, int, float)):
        raise RuntimeError("JSON含非法类型")
    if isinstance(value, float) and not math.isfinite(value):
        raise RuntimeError("JSON含非有限浮点数")


def reject_secrets(document):
    serialized = json.dumps(document, ensure_ascii=False, allow_nan=False)
    if any(pattern.search(serialized) for pattern in SECRET_PATTERNS):
        raise RuntimeError("内容疑似包含secret")


def lstat_regular(path: Path, *, maximum: int, allow_empty=False):
    try:
        info = path.lstat()
    except FileNotFoundError as exc:
        raise RuntimeError(f"缺少文件: {path}") from exc
    if not stat.S_ISREG(info.st_mode):
        raise RuntimeError(f"必须是普通文件: {path}")
    if info.st_mode & 0o111:
        raise RuntimeError(f"文件不得可执行: {path}")
    if info.st_size > maximum or (not allow_empty and info.st_size <= 0):
        raise RuntimeError(f"文件大小非法: {path}")
    return info


def load_json_limited(path: Path):
    lstat_regular(path, maximum=MAX_ARTIFACT_FILE)
    try:
        document = json.loads(
            path.read_text(encoding="utf-8"), parse_constant=reject_json_constant,
            object_pairs_hook=strict_json_object)
    except Exception as exc:
        raise RuntimeError(f"JSON解析失败: {path}") from exc
    safe_json_tree(document)
    reject_secrets(document)
    return document


def validate_raw_directory(root: Path):
    try:
        root_info = root.lstat()
    except FileNotFoundError as exc:
        raise RuntimeError("raw artifact目录不存在") from exc
    if not stat.S_ISDIR(root_info.st_mode):
        raise RuntimeError("raw artifact必须是非symlink目录")
    actual = set()
    with os.scandir(root) as entries:
        for entry in entries:
            actual.add(entry.name)
            info = entry.stat(follow_symlinks=False)
            if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o111:
                raise RuntimeError(f"raw artifact含特殊、目录、symlink或可执行项: {entry.name}")
            if info.st_size <= 0 or info.st_size > MAX_ARTIFACT_FILE:
                raise RuntimeError(f"raw artifact文件大小非法: {entry.name}")
    if actual != RAW_FILES:
        raise RuntimeError("raw artifact文件集合无效")


def valid_timestamp(value) -> dt.datetime:
    if not isinstance(value, str) or len(value) > 40:
        raise RuntimeError("时间戳格式无效")
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise RuntimeError("时间戳无法解析") from exc
    if parsed.tzinfo is None:
        raise RuntimeError("时间戳必须包含时区")
    return parsed.astimezone(dt.timezone.utc)


def valid_date(value) -> str:
    if not isinstance(value, str):
        raise RuntimeError("日期必须是字符串")
    try:
        return dt.date.fromisoformat(value).isoformat()
    except ValueError as exc:
        raise RuntimeError("ISO日期无效") from exc


def bounded_int(value, name: str, minimum=0, maximum=1_000_000) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise RuntimeError(f"{name}计数无效")
    return value


def bounded_float(value, name: str, minimum=0.0, maximum=7200.0) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise RuntimeError(f"{name}数值无效")
    result = float(value)
    if not math.isfinite(result) or not minimum <= result <= maximum:
        raise RuntimeError(f"{name}数值越界")
    return result


def safe_error(value) -> str | None:
    if value is None:
        return None
    if isinstance(value, str) and SAFE_CODE_RE.fullmatch(value):
        return value
    return "redacted-error"


def safe_relative_path(value) -> str:
    if not isinstance(value, str) or not 1 <= len(value) <= 500 or has_control(value) or "\\" in value:
        raise RuntimeError("仓库path非法")
    parts = value.split("/")
    if any(not part or part in {".", ".."} for part in parts):
        raise RuntimeError("仓库path traversal")
    return value


def validate_observed_by(value, *, legacy=False) -> list[str]:
    if not isinstance(value, list) or len(value) > MAX_EVIDENCE:
        raise RuntimeError("observed_by结构无效")
    output = []
    for item in value:
        if item == "manual-seed":
            if legacy:
                item = "seed-candidate"
            else:
                raise RuntimeError("raw artifact不得声明manual-seed")
        if item == "seed-candidate":
            output.append(item)
        elif isinstance(item, str) and TRUST_KEY_RE.fullmatch(item.casefold()):
            output.append(item.casefold())
        else:
            raise RuntimeError(f"observed_by身份非法: {item!r}")
    return sorted(set(output))


def load_policy_lines(path: Path) -> list[str]:
    lstat_regular(path, maximum=MAX_POLICY_FILE, allow_empty=True)
    lines = path.read_text(encoding="utf-8-sig").splitlines()
    if len(lines) > MAX_POLICY_LINES:
        raise RuntimeError(f"policy文件行数过多: {path}")
    return [line.strip() for line in lines if line.strip() and not line.lstrip().startswith("#")]


def load_trusted_programs(baseline: Path) -> set[str]:
    trusted = set()
    for value in load_policy_lines(baseline / "discovery/trusted_programs.txt"):
        value = value.casefold()
        if not TRUST_KEY_RE.fullmatch(value):
            raise RuntimeError(f"信任项格式非法: {value!r}")
        trusted.add(value)
    return trusted


def load_direct_seeds(baseline: Path) -> set[str]:
    direct = set()
    for value in load_policy_lines(baseline / "discovery/seeds.txt"):
        try:
            if is_repository_seed(value):
                continue
            canonical = canonicalize_url(value)
        except UrlPolicyError as exc:
            raise RuntimeError(f"seed URL非法: {value!r}") from exc
        direct.add(canonical)
    return direct


def canonical_state_record(url: str, record: dict) -> dict:
    if not isinstance(record, dict) or not set(record) <= LEGACY_STATE_FIELDS:
        raise RuntimeError(f"state候选字段集合无效: {url}")
    required = {
        "first_seen", "last_seen", "observed_dates", "successful_runs", "consecutive_successes",
        "stable_successes", "last_sha256", "status", "max_program_score", "trusted_evidence",
        "redundant",
    }
    if not required <= set(record) or ("evidence" not in record and "observed_by" not in record):
        raise RuntimeError(f"state候选缺少字段: {url}")
    first_seen = valid_date(record["first_seen"])
    last_seen = valid_date(record["last_seen"])
    if first_seen > last_seen:
        raise RuntimeError(f"state候选日期倒置: {url}")
    dates = record["observed_dates"]
    if not isinstance(dates, list) or len(dates) > 30:
        raise RuntimeError(f"state observed_dates无效: {url}")
    normalized_dates = [valid_date(value) for value in dates]
    if normalized_dates != sorted(set(normalized_dates)):
        raise RuntimeError(f"state observed_dates必须有序且唯一: {url}")
    successful = bounded_int(record["successful_runs"], "successful_runs", maximum=100000)
    consecutive = bounded_int(record["consecutive_successes"], "consecutive_successes", maximum=100000)
    stable = bounded_int(record["stable_successes"], "stable_successes", maximum=100000)
    if successful > len(normalized_dates) or consecutive > successful or stable > consecutive:
        raise RuntimeError(f"state probation计数关系无效: {url}")
    if type(record["trusted_evidence"]) is not bool or type(record["redundant"]) is not bool:
        raise RuntimeError(f"state布尔字段类型无效: {url}")
    status_value = record["status"]
    if status_value not in {"new", "valid", "rejected", "redundant", "promoted", "absent"}:
        raise RuntimeError(f"state状态无效: {url}")
    digest = record["last_sha256"]
    if digest is not None and (not isinstance(digest, str) or not SHA256_RE.fullmatch(digest)):
        raise RuntimeError(f"state hash无效: {url}")
    observed_input = record.get("observed_by", record.get("evidence"))
    if "observed_by" in record and "evidence" in record:
        raise RuntimeError(f"state不得同时包含evidence和observed_by: {url}")
    observed_by = validate_observed_by(observed_input, legacy=True)
    result = {
        "first_seen": first_seen,
        "last_seen": last_seen,
        "observed_dates": normalized_dates,
        "successful_runs": successful,
        "consecutive_successes": consecutive,
        "stable_successes": stable,
        "last_sha256": digest,
        "status": status_value,
        "observed_by": observed_by,
        "max_program_score": bounded_int(record["max_program_score"], "max_program_score", maximum=100),
        "trusted_evidence": False,
        "trusted_provenance": [],
        "redundant": record["redundant"],
        "last_error": safe_error(record.get("last_error")),
        "last_items": None,
        "last_new_items": None,
        "last_overlap_items": None,
        "last_latency": None,
    }
    for field in ("last_items", "last_new_items", "last_overlap_items"):
        value = record.get(field)
        result[field] = None if value is None else bounded_int(value, field, maximum=50000)
    latency = record.get("last_latency")
    result["last_latency"] = None if latency is None else bounded_float(latency, "last_latency")
    promoted_on = record.get("promoted_on")
    if promoted_on is not None:
        result["promoted_on"] = valid_date(promoted_on)
    return result


def load_current_state(baseline: Path) -> dict:
    document = load_json_limited(baseline / "discovery/state.json")
    if not isinstance(document, dict) or document.get("version") != STATE_VERSION:
        raise RuntimeError("baseline state版本无效")
    if set(document) - {"version", "updated", "candidates", "promoted"}:
        raise RuntimeError("baseline state字段集合无效")
    candidates = document.get("candidates")
    promoted = document.get("promoted")
    if not isinstance(candidates, dict) or len(candidates) > MAX_CANDIDATES:
        raise RuntimeError("baseline state candidates无效")
    if not isinstance(promoted, list) or len(promoted) > MAX_LINKS:
        raise RuntimeError("baseline state promoted无效")
    normalized = {}
    for raw_url, record in candidates.items():
        try:
            url = canonicalize_url(raw_url)
        except UrlPolicyError as exc:
            raise RuntimeError("baseline state包含非法URL") from exc
        if url in normalized:
            raise RuntimeError("baseline state包含canonical重复URL")
        normalized[url] = canonical_state_record(url, record)
    promoted_urls = []
    seen = set()
    for raw_url in promoted:
        try:
            url = canonicalize_url(raw_url)
        except UrlPolicyError as exc:
            raise RuntimeError("baseline promoted包含非法URL") from exc
        if url in seen:
            raise RuntimeError("baseline promoted包含重复URL")
        seen.add(url)
        promoted_urls.append(url)
    state = {"version": STATE_VERSION, "candidates": normalized, "promoted": sorted(promoted_urls)}
    if "updated" in document:
        state["updated"] = valid_timestamp(document["updated"]).isoformat().replace("+00:00", "Z")
    return state


def sanitize_snapshot_complete(declared: bool, errors: list[dict]) -> bool:
    return declared and not any(
        item.get("error") in {"http-403", "http-429", "deadline"}
        for item in errors if isinstance(item, dict)
    )


def parse_latest(incoming: Path):
    raw = load_json_limited(incoming / "latest.json")
    if not isinstance(raw, dict) or raw.get("version") != 1:
        raise RuntimeError("latest结构无效")
    updated_dt = valid_timestamp(raw.get("updated"))
    today = dt.datetime.now(dt.timezone.utc).date()
    if abs((today - updated_dt.date()).days) > 1:
        raise RuntimeError("artifact日期不在允许窗口")
    if raw.get("analysis_mode") != "static-only" or raw.get("third_party_code_executed") is not False:
        raise RuntimeError("latest必须声明仅静态分析")
    complete = raw.get("snapshot_complete", True)
    if type(complete) is not bool:
        raise RuntimeError("snapshot_complete必须为bool")
    run_identity = raw.get("run_identity", "legacy:" + raw["updated"])
    if not isinstance(run_identity, str) or not RUN_ID_RE.fullmatch(run_identity):
        raise RuntimeError("run_identity格式无效")
    provider_errors = raw.get("provider_errors", [])
    if not isinstance(provider_errors, list) or len(provider_errors) > 100:
        raise RuntimeError("provider_errors结构无效")
    canonical_errors = []
    for item in provider_errors:
        if not isinstance(item, dict):
            canonical_errors.append({"error": "redacted-error"})
            continue
        sanitized = {"error": safe_error(item.get("error")) or "unknown-error"}
        provider = item.get("provider")
        if isinstance(provider, str) and SAFE_CODE_RE.fullmatch(provider):
            sanitized["provider"] = provider
        phase = item.get("phase")
        if isinstance(phase, str) and SAFE_CODE_RE.fullmatch(phase):
            sanitized["phase"] = phase
        repository = item.get("repository")
        if isinstance(repository, str) and REPOSITORY_RE.fullmatch(repository):
            sanitized["repository"] = repository
        canonical_errors.append(sanitized)
    complete = sanitize_snapshot_complete(complete, canonical_errors)
    input_bytes = raw.get("input_bytes", {})
    if not isinstance(input_bytes, dict) or set(input_bytes) != {
            "platform_static_analysis", "candidate_cache", "candidate_network"}:
        raise RuntimeError("latest input_bytes结构无效")
    latest = {
        "version": 1,
        "updated": updated_dt.isoformat().replace("+00:00", "Z"),
        "duration_s": bounded_float(raw.get("duration_s"), "duration_s", maximum=10000),
        "repositories_discovered": bounded_int(raw.get("repositories_discovered"), "repositories_discovered", maximum=500),
        "candidates_extracted": bounded_int(raw.get("candidates_extracted"), "candidates_extracted", maximum=10000),
        "input_bytes": {
            name: bounded_int(input_bytes[name], name, maximum=1024 * 1024 * 1024)
            for name in sorted(input_bytes)
        },
        "regex_validations": bounded_int(raw.get("regex_validations"), "regex_validations", maximum=10000),
        "provider_errors": canonical_errors,
        "analysis_mode": "static-only",
        "third_party_code_executed": False,
        "snapshot_complete": complete,
        "run_identity": run_identity,
    }
    return latest, updated_dt.date().isoformat()


def load_observations(incoming: Path, observed_date: str):
    specs = (
        ("candidates.json", "candidates", "valid"),
        ("redundant.json", "redundant", "redundant"),
        ("rejected.json", "rejected", "rejected"),
    )
    observations = {}
    reports = {}
    for filename, field, status_value in specs:
        document = load_json_limited(incoming / filename)
        if not isinstance(document, dict) or document.get("version") != 1:
            raise RuntimeError(f"{filename}版本无效")
        if valid_timestamp(document.get("updated")).date().isoformat() != observed_date:
            raise RuntimeError(f"{filename}日期与latest不一致")
        entries = document.get(field)
        if not isinstance(entries, list) or len(entries) > MAX_CANDIDATES:
            raise RuntimeError(f"{filename}条目结构无效")
        canonical_entries = []
        for raw in entries:
            if not isinstance(raw, dict):
                raise RuntimeError(f"{filename}候选必须是对象")
            try:
                url = canonicalize_url(raw.get("url"))
            except (UrlPolicyError, TypeError) as exc:
                raise RuntimeError(f"{filename}包含非法URL") from exc
            if url in observations:
                raise RuntimeError(f"候选同时出现在多个状态文件: {url}")
            observed_input = raw.get("observed_by", raw.get("evidence"))
            if observed_input is None or ("observed_by" in raw and "evidence" in raw):
                raise RuntimeError(f"{filename} observed_by缺失或冲突")
            observed_by = validate_observed_by(observed_input)
            digest = raw.get("sha256")
            if digest is not None and (not isinstance(digest, str) or not SHA256_RE.fullmatch(digest)):
                raise RuntimeError(f"{filename} hash无效")
            items = raw.get("items")
            new_items = raw.get("new_items")
            overlap_items = raw.get("overlap_items")
            for name, value in (("items", items), ("new_items", new_items), ("overlap_items", overlap_items)):
                if value is not None:
                    bounded_int(value, name, maximum=50000)
            ok = raw.get("ok")
            if status_value in {"valid", "redundant"}:
                if ok is not True or digest is None or items is None or new_items is None or overlap_items is None:
                    raise RuntimeError(f"{filename}有效候选字段不完整")
                if status_value == "valid" and new_items < 1:
                    raise RuntimeError("valid候选必须包含新增条目")
                if status_value == "redundant" and new_items != 0:
                    raise RuntimeError("redundant候选new_items必须为0")
            elif ok is not False:
                raise RuntimeError("rejected候选ok必须为false")
            observation = {
                "status": status_value,
                "sha256": digest,
                "items": items,
                "new_items": new_items,
                "overlap_items": overlap_items,
                "error": safe_error(raw.get("error")),
                "observed_by": observed_by,
            }
            observations[url] = observation
            entry = {"url": url, "ok": status_value != "rejected", "observed_by": observed_by}
            if digest is not None:
                entry["sha256"] = digest
            if status_value != "rejected":
                entry.update({
                    "items": items,
                    "new_items": new_items,
                    "overlap_items": overlap_items,
                    "redundant": status_value == "redundant",
                })
            else:
                entry["error"] = observation["error"] or "rejected"
            canonical_entries.append(entry)
        reports[field] = {
            "version": 1,
            "updated": valid_timestamp(document["updated"]).isoformat().replace("+00:00", "Z"),
            field: sorted(canonical_entries, key=lambda item: item["url"]),
        }
    return observations, reports


def sanitize_programs(incoming: Path, observed_date: str):
    document = load_json_limited(incoming / "programs.json")
    if not isinstance(document, dict) or document.get("version") != 1:
        raise RuntimeError("programs.json版本无效")
    updated = valid_timestamp(document.get("updated"))
    if updated.date().isoformat() != observed_date:
        raise RuntimeError("programs.json日期与latest不一致")
    entries = document.get("programs")
    if not isinstance(entries, list) or len(entries) > MAX_PROGRAMS:
        raise RuntimeError("programs列表无效")
    result = []
    seen = set()
    for raw in entries:
        if not isinstance(raw, dict):
            raise RuntimeError("program条目必须是对象")
        platform = raw.get("platform")
        repository = raw.get("repository")
        if platform not in {"github", "gitlab", "gitee", "codeberg"}:
            raise RuntimeError("program platform无效")
        if not isinstance(repository, str) or not REPOSITORY_RE.fullmatch(repository):
            raise RuntimeError("program repository无效")
        key = f"{platform}:{repository.casefold()}"
        if key in seen:
            raise RuntimeError("program repository重复")
        seen.add(key)
        branch = raw.get("default_branch")
        if not isinstance(branch, str) or not SAFE_REF_RE.fullmatch(branch) or ".." in branch:
            raise RuntimeError("program default_branch无效")
        commit = raw.get("commit")
        if not isinstance(commit, str) or not re.fullmatch(r"[0-9a-f]{7,64}", commit):
            raise RuntimeError("program commit无效")
        categories = raw.get("categories", [])
        if not isinstance(categories, list) or len(categories) > 20 or any(item not in ALLOWED_CATEGORIES for item in categories):
            raise RuntimeError("program categories无效")
        signals = raw.get("signals", [])
        if not isinstance(signals, list) or len(signals) > 30 or any(
                not isinstance(item, str) or not SAFE_SIGNAL_RE.fullmatch(item) for item in signals):
            raise RuntimeError("program signals无效")
        evidence_files = raw.get("evidence_files", [])
        if not isinstance(evidence_files, list) or len(evidence_files) > 30:
            raise RuntimeError("program evidence_files无效")
        clean_evidence_files = []
        for item in evidence_files:
            if not isinstance(item, dict):
                raise RuntimeError("program evidence_file结构无效")
            clean_evidence_files.append({
                "path": safe_relative_path(item.get("path")),
                "score": bounded_int(item.get("score"), "evidence score", maximum=1000),
            })
        generated = raw.get("generated_source_files", [])
        if not isinstance(generated, list) or len(generated) > 240:
            raise RuntimeError("program generated_source_files无效")
        clean_generated = []
        for item in generated:
            if not isinstance(item, dict):
                raise RuntimeError("generated source结构无效")
            try:
                source_url = canonicalize_url(item.get("url"))
            except (UrlPolicyError, TypeError) as exc:
                raise RuntimeError("generated source URL无效") from exc
            if repository_key_for_url(source_url) != key:
                raise RuntimeError("generated source URL与program repository不匹配")
            clean_generated.append({
                "path": safe_relative_path(item.get("path")),
                "items": bounded_int(item.get("items"), "generated items", maximum=50000),
                "url": source_url,
            })
        host = {"github": "github.com", "gitlab": "gitlab.com", "gitee": "gitee.com", "codeberg": "codeberg.org"}[platform]
        result.append({
            "platform": platform,
            "repository": repository,
            "url": f"https://{host}/{repository}",
            "default_branch": branch,
            "commit": commit,
            "score": bounded_int(raw.get("score"), "program score", maximum=100),
            "categories": sorted(set(categories)),
            "signals": sorted(set(signals)),
            "files_scanned": bounded_int(raw.get("files_scanned"), "files_scanned", maximum=1000),
            "evidence_files": sorted(clean_evidence_files, key=lambda item: (item["path"], item["score"])),
            "extracted_url_count": bounded_int(raw.get("extracted_url_count"), "extracted_url_count", maximum=10000),
            "generated_source_files": sorted(clean_generated, key=lambda item: item["path"]),
        })
    return {
        "version": 1,
        "updated": updated.isoformat().replace("+00:00", "Z"),
        "programs": sorted(result, key=lambda item: (item["platform"], item["repository"].casefold())),
    }


def derive_trusted_provenance(url: str, observed_by: list[str], direct_seeds: set[str],
                              trusted_programs: set[str]) -> list[str]:
    derived = []
    if url in direct_seeds:
        derived.append("manual-seed")
    repository_key = repository_key_for_url(url)
    if repository_key is not None and repository_key in trusted_programs and repository_key in observed_by:
        derived.append(repository_key)
    return sorted(derived)


def update_state(current: dict, observations: dict, observed_date: str,
                 direct_seeds: set[str], trusted_programs: set[str], snapshot_complete=True):
    state = copy.deepcopy(current)
    candidates = state["candidates"]
    for url, record in candidates.items():
        record["trusted_evidence"] = False
        record["trusted_provenance"] = []
        if url not in observations:
            record["consecutive_successes"] = 0
            record["stable_successes"] = 0
            record["redundant"] = False
            if record["status"] != "promoted":
                record["status"] = "absent"
                record["last_error"] = "absent-from-snapshot"
    for url, observation in observations.items():
        record = candidates.get(url)
        if record is None:
            record = {
                "first_seen": observed_date,
                "last_seen": observed_date,
                "observed_dates": [],
                "successful_runs": 0,
                "consecutive_successes": 0,
                "stable_successes": 0,
                "last_sha256": None,
                "status": "new",
                "observed_by": [],
                "max_program_score": 0,
                "trusted_evidence": False,
                "trusted_provenance": [],
                "redundant": False,
                "last_error": None,
                "last_items": None,
                "last_new_items": None,
                "last_overlap_items": None,
                "last_latency": None,
            }
        previous_last_seen = valid_date(record["last_seen"])
        old_dates = list(record["observed_dates"])
        new_day = observed_date not in old_dates
        if new_day and old_dates:
            expected = (dt.date.fromisoformat(previous_last_seen) + dt.timedelta(days=1)).isoformat()
            if observed_date != expected:
                record["consecutive_successes"] = 0
                record["stable_successes"] = 0
        if new_day:
            old_dates.append(observed_date)
            old_dates = sorted(set(old_dates))[-30:]
        record["observed_dates"] = old_dates
        record["last_seen"] = observed_date
        record["observed_by"] = sorted(set(record["observed_by"]) | set(observation["observed_by"]))[:MAX_EVIDENCE]
        provenance = derive_trusted_provenance(
            url, observation["observed_by"], direct_seeds, trusted_programs)
        record["trusted_provenance"] = provenance
        record["trusted_evidence"] = bool(provenance)
        record["redundant"] = observation["status"] == "redundant"
        eligible = observation["status"] == "valid" and snapshot_complete is True
        if not eligible:
            record["consecutive_successes"] = 0
            record["stable_successes"] = 0
        elif new_day:
            record["successful_runs"] = min(30, record["successful_runs"] + 1)
            record["consecutive_successes"] = min(30, record["consecutive_successes"] + 1)
            if record["last_sha256"] == observation["sha256"]:
                record["stable_successes"] = min(30, record["stable_successes"] + 1)
            else:
                record["stable_successes"] = 1
            record["last_sha256"] = observation["sha256"]
        record["status"] = observation["status"]
        record["last_error"] = observation["error"]
        record["last_items"] = observation["items"]
        record["last_new_items"] = observation["new_items"]
        record["last_overlap_items"] = observation["overlap_items"]
        record["last_latency"] = None
        candidates[url] = record
    state["updated"] = dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    return state


def days_between(first: str, current: str) -> int:
    try:
        return (dt.date.fromisoformat(current) - dt.date.fromisoformat(first)).days
    except (TypeError, ValueError):
        return -1


def probation_ready(record: dict, date: str) -> bool:
    return (
        record.get("status") == "valid"
        and record.get("trusted_evidence") is True
        and bool(record.get("trusted_provenance"))
        and record.get("redundant") is False
        and record.get("successful_runs", 0) >= PROBATION_MIN_RUNS
        and record.get("consecutive_successes", 0) >= PROBATION_MIN_RUNS
        and record.get("stable_successes", 0) >= PROBATION_MIN_STABLE_RUNS
        and days_between(record.get("first_seen"), date) >= PROBATION_MIN_DAYS
    )


def load_links(baseline: Path):
    path = baseline / "all_animeko_links.txt"
    lstat_regular(path, maximum=MAX_LINK_FILE_SIZE)
    try:
        lines = path.read_text(encoding="utf-8-sig").splitlines()
    except UnicodeDecodeError as exc:
        raise RuntimeError("链接文件UTF-8无效") from exc
    output_lines = []
    links = []
    seen = set()
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            if len(line) > 1000 or has_control(line):
                raise RuntimeError("链接文件注释或空行非法")
            output_lines.append(line)
            continue
        try:
            canonical = canonicalize_url(stripped)
        except UrlPolicyError as exc:
            raise RuntimeError(f"既有正式链接非法: {stripped[:120]}") from exc
        if canonical in seen:
            raise RuntimeError("既有正式链接含canonical重复")
        seen.add(canonical)
        links.append(canonical)
        output_lines.append(canonical)
        if len(links) > MAX_LINKS:
            raise RuntimeError("正式链接数量超过上限")
    if not links:
        raise RuntimeError("正式链接清单为空")
    return output_lines, links


def prepare_links(baseline: Path, state: dict, observed_date: str):
    lines, links = load_links(baseline)
    existing = set(links)
    existing_resources = {resource_key_for_url(url) for url in links}
    promoted = set(state["promoted"])
    ready = []
    ready_resources = set()
    for url, record in sorted(state["candidates"].items()):
        resource = resource_key_for_url(url)
        if (url in existing or url in promoted or resource in existing_resources
                or resource in ready_resources or not probation_ready(record, observed_date)):
            continue
        ready.append(url)
        ready_resources.add(resource)
    if len(ready) > MAX_LINK_ADDITIONS:
        raise RuntimeError("单次晋升链接超过上限")
    if len(existing) + len(ready) > MAX_LINKS:
        raise RuntimeError("晋升后正式链接数量超过上限")
    if ready and lines and lines[-1] != "":
        lines.extend(ready)
    else:
        lines.extend(ready)
    state["promoted"] = sorted(promoted | set(ready))
    for url in ready:
        state["candidates"][url]["status"] = "promoted"
        state["candidates"][url]["promoted_on"] = observed_date
    data = ("\n".join(lines) + "\n").encode("utf-8")
    if len(data) > MAX_LINK_FILE_SIZE:
        raise RuntimeError("晋升后链接文件超过大小上限")
    return data, ready


def add_probation_to_reports(reports: dict, state: dict, observed_date: str):
    for field in ("candidates", "redundant", "rejected"):
        for entry in reports[field][field]:
            record = state["candidates"][entry["url"]]
            entry["probation"] = {
                "successful_runs": record["successful_runs"],
                "consecutive_successes": record["consecutive_successes"],
                "stable_successes": record["stable_successes"],
                "first_seen": record["first_seen"],
                "trusted_evidence": record["trusted_evidence"],
                "trusted_provenance": record["trusted_provenance"],
                "redundant": record["redundant"],
                "ready": probation_ready(record, observed_date),
            }


def build_payloads(incoming: Path, baseline: Path):
    validate_raw_directory(incoming)
    latest, observed_date = parse_latest(incoming)
    trusted_programs = load_trusted_programs(baseline)
    direct_seeds = load_direct_seeds(baseline)
    current = load_current_state(baseline)
    observations, reports = load_observations(incoming, observed_date)
    programs = sanitize_programs(incoming, observed_date)
    state = update_state(
        current, observations, observed_date, direct_seeds, trusted_programs,
        snapshot_complete=latest["snapshot_complete"])
    add_probation_to_reports(reports, state, observed_date)
    links_data, promoted = prepare_links(baseline, state, observed_date)
    latest.update({
        "programs_identified": len(programs["programs"]),
        "candidates_checked": len(observations),
        "valid_candidates": len(reports["candidates"]["candidates"]),
        "redundant_candidates": len(reports["redundant"]["redundant"]),
        "rejected_candidates": len(reports["rejected"]["rejected"]),
        "promoted": promoted,
        "trusted_programs": len(trusted_programs),
    })
    promotion = {
        "version": 1,
        "applied_at": dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "observed_date": observed_date,
        "run_identity": latest["run_identity"],
        "snapshot_complete": latest["snapshot_complete"],
        "observations": len(observations),
        "trusted_programs": len(trusted_programs),
        "direct_seeds": len(direct_seeds),
        "promoted": promoted,
        "mode": "offline-artifact-sanitization",
        "network_used": False,
    }
    objects = {
        "discovery/state.json": state,
        "discovery/programs.json": programs,
        "discovery/candidates.json": reports["candidates"],
        "discovery/redundant.json": reports["redundant"],
        "discovery/rejected.json": reports["rejected"],
        "discovery/latest.json": latest,
        "discovery/promotion.json": promotion,
    }
    payloads = {"all_animeko_links.txt": links_data}
    for name, document in objects.items():
        safe_json_tree(document)
        reject_secrets(document)
        payloads[name] = json_bytes(document)
    if set(payloads) != set(OUTPUT_FILES):
        raise RuntimeError("内部输出文件集合错误")
    if any(not data or len(data) > MAX_ARTIFACT_FILE for data in payloads.values()):
        raise RuntimeError("sanitized输出大小非法")
    return payloads, promotion


def _write_file(path: Path, data: bytes):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    fd = os.open(path, flags, 0o600)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(path, 0o644, follow_symlinks=False)
    except Exception:
        try:
            os.close(fd)
        except OSError:
            pass
        raise


def scan_output_tree(root: Path, include_manifest=True):
    expected_root = {"all_animeko_links.txt", "discovery"}
    if include_manifest:
        expected_root.add("sanitized-manifest.json")
    expected_discovery = {Path(name).name for name in OUTPUT_FILES if name.startswith("discovery/")}
    with os.scandir(root) as entries:
        found = set()
        for entry in entries:
            found.add(entry.name)
            info = entry.stat(follow_symlinks=False)
            if entry.name == "discovery":
                if not stat.S_ISDIR(info.st_mode):
                    raise RuntimeError("sanitized discovery必须是普通目录")
            elif not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o644:
                raise RuntimeError("sanitized根文件类型或mode无效")
        if found != expected_root:
            raise RuntimeError("sanitized根目录文件集合无效")
    with os.scandir(root / "discovery") as entries:
        found = set()
        for entry in entries:
            found.add(entry.name)
            info = entry.stat(follow_symlinks=False)
            if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o644:
                raise RuntimeError("sanitized discovery文件类型或mode无效")
        if found != expected_discovery:
            raise RuntimeError("sanitized discovery文件集合无效")


def write_output_tree(output: Path, payloads: dict[str, bytes]):
    if output.exists() or output.is_symlink():
        raise RuntimeError("sanitized output必须是尚不存在的新目录")
    parent = output.parent
    try:
        parent_info = parent.lstat()
    except FileNotFoundError as exc:
        raise RuntimeError("sanitized output父目录不存在") from exc
    if not stat.S_ISDIR(parent_info.st_mode):
        raise RuntimeError("sanitized output父路径必须是普通目录")
    stage = Path(tempfile.mkdtemp(prefix=".animeko-sanitized-", dir=parent))
    try:
        for relative in OUTPUT_FILES:
            _write_file(stage / relative, payloads[relative])
        scan_output_tree(stage, include_manifest=False)
        files = {}
        for relative in OUTPUT_FILES:
            path = stage / relative
            info = path.lstat()
            if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o644:
                raise RuntimeError(f"sanitized输出mode验证失败: {relative}")
            data = path.read_bytes()
            files[relative] = {
                "size": len(data),
                "sha256": hashlib.sha256(data).hexdigest(),
                "mode": "100644",
            }
        manifest = {"version": 1, "files": files, "network_used": False}
        _write_file(stage / "sanitized-manifest.json", json_bytes(manifest))
        scan_output_tree(stage, include_manifest=True)
        os.replace(stage, output)
    except Exception:
        shutil.rmtree(stage, ignore_errors=True)
        raise


def validated_directory_argument(path: Path, label: str) -> Path:
    try:
        info = path.lstat()
    except FileNotFoundError as exc:
        raise RuntimeError(f"{label}目录不存在") from exc
    if not stat.S_ISDIR(info.st_mode):
        raise RuntimeError(f"{label}必须是非symlink普通目录")
    resolved = path.resolve(strict=True)
    if not stat.S_ISDIR(resolved.lstat().st_mode):
        raise RuntimeError(f"{label}解析后不是普通目录")
    return resolved


def paths_overlap(first: Path, second: Path) -> bool:
    return first == second or first in second.parents or second in first.parents


def apply_artifact(incoming: Path, baseline: Path, output: Path):
    incoming = validated_directory_argument(incoming, "raw")
    baseline = validated_directory_argument(baseline, "baseline")
    output = output.parent.resolve(strict=True) / output.name
    if paths_overlap(incoming, baseline) or paths_overlap(output, incoming) or paths_overlap(output, baseline):
        raise RuntimeError("raw、baseline和output不得相同或相互嵌套")
    payloads, report = build_payloads(incoming, baseline)
    write_output_tree(output, payloads)
    print(json.dumps(report, ensure_ascii=False, indent=2))


def _observation(status="valid", observed_by=None):
    return {
        "status": status,
        "sha256": "a" * 64 if status != "rejected" else None,
        "items": 1 if status != "rejected" else None,
        "new_items": 1 if status == "valid" else 0 if status == "redundant" else None,
        "overlap_items": 0 if status != "rejected" else None,
        "error": None if status != "rejected" else "rejected",
        "observed_by": observed_by or [],
    }


def run_selftests():
    import unittest

    class T(unittest.TestCase):
        def test_artifact_manual_seed_rejected(self):
            with self.assertRaises(RuntimeError):
                validate_observed_by(["manual-seed"])

        def test_trusted_program_requires_url_relationship(self):
            trusted = {"github:trusted/repo"}
            self.assertEqual(derive_trusted_provenance(
                "https://raw.githubusercontent.com/attacker/repo/main/x.json",
                ["github:trusted/repo"], set(), trusted), [])
            self.assertEqual(derive_trusted_provenance(
                "https://raw.githubusercontent.com/trusted/repo/main/x.json",
                ["github:trusted/repo"], set(), trusted), ["github:trusted/repo"])

        def test_forged_trusted_program_cannot_promote(self):
            url = "https://raw.githubusercontent.com/attacker/repo/main/x.json"
            state = {"version": 2, "candidates": {}, "promoted": []}
            observation = _observation(observed_by=["github:trusted/repo"])
            for date in ("2026-08-20", "2026-08-21", "2026-08-22"):
                state = update_state(state, {url: observation}, date, set(), {"github:trusted/repo"})
            record = state["candidates"][url]
            self.assertFalse(record["trusted_evidence"])
            self.assertFalse(probation_ready(record, "2026-08-22"))

        def test_manual_seed_is_local_exact_match(self):
            url = "https://sources.example.org/animeko.json"
            self.assertEqual(derive_trusted_provenance(url, [], {url}, set()), ["manual-seed"])
            self.assertEqual(derive_trusted_provenance(url + "?v=2", [], {url}, set()), [])

        def test_private_port_fragment_and_traversal_rejected(self):
            bad = (
                "https://127.0.0.1/source.json", "https://localhost/source.json",
                "https://example.org:0/source.json", "https://example.org:99999/source.json",
                "https://example.org/source.json#fragment",
                "https://github.com/o/r/raw/main/%252e%252e/source.json",
                "https://raw.githubusercontent.com/o/r/refs/heads/feature/foo/source.json",
            )
            for value in bad:
                with self.subTest(value=value), self.assertRaises(ValueError):
                    canonicalize_url(value)

        def test_absence_resets_consecutive(self):
            url = "https://sources.example.org/source.json"
            state = {"version": 2, "candidates": {}, "promoted": []}
            for date in ("2026-08-20", "2026-08-21"):
                state = update_state(state, {url: _observation(observed_by=["seed-candidate"])}, date, {url}, set())
            self.assertEqual(state["candidates"][url]["consecutive_successes"], 2)
            state = update_state(state, {}, "2026-08-22", {url}, set())
            state = update_state(state, {url: _observation(observed_by=["seed-candidate"])}, "2026-08-23", {url}, set())
            self.assertEqual(state["candidates"][url]["consecutive_successes"], 1)
            self.assertFalse(probation_ready(state["candidates"][url], "2026-08-23"))

        def test_calendar_gap_resets_consecutive(self):
            url = "https://sources.example.org/source.json"
            state = {"version": 2, "candidates": {}, "promoted": []}
            state = update_state(state, {url: _observation()}, "2026-08-20", {url}, set())
            state = update_state(state, {url: _observation()}, "2026-08-22", {url}, set())
            self.assertEqual(state["candidates"][url]["consecutive_successes"], 1)

        def test_rate_limit_forces_sanitized_snapshot_incomplete(self):
            self.assertTrue(sanitize_snapshot_complete(True, []))
            self.assertTrue(sanitize_snapshot_complete(True, [{"error": "missing-credential"}]))
            for code in ("http-403", "http-429", "deadline"):
                with self.subTest(code=code):
                    self.assertFalse(sanitize_snapshot_complete(True, [{"error": code}]))

        def test_incomplete_snapshot_cannot_advance_probation(self):
            url = "https://sources.example.org/source.json"
            state = {"version": 2, "candidates": {}, "promoted": []}
            state = update_state(
                state, {url: _observation()}, "2026-08-20", {url}, set(), snapshot_complete=False)
            self.assertEqual(state["candidates"][url]["successful_runs"], 0)
            self.assertEqual(state["candidates"][url]["consecutive_successes"], 0)

        def test_raw_directory_rejects_directory_symlink_and_executable(self):
            for kind in ("directory", "symlink", "executable"):
                with self.subTest(kind=kind), tempfile.TemporaryDirectory() as td:
                    root = Path(td)
                    for name in RAW_FILES:
                        (root / name).write_text("{}")
                    target = root / "latest.json"
                    if kind == "directory":
                        target.unlink()
                        target.mkdir()
                    elif kind == "symlink":
                        target.unlink()
                        target.symlink_to("programs.json")
                    else:
                        target.chmod(0o755)
                    with self.assertRaises(RuntimeError):
                        validate_raw_directory(root)

        def test_cli_directory_argument_rejects_symlink_before_resolve(self):
            with tempfile.TemporaryDirectory() as td:
                root = Path(td)
                real = root / "real"
                real.mkdir()
                link = root / "link"
                link.symlink_to(real, target_is_directory=True)
                with self.assertRaises(RuntimeError):
                    validated_directory_argument(link, "raw")
                self.assertEqual(validated_directory_argument(real, "raw"), real.resolve())

        def test_output_is_atomic_new_tree(self):
            payloads = {name: b"{}\n" for name in OUTPUT_FILES}
            payloads["all_animeko_links.txt"] = b"https://sources.example.org/x.json\n"
            with tempfile.TemporaryDirectory() as td:
                output = Path(td) / "output"
                write_output_tree(output, payloads)
                self.assertTrue((output / "sanitized-manifest.json").is_file())
                self.assertFalse((Path(td) / "sanitized-manifest.json").exists())
                with self.assertRaises(RuntimeError):
                    write_output_tree(output, payloads)

        def test_invalid_state_bool_rejected(self):
            record = {
                "first_seen": "2026-08-20", "last_seen": "2026-08-20",
                "observed_dates": ["2026-08-20"], "successful_runs": 1,
                "consecutive_successes": 1, "stable_successes": 1,
                "last_sha256": "a" * 64, "status": "valid", "evidence": [],
                "max_program_score": 1, "trusted_evidence": "false", "redundant": False,
            }
            with self.assertRaises(RuntimeError):
                canonical_state_record("https://sources.example.org/x.json", record)

        def test_unknown_raw_fields_are_not_copied(self):
            updated = "2026-08-23T00:00:00Z"
            with tempfile.TemporaryDirectory() as td:
                root = Path(td)
                documents = {
                    "candidates.json": {"version": 1, "updated": updated, "candidates": [{
                        "ok": True, "url": "https://sources.example.org/x.json",
                        "sha256": "a" * 64, "items": 1, "new_items": 1,
                        "overlap_items": 0, "observed_by": ["seed-candidate"],
                        "headers": {"Authorization": "not-copied"}, "details": ["not-copied"],
                    }]},
                    "redundant.json": {"version": 1, "updated": updated, "redundant": []},
                    "rejected.json": {"version": 1, "updated": updated, "rejected": []},
                }
                for name, document in documents.items():
                    (root / name).write_bytes(json_bytes(document))
                _, reports = load_observations(root, "2026-08-23")
                entry = reports["candidates"]["candidates"][0]
                self.assertNotIn("headers", entry)
                self.assertNotIn("details", entry)

        def test_failed_tree_write_leaves_no_output(self):
            payloads = {name: b"{}\n" for name in OUTPUT_FILES[:-1]}
            with tempfile.TemporaryDirectory() as td:
                output = Path(td) / "output"
                with self.assertRaises(KeyError):
                    write_output_tree(output, payloads)
                self.assertFalse(output.exists())

        def test_new_transport_mirror_does_not_duplicate_existing_resource(self):
            raw = "https://raw.githubusercontent.com/o/r/main/x.json"
            mirror = "https://cdn.jsdelivr.net/gh/o/r@main/x.json"
            state = {"version": 2, "candidates": {}, "promoted": []}
            for date in ("2026-08-21", "2026-08-22", "2026-08-23"):
                state = update_state(state, {mirror: _observation()}, date, {mirror}, set())
            with tempfile.TemporaryDirectory() as td:
                baseline = Path(td)
                (baseline / "all_animeko_links.txt").write_text(raw + "\n")
                _, ready = prepare_links(baseline, state, "2026-08-23")
                self.assertEqual(ready, [])

        def test_links_symlink_and_limit_rejected(self):
            with tempfile.TemporaryDirectory() as td:
                baseline = Path(td)
                target = baseline / "target"
                target.write_text("https://sources.example.org/x.json\n")
                (baseline / "all_animeko_links.txt").symlink_to(target)
                with self.assertRaises(RuntimeError):
                    load_links(baseline)
            with tempfile.TemporaryDirectory() as td:
                baseline = Path(td)
                data = "".join(f"https://source{i}.example.org/x.json\n" for i in range(MAX_LINKS + 1))
                (baseline / "all_animeko_links.txt").write_text(data)
                with self.assertRaises(RuntimeError):
                    load_links(baseline)

        def test_long_json_key_allowed_only_for_canonical_url(self):
            long_url = "https://sources.example.org/" + ("a" * 220) + ".json"
            safe_json_tree({long_url: {"status": "valid"}})
            with self.assertRaises(RuntimeError):
                safe_json_tree({"x" * 201: {}})
            with self.assertRaises(RuntimeError):
                safe_json_tree({"https://127.0.0.1/" + ("a" * 220): {}})

        def test_secret_patterns(self):
            with self.assertRaises(RuntimeError):
                reject_secrets({"error": "github_pat_abcdefghijklmnopqrstuvwxyz123456"})

    result = unittest.TextTestRunner(verbosity=1).run(
        unittest.defaultTestLoader.loadTestsFromTestCase(T))
    raise SystemExit(0 if result.wasSuccessful() else 1)


def main():
    parser = argparse.ArgumentParser(description="离线清洗Animeko发现artifact并生成独立sanitized staging tree")
    parser.add_argument("--test", action="store_true")
    parser.add_argument("--apply", type=Path, metavar="RAW_DIR")
    parser.add_argument("--baseline", type=Path, metavar="BASELINE_DIR")
    parser.add_argument("--output", type=Path, metavar="OUTPUT_DIR")
    args = parser.parse_args()
    if args.test:
        if args.apply or args.baseline or args.output:
            parser.error("--test不得与apply参数同时使用")
        run_selftests()
    if not (args.apply and args.baseline and args.output):
        parser.error("--apply、--baseline与--output必须同时提供")
    apply_artifact(args.apply, args.baseline, args.output)


if __name__ == "__main__":
    main()
