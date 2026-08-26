#!/usr/bin/env python3

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import importlib.util
import json
import math
import os
import re
import stat
import tempfile
from pathlib import Path


def _load_url_policy():
    path = Path(__file__).resolve().with_name("animeko_url_policy.py")
    if not path.is_file():
        raise RuntimeError("缺少同目录 animeko_url_policy.py")
    spec = importlib.util.spec_from_file_location("animeko_publisher_url_policy", path)
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

MAX_FILE_SIZE = 5 * 1024 * 1024
MAX_LINK_FILE_SIZE = 1024 * 1024
MAX_LINKS = 5000
MAX_CANDIDATES = 5000
MAX_POLICY_FILE = 64 * 1024
MAX_POLICY_LINES = 1000
INITIAL_STATE = {"version": 2, "candidates": {}, "promoted": []}
SHA256_RE = re.compile(r"[0-9a-f]{64}\Z")
TRUST_KEY_RE = re.compile(r"(?:manual-seed|(?:github|gitlab|gitee|codeberg):[a-z0-9_.-]+(?:/[a-z0-9_.-]+)+)\Z")
OBSERVED_BY_RE = re.compile(r"(?:seed-candidate|(?:github|gitlab|gitee|codeberg):[a-z0-9_.-]+(?:/[a-z0-9_.-]+)+)\Z")
SAFE_CODE_RE = re.compile(r"[-A-Za-z0-9_.:]{1,128}\Z")
SAFE_PATH_RE = re.compile(r"[^\x00-\x1f\x7f\\]{1,500}\Z")
SAFE_SIGNAL_RE = re.compile(r"[A-Za-z0-9_.:/-]{1,80}\Z")
SAFE_REF_RE = re.compile(r"[A-Za-z0-9_./-]{1,255}\Z")
RUN_ID_RE = re.compile(r"(?:github:[0-9]+:[0-9]+|local:[A-Za-z0-9_.:-]{1,80}|legacy:[0-9T:+Z-]{1,40})\Z")
ALLOWED_CATEGORIES = frozenset({
    "aggregator", "generator", "converter", "validator", "workflow-bot", "mirror-sync",
    "editor-or-service", "subscription",
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
EXPECTED_FILES = (
    "all_animeko_links.txt",
    "discovery/state.json",
    "discovery/programs.json",
    "discovery/candidates.json",
    "discovery/redundant.json",
    "discovery/rejected.json",
    "discovery/latest.json",
    "discovery/promotion.json",
)
MANIFEST_NAME = "sanitized-manifest.json"
STATE_RECORD_FIELDS = {
    "first_seen", "last_seen", "observed_dates", "successful_runs", "consecutive_successes",
    "stable_successes", "last_sha256", "status", "observed_by", "max_program_score",
    "trusted_evidence", "trusted_provenance", "redundant", "last_error", "last_items",
    "last_new_items", "last_overlap_items", "last_latency", "promoted_on",
}
PROGRAM_FIELDS = {
    "platform", "repository", "url", "default_branch", "commit", "score", "categories",
    "signals", "files_scanned", "evidence_files", "extracted_url_count", "generated_source_files",
}
PROBATION_FIELDS = {
    "successful_runs", "consecutive_successes", "stable_successes", "first_seen",
    "trusted_evidence", "trusted_provenance", "redundant", "ready",
}


def reject_json_constant(value):
    raise ValueError(f"非法JSON常量: {value}")


def strict_json_object(pairs):
    obj = {}
    for key, value in pairs:
        if key in obj:
            raise ValueError(f"JSON重复键: {key}")
        obj[key] = value
    return obj


def strict_json(data: bytes):
    return json.loads(
        data.decode("utf-8"), parse_constant=reject_json_constant,
        object_pairs_hook=strict_json_object)


def has_control(value: str) -> bool:
    return any(ord(ch) < 32 or ord(ch) == 127 for ch in value)


def validate_tree(value, depth=0, nodes=None):
    if nodes is None:
        nodes = [0]
    nodes[0] += 1
    if depth > 30 or nodes[0] > 100000:
        raise RuntimeError("sanitized JSON过深或节点过多")
    if isinstance(value, str):
        if len(value) > 10000 or has_control(value):
            raise RuntimeError("sanitized JSON字符串非法")
    elif isinstance(value, list):
        for item in value:
            validate_tree(item, depth + 1, nodes)
    elif isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str) or has_control(key):
                raise RuntimeError("sanitized JSON字段名非法")
            if len(key) > 200:
                try:
                    is_canonical_url_key = len(key) <= 8192 and canonicalize_url(key) == key
                except (UrlPolicyError, TypeError):
                    is_canonical_url_key = False
                if not is_canonical_url_key:
                    raise RuntimeError("sanitized超长JSON键必须是canonical URL")
            validate_tree(item, depth + 1, nodes)
    elif value is not None and not isinstance(value, (bool, int, float)):
        raise RuntimeError("sanitized JSON类型非法")
    if isinstance(value, float) and not math.isfinite(value):
        raise RuntimeError("sanitized JSON含非有限浮点数")


def valid_url(value) -> bool:
    try:
        return canonicalize_url(value) == value
    except (UrlPolicyError, TypeError):
        return False


def valid_timestamp(value) -> bool:
    if not isinstance(value, str) or len(value) > 40:
        return False
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return False
    return parsed.tzinfo is not None


def valid_date(value) -> bool:
    if not isinstance(value, str):
        return False
    try:
        return dt.date.fromisoformat(value).isoformat() == value
    except ValueError:
        return False


def is_int(value, minimum=0, maximum=1_000_000):
    return not isinstance(value, bool) and isinstance(value, int) and minimum <= value <= maximum


def is_number(value, minimum=0.0, maximum=10000.0):
    return (
        not isinstance(value, bool) and isinstance(value, (int, float))
        and math.isfinite(float(value)) and minimum <= float(value) <= maximum
    )


def safe_input_file(root: Path, relative: str) -> Path:
    path = root / relative
    try:
        info = path.lstat()
    except FileNotFoundError as exc:
        raise RuntimeError(f"sanitized文件缺失: {relative}") from exc
    if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o644:
        raise RuntimeError(f"sanitized文件必须是0644普通文件: {relative}")
    if info.st_size <= 0 or info.st_size > MAX_FILE_SIZE:
        raise RuntimeError(f"sanitized文件大小非法: {relative}")
    return path


def scan_artifact_tree(root: Path):
    try:
        root_info = root.lstat()
    except FileNotFoundError as exc:
        raise RuntimeError("sanitized artifact目录不存在") from exc
    if not stat.S_ISDIR(root_info.st_mode):
        raise RuntimeError("sanitized artifact必须是非symlink目录")
    expected_root = {MANIFEST_NAME, "all_animeko_links.txt", "discovery"}
    expected_discovery = {Path(name).name for name in EXPECTED_FILES if name.startswith("discovery/")}
    with os.scandir(root) as entries:
        found = set()
        for entry in entries:
            found.add(entry.name)
            info = entry.stat(follow_symlinks=False)
            if entry.name == "discovery":
                if not stat.S_ISDIR(info.st_mode):
                    raise RuntimeError("sanitized discovery项必须是普通目录")
            elif not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o644:
                raise RuntimeError(f"sanitized根目录含特殊或错误mode项: {entry.name}")
        if found != expected_root:
            raise RuntimeError("sanitized根目录文件集合无效")
    with os.scandir(root / "discovery") as entries:
        found = set()
        for entry in entries:
            found.add(entry.name)
            info = entry.stat(follow_symlinks=False)
            if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o644:
                raise RuntimeError(f"sanitized discovery含特殊或错误mode项: {entry.name}")
        if found != expected_discovery:
            raise RuntimeError("sanitized discovery文件集合无效")


def validate_manifest(root: Path):
    scan_artifact_tree(root)
    manifest_path = safe_input_file(root, MANIFEST_NAME)
    manifest = strict_json(manifest_path.read_bytes())
    validate_tree(manifest)
    if not isinstance(manifest, dict) or manifest.get("version") != 1:
        raise RuntimeError("sanitized manifest版本无效")
    if set(manifest) != {"version", "files", "network_used"} or manifest.get("network_used") is not False:
        raise RuntimeError("sanitized manifest字段或network_used无效")
    files = manifest.get("files")
    if not isinstance(files, dict) or set(files) != set(EXPECTED_FILES):
        raise RuntimeError("sanitized manifest文件集合不匹配")
    payloads = {}
    for relative in EXPECTED_FILES:
        path = safe_input_file(root, relative)
        data = path.read_bytes()
        metadata = files.get(relative)
        if not isinstance(metadata, dict) or set(metadata) != {"mode", "size", "sha256"}:
            raise RuntimeError(f"manifest条目无效: {relative}")
        if metadata.get("mode") != "100644" or metadata.get("size") != len(data):
            raise RuntimeError(f"manifest mode或size不匹配: {relative}")
        digest = metadata.get("sha256")
        if not isinstance(digest, str) or not SHA256_RE.fullmatch(digest):
            raise RuntimeError(f"manifest hash格式无效: {relative}")
        if hashlib.sha256(data).hexdigest() != digest:
            raise RuntimeError(f"manifest hash不匹配: {relative}")
        payloads[relative] = data
    return payloads


def validate_string_list(value, pattern, maximum=30):
    return (
        isinstance(value, list) and len(value) <= maximum
        and len(value) == len(set(value))
        and all(isinstance(item, str) and pattern.fullmatch(item) for item in value)
    )


def valid_relative_path(value):
    return (
        isinstance(value, str) and SAFE_PATH_RE.fullmatch(value) is not None
        and all(part and part not in {".", ".."} for part in value.split("/"))
    )


def validate_probation(value):
    if not isinstance(value, dict) or set(value) != PROBATION_FIELDS:
        raise RuntimeError("probation字段集合无效")
    for field in ("successful_runs", "consecutive_successes", "stable_successes"):
        if not is_int(value[field], maximum=100000):
            raise RuntimeError("probation计数无效")
    if (value["stable_successes"] > value["consecutive_successes"]
            or value["consecutive_successes"] > value["successful_runs"]):
        raise RuntimeError("probation计数关系无效")
    if not valid_date(value["first_seen"]):
        raise RuntimeError("probation first_seen无效")
    if type(value["trusted_evidence"]) is not bool or type(value["redundant"]) is not bool or type(value["ready"]) is not bool:
        raise RuntimeError("probation布尔字段无效")
    if not validate_string_list(value["trusted_provenance"], TRUST_KEY_RE, maximum=20):
        raise RuntimeError("probation trusted_provenance无效")
    if value["trusted_evidence"] != bool(value["trusted_provenance"]):
        raise RuntimeError("probation trust派生关系无效")


def validate_candidate_report(document, field: str):
    if not isinstance(document, dict) or set(document) != {"version", "updated", field}:
        raise RuntimeError(f"{field}报告字段集合无效")
    if document.get("version") != 1 or not valid_timestamp(document.get("updated")):
        raise RuntimeError(f"{field}报告版本或时间无效")
    entries = document[field]
    if not isinstance(entries, list) or len(entries) > MAX_CANDIDATES:
        raise RuntimeError(f"{field}报告条目无效")
    previous = None
    for entry in entries:
        common = {"url", "ok", "observed_by", "probation"}
        if field == "rejected":
            allowed = common | {"sha256", "error"}
            required = common | {"error"}
        else:
            allowed = common | {"sha256", "items", "new_items", "overlap_items", "redundant"}
            required = allowed
        if not isinstance(entry, dict) or not required <= set(entry) or not set(entry) <= allowed:
            raise RuntimeError(f"{field}条目字段集合无效")
        url = entry.get("url")
        if not valid_url(url) or (previous is not None and url <= previous):
            raise RuntimeError(f"{field}条目URL无效、重复或未排序")
        previous = url
        if not validate_string_list(entry.get("observed_by"), OBSERVED_BY_RE, maximum=20):
            raise RuntimeError(f"{field} observed_by无效")
        validate_probation(entry.get("probation"))
        digest = entry.get("sha256")
        if digest is not None and (not isinstance(digest, str) or not SHA256_RE.fullmatch(digest)):
            raise RuntimeError(f"{field} hash无效")
        if field == "rejected":
            if entry.get("ok") is not False or not isinstance(entry.get("error"), str) or not SAFE_CODE_RE.fullmatch(entry["error"]):
                raise RuntimeError("rejected条目状态或error无效")
        else:
            if entry.get("ok") is not True or entry.get("sha256") is None:
                raise RuntimeError(f"{field}条目状态无效")
            for name in ("items", "new_items", "overlap_items"):
                if not is_int(entry.get(name), maximum=50000):
                    raise RuntimeError(f"{field}计数无效")
            expected_redundant = field == "redundant"
            if entry.get("redundant") is not expected_redundant:
                raise RuntimeError(f"{field} redundant状态无效")
            if (field == "candidates" and entry["new_items"] < 1) or (field == "redundant" and entry["new_items"] != 0):
                raise RuntimeError(f"{field} new_items无效")


def validate_programs(document):
    if not isinstance(document, dict) or set(document) != {"version", "updated", "programs"}:
        raise RuntimeError("programs字段集合无效")
    if document.get("version") != 1 or not valid_timestamp(document.get("updated")):
        raise RuntimeError("programs版本或时间无效")
    programs = document["programs"]
    if not isinstance(programs, list) or len(programs) > 500:
        raise RuntimeError("programs条目数无效")
    identities = set()
    for item in programs:
        if not isinstance(item, dict) or set(item) != PROGRAM_FIELDS:
            raise RuntimeError("program字段集合无效")
        if item.get("platform") not in {"github", "gitlab", "gitee", "codeberg"}:
            raise RuntimeError("program platform无效")
        identity = f"{item['platform']}:{str(item.get('repository', '')).casefold()}"
        if not TRUST_KEY_RE.fullmatch(identity) or identity in identities:
            raise RuntimeError("program identity无效或重复")
        identities.add(identity)
        host = {"github": "github.com", "gitlab": "gitlab.com", "gitee": "gitee.com", "codeberg": "codeberg.org"}[item["platform"]]
        if item.get("url") != f"https://{host}/{item['repository']}":
            raise RuntimeError("program URL无效")
        if not isinstance(item.get("commit"), str) or not re.fullmatch(r"[0-9a-f]{7,64}", item["commit"]):
            raise RuntimeError("program commit无效")
        branch = item.get("default_branch")
        if not isinstance(branch, str) or not SAFE_REF_RE.fullmatch(branch) or ".." in branch:
            raise RuntimeError("program default_branch无效")
        for name in ("score", "files_scanned", "extracted_url_count"):
            if not is_int(item.get(name), maximum=10000):
                raise RuntimeError(f"program {name}无效")
        categories = item.get("categories")
        signals = item.get("signals")
        if (not isinstance(categories, list) or categories != sorted(set(categories))
                or len(categories) > 20 or any(value not in ALLOWED_CATEGORIES for value in categories)):
            raise RuntimeError("program categories无效")
        if not validate_string_list(signals, SAFE_SIGNAL_RE, maximum=30) or signals != sorted(signals):
            raise RuntimeError("program signals无效")
        evidence = item.get("evidence_files")
        generated = item.get("generated_source_files")
        if not isinstance(evidence, list) or len(evidence) > 30 or not isinstance(generated, list) or len(generated) > 240:
            raise RuntimeError("program嵌套条目数量无效")
        for entry in evidence:
            if (not isinstance(entry, dict) or set(entry) != {"path", "score"}
                    or not valid_relative_path(entry.get("path")) or not is_int(entry.get("score"), maximum=1000)):
                raise RuntimeError("program evidence_file无效")
        for entry in generated:
            if not isinstance(entry, dict) or set(entry) != {"path", "items", "url"}:
                raise RuntimeError("program generated_source无效")
            if (not valid_relative_path(entry.get("path")) or not valid_url(entry.get("url"))
                    or not is_int(entry.get("items"), maximum=50000)
                    or repository_key_for_url(entry["url"]) != identity):
                raise RuntimeError("program generated_source内容无效")


def program_identity(item: dict) -> str:
    return f"{item['platform']}:{item['repository'].casefold()}"


def validate_program_transition(current: list[dict], new: list[dict]):
    current_identities = {program_identity(item) for item in current}
    new_identities = {program_identity(item) for item in new}
    if not current_identities <= new_identities:
        raise RuntimeError("sanitized programs不得删除历史program")


def load_current_programs_baseline(path=Path("discovery/programs.json")) -> list[dict]:
    try:
        info = path.lstat()
    except FileNotFoundError:
        return []
    if (not stat.S_ISREG(info.st_mode) or info.st_mode & 0o111
            or info.st_size <= 0 or info.st_size > MAX_FILE_SIZE):
        raise RuntimeError("publish checkout既有programs文件无效")
    document = strict_json(path.read_bytes())
    validate_tree(document)
    validate_programs(document)
    return document["programs"]


def load_local_policy_lines(path: Path):
    try:
        info = path.lstat()
    except FileNotFoundError as exc:
        raise RuntimeError(f"缺少本地trust policy: {path}") from exc
    if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o111 or info.st_size > MAX_POLICY_FILE:
        raise RuntimeError(f"本地trust policy文件类型、mode或大小无效: {path}")
    lines = path.read_text(encoding="utf-8-sig").splitlines()
    if len(lines) > MAX_POLICY_LINES:
        raise RuntimeError("本地trust policy行数过多")
    return [line.strip() for line in lines if line.strip() and not line.lstrip().startswith("#")]


def load_local_trust_policy():
    trusted = set()
    for value in load_local_policy_lines(Path("discovery/trusted_programs.txt")):
        value = value.casefold()
        if not TRUST_KEY_RE.fullmatch(value) or value == "manual-seed":
            raise RuntimeError("本地trusted_programs条目无效")
        trusted.add(value)
    seeds = set()
    for value in load_local_policy_lines(Path("discovery/seeds.txt")):
        try:
            if is_repository_seed(value):
                continue
            seeds.add(canonicalize_url(value))
        except UrlPolicyError as exc:
            raise RuntimeError("本地seed URL无效") from exc
    return seeds, trusted


def validate_state(document, direct_seeds: set[str], trusted_programs: set[str]):
    if not isinstance(document, dict) or set(document) != {"version", "updated", "candidates", "promoted"}:
        raise RuntimeError("state字段集合无效")
    if document.get("version") != 2 or not valid_timestamp(document.get("updated")):
        raise RuntimeError("state版本或时间无效")
    candidates = document["candidates"]
    promoted = document["promoted"]
    if not isinstance(candidates, dict) or len(candidates) > MAX_CANDIDATES:
        raise RuntimeError("state candidates无效")
    if not isinstance(promoted, list) or len(promoted) > MAX_LINKS or promoted != sorted(set(promoted)):
        raise RuntimeError("state promoted无效")
    if any(not valid_url(url) for url in promoted):
        raise RuntimeError("state promoted URL无效")
    for url, record in candidates.items():
        if not valid_url(url) or not isinstance(record, dict) or not set(record) <= STATE_RECORD_FIELDS:
            raise RuntimeError("state候选字段无效")
        required = STATE_RECORD_FIELDS - {"promoted_on"}
        if not required <= set(record):
            raise RuntimeError("state候选缺少字段")
        if record["status"] not in {"new", "valid", "rejected", "redundant", "promoted", "absent"}:
            raise RuntimeError("state候选status无效")
        if type(record["trusted_evidence"]) is not bool or type(record["redundant"]) is not bool:
            raise RuntimeError("state候选bool字段无效")
        if not validate_string_list(record["observed_by"], OBSERVED_BY_RE, maximum=20):
            raise RuntimeError("state observed_by无效")
        if not validate_string_list(record["trusted_provenance"], TRUST_KEY_RE, maximum=20):
            raise RuntimeError("state trusted_provenance无效")
        if record["trusted_evidence"] != bool(record["trusted_provenance"]):
            raise RuntimeError("state trust派生关系无效")
        for provenance in record["trusted_provenance"]:
            if provenance == "manual-seed":
                if url not in direct_seeds:
                    raise RuntimeError("state manual-seed并非本地精确seed")
            elif (provenance not in trusted_programs or provenance not in record["observed_by"]
                  or repository_key_for_url(url) != provenance):
                raise RuntimeError("state trusted program provenance关系无效")
        dates = record["observed_dates"]
        if not isinstance(dates, list) or dates != sorted(set(dates)) or len(dates) > 30 or any(not valid_date(x) for x in dates):
            raise RuntimeError("state observed_dates无效")
        if not valid_date(record["first_seen"]) or not valid_date(record["last_seen"]):
            raise RuntimeError("state日期无效")
        counters = [record["successful_runs"], record["consecutive_successes"], record["stable_successes"]]
        if any(not is_int(value, maximum=100000) for value in counters):
            raise RuntimeError("state计数无效")
        if counters[0] > len(dates) or counters[2] > counters[1] or counters[1] > counters[0]:
            raise RuntimeError("state计数关系无效")
        digest = record["last_sha256"]
        if digest is not None and (not isinstance(digest, str) or not SHA256_RE.fullmatch(digest)):
            raise RuntimeError("state hash无效")
        if record.get("last_error") is not None and not SAFE_CODE_RE.fullmatch(record["last_error"]):
            raise RuntimeError("state error无效")
        for field in ("last_items", "last_new_items", "last_overlap_items"):
            if record[field] is not None and not is_int(record[field], maximum=50000):
                raise RuntimeError("state item计数无效")
        if record["last_latency"] is not None and not is_number(record["last_latency"], maximum=7200):
            raise RuntimeError("state latency无效")
        if "promoted_on" in record and not valid_date(record["promoted_on"]):
            raise RuntimeError("state promoted_on无效")


def validate_latest(document):
    fields = {
        "version", "updated", "duration_s", "repositories_discovered", "programs_identified",
        "candidates_extracted", "candidates_checked", "valid_candidates", "redundant_candidates",
        "rejected_candidates", "promoted", "input_bytes", "regex_validations", "trusted_programs",
        "provider_errors", "analysis_mode", "third_party_code_executed", "snapshot_complete",
        "run_identity",
    }
    if not isinstance(document, dict) or set(document) != fields or document.get("version") != 1:
        raise RuntimeError("latest字段集合或版本无效")
    if not valid_timestamp(document["updated"]) or document["analysis_mode"] != "static-only":
        raise RuntimeError("latest时间或分析模式无效")
    if document["third_party_code_executed"] is not False or type(document["snapshot_complete"]) is not bool:
        raise RuntimeError("latest安全声明无效")
    for name in (
            "repositories_discovered", "programs_identified", "candidates_extracted", "candidates_checked",
            "valid_candidates", "redundant_candidates", "rejected_candidates", "regex_validations",
            "trusted_programs"):
        if not is_int(document[name], maximum=100000):
            raise RuntimeError(f"latest {name}无效")
    if not is_number(document["duration_s"]):
        raise RuntimeError("latest duration无效")
    if not isinstance(document["promoted"], list) or any(not valid_url(url) for url in document["promoted"]):
        raise RuntimeError("latest promoted无效")
    if not isinstance(document["provider_errors"], list) or len(document["provider_errors"]) > 100:
        raise RuntimeError("latest provider_errors无效")
    for item in document["provider_errors"]:
        if not isinstance(item, dict) or not set(item) <= {"error", "provider", "phase", "repository"}:
            raise RuntimeError("latest provider_error字段无效")
        if not isinstance(item.get("error"), str) or not SAFE_CODE_RE.fullmatch(item["error"]):
            raise RuntimeError("latest provider error code无效")
    inputs = document["input_bytes"]
    if not isinstance(inputs, dict) or set(inputs) != {"candidate_cache", "candidate_network", "platform_static_analysis"}:
        raise RuntimeError("latest input_bytes字段无效")
    if any(not is_int(value, maximum=1024 * 1024 * 1024) for value in inputs.values()):
        raise RuntimeError("latest input_bytes计数无效")


def validate_promotion(document):
    fields = {
        "version", "applied_at", "observed_date", "run_identity", "snapshot_complete", "observations",
        "trusted_programs", "direct_seeds", "promoted", "mode", "network_used",
    }
    if not isinstance(document, dict) or set(document) != fields or document.get("version") != 1:
        raise RuntimeError("promotion字段集合或版本无效")
    if not valid_timestamp(document["applied_at"]) or not valid_date(document["observed_date"]):
        raise RuntimeError("promotion时间无效")
    if document["network_used"] is not False or document["mode"] != "offline-artifact-sanitization":
        raise RuntimeError("promotion离线声明无效")
    if type(document["snapshot_complete"]) is not bool:
        raise RuntimeError("promotion snapshot_complete无效")
    for name in ("observations", "trusted_programs", "direct_seeds"):
        if not is_int(document[name], maximum=100000):
            raise RuntimeError(f"promotion {name}无效")
    if not isinstance(document["promoted"], list) or any(not valid_url(url) for url in document["promoted"]):
        raise RuntimeError("promotion promoted无效")


def parse_link_sequence(data: bytes) -> list[str]:
    if len(data) > MAX_LINK_FILE_SIZE:
        raise RuntimeError("正式链接文件过大")
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise RuntimeError("正式链接UTF-8无效") from exc
    links = []
    seen = set()
    for line in text.splitlines():
        value = line.strip()
        if not value or value.startswith("#"):
            if len(line) > 1000 or has_control(line):
                raise RuntimeError("正式链接注释非法")
            continue
        if not valid_url(value) or value in seen:
            raise RuntimeError("正式链接非法、未canonicalize或重复")
        seen.add(value)
        links.append(value)
        if len(links) > MAX_LINKS:
            raise RuntimeError("正式链接数量超过上限")
    if not links:
        raise RuntimeError("正式链接清单为空")
    return links


def validate_links(data: bytes):
    return len(parse_link_sequence(data))


def merge_pending_link_payloads(current_data: bytes, existing_data: bytes, target_data: bytes) -> bytes:
    current = parse_link_sequence(current_data)
    existing = parse_link_sequence(existing_data)
    target = parse_link_sequence(target_data)
    if existing[:len(current)] != current or target[:len(current)] != current:
        raise RuntimeError("待确认或本轮links不再以当前main正式链接为前缀")

    merged_pending = []
    seen_urls = set(current)
    seen_resources = {resource_key_for_url(url) for url in current}
    for url in existing[len(current):] + target[len(current):]:
        if url in seen_urls:
            continue
        resource = resource_key_for_url(url)
        if resource in seen_resources:
            continue
        seen_urls.add(url)
        seen_resources.add(resource)
        merged_pending.append(url)
    if len(current) + len(merged_pending) > MAX_LINKS:
        raise RuntimeError("累计待确认链接后超过正式链接数量上限")
    if not merged_pending:
        return current_data
    base = current_data if current_data.endswith(b"\n") else current_data + b"\n"
    output = base + b"".join((url + "\n").encode("utf-8") for url in merged_pending)
    parse_link_sequence(output)
    return output


def read_link_payload_file(path: Path) -> bytes:
    try:
        info = path.lstat()
    except FileNotFoundError as exc:
        raise RuntimeError(f"links输入文件缺失: {path}") from exc
    if (not stat.S_ISREG(info.st_mode) or info.st_mode & 0o111
            or info.st_size <= 0 or info.st_size > MAX_LINK_FILE_SIZE):
        raise RuntimeError(f"links输入文件类型、mode或大小无效: {path}")
    data = path.read_bytes()
    parse_link_sequence(data)
    return data


def merge_pending_link_files(current: Path, existing: Path, target: Path, output: Path):
    payload = merge_pending_link_payloads(
        read_link_payload_file(current),
        read_link_payload_file(existing),
        read_link_payload_file(target),
    )
    _write_atomic(output, payload)
    print(json.dumps({
        "merged": True,
        "links": len(parse_link_sequence(payload)),
        "output": str(output),
    }, ensure_ascii=False))


def validate_link_transition(current_links: list[str], new_links: list[str], promoted: list[str]):
    if promoted != sorted(set(promoted)):
        raise RuntimeError("promotion.promoted必须排序且唯一")
    if new_links != current_links + promoted:
        raise RuntimeError("正式links变化必须严格等于既有顺序加promotion.promoted追加")


def validate_run_binding(latest: dict, promotion: dict, expected_run_identity: str, *, current_date=None):
    if not isinstance(expected_run_identity, str) or not RUN_ID_RE.fullmatch(expected_run_identity):
        raise RuntimeError("expected run identity格式无效")
    if latest["run_identity"] != expected_run_identity or promotion["run_identity"] != expected_run_identity:
        raise RuntimeError("sanitized artifact与当前run identity不匹配")
    observed_date = dt.date.fromisoformat(promotion["observed_date"])
    current_date = current_date or dt.datetime.now(dt.timezone.utc).date()
    if abs((current_date - observed_date).days) > 1:
        raise RuntimeError("sanitized artifact observed_date已过期")
    latest_date = (
        dt.datetime.fromisoformat(latest["updated"].replace("Z", "+00:00"))
        .astimezone(dt.timezone.utc).date()
    )
    if latest_date != observed_date:
        raise RuntimeError("latest.updated与promotion.observed_date不一致")


def load_current_state_baseline(path=Path("discovery/state.json")):
    try:
        info = path.lstat()
    except FileNotFoundError:
        return {"version": 2, "candidates": {}, "promoted": []}
    if (not stat.S_ISREG(info.st_mode) or info.st_mode & 0o111
            or info.st_size <= 0 or info.st_size > MAX_FILE_SIZE):
        raise RuntimeError("publish checkout既有state文件无效")
    document = strict_json(path.read_bytes())
    validate_tree(document)
    if not isinstance(document, dict) or document.get("version") != INITIAL_STATE["version"]:
        raise RuntimeError("publish checkout既有state结构无效")
    if set(document) - {"version", "updated", "candidates", "promoted"}:
        raise RuntimeError("publish checkout既有state字段集合无效")
    candidates = document.get("candidates")
    promoted = document.get("promoted")
    if not isinstance(candidates, dict) or len(candidates) > MAX_CANDIDATES:
        raise RuntimeError("publish checkout既有state candidates无效")
    if (not isinstance(promoted, list) or len(promoted) > MAX_LINKS
            or promoted != sorted(set(promoted)) or any(not valid_url(url) for url in promoted)):
        raise RuntimeError("publish checkout既有state promoted无效")
    if "updated" in document and not valid_timestamp(document["updated"]):
        raise RuntimeError("publish checkout既有state updated无效")
    return document


def validate_payloads(payloads: dict[str, bytes], expected_run_identity: str):
    new_links = parse_link_sequence(payloads["all_animeko_links.txt"])
    link_count = len(new_links)
    documents = {}
    for relative, data in payloads.items():
        if not relative.endswith(".json"):
            continue
        document = strict_json(data)
        validate_tree(document)
        serialized = json.dumps(document, ensure_ascii=False, allow_nan=False)
        if any(pattern.search(serialized) for pattern in SECRET_PATTERNS):
            raise RuntimeError(f"sanitized JSON疑似包含secret: {relative}")
        documents[relative] = document
    direct_seeds, trusted_programs = load_local_trust_policy()
    validate_state(documents["discovery/state.json"], direct_seeds, trusted_programs)
    programs_document = documents["discovery/programs.json"]
    validate_programs(programs_document)
    validate_program_transition(
        load_current_programs_baseline(), programs_document["programs"])
    validate_candidate_report(documents["discovery/candidates.json"], "candidates")
    validate_candidate_report(documents["discovery/redundant.json"], "redundant")
    validate_candidate_report(documents["discovery/rejected.json"], "rejected")
    latest = documents["discovery/latest.json"]
    promotion = documents["discovery/promotion.json"]
    state = documents["discovery/state.json"]
    validate_latest(latest)
    validate_promotion(promotion)
    validate_run_binding(latest, promotion, expected_run_identity)

    reports = {
        field: documents[f"discovery/{field}.json"][field]
        for field in ("candidates", "redundant", "rejected")
    }
    report_urls = [entry["url"] for entries in reports.values() for entry in entries]
    if len(report_urls) != len(set(report_urls)) or any(url not in state["candidates"] for url in report_urls):
        raise RuntimeError("跨报告候选URL重复或不在state")
    for entries in reports.values():
        for entry in entries:
            record = state["candidates"][entry["url"]]
            expected_probation = {
                "successful_runs": record["successful_runs"],
                "consecutive_successes": record["consecutive_successes"],
                "stable_successes": record["stable_successes"],
                "first_seen": record["first_seen"],
                "trusted_evidence": record["trusted_evidence"],
                "trusted_provenance": record["trusted_provenance"],
                "redundant": record["redundant"],
                "ready": (
                    (record["status"] == "valid"
                     or (record["status"] == "promoted"
                         and entry["url"] in promotion["promoted"]
                         and record.get("promoted_on") == promotion["observed_date"]))
                    and record["trusted_evidence"] is True
                    and bool(record["trusted_provenance"]) and record["redundant"] is False
                    and record["successful_runs"] >= 3 and record["consecutive_successes"] >= 3
                    and record["stable_successes"] >= 3
                    and (dt.date.fromisoformat(promotion["observed_date"])
                         - dt.date.fromisoformat(record["first_seen"])).days >= 2
                ),
            }
            if entry["probation"] != expected_probation:
                raise RuntimeError("报告probation与state不一致")
    if latest["candidates_checked"] != len(report_urls):
        raise RuntimeError("latest candidates_checked与报告不一致")
    if latest["valid_candidates"] != len(reports["candidates"]):
        raise RuntimeError("latest valid_candidates与报告不一致")
    if latest["redundant_candidates"] != len(reports["redundant"]):
        raise RuntimeError("latest redundant_candidates与报告不一致")
    if latest["rejected_candidates"] != len(reports["rejected"]):
        raise RuntimeError("latest rejected_candidates与报告不一致")
    if latest["programs_identified"] != len(documents["discovery/programs.json"]["programs"]):
        raise RuntimeError("latest programs_identified与报告不一致")
    if latest["promoted"] != promotion["promoted"]:
        raise RuntimeError("latest与promotion的promoted不一致")
    if latest["run_identity"] != promotion["run_identity"] or latest["snapshot_complete"] is not promotion["snapshot_complete"]:
        raise RuntimeError("latest与promotion run identity不一致")
    promoted_now = promotion["promoted"]
    for url in promoted_now:
        record = state["candidates"].get(url)
        if (not isinstance(record, dict) or record.get("status") != "promoted"
                or url not in state["promoted"]):
            raise RuntimeError("promotion必须同步为滚动PR中的promoted候选")
    if not set(state["promoted"]) <= set(new_links):
        raise RuntimeError("state.promoted只能记录当前正式清单或滚动PR中的链接")
    promotion_resources = [resource_key_for_url(url) for url in promoted_now]
    if len(promotion_resources) != len(set(promotion_resources)):
        raise RuntimeError("promotion含同一资源的transport变体")

    current_path = Path("all_animeko_links.txt")
    try:
        current_info = current_path.lstat()
    except FileNotFoundError as exc:
        raise RuntimeError("publish checkout缺少既有链接清单") from exc
    if not stat.S_ISREG(current_info.st_mode) or current_info.st_mode & 0o111 or current_info.st_size > MAX_LINK_FILE_SIZE:
        raise RuntimeError("publish checkout既有链接清单无效")
    current_data = current_path.read_bytes()
    current_links = parse_link_sequence(current_data)
    validate_link_transition(current_links, new_links, promoted_now)
    current_resources = {resource_key_for_url(url) for url in current_links}
    if any(resource in current_resources for resource in promotion_resources):
        raise RuntimeError("promotion试图新增既有资源的transport变体")

    current_state = load_current_state_baseline()
    current_candidates = current_state["candidates"]
    current_promoted = current_state["promoted"]
    if not set(current_candidates) <= set(state["candidates"]):
        raise RuntimeError("sanitized state不得删除历史candidate")
    if not set(current_promoted) <= set(state["promoted"]):
        raise RuntimeError("sanitized state不得删除历史promoted链接")
    for url, old_record in current_candidates.items():
        new_record = state["candidates"][url]
        if not isinstance(old_record, dict):
            raise RuntimeError("publish checkout历史candidate结构无效")
        if old_record.get("first_seen") != new_record.get("first_seen"):
            raise RuntimeError("sanitized state不得改写candidate first_seen")
        old_success = old_record.get("successful_runs", 0)
        if not is_int(old_success, maximum=100000) or new_record["successful_runs"] < min(old_success, 30):
            raise RuntimeError("sanitized state不得降低candidate successful_runs")
        old_dates = old_record.get("observed_dates", [])
        new_dates = new_record["observed_dates"]
        if not isinstance(old_dates, list) or any(not valid_date(value) for value in old_dates):
            raise RuntimeError("publish checkout历史candidate日期无效")
        if old_dates != new_dates:
            if len(old_dates) < 30:
                if new_dates[:len(old_dates)] != old_dates:
                    raise RuntimeError("sanitized state不得删除或重排candidate历史日期")
            elif new_dates[:29] != old_dates[1:]:
                raise RuntimeError("sanitized state历史日期只能按30日窗口滚动")
    return link_count


def _write_atomic(path: Path, data: bytes):
    if path.parent.is_symlink():
        raise RuntimeError(f"目标目录不得为symlink: {path.parent}")
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.tmp-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary, 0o644, follow_symlinks=False)
        os.replace(temporary, path)
    except Exception:
        try:
            os.close(fd)
        except OSError:
            pass
        try:
            os.remove(temporary)
        except OSError:
            pass
        raise


def apply_payloads_transactionally(payloads: dict[str, bytes]):
    originals = {}
    for relative in EXPECTED_FILES:
        target = Path(relative)
        if target.parent.is_symlink() or target.is_symlink():
            raise RuntimeError(f"目标路径不得为symlink: {relative}")
        if target.exists():
            info = target.lstat()
            if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_FILE_SIZE:
                raise RuntimeError(f"既有目标必须是受限普通文件: {relative}")
            originals[relative] = target.read_bytes()
        else:
            originals[relative] = None
    written = []
    try:
        for relative in EXPECTED_FILES:
            _write_atomic(Path(relative), payloads[relative])
            written.append(relative)
    except Exception as exc:
        rollback_errors = []
        for relative in reversed(written):
            target = Path(relative)
            try:
                if originals[relative] is None:
                    target.unlink(missing_ok=True)
                else:
                    _write_atomic(target, originals[relative])
            except Exception as rollback_exc:
                rollback_errors.append(f"{relative}:{type(rollback_exc).__name__}")
        if rollback_errors:
            raise RuntimeError("publish失败且rollback不完整: " + ",".join(rollback_errors)) from exc
        raise


def verify_sanitized(root: Path, expected_run_identity: str):
    payloads = validate_manifest(root)
    link_count = validate_payloads(payloads, expected_run_identity)
    manifest_sha256 = hashlib.sha256((root / MANIFEST_NAME).read_bytes()).hexdigest()
    return payloads, link_count, manifest_sha256


def apply_sanitized(root: Path, expected_run_identity: str, *, apply: bool):
    payloads, link_count, manifest_sha256 = verify_sanitized(root, expected_run_identity)
    if apply:
        apply_payloads_transactionally(payloads)
    print(json.dumps({
        "verified": True,
        "applied": apply,
        "files": len(EXPECTED_FILES),
        "links": link_count,
        "manifest_sha256": manifest_sha256,
        "run_identity": expected_run_identity,
        "network_used": False,
    }, ensure_ascii=False, indent=2))


def run_selftests():
    import unittest

    class T(unittest.TestCase):
        def test_tree_scan_rejects_extra_and_special(self):
            with tempfile.TemporaryDirectory() as td:
                root = Path(td)
                (root / "extra").write_text("x")
                with self.assertRaises(RuntimeError):
                    scan_artifact_tree(root)

        def test_strict_json_rejects_duplicates(self):
            with self.assertRaises(ValueError):
                strict_json(b'{"x":1,"x":2}')

        def test_url_policy_rejects_private_port_fragment(self):
            for value in (
                    "https://127.0.0.1/x.json", "https://localhost/x.json",
                    "https://example.org:0/x.json", "https://example.org:99999/x.json",
                    "https://example.org/x.json#fragment"):
                with self.subTest(value=value):
                    self.assertFalse(valid_url(value))

        def test_long_json_key_allowed_only_for_canonical_url(self):
            long_url = "https://sources.example.org/" + ("a" * 220) + ".json"
            validate_tree({long_url: {"status": "valid"}})
            with self.assertRaises(RuntimeError):
                validate_tree({"x" * 201: {}})
            with self.assertRaises(RuntimeError):
                validate_tree({"https://127.0.0.1/" + ("a" * 220): {}})

        def test_links_reject_duplicates(self):
            with self.assertRaises(RuntimeError):
                validate_links(b"https://sources.example.org/x.json\nhttps://sources.example.org/x.json\n")

        def test_empty_promotion_cannot_replace_or_delete_links(self):
            current = ["https://sources.example.org/original.json"]
            for changed in (
                    [],
                    ["https://sources.example.org/replaced.json"],
                    current + ["https://sources.example.org/undeclared.json"]):
                with self.subTest(changed=changed), self.assertRaises(RuntimeError):
                    validate_link_transition(current, changed, [])
            validate_link_transition(current, current, [])

        def test_only_declared_sorted_append_is_allowed(self):
            current = ["https://sources.example.org/original.json"]
            promoted = ["https://sources.example.org/a.json", "https://sources.example.org/b.json"]
            validate_link_transition(current, current + promoted, promoted)
            with self.assertRaises(RuntimeError):
                validate_link_transition(current, current + list(reversed(promoted)), list(reversed(promoted)))

        def test_pending_links_accumulate_without_replacing_old_items(self):
            current = b"# official\nhttps://sources.example.org/original.json\n"
            old = current + b"https://sources.example.org/week-one.json\n"
            new = current + b"https://sources.example.org/week-two.json\n"
            merged = merge_pending_link_payloads(current, old, new)
            self.assertEqual(parse_link_sequence(merged), [
                "https://sources.example.org/original.json",
                "https://sources.example.org/week-one.json",
                "https://sources.example.org/week-two.json",
            ])
            self.assertTrue(merged.startswith(current))

        def test_pending_links_deduplicate_url_and_resource_variants(self):
            current = b"https://sources.example.org/original.json\n"
            raw = "https://raw.githubusercontent.com/o/r/main/x.json"
            mirror = "https://cdn.jsdelivr.net/gh/o/r@main/x.json"
            old = current + (raw + "\n").encode()
            new = current + (raw + "\n" + mirror + "\n").encode()
            merged = merge_pending_link_payloads(current, old, new)
            self.assertEqual(parse_link_sequence(merged), [
                "https://sources.example.org/original.json", raw,
            ])

        def test_pending_links_reject_stale_or_replaced_main_prefix(self):
            current = b"https://sources.example.org/original.json\n"
            replaced = b"https://sources.example.org/replaced.json\n"
            with self.assertRaises(RuntimeError):
                merge_pending_link_payloads(current, replaced, current)
            with self.assertRaises(RuntimeError):
                merge_pending_link_payloads(current, current, replaced)

        def test_run_binding_rejects_mismatch_and_stale_artifact(self):
            latest = {"run_identity": "github:1:1", "updated": "2026-08-23T00:00:00Z"}
            promotion = {"run_identity": "github:1:1", "observed_date": "2026-08-23"}
            validate_run_binding(latest, promotion, "github:1:1", current_date=dt.date(2026, 8, 24))
            with self.assertRaises(RuntimeError):
                validate_run_binding(latest, promotion, "github:2:1", current_date=dt.date(2026, 8, 24))
            with self.assertRaises(RuntimeError):
                validate_run_binding(latest, promotion, "github:1:1", current_date=dt.date(2026, 8, 25))

        def test_run_binding_normalizes_offset_timestamp_to_utc(self):
            latest = {"run_identity": "github:1:1", "updated": "2026-08-24T01:00:00+02:00"}
            promotion = {"run_identity": "github:1:1", "observed_date": "2026-08-23"}
            validate_run_binding(latest, promotion, "github:1:1", current_date=dt.date(2026, 8, 24))

        def test_missing_state_uses_safe_bootstrap_but_symlink_fails(self):
            with tempfile.TemporaryDirectory() as td:
                root = Path(td)
                missing = root / "state.json"
                self.assertEqual(load_current_state_baseline(missing), INITIAL_STATE)
                target = root / "target.json"
                target.write_text('{"version":2,"candidates":{},"promoted":[]}')
                missing.symlink_to(target)
                with self.assertRaises(RuntimeError):
                    load_current_state_baseline(missing)

        def test_program_transition_is_append_only_by_identity(self):
            first = {"platform": "github", "repository": "owner/first"}
            second = {"platform": "gitlab", "repository": "owner/second"}
            validate_program_transition([first], [first, second])
            with self.assertRaises(RuntimeError):
                validate_program_transition([first, second], [second])

        def test_missing_program_inventory_bootstraps_but_symlink_fails(self):
            with tempfile.TemporaryDirectory() as td:
                root = Path(td)
                missing = root / "programs.json"
                self.assertEqual(load_current_programs_baseline(missing), [])
                target = root / "target.json"
                target.write_text('{"version":1,"updated":"2026-08-24T00:00:00Z","programs":[]}')
                missing.symlink_to(target)
                with self.assertRaises(RuntimeError):
                    load_current_programs_baseline(missing)

        def test_expected_paths_exclude_workflow_and_manifest(self):
            self.assertNotIn(".github/workflows/discover.yml", EXPECTED_FILES)
            self.assertNotIn(MANIFEST_NAME, EXPECTED_FILES)
            self.assertEqual(len(EXPECTED_FILES), len(set(EXPECTED_FILES)))

        def test_secret_patterns(self):
            serialized = '{"x":"glpat-abcdefghijklmnop"}'
            self.assertTrue(any(pattern.search(serialized) for pattern in SECRET_PATTERNS))

        def test_atomic_writer_sets_mode(self):
            with tempfile.TemporaryDirectory() as td:
                path = Path(td) / "x"
                _write_atomic(path, b"x")
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o644)

    result = unittest.TextTestRunner(verbosity=1).run(
        unittest.defaultTestLoader.loadTestsFromTestCase(T))
    raise SystemExit(0 if result.wasSuccessful() else 1)


def main():
    parser = argparse.ArgumentParser(description="严格验证并安装离线sanitized discovery artifact")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--apply", type=Path, metavar="DIR")
    group.add_argument("--verify", type=Path, metavar="DIR")
    group.add_argument("--test", action="store_true")
    group.add_argument(
        "--merge-pending-links", type=Path, nargs=4,
        metavar=("CURRENT", "EXISTING", "TARGET", "OUTPUT"))
    parser.add_argument("--expected-run-identity")
    args = parser.parse_args()
    if args.test:
        if args.expected_run_identity:
            parser.error("--test不得携带expected run identity")
        run_selftests()
    if args.merge_pending_links:
        if args.expected_run_identity:
            parser.error("--merge-pending-links不得携带expected run identity")
        merge_pending_link_files(*args.merge_pending_links)
        return
    artifact = args.apply or args.verify
    if not args.expected_run_identity:
        parser.error("--apply/--verify必须提供--expected-run-identity")
    apply_sanitized(
        artifact, args.expected_run_identity, apply=args.apply is not None)


if __name__ == "__main__":
    main()
