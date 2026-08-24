#!/usr/bin/env python3

from __future__ import annotations

import argparse
import base64
import copy
import datetime as dt
import hashlib
import html
import importlib.util
import json
import os
import re
import stat
import sys
import tempfile
import time
from collections import defaultdict
from pathlib import Path
from urllib.parse import quote, unquote, urlsplit

from animeko_url_policy import UrlPolicyError, canonicalize_url

try:
    import requests
except ImportError:
    sys.exit("缺少依赖 requests：请先安装 requests==2.34.2 urllib3==2.7.0")


def env_int(name: str, default: int, minimum: int, maximum: int) -> int:
    try:
        value = int(os.environ.get(name, default))
    except (TypeError, ValueError):
        return default
    return min(max(value, minimum), maximum)


DISCOVERY_DIR = Path("discovery")
STATE_PATH = DISCOVERY_DIR / "state.json"
PROGRAMS_PATH = DISCOVERY_DIR / "programs.json"
CANDIDATES_PATH = DISCOVERY_DIR / "candidates.json"
REJECTED_PATH = DISCOVERY_DIR / "rejected.json"
REDUNDANT_PATH = DISCOVERY_DIR / "redundant.json"
LATEST_PATH = DISCOVERY_DIR / "latest.json"
SEEDS_PATH = DISCOVERY_DIR / "seeds.txt"
TRUSTED_PROGRAMS_PATH = DISCOVERY_DIR / "trusted_programs.txt"
LINKS_PATH = Path("all_animeko_links.txt")
LOCK_PATH = Path(".discover_animeko.lock")

STATE_VERSION = 2
MAX_API_RESPONSE = 4 * 1024 * 1024
MAX_FILE_BYTES = 512 * 1024
MAX_LINK_FILE_SIZE = 1024 * 1024
MAX_SOURCE_LINKS = 5000
MAX_TREE_ENTRIES = env_int("DISCOVERY_MAX_TREE_ENTRIES", 5000, 100, 20000)
MAX_FILES_PER_REPO = env_int("DISCOVERY_MAX_FILES_PER_REPO", 240, 20, 1000)
MAX_REPOSITORIES = env_int("DISCOVERY_MAX_REPOSITORIES", 120, 1, 500)
MAX_CANDIDATES = env_int("DISCOVERY_MAX_CANDIDATES", 500, 1, 2000)
MAX_CANDIDATE_INPUT = env_int(
    "DISCOVERY_MAX_CANDIDATE_INPUT", 64 * 1024 * 1024, 1024 * 1024, 512 * 1024 * 1024)
MAX_DISCOVERY_INPUT = env_int(
    "DISCOVERY_MAX_PLATFORM_INPUT", 256 * 1024 * 1024, 4 * 1024 * 1024, 1024 * 1024 * 1024)
MAX_REGEX_VALIDATIONS = env_int("DISCOVERY_MAX_REGEX_VALIDATIONS", 100, 1, 500)
DISCOVERY_DEADLINE_SECONDS = env_int("DISCOVERY_DEADLINE_SECONDS", 2400, 60, 7200)
MIN_PROGRAM_SCORE = 5
PROBATION_MIN_RUNS = 3
PROBATION_MIN_DAYS = 2
PROBATION_MIN_STABLE_RUNS = 3
MAX_EVIDENCE_PER_CANDIDATE = 20

TEXT_SUFFIXES = {
    ".py", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".go", ".rs", ".java", ".kt", ".kts",
    ".sh", ".bash", ".ps1", ".yml", ".yaml", ".json", ".json5", ".toml", ".ini", ".txt",
    ".md", ".rst", ".html", ".vue", ".svelte",
}

SEARCH_QUERIES = (
    "animeko data source",
    "animeko source",
    "Animeko 数据源",
    "Animeko 聚合源",
    "Ani 数据源 mediaSources",
)

GITHUB_CODE_QUERIES = (
    '"exportedMediaSourceDataList"',
    '"SelectorMediaSourceArguments"',
    '"RssMediaSourceArguments"',
    '"all_animeko_links.txt"',
    '"factoryId" "web-selector"',
    '"python update_sources.py" animeko',
)

PROGRAM_SIGNALS = {
    "animeko": 2,
    "exportedmediasourcedatalist": 4,
    "mediasources": 1,
    "factoryid": 1,
    "web-selector": 2,
    "rssmediasourcearguments": 4,
    "selectormediasourcearguments": 4,
    "all_animeko_links": 5,
    "canonical_links": 3,
    "update_sources.py": 3,
    "dist/all.json": 2,
    "searchconfig": 1,
}

URL_RE = re.compile(r"https?://[^\s\"'<>`]+", re.IGNORECASE)
SHA_RE = re.compile(r"[0-9a-f]{40}\Z")
REPOSITORY_COMPONENT_RE = re.compile(r"[A-Za-z0-9_.-]{1,100}\Z")
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


def safe_repository_name(full_name: str) -> bool:
    if not isinstance(full_name, str):
        return False
    parts = full_name.strip("/").split("/")
    return len(parts) >= 2 and all(
        part not in {".", ".."} and REPOSITORY_COMPONENT_RE.fullmatch(part)
        for part in parts
    )


def safe_ref_name(ref: str) -> bool:
    return (
        isinstance(ref, str)
        and 1 <= len(ref) <= 255
        and not ref.startswith(("/", "."))
        and not ref.endswith(("/", "."))
        and ".." not in ref
        and "@{" not in ref
        and "\\" not in ref
        and not any(ord(ch) < 32 or ord(ch) == 127 for ch in ref)
    )


def safe_repository_path(path: str) -> bool:
    if not isinstance(path, str) or not path or "\\" in path:
        return False
    parts = path.split("/")
    return all(
        part not in {"", ".", ".."}
        and not any(ord(ch) < 32 or ord(ch) == 127 for ch in part)
        for part in parts
    )


def acquire_discovery_lock():
    flags = os.O_RDWR | os.O_CREAT
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    fd = os.open(LOCK_PATH, flags, 0o600)
    handle = os.fdopen(fd, "r+", encoding="utf-8")
    try:
        try:
            import fcntl
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except ImportError:
            import msvcrt
            handle.seek(0)
            if not handle.read(1):
                handle.write("0")
                handle.flush()
            handle.seek(0)
            msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
    except (BlockingIOError, OSError) as exc:
        handle.close()
        raise RuntimeError("已有另一个发现进程正在运行") from exc
    handle.seek(0)
    handle.truncate()
    handle.write(str(os.getpid()))
    handle.flush()
    return handle


def utc_now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def utc_date() -> str:
    return utc_now().date().isoformat()


def iso_now() -> str:
    return utc_now().replace(microsecond=0).isoformat().replace("+00:00", "Z")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def json_bytes(obj) -> bytes:
    return (json.dumps(obj, ensure_ascii=False, sort_keys=True, indent=2, allow_nan=False) + "\n").encode("utf-8")


def write_bytes_atomic(path: Path, data: bytes):
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.parent.is_symlink():
        raise RuntimeError(f"写入目录不得是符号链接: {path.parent}")
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.tmp-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
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


def write_json_atomic(path: Path, obj):
    write_bytes_atomic(path, json_bytes(obj))


def load_json(path: Path, default):
    try:
        if path.is_symlink() or path.stat().st_size > MAX_API_RESPONSE:
            return copy.deepcopy(default)
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return copy.deepcopy(default)


def load_updater():
    path = Path(__file__).resolve().with_name("update_sources.py")
    if not path.is_file():
        raise RuntimeError("缺少同目录 update_sources.py")
    spec = importlib.util.spec_from_file_location("animeko_discovery_updater", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("无法加载 update_sources.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class ApiError(RuntimeError):
    pass


class ApiClient:
    def __init__(self):
        self.session = requests.Session()
        self.session.trust_env = False
        self.github_token = os.environ.get("GITHUB_TOKEN", "")
        self.gitee_token = os.environ.get("GITEE_TOKEN", "")
        self.brave_token = os.environ.get("BRAVE_SEARCH_API_KEY", "")
        self.errors = []
        self.bytes_downloaded = 0
        self.deadline = time.monotonic() + DISCOVERY_DEADLINE_SECONDS

    def close(self):
        self.session.close()

    def expired(self) -> bool:
        return time.monotonic() >= self.deadline

    def redact(self, value: str) -> str:
        result = value
        for secret in (self.github_token, self.gitee_token, self.brave_token):
            if secret:
                result = result.replace(secret, "[REDACTED]")
        return result

    def _request(self, url: str, *, params=None, headers=None, allowed_hosts=(), max_size=MAX_API_RESPONSE):
        if self.expired():
            raise ApiError("发现任务已达到全局时间上限")
        parsed = urlsplit(url)
        host = (parsed.hostname or "").lower().rstrip(".")
        if parsed.scheme != "https" or host not in set(allowed_hosts):
            raise ApiError(f"API信任边界拒绝: {url}")
        request_headers = {"Accept": "application/json", "User-Agent": "animeko-discovery/1"}
        if headers:
            request_headers.update(headers)
        try:
            with self.session.get(
                    url, params=params, headers=request_headers, timeout=(5, 25),
                    allow_redirects=False, stream=True) as response:
                if response.status_code != 200:
                    raise ApiError(f"HTTP {response.status_code}: {url}")
                length = response.headers.get("Content-Length")
                if length and length.isdigit():
                    declared = int(length)
                    if declared > max_size:
                        raise ApiError(f"响应过大: {url}")
                    if self.bytes_downloaded + declared > MAX_DISCOVERY_INPUT:
                        raise ApiError("平台静态分析输入超过全局预算")
                chunks = []
                size = 0
                for chunk in response.iter_content(64 * 1024):
                    if not chunk:
                        continue
                    size += len(chunk)
                    if size > max_size:
                        raise ApiError(f"响应超过上限: {url}")
                    if self.bytes_downloaded + len(chunk) > MAX_DISCOVERY_INPUT:
                        raise ApiError("平台静态分析输入超过全局预算")
                    self.bytes_downloaded += len(chunk)
                    chunks.append(chunk)
                return b"".join(chunks)
        except requests.RequestException as exc:
            raise ApiError(self.redact(f"网络请求失败: {type(exc).__name__}: {exc}")) from exc

    def json(self, url: str, *, params=None, headers=None, allowed_hosts=()):
        raw = self._request(url, params=params, headers=headers, allowed_hosts=allowed_hosts)
        try:
            return json.loads(raw.decode("utf-8"))
        except Exception as exc:
            raise ApiError(f"API JSON无效: {url}") from exc

    def github_json(self, path: str, params=None):
        headers = {"Authorization": f"Bearer {self.github_token}"} if self.github_token else {}
        return self.json(
            "https://api.github.com" + path, params=params, headers=headers,
            allowed_hosts=("api.github.com",))

    def gitlab_json(self, path: str, params=None):
        return self.json(
            "https://gitlab.com/api/v4" + path, params=params,
            allowed_hosts=("gitlab.com",))

    def codeberg_json(self, path: str, params=None):
        return self.json(
            "https://codeberg.org/api/v1" + path, params=params,
            allowed_hosts=("codeberg.org",))

    def gitee_json(self, path: str, params=None):
        query = dict(params or {})
        if self.gitee_token:
            query["access_token"] = self.gitee_token
        return self.json(
            "https://gitee.com/api/v5" + path, params=query,
            allowed_hosts=("gitee.com",))

    def trusted_text(self, url: str, hosts) -> str:
        raw = self._request(url, allowed_hosts=hosts, max_size=MAX_FILE_BYTES)
        return raw.decode("utf-8-sig", "replace")


def sanitize_provider_errors(errors, client: ApiClient) -> list[dict]:
    output = []
    safe_field = re.compile(r"[A-Za-z0-9_.:-]{1,128}\Z")
    for raw in errors[:100]:
        if not isinstance(raw, dict):
            raw = {"error": "invalid-error-record"}
        error_text = client.redact(str(raw.get("error") or "unknown-error"))
        for pattern in SECRET_PATTERNS:
            error_text = pattern.sub("[REDACTED]", error_text)
        status = re.search(r"\bHTTP\s+([1-5][0-9]{2})\b", error_text, re.IGNORECASE)
        if status:
            error_code = "http-" + status.group(1)
        elif "时间上限" in error_text or "deadline" in error_text.casefold():
            error_code = "deadline"
        elif "缺少" in error_text and ("TOKEN" in error_text or "token" in error_text):
            error_code = "missing-credential"
        elif safe_field.fullmatch(error_text):
            error_code = error_text
        else:
            error_code = "error-" + hashlib.sha256(error_text.encode("utf-8", "replace")).hexdigest()[:16]
        item = {"error": error_code}
        for field in ("provider", "phase"):
            value = raw.get(field)
            if isinstance(value, str) and safe_field.fullmatch(value):
                item[field] = value
        repository = raw.get("repository")
        if isinstance(repository, str) and safe_repository_name(repository):
            item["repository"] = repository
        output.append(item)
    return output


class Repository:
    def __init__(self, platform: str, full_name: str, web_url: str, default_branch: str = "main",
                 identifier=None, description="", evidence=None):
        normalized_name = full_name.strip("/") if isinstance(full_name, str) else ""
        normalized_branch = default_branch or "main"
        if not safe_repository_name(normalized_name):
            raise ValueError(f"仓库名称非法: {full_name!r}")
        if not safe_ref_name(normalized_branch):
            raise ValueError(f"默认分支非法: {normalized_branch!r}")
        self.platform = platform
        self.full_name = normalized_name
        self.web_url = web_url.rstrip("/")
        self.default_branch = normalized_branch
        self.identifier = identifier if identifier is not None else self.full_name
        self.description = description or ""
        self.evidence = list(evidence or [])
        self.commit = ""

    @property
    def key(self):
        return f"{self.platform}:{self.full_name.casefold()}"

    def as_dict(self):
        return {
            "platform": self.platform,
            "repository": self.full_name,
            "url": self.web_url,
            "default_branch": self.default_branch,
            "commit": self.commit,
            "description": self.description[:500],
            "search_evidence": sorted(set(self.evidence))[:20],
        }


def merge_repository(target: dict[str, Repository], repository: Repository):
    current = target.get(repository.key)
    if current is None:
        target[repository.key] = repository
        return
    current.evidence = sorted(set(current.evidence + repository.evidence))[:20]
    if not current.description and repository.description:
        current.description = repository.description
    if current.default_branch == "main" and repository.default_branch != "main":
        current.default_branch = repository.default_branch


def github_repository(item, evidence) -> Repository | None:
    full_name = item.get("full_name") or ((item.get("repository") or {}).get("full_name"))
    if not isinstance(full_name, str) or full_name.count("/") != 1:
        return None
    repo = item.get("repository") if isinstance(item.get("repository"), dict) else item
    return Repository(
        "github", full_name, repo.get("html_url") or f"https://github.com/{full_name}",
        repo.get("default_branch") or "main", full_name, repo.get("description") or "", [evidence])


def discover_github(client: ApiClient, repositories: dict[str, Repository], limit: int):
    for query in SEARCH_QUERIES:
        try:
            payload = client.github_json("/search/repositories", {"q": query, "per_page": 20})
            for item in payload.get("items", [])[:20]:
                repo = github_repository(item, f"repository-search:{query}")
                if repo:
                    merge_repository(repositories, repo)
        except Exception as exc:
            client.errors.append({"provider": "github-repository", "query": query, "error": str(exc)})
        if len(repositories) >= limit:
            break
    if not client.github_token:
        client.errors.append({"provider": "github-code", "error": "缺少GITHUB_TOKEN，跳过全局代码搜索"})
        return
    for query in GITHUB_CODE_QUERIES:
        try:
            payload = client.github_json("/search/code", {"q": query, "per_page": 30})
            for item in payload.get("items", [])[:30]:
                repo = github_repository(item, f"code-search:{query}:{item.get('path', '')}")
                if repo:
                    merge_repository(repositories, repo)
        except Exception as exc:
            client.errors.append({"provider": "github-code", "query": query, "error": str(exc)})
        if len(repositories) >= limit:
            break


def discover_gitlab(client: ApiClient, repositories: dict[str, Repository], limit: int):
    for query in ("animeko", "animeko source", "animeko 数据源"):
        try:
            items = client.gitlab_json("/projects", {
                "search": query, "simple": "true", "per_page": 30, "order_by": "last_activity_at"})
            for item in items[:30]:
                full_name = item.get("path_with_namespace")
                if isinstance(full_name, str):
                    merge_repository(repositories, Repository(
                        "gitlab", full_name, item.get("web_url") or f"https://gitlab.com/{full_name}",
                        item.get("default_branch") or "main", item.get("id"),
                        item.get("description") or "", [f"project-search:{query}"]))
        except Exception as exc:
            client.errors.append({"provider": "gitlab", "query": query, "error": str(exc)})
        if len(repositories) >= limit:
            break


def discover_codeberg(client: ApiClient, repositories: dict[str, Repository], limit: int):
    for query in ("animeko", "animeko-source", "animeko source"):
        try:
            payload = client.codeberg_json("/repos/search", {"q": query, "limit": 30})
            for item in payload.get("data", [])[:30]:
                full_name = item.get("full_name")
                if isinstance(full_name, str):
                    merge_repository(repositories, Repository(
                        "codeberg", full_name,
                        item.get("html_url") or f"https://codeberg.org/{full_name}",
                        item.get("default_branch") or "main", full_name,
                        item.get("description") or "", [f"repository-search:{query}"]))
        except Exception as exc:
            client.errors.append({"provider": "codeberg", "query": query, "error": str(exc)})
        if len(repositories) >= limit:
            break


def discover_gitee(client: ApiClient, repositories: dict[str, Repository], limit: int):
    for query in ("animeko", "animeko source", "animeko 数据源"):
        try:
            items = client.gitee_json("/search/repositories", {"q": query, "per_page": 30})
            if not isinstance(items, list):
                raise ApiError("Gitee搜索返回结构无效")
            for item in items[:30]:
                full_name = item.get("full_name")
                if isinstance(full_name, str):
                    merge_repository(repositories, Repository(
                        "gitee", full_name,
                        item.get("html_url") or f"https://gitee.com/{full_name}",
                        item.get("default_branch") or "master", full_name,
                        item.get("description") or "", [f"repository-search:{query}"]))
        except Exception as exc:
            client.errors.append({"provider": "gitee", "query": query, "error": str(exc)})
        if len(repositories) >= limit:
            break


def discover_brave(client: ApiClient, repositories: dict[str, Repository]) -> list[str]:
    if not client.brave_token:
        client.errors.append({"provider": "brave-web", "error": "缺少BRAVE_SEARCH_API_KEY，跳过公共网页搜索"})
        return []
    direct = []
    queries = (
        'Animeko 数据源 github OR gitee OR gitlab OR codeberg',
        '"exportedMediaSourceDataList" Animeko',
        '"SelectorMediaSourceArguments"',
        '"all_animeko_links.txt"',
        'Animeko source generator converter validator',
    )
    for query in queries:
        try:
            payload = client.json(
                "https://api.search.brave.com/res/v1/web/search",
                params={"q": query, "count": 20, "safesearch": "off"},
                headers={"X-Subscription-Token": client.brave_token},
                allowed_hosts=("api.search.brave.com",))
            for item in ((payload.get("web") or {}).get("results") or [])[:20]:
                url = item.get("url")
                if not isinstance(url, str):
                    continue
                repo = repository_from_url(url, f"brave-search:{query}")
                if repo:
                    merge_repository(repositories, repo)
                else:
                    candidate = clean_extracted_url(url)
                    if candidate:
                        direct.append(candidate)
        except Exception as exc:
            client.errors.append({"provider": "brave-web", "query": query, "error": str(exc)})
    return direct


def repository_from_url(url: str, evidence: str) -> Repository | None:
    try:
        parsed = urlsplit(url)
    except Exception:
        return None
    host = (parsed.hostname or "").lower().rstrip(".")
    parts = [unquote(part) for part in parsed.path.split("/") if part]
    if host in {"github.com", "codeberg.org", "gitee.com"} and len(parts) >= 2:
        platform = {"github.com": "github", "codeberg.org": "codeberg", "gitee.com": "gitee"}[host]
        full_name = "/".join(parts[:2]).removesuffix(".git")
        return Repository(platform, full_name, f"https://{host}/{full_name}", evidence=[evidence])
    if host == "gitlab.com" and len(parts) >= 2:
        if "-" in parts:
            parts = parts[:parts.index("-")]
        full_name = "/".join(parts).removesuffix(".git")
        return Repository("gitlab", full_name, f"https://gitlab.com/{full_name}", evidence=[evidence])
    return None


def load_seeds(repositories: dict[str, Repository]) -> list[str]:
    if not SEEDS_PATH.exists() or SEEDS_PATH.is_symlink():
        return []
    direct = []
    for line in SEEDS_PATH.read_text(encoding="utf-8-sig").splitlines():
        value = line.strip()
        if not value or value.startswith("#"):
            continue
        repo = repository_from_url(value, "manual-seed")
        if repo:
            merge_repository(repositories, repo)
        else:
            candidate = clean_extracted_url(value)
            if candidate:
                direct.append(candidate)
    return direct


def load_trusted_programs() -> set[str]:
    trusted = {"manual-seed"}
    if not TRUSTED_PROGRAMS_PATH.exists() or TRUSTED_PROGRAMS_PATH.is_symlink():
        return trusted
    for line in TRUSTED_PROGRAMS_PATH.read_text(encoding="utf-8-sig").splitlines():
        value = line.strip().casefold()
        if not value or value.startswith("#"):
            continue
        if re.fullmatch(r"(?:github|gitlab|gitee|codeberg):[a-z0-9_.-]+(?:/[a-z0-9_.-]+)+", value):
            trusted.add(value)
    return trusted


def existing_source_identities(updater) -> set[tuple]:
    path = Path("dist/all.json")
    if not path.is_file() or path.is_symlink():
        return set()
    try:
        obj = updater.load_json_file(str(path))
        items = updater.extract(obj)
        if not isinstance(items, list):
            return set()
        identities = set()
        for item in items:
            if not isinstance(item, dict):
                continue
            arguments = item.get("arguments") or {}
            name = arguments.get("name")
            identities.add((item.get("factoryId"), name, updater.url_of(item)))
        return identities
    except Exception:
        return set()


def path_priority(path: str) -> tuple[int, int, str]:
    lower = path.lower()
    name = lower.rsplit("/", 1)[-1]
    score = 0
    for token, weight in (
        ("animeko", 12), ("all_animeko_links", 12), ("canonical_links", 10),
        ("update_source", 9), ("discover", 8), ("workflow", 6), ("readme", 6),
        ("dist/", 5), ("source", 4), ("config", 3), ("subscription", 3),
    ):
        if token in lower:
            score += weight
    if name in {"package.json", "pyproject.toml", "requirements.txt", "go.mod", "cargo.toml"}:
        score += 4
    return (-score, len(path), path)


def relevant_path(path: str, size: int | None) -> bool:
    if not safe_repository_path(path):
        return False
    if size is not None and size > MAX_FILE_BYTES:
        return False
    lower = path.lower()
    suffix = Path(lower).suffix
    if suffix not in TEXT_SUFFIXES and not lower.endswith(("dockerfile", "makefile")):
        return False
    if any(part in lower for part in ("node_modules/", ".git/", "vendor/", "build/", "dist/assets/")):
        return False
    return True


def resolve_repository(client: ApiClient, repo: Repository):
    if repo.platform == "github":
        payload = client.github_json(f"/repos/{repo.full_name}/commits/{quote(repo.default_branch, safe='')}")
        repo.commit = payload.get("sha") or ""
    elif repo.platform == "gitlab":
        project = quote(str(repo.identifier), safe="")
        payload = client.gitlab_json(
            f"/projects/{project}/repository/commits/{quote(repo.default_branch, safe='')}")
        repo.commit = payload.get("id") or ""
    elif repo.platform == "codeberg":
        payload = client.codeberg_json(
            f"/repos/{repo.full_name}/branches/{quote(repo.default_branch, safe='')}")
        repo.commit = ((payload.get("commit") or {}).get("id") or "")
    elif repo.platform == "gitee":
        payload = client.gitee_json(
            f"/repos/{repo.full_name}/branches/{quote(repo.default_branch, safe='')}")
        repo.commit = ((payload.get("commit") or {}).get("sha") or "")
    if not SHA_RE.fullmatch(repo.commit):
        raise ApiError(f"无法解析immutable commit: {repo.key}")


def repository_tree(client: ApiClient, repo: Repository) -> list[dict]:
    if repo.platform == "github":
        payload = client.github_json(f"/repos/{repo.full_name}/git/trees/{repo.commit}", {"recursive": "1"})
        entries = payload.get("tree", [])
        if payload.get("truncated"):
            raise ApiError(f"GitHub tree被截断: {repo.full_name}")
        return [{"path": e.get("path"), "size": e.get("size"), "type": e.get("type")}
                for e in entries if e.get("type") == "blob"]
    if repo.platform == "gitlab":
        project = quote(str(repo.identifier), safe="")
        entries = []
        for page in range(1, 6):
            batch = client.gitlab_json(f"/projects/{project}/repository/tree", {
                "ref": repo.commit, "recursive": "true", "per_page": 100, "page": page})
            entries.extend({"path": e.get("path"), "size": None, "type": e.get("type")}
                           for e in batch if e.get("type") == "blob")
            if len(batch) < 100:
                break
        return entries
    if repo.platform in {"codeberg", "gitee"}:
        getter = client.codeberg_json if repo.platform == "codeberg" else client.gitee_json
        payload = getter(f"/repos/{repo.full_name}/git/trees/{repo.commit}", {"recursive": "1"})
        return [{"path": e.get("path"), "size": e.get("size"), "type": e.get("type")}
                for e in payload.get("tree", []) if e.get("type") in {"blob", "file"}]
    return []


def repository_file(client: ApiClient, repo: Repository, path: str) -> bytes:
    if not safe_repository_path(path):
        raise ApiError(f"仓库文件路径非法: {repo.key}:{path!r}")
    if repo.platform == "github":
        owner, name = repo.full_name.split("/", 1)
        encoded = "/".join(quote(part, safe="") for part in path.split("/"))
        url = f"https://raw.githubusercontent.com/{owner}/{name}/{repo.commit}/{encoded}"
        return client._request(url, allowed_hosts=("raw.githubusercontent.com",), max_size=MAX_FILE_BYTES)
    if repo.platform == "gitlab":
        project = quote(str(repo.identifier), safe="")
        file_path = quote(path, safe="")
        return client._request(
            f"https://gitlab.com/api/v4/projects/{project}/repository/files/{file_path}/raw",
            params={"ref": repo.commit}, allowed_hosts=("gitlab.com",), max_size=MAX_FILE_BYTES)
    getter = client.codeberg_json if repo.platform == "codeberg" else client.gitee_json
    payload = getter(
        f"/repos/{repo.full_name}/contents/{quote(path, safe='/')}", {"ref": repo.commit})
    encoded = payload.get("content")
    if not isinstance(encoded, str):
        raise ApiError(f"文件内容缺失: {repo.key}:{path}")
    data = base64.b64decode(encoded, validate=False)
    if len(data) > MAX_FILE_BYTES:
        raise ApiError(f"文件过大: {repo.key}:{path}")
    return data


def branch_raw_url(repo: Repository, path: str) -> str:
    if not safe_repository_path(path):
        raise ValueError(f"仓库文件路径非法: {path!r}")
    encoded = "/".join(quote(part, safe="") for part in path.split("/"))
    branch = quote(repo.default_branch, safe="/")
    if repo.platform == "github":
        return f"https://raw.githubusercontent.com/{repo.full_name}/{branch}/{encoded}"
    if repo.platform == "gitlab":
        return f"https://gitlab.com/{repo.full_name}/-/raw/{branch}/{encoded}"
    if repo.platform == "codeberg":
        return f"https://codeberg.org/{repo.full_name}/raw/branch/{branch}/{encoded}"
    if repo.platform == "gitee":
        return f"https://gitee.com/{repo.full_name}/raw/{branch}/{encoded}"
    raise ValueError(repo.platform)


def clean_extracted_url(value: str) -> str | None:
    value = html.unescape(value.replace("\\/", "/")).strip()
    for delimiter in (")", "，", "。", "；", "】", "」", "』"):
        value = value.split(delimiter, 1)[0]
    if any(marker in value for marker in ("{", "}", "${", "{{", "<owner>", "example.com")):
        return None
    value = value.rstrip(",.;]>")
    try:
        value = canonicalize_url(value)
    except UrlPolicyError:
        return None
    lower = value.lower()
    parsed = urlsplit(value)
    host = parsed.hostname or ""
    if parsed.path.lower().endswith((
            ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".mp4", ".m3u8", ".css")):
        return None
    if host in {"api.github.com", "api.gitlab.com"}:
        return None
    if host == "github.com" and not any(marker in parsed.path for marker in ("/raw/", "/blob/", "/gist/")):
        return None
    likely = (
        lower.endswith((".json", ".json5", ".txt"))
        or host in {"raw.githubusercontent.com", "cdn.jsdelivr.net", "raw.githack.com",
                    "gitlab.com", "gitee.com", "codeberg.org", "raw.atomgit.com"}
        or any(token in lower for token in ("animeko", "media-source", "mediasource", "subscription", "/source/", "/config/"))
    )
    return value if likely else None


def extract_urls(text: str) -> set[str]:
    normalized = html.unescape(text.replace("\\/", "/"))
    out = set()
    for match in URL_RE.finditer(normalized):
        value = clean_extracted_url(match.group(0))
        if value:
            out.add(value)
    return out


def score_program(path: str, text: str, repository: Repository) -> tuple[int, list[str], list[str]]:
    lower = (path + "\n" + text[:MAX_FILE_BYTES]).lower()
    score = 0
    signals = []
    for token, weight in PROGRAM_SIGNALS.items():
        if token in lower:
            score += weight
            signals.append(token)
    categories = []
    if any(token in lower for token in ("build_merged", "aggregate", "聚合", "all_animeko_links")):
        categories.append("aggregator")
    if any(token in lower for token in ("json.dump", "json.stringify", "exportedmediasourcedatalist")):
        categories.append("generator")
    if any(token in lower for token in ("convert", "converter", "转换", "tvbox", "kazumi")):
        categories.append("converter")
    if any(token in lower for token in ("validate_item", "validator", "校验", "selftest")):
        categories.append("validator")
    if any(token in lower for token in ("schedule:", "workflow_dispatch", "git commit", "cron:")):
        categories.append("workflow-bot")
    if any(token in lower for token in ("mirror", "镜像", "proxy", "同步")):
        categories.append("mirror-sync")
    if any(token in lower for token in ("editor", "编辑器", "server", "fastapi", "express(")):
        categories.append("editor-or-service")
    if path.lower().endswith((".json", ".txt")) and "mediasources" in lower:
        categories.append("subscription")
    if repository.evidence:
        score += min(3, len(repository.evidence))
    return score, sorted(set(signals)), sorted(set(categories))


def looks_like_source_json(updater, data: bytes, origin: str) -> tuple[bool, int]:
    try:
        candidates, valid = updater.try_parse(data, origin)
        return bool(valid), len(candidates)
    except Exception:
        return False, 0


def analyze_repository(client: ApiClient, updater, repo: Repository,
                       candidate_evidence: dict[str, set[str]]) -> dict:
    resolve_repository(client, repo)
    tree = repository_tree(client, repo)
    if len(tree) > MAX_TREE_ENTRIES:
        raise ApiError(f"仓库文件过多: {repo.key} {len(tree)}")
    files = [e for e in tree if isinstance(e.get("path"), str) and relevant_path(e["path"], e.get("size"))]
    files.sort(key=lambda entry: path_priority(entry["path"]))
    files = files[:MAX_FILES_PER_REPO]
    record = repo.as_dict()
    record.update({"score": 0, "categories": [], "signals": [], "files_scanned": 0,
                   "evidence_files": [], "extracted_url_count": 0, "generated_source_files": []})
    categories = set()
    signals = set()
    extracted = set()
    for entry in files:
        path = entry["path"]
        try:
            data = repository_file(client, repo, path)
        except Exception as exc:
            client.errors.append({"provider": repo.platform, "repository": repo.full_name,
                                  "path": path, "error": str(exc)})
            continue
        record["files_scanned"] += 1
        text = data.decode("utf-8-sig", "replace")
        score, file_signals, file_categories = score_program(path, text, repo)
        if score:
            record["score"] += score
            signals.update(file_signals)
            categories.update(file_categories)
            record["evidence_files"].append({"path": path, "score": score})
        urls = extract_urls(text)
        extracted.update(urls)
        valid_json, item_count = looks_like_source_json(updater, data, branch_raw_url(repo, path))
        if valid_json:
            generated = branch_raw_url(repo, path)
            extracted.add(generated)
            record["generated_source_files"].append({"path": path, "items": item_count, "url": generated})
    record["score"] = min(record["score"], 100)
    record["signals"] = sorted(signals)
    record["categories"] = sorted(categories)
    record["evidence_files"] = sorted(
        record["evidence_files"], key=lambda item: (-item["score"], item["path"]))[:30]
    record["generated_source_files"] = sorted(record["generated_source_files"], key=lambda item: item["path"])
    record["extracted_url_count"] = len(extracted)
    if record["score"] >= MIN_PROGRAM_SCORE or record["generated_source_files"]:
        for url in extracted:
            candidate_evidence[url].add(repo.key)
    return record


def initial_state():
    return {"version": STATE_VERSION, "candidates": {}, "promoted": []}


def load_state() -> dict:
    state = load_json(STATE_PATH, initial_state())
    if not isinstance(state, dict) or state.get("version") != STATE_VERSION:
        return initial_state()
    if not isinstance(state.get("candidates"), dict) or not isinstance(state.get("promoted"), list):
        return initial_state()
    return state


def existing_links(updater) -> set[str]:
    try:
        info = LINKS_PATH.lstat()
    except FileNotFoundError:
        return set()
    if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o111:
        raise RuntimeError("all_animeko_links.txt必须是非可执行普通文件")
    if info.st_size > MAX_LINK_FILE_SIZE:
        raise RuntimeError("all_animeko_links.txt超过大小上限")
    try:
        lines = LINKS_PATH.read_text(encoding="utf-8-sig").splitlines()
    except UnicodeDecodeError as exc:
        raise RuntimeError("all_animeko_links.txt不是有效UTF-8") from exc
    out = set()
    count = 0
    for line in lines:
        value = line.strip()
        if not value or value.startswith("#"):
            continue
        count += 1
        if count > MAX_SOURCE_LINKS:
            raise RuntimeError("all_animeko_links.txt链接数量超过上限")
        try:
            canonical = updater.normalize(value)
        except Exception as exc:
            raise RuntimeError("all_animeko_links.txt包含非法URL") from exc
        out.add(canonical)
    return out


class RegexValidationBudget:
    def __init__(self, limit: int):
        self.limit = limit
        self.used = 0

    def consume(self) -> bool:
        if self.used >= self.limit:
            return False
        self.used += 1
        return True


def validate_candidate(updater, url: str, budget, regex_budget: RegexValidationBudget,
                       existing_identities: set[tuple], global_deadline: float) -> dict:
    started = time.monotonic()
    if started >= global_deadline:
        return {"ok": False, "url": url, "error": "global-deadline"}
    try:
        canon = updater.normalize(url)
    except Exception as exc:
        return {"ok": False, "url": url, "error": f"normalize:{type(exc).__name__}"}
    try:
        data, meta = updater.fetch_url(
            canon, None, min(time.monotonic() + 40, global_deadline), input_budget=budget)
    except Exception as exc:
        return {"ok": False, "url": canon, "error": f"fetch:{type(exc).__name__}"}
    if data is None:
        return {"ok": False, "url": canon, "error": (meta or {}).get("error") or "fetch-failed"}
    parsed_fail = []
    candidates, valid = updater.try_parse(data, canon, parsed_fail)
    if not valid:
        return {"ok": False, "url": canon, "error": "invalid-animeko-source",
                "details": parsed_fail[:5], "sha256": sha256_bytes(data)}
    regexes = []
    candidate_identities = set()
    for _, _, item, _ in candidates:
        arguments = item.get("arguments") or {}
        search_config = arguments.get("searchConfig") or {}
        updater.collect_known_regex_fields(search_config, regexes)
        candidate_identities.add((item.get("factoryId"), arguments.get("name"), updater.url_of(item)))
    unique_regexes = list(dict.fromkeys(regexes))
    if unique_regexes:
        if not regex_budget.consume():
            return {"ok": False, "url": canon, "error": "regex-validation-budget",
                    "sha256": sha256_bytes(data)}
        regex_failures, regex_mode = updater.java_check_regexes(unique_regexes)
        if regex_mode != "java" or regex_failures:
            return {"ok": False, "url": canon, "error": f"regex-validation:{regex_mode}",
                    "details": regex_failures[:5], "sha256": sha256_bytes(data)}
    overlap = len(candidate_identities & existing_identities)
    new_items = len(candidate_identities - existing_identities)
    final_url = meta.get("final_url")
    safe_final_url = clean_extracted_url(final_url) if isinstance(final_url, str) else None
    return {
        "ok": True,
        "url": canon,
        "sha256": sha256_bytes(data),
        "items": len(candidates),
        "overlap_items": overlap,
        "new_items": new_items,
        "redundant": bool(existing_identities) and new_items == 0,
        "latency": round(time.monotonic() - started, 3),
        "final_url": safe_final_url,
    }


def update_candidate_state(state: dict, result: dict, evidence: set[str], program_scores: dict[str, int],
                           today: str, trusted_programs: set[str] | None = None):
    trusted_programs = trusted_programs or set()
    url = result["url"]
    candidates = state["candidates"]
    current = candidates.get(url)
    if not isinstance(current, dict):
        current = {
            "first_seen": today,
            "last_seen": today,
            "observed_dates": [],
            "successful_runs": 0,
            "consecutive_successes": 0,
            "stable_successes": 0,
            "last_sha256": None,
            "status": "new",
            "evidence": [],
            "max_program_score": 0,
            "trusted_evidence": False,
            "redundant": False,
        }
    observed_dates = current.get("observed_dates", [])
    if not isinstance(observed_dates, list) or len(observed_dates) > 30:
        raise RuntimeError(f"候选observed_dates无效: {url}")
    previous_last_seen = current.get("last_seen")
    new_day = today not in observed_dates
    if new_day and observed_dates:
        try:
            expected_day = (dt.date.fromisoformat(previous_last_seen) + dt.timedelta(days=1)).isoformat()
        except (TypeError, ValueError) as exc:
            raise RuntimeError(f"候选last_seen无效: {url}") from exc
        if today != expected_day:
            current["consecutive_successes"] = 0
            current["stable_successes"] = 0
    current["last_seen"] = today
    current["evidence"] = sorted(set(current.get("evidence", [])) | set(evidence))[:MAX_EVIDENCE_PER_CANDIDATE]
    current["max_program_score"] = max(
        [current.get("max_program_score", 0), *[program_scores.get(key, 0) for key in evidence]])
    current["trusted_evidence"] = bool(
        current.get("trusted_evidence") or set(evidence) & trusted_programs)
    current["redundant"] = bool(result.get("redundant"))
    if new_day:
        current.setdefault("observed_dates", []).append(today)
        current["observed_dates"] = current["observed_dates"][-30:]
    eligible_success = bool(result.get("ok") and not result.get("redundant"))
    if not eligible_success:
        current["consecutive_successes"] = 0
        current["stable_successes"] = 0
    elif new_day:
        current["successful_runs"] = min(30, current.get("successful_runs", 0) + 1)
        current["consecutive_successes"] = min(30, current.get("consecutive_successes", 0) + 1)
        if current.get("last_sha256") == result.get("sha256"):
            current["stable_successes"] = min(30, current.get("stable_successes", 0) + 1)
        else:
            current["stable_successes"] = 1
        current["last_sha256"] = result.get("sha256")
    current["status"] = (
        "redundant" if result.get("ok") and result.get("redundant")
        else "valid" if result.get("ok") else "rejected")
    current["last_error"] = result.get("error")
    current["last_items"] = result.get("items")
    current["last_new_items"] = result.get("new_items")
    current["last_overlap_items"] = result.get("overlap_items")
    current["last_latency"] = result.get("latency")
    candidates[url] = current
    return current


def reset_absent_candidates(state: dict, observed_urls: set[str]):
    candidates = state.get("candidates")
    if not isinstance(candidates, dict):
        raise RuntimeError("state candidates无效")
    for url, record in candidates.items():
        if url in observed_urls:
            continue
        if not isinstance(record, dict):
            raise RuntimeError(f"候选state无效: {url}")
        record["consecutive_successes"] = 0
        record["stable_successes"] = 0
        record["redundant"] = False
        if record.get("status") != "promoted":
            record["status"] = "absent"
            record["last_error"] = "absent-from-snapshot"


def days_between(first: str, current: str) -> int:
    try:
        return (dt.date.fromisoformat(current) - dt.date.fromisoformat(first)).days
    except Exception:
        return -1


def probation_ready(record: dict, today: str) -> bool:
    return (
        record.get("status") == "valid"
        and record.get("successful_runs", 0) >= PROBATION_MIN_RUNS
        and record.get("consecutive_successes", 0) >= PROBATION_MIN_RUNS
        and record.get("stable_successes", 0) >= PROBATION_MIN_STABLE_RUNS
        and days_between(record.get("first_seen", ""), today) >= PROBATION_MIN_DAYS
        and record.get("max_program_score", 0) >= MIN_PROGRAM_SCORE
        and record.get("trusted_evidence") is True
        and record.get("redundant") is not True
        and bool(record.get("evidence"))
    )


def validate_state_files() -> list[str]:
    problems = []
    state = load_json(STATE_PATH, None)
    if not isinstance(state, dict) or state.get("version") != STATE_VERSION:
        problems.append("state.json版本或结构无效")
        return problems
    candidates = state.get("candidates")
    if not isinstance(candidates, dict) or len(candidates) > 10000:
        problems.append("state.json candidates无效")
        return problems
    for url, record in candidates.items():
        if not isinstance(url, str) or not url.startswith("https://") or not isinstance(record, dict):
            problems.append(f"候选结构无效: {url!r}")
            continue
        if record.get("status") not in {"new", "valid", "rejected", "redundant", "promoted", "absent"}:
            problems.append(f"候选状态无效: {url}")
        if record.get("status") == "promoted" and record.get("trusted_evidence") is not True:
            problems.append(f"未受信任候选不得晋升: {url}")
        digest = record.get("last_sha256")
        if digest is not None and not re.fullmatch(r"[0-9a-f]{64}", digest):
            problems.append(f"候选hash无效: {url}")
    report_specs = (
        (CANDIDATES_PATH, "candidates"),
        (REJECTED_PATH, "rejected"),
        (REDUNDANT_PATH, "redundant"),
    )
    for path, field in report_specs:
        document = load_json(path, None)
        entries = document.get(field) if isinstance(document, dict) else None
        if not isinstance(entries, list):
            problems.append(f"{path}缺失或结构无效")
            continue
        for entry in entries:
            observed_by = (entry.get("observed_by", entry.get("evidence"))
                           if isinstance(entry, dict) else None)
            if (not isinstance(entry, dict) or not isinstance(observed_by, list)
                    or "manual-seed" in observed_by):
                problems.append(f"{path}含非法observed_by")
                break
            try:
                if canonicalize_url(entry.get("url")) != entry.get("url"):
                    problems.append(f"{path}含未canonicalize URL")
                    break
            except (UrlPolicyError, TypeError):
                problems.append(f"{path}含非法URL")
                break
    for path in (PROGRAMS_PATH, CANDIDATES_PATH, REJECTED_PATH, REDUNDANT_PATH, LATEST_PATH):
        document = load_json(path, None)
        if not isinstance(document, dict):
            problems.append(f"{path}缺失或JSON无效")
            continue
        serialized = json.dumps(document, ensure_ascii=False, allow_nan=False)
        if any(pattern.search(serialized) for pattern in SECRET_PATTERNS):
            problems.append(f"{path}疑似包含secret")
    return problems


def run_discovery():
    started = time.time()
    today = utc_date()
    lock_handle = acquire_discovery_lock()
    DISCOVERY_DIR.mkdir(parents=True, exist_ok=True)
    updater = load_updater()
    client = ApiClient()
    repositories: dict[str, Repository] = {}
    candidate_evidence: dict[str, set[str]] = defaultdict(set)
    direct_seeds = load_seeds(repositories)
    trusted_programs = load_trusted_programs()
    source_identities = existing_source_identities(updater)
    try:
        discover_github(client, repositories, MAX_REPOSITORIES)
        discover_gitlab(client, repositories, MAX_REPOSITORIES)
        discover_codeberg(client, repositories, MAX_REPOSITORIES)
        discover_gitee(client, repositories, MAX_REPOSITORIES)
        direct_seeds.extend(discover_brave(client, repositories))
        repositories = dict(sorted(repositories.items())[:MAX_REPOSITORIES])
        program_records = []
        for repo in repositories.values():
            if client.expired():
                client.errors.append({"phase": "repository-analysis", "error": "达到全局时间上限"})
                break
            try:
                record = analyze_repository(client, updater, repo, candidate_evidence)
                if record["score"] >= MIN_PROGRAM_SCORE or record["generated_source_files"]:
                    program_records.append(record)
            except Exception as exc:
                client.errors.append({"provider": repo.platform, "repository": repo.full_name,
                                      "error": str(exc)})
        for url in direct_seeds:
            candidate_evidence[url].add("manual-seed")
        program_records.sort(key=lambda item: (-item["score"], item["platform"], item["repository"].casefold()))
        program_scores = {
            f"{record['platform']}:{record['repository'].casefold()}": record["score"]
            for record in program_records
        }
        program_scores["manual-seed"] = MIN_PROGRAM_SCORE
        known_links = existing_links(updater)
        canonical_evidence: dict[str, set[str]] = defaultdict(set)
        for original_url, evidence in candidate_evidence.items():
            try:
                canonical = updater.normalize(original_url)
            except Exception:
                canonical = original_url
            if canonical not in known_links:
                canonical_evidence[canonical].update(evidence)
        candidates_to_check = sorted(canonical_evidence)[:MAX_CANDIDATES]
        budget = updater._InputBudget(MAX_CANDIDATE_INPUT)
        regex_budget = RegexValidationBudget(MAX_REGEX_VALIDATIONS)
        validation_results = []
        state = load_state()
        current_valid = []
        current_rejected = []
        current_redundant = []
        for original_url in candidates_to_check:
            if client.expired():
                client.errors.append({"phase": "candidate-validation", "error": "达到全局时间上限"})
                break
            result = validate_candidate(
                updater, original_url, budget, regex_budget, source_identities, client.deadline)
            evidence = canonical_evidence[original_url]
            record = update_candidate_state(
                state, result, evidence, program_scores, today, trusted_programs)
            observed_by = sorted("seed-candidate" if item == "manual-seed" else item for item in evidence)
            output = {**result, "observed_by": observed_by, "probation": {
                "successful_runs": record.get("successful_runs", 0),
                "consecutive_successes": record.get("consecutive_successes", 0),
                "stable_successes": record.get("stable_successes", 0),
                "first_seen": record.get("first_seen"),
                "trusted_evidence": record.get("trusted_evidence", False),
                "redundant": record.get("redundant", False),
                "ready": probation_ready(record, today),
            }}
            validation_results.append(output)
            if result.get("ok") and result.get("redundant"):
                current_redundant.append(output)
            elif result.get("ok"):
                current_valid.append(output)
            else:
                current_rejected.append(output)
        reset_absent_candidates(state, {result["url"] for result in validation_results})
        snapshot_complete = not client.expired()
        if not snapshot_complete:
            for record in state["candidates"].values():
                record["consecutive_successes"] = 0
                record["stable_successes"] = 0
        promoted = []
        state["updated"] = iso_now()
        cache_bytes, network_bytes = budget.totals()
        github_run_id = os.environ.get("GITHUB_RUN_ID", "")
        github_run_attempt = os.environ.get("GITHUB_RUN_ATTEMPT", "1")
        run_identity = (
            f"github:{github_run_id}:{github_run_attempt}"
            if github_run_id.isdigit() and github_run_attempt.isdigit()
            else "local:" + utc_now().strftime("%Y%m%dT%H%M%SZ")
        )
        programs_document = {"version": 1, "updated": iso_now(), "programs": program_records}
        candidates_document = {"version": 1, "updated": iso_now(), "candidates": current_valid}
        rejected_document = {"version": 1, "updated": iso_now(), "rejected": current_rejected}
        redundant_document = {"version": 1, "updated": iso_now(), "redundant": current_redundant}
        sanitized_errors = sanitize_provider_errors(client.errors, client)
        latest = {
            "version": 1,
            "updated": iso_now(),
            "duration_s": round(time.time() - started, 2),
            "repositories_discovered": len(repositories),
            "programs_identified": len(program_records),
            "candidates_extracted": len(candidate_evidence),
            "candidates_checked": len(validation_results),
            "valid_candidates": len(current_valid),
            "redundant_candidates": len(current_redundant),
            "rejected_candidates": len(current_rejected),
            "promoted": promoted,
            "input_bytes": {
                "platform_static_analysis": client.bytes_downloaded,
                "candidate_cache": cache_bytes,
                "candidate_network": network_bytes,
            },
            "regex_validations": regex_budget.used,
            "trusted_programs": len(trusted_programs - {"manual-seed"}),
            "provider_errors": sanitized_errors,
            "analysis_mode": "static-only",
            "third_party_code_executed": False,
            "snapshot_complete": snapshot_complete,
            "run_identity": run_identity,
        }
        write_json_atomic(PROGRAMS_PATH, programs_document)
        write_json_atomic(CANDIDATES_PATH, candidates_document)
        write_json_atomic(REJECTED_PATH, rejected_document)
        write_json_atomic(REDUNDANT_PATH, redundant_document)
        write_json_atomic(STATE_PATH, state)
        write_json_atomic(LATEST_PATH, latest)
        print(json.dumps(latest, ensure_ascii=False, indent=2))
    finally:
        client.close()
        lock_handle.close()


def run_selftests():
    import unittest

    class T(unittest.TestCase):
        def test_extract_urls(self):
            text = r'''a="https:\/\/raw.githubusercontent.com\/o\/r\/main\/x.json"
                       b=https://example.com/icon.png
                       c=https://site.example/search?wd={keyword}'''
            self.assertEqual(
                extract_urls(text),
                {"https://raw.githubusercontent.com/o/r/main/x.json"})

        def test_repository_from_url(self):
            repo = repository_from_url("https://github.com/Owner/Repo/blob/main/x.py", "seed")
            self.assertEqual(repo.platform, "github")
            self.assertEqual(repo.full_name, "Owner/Repo")
            gitlab = repository_from_url("https://gitlab.com/group/sub/repo/-/blob/main/x", "seed")
            self.assertEqual(gitlab.full_name, "group/sub/repo")

        def test_program_scoring_categories(self):
            repo = Repository("github", "o/r", "https://github.com/o/r", evidence=["code"])
            score, signals, categories = score_program(
                "update_sources.py",
                'exportedMediaSourceDataList factoryId web-selector json.dump all_animeko_links', repo)
            self.assertGreaterEqual(score, MIN_PROGRAM_SCORE)
            self.assertIn("aggregator", categories)
            self.assertIn("generator", categories)
            self.assertIn("exportedmediasourcedatalist", signals)

        def test_path_priority(self):
            paths = ["src/util.py", ".github/workflows/update.yml", "all_animeko_links.txt"]
            self.assertEqual(sorted(paths, key=lambda p: path_priority(p))[0], "all_animeko_links.txt")

        def test_candidate_probation_requires_three_dates(self):
            state = initial_state()
            scores = {"github:o/r": 20}
            for date in ("2026-08-20", "2026-08-21"):
                record = update_candidate_state(
                    state, {"ok": True, "url": "https://x.example/source.json",
                            "sha256": "a" * 64, "items": 2}, {"github:o/r"}, scores, date,
                    {"github:o/r"})
                self.assertFalse(probation_ready(record, date))
            record = update_candidate_state(
                state, {"ok": True, "url": "https://x.example/source.json",
                        "sha256": "a" * 64, "items": 2}, {"github:o/r"}, scores, "2026-08-22",
                {"github:o/r"})
            self.assertTrue(probation_ready(record, "2026-08-22"))

        def test_untrusted_high_score_program_cannot_promote(self):
            state = initial_state()
            scores = {"github:attacker/repo": 100}
            for date in ("2026-08-20", "2026-08-21", "2026-08-22"):
                record = update_candidate_state(
                    state, {"ok": True, "url": "https://x.example/source.json",
                            "sha256": "a" * 64, "items": 2, "new_items": 2},
                    {"github:attacker/repo"}, scores, date, set())
            self.assertFalse(record["trusted_evidence"])
            self.assertFalse(probation_ready(record, "2026-08-22"))

        def test_manual_seed_can_promote_only_after_probation(self):
            state = initial_state()
            scores = {"manual-seed": MIN_PROGRAM_SCORE}
            for date in ("2026-08-20", "2026-08-21", "2026-08-22"):
                record = update_candidate_state(
                    state, {"ok": True, "url": "https://x.example/source.json",
                            "sha256": "a" * 64, "items": 2, "new_items": 2},
                    {"manual-seed"}, scores, date, {"manual-seed"})
            self.assertTrue(probation_ready(record, "2026-08-22"))

        def test_redundant_candidate_never_promotes(self):
            state = initial_state()
            scores = {"github:o/r": 20}
            for date in ("2026-08-20", "2026-08-21", "2026-08-22"):
                record = update_candidate_state(
                    state, {"ok": True, "url": "https://x.example/source.json",
                            "sha256": "a" * 64, "items": 2, "new_items": 0,
                            "redundant": True}, {"github:o/r"}, scores, date, {"github:o/r"})
            self.assertEqual(record["status"], "redundant")
            self.assertFalse(probation_ready(record, "2026-08-22"))

        def test_calendar_gap_resets_discovery_probation(self):
            state = initial_state()
            scores = {"github:o/r": 20}
            for date in ("2026-08-20", "2026-08-22"):
                record = update_candidate_state(
                    state, {"ok": True, "url": "https://sources.example.org/source.json",
                            "sha256": "a" * 64, "items": 2, "new_items": 2},
                    {"github:o/r"}, scores, date, {"github:o/r"})
            self.assertEqual(record["consecutive_successes"], 1)
            self.assertFalse(probation_ready(record, "2026-08-22"))

        def test_absence_resets_discovery_probation(self):
            state = initial_state()
            scores = {"github:o/r": 20}
            url = "https://sources.example.org/source.json"
            for date in ("2026-08-20", "2026-08-21"):
                update_candidate_state(
                    state, {"ok": True, "url": url, "sha256": "a" * 64,
                            "items": 2, "new_items": 2},
                    {"github:o/r"}, scores, date, {"github:o/r"})
            reset_absent_candidates(state, set())
            record = update_candidate_state(
                state, {"ok": True, "url": url, "sha256": "a" * 64,
                        "items": 2, "new_items": 2},
                {"github:o/r"}, scores, "2026-08-23", {"github:o/r"})
            self.assertEqual(record["consecutive_successes"], 1)
            self.assertFalse(probation_ready(record, "2026-08-23"))

        def test_hash_change_resets_stability(self):
            state = initial_state()
            scores = {"github:o/r": 20}
            update_candidate_state(state, {"ok": True, "url": "https://x/source.json",
                                           "sha256": "a" * 64}, {"github:o/r"}, scores, "2026-08-20")
            record = update_candidate_state(state, {"ok": True, "url": "https://x/source.json",
                                                    "sha256": "b" * 64}, {"github:o/r"}, scores, "2026-08-21")
            self.assertEqual(record["stable_successes"], 1)
            self.assertFalse(probation_ready(record, "2026-08-21"))

        def test_failure_resets_consecutive_success(self):
            state = initial_state()
            scores = {"github:o/r": 20}
            update_candidate_state(state, {"ok": True, "url": "https://x/source.json",
                                           "sha256": "a" * 64}, {"github:o/r"}, scores, "2026-08-20")
            record = update_candidate_state(state, {"ok": False, "url": "https://x/source.json",
                                                    "error": "failed"}, {"github:o/r"}, scores, "2026-08-21")
            self.assertEqual(record["consecutive_successes"], 0)
            self.assertEqual(record["stable_successes"], 0)

        def test_same_day_not_double_counted(self):
            state = initial_state()
            scores = {"github:o/r": 20}
            for _ in range(3):
                record = update_candidate_state(
                    state, {"ok": True, "url": "https://x/source.json",
                            "sha256": "a" * 64}, {"github:o/r"}, scores, "2026-08-20")
            self.assertEqual(record["successful_runs"], 1)
            self.assertEqual(record["observed_dates"], ["2026-08-20"])

        def test_same_day_failure_resets_probation(self):
            state = initial_state()
            scores = {"github:o/r": 20}
            update_candidate_state(
                state, {"ok": True, "url": "https://x/source.json", "sha256": "a" * 64},
                {"github:o/r"}, scores, "2026-08-20")
            record = update_candidate_state(
                state, {"ok": False, "url": "https://x/source.json", "error": "flaky"},
                {"github:o/r"}, scores, "2026-08-20")
            self.assertEqual(record["consecutive_successes"], 0)
            self.assertEqual(record["stable_successes"], 0)

        def test_low_confidence_never_promotes(self):
            state = initial_state()
            for date in ("2026-08-20", "2026-08-21", "2026-08-22"):
                record = update_candidate_state(
                    state, {"ok": True, "url": "https://x/source.json",
                            "sha256": "a" * 64}, {"manual-seed"}, {}, date)
            self.assertFalse(probation_ready(record, "2026-08-22"))

        def test_clean_url_rejects_runtime_search_and_media(self):
            self.assertIsNone(clean_extracted_url("https://x.example/search?q={keyword}"))
            self.assertIsNone(clean_extracted_url("https://x.example/a.png"))
            self.assertIsNone(clean_extracted_url("https://api.github.com/repos/o/animeko/contents/x.json"))
            self.assertIsNone(clean_extracted_url("https://user:secret@x.example/source.json"))
            self.assertIsNone(clean_extracted_url("https://x.example/source.json?access_token=secret"))
            self.assertIsNone(clean_extracted_url("https://github.com/open-ani/animeko"))
            self.assertEqual(
                clean_extracted_url("https://sources.example.org/animeko/source.json"),
                "https://sources.example.org/animeko/source.json")
            self.assertEqual(
                clean_extracted_url("https://raw.githubusercontent.com/o/r/main/x.json)后续文字"),
                "https://raw.githubusercontent.com/o/r/main/x.json")

        def test_relevant_path_limits(self):
            self.assertTrue(relevant_path("src/update_sources.py", 100))
            self.assertFalse(relevant_path("../update_sources.py", 100))
            self.assertFalse(relevant_path("src/../../secret.py", 100))
            self.assertFalse(relevant_path("node_modules/x.js", 100))
            self.assertFalse(relevant_path("huge.py", MAX_FILE_BYTES + 1))
            self.assertFalse(safe_repository_name("owner/../repo"))
            self.assertFalse(safe_ref_name("../main"))

        def test_api_error_redacts_all_credentials(self):
            client = ApiClient()
            try:
                client.github_token = hashlib.sha256(b"github-test").hexdigest()
                client.gitee_token = hashlib.sha256(b"gitee-test").hexdigest()
                client.brave_token = hashlib.sha256(b"brave-test").hexdigest()
                redacted = client.redact(" ".join(
                    (client.github_token, client.gitee_token, client.brave_token)))
                self.assertTrue(all(token not in redacted for token in (
                    client.github_token, client.gitee_token, client.brave_token)))
                self.assertEqual(redacted.count("[REDACTED]"), 3)
            finally:
                client.close()

        def test_provider_errors_are_field_sanitized_before_output(self):
            client = ApiClient()
            try:
                client.github_token = "github_pat_" + ("a" * 32)
                errors = [{
                    "provider": "github-code",
                    "query": "untrusted query must not persist",
                    "path": "Bearer attacker-controlled-value",
                    "error": "request failed " + client.github_token,
                }]
                sanitized = sanitize_provider_errors(errors, client)
                serialized = json.dumps(sanitized)
                self.assertNotIn(client.github_token, serialized)
                self.assertNotIn("untrusted query", serialized)
                self.assertNotIn("attacker-controlled", serialized)
                self.assertEqual(set(sanitized[0]), {"provider", "error"})
            finally:
                client.close()

        def test_existing_links_rejects_symlink_invalid_and_over_limit(self):
            old_links = globals()["LINKS_PATH"]

            class Updater:
                @staticmethod
                def normalize(value):
                    return canonicalize_url(value)

            with tempfile.TemporaryDirectory() as td:
                root = Path(td)
                target = root / "target.txt"
                target.write_text("https://sources.example.org/x.json\n")
                globals()["LINKS_PATH"] = root / "links.txt"
                globals()["LINKS_PATH"].symlink_to(target)
                try:
                    with self.assertRaises(RuntimeError):
                        existing_links(Updater)
                finally:
                    globals()["LINKS_PATH"] = old_links
            with tempfile.TemporaryDirectory() as td:
                root = Path(td)
                globals()["LINKS_PATH"] = root / "links.txt"
                globals()["LINKS_PATH"].write_text("https://127.0.0.1/x.json\n")
                try:
                    with self.assertRaises(RuntimeError):
                        existing_links(Updater)
                finally:
                    globals()["LINKS_PATH"] = old_links
            with tempfile.TemporaryDirectory() as td:
                root = Path(td)
                globals()["LINKS_PATH"] = root / "links.txt"
                globals()["LINKS_PATH"].write_text("".join(
                    f"https://source{i}.example.org/x.json\n" for i in range(MAX_SOURCE_LINKS + 1)))
                try:
                    with self.assertRaises(RuntimeError):
                        existing_links(Updater)
                finally:
                    globals()["LINKS_PATH"] = old_links

        def test_regex_validation_budget_is_hard(self):
            budget = RegexValidationBudget(2)
            self.assertTrue(budget.consume())
            self.assertTrue(budget.consume())
            self.assertFalse(budget.consume())
            self.assertEqual(budget.used, 2)

        def test_state_validation_rejects_bad_hash(self):
            old_dir = globals()["DISCOVERY_DIR"]
            old_state = globals()["STATE_PATH"]
            old_paths = (globals()["PROGRAMS_PATH"], globals()["CANDIDATES_PATH"],
                         globals()["REJECTED_PATH"], globals()["REDUNDANT_PATH"],
                         globals()["LATEST_PATH"])
            with tempfile.TemporaryDirectory() as td:
                base = Path(td)
                globals()["DISCOVERY_DIR"] = base
                globals()["STATE_PATH"] = base / "state.json"
                globals()["PROGRAMS_PATH"] = base / "programs.json"
                globals()["CANDIDATES_PATH"] = base / "candidates.json"
                globals()["REJECTED_PATH"] = base / "rejected.json"
                globals()["REDUNDANT_PATH"] = base / "redundant.json"
                globals()["LATEST_PATH"] = base / "latest.json"
                try:
                    write_json_atomic(globals()["STATE_PATH"], {
                        "version": STATE_VERSION, "promoted": [], "candidates": {
                            "https://x/source.json": {"status": "valid", "last_sha256": "bad"}}})
                    for path in (globals()["PROGRAMS_PATH"], globals()["CANDIDATES_PATH"],
                                 globals()["REJECTED_PATH"], globals()["REDUNDANT_PATH"],
                                 globals()["LATEST_PATH"]):
                        write_json_atomic(path, {})
                    self.assertTrue(any("hash" in p for p in validate_state_files()))
                finally:
                    globals()["DISCOVERY_DIR"] = old_dir
                    globals()["STATE_PATH"] = old_state
                    (globals()["PROGRAMS_PATH"], globals()["CANDIDATES_PATH"],
                     globals()["REJECTED_PATH"], globals()["REDUNDANT_PATH"],
                     globals()["LATEST_PATH"]) = old_paths

    result = unittest.TextTestRunner(verbosity=1).run(
        unittest.defaultTestLoader.loadTestsFromTestCase(T))
    raise SystemExit(0 if result.wasSuccessful() else 1)


def main():
    parser = argparse.ArgumentParser(description="静态发现Animeko数据源生态程序和订阅候选")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--discover", action="store_true", help="搜索并静态分析公开程序仓库")
    group.add_argument("--test", action="store_true", help="运行内置测试")
    group.add_argument("--validate-state", action="store_true", help="校验发现状态文件")
    args = parser.parse_args()
    if args.test:
        run_selftests()
    if args.validate_state:
        problems = validate_state_files()
        if problems:
            for problem in problems:
                print(problem, file=sys.stderr)
            raise SystemExit(1)
        print("discovery state valid")
        return
    run_discovery()


if __name__ == "__main__":
    main()
