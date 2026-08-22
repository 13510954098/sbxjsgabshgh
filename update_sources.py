#!/usr/bin/env python3

from __future__ import annotations

import base64
import copy
import gzip
import hashlib
import ipaddress
import io
import json
import math
import os
import re
import shutil
import socket
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlsplit, urlunsplit, urljoin, quote, unquote

try:
    import requests
    from requests.adapters import HTTPAdapter
    import urllib3
    from urllib3.connection import HTTPConnection, HTTPSConnection
    from urllib3.connectionpool import HTTPConnectionPool, HTTPSConnectionPool
    from urllib3.poolmanager import PoolManager
except ImportError:
    sys.exit("缺少依赖 requests：请先 `pip install requests==2.33.0 urllib3==2.7.0`")
def _dependency_version(value):
    match = re.match(r"^(\d+)\.(\d+)", value)
    return (int(match.group(1)), int(match.group(2))) if match else None


_requests_version = _dependency_version(requests.__version__)
_urllib3_version = _dependency_version(urllib3.__version__)
if (_requests_version is None or _requests_version[0] != 2 or _requests_version < (2, 33)
        or _urllib3_version is None or _urllib3_version[0] != 2 or _urllib3_version < (2, 7)):
    sys.exit(f"依赖版本不兼容：requests={requests.__version__}, urllib3={urllib3.__version__}；"
             "需要 requests>=2.33,<3 和 urllib3>=2.7,<3")

UA_DEFAULT = ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 "
              "(KHTML, like Gecko) Version/17.0 Safari/605.1.15")
UA_FALLBACK = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
               "(KHTML, like Gecko) Chrome/124.0 Safari/537.36")
TIMEOUT = (5, 20)
DNS_TIMEOUT = 5
DNS_MAX_OUTSTANDING = 32
MAX_WORKERS = 12
MAX_RESP_SIZE = 2 * 1024 * 1024
MAX_TOTAL_INPUT_SIZE = 64 * 1024 * 1024
MAX_ITEMS_PER_SOURCE = 2000
MIN_SOURCE_ITEM_VALID_RATIO = 0.50
MAX_TOTAL_CANDIDATES = 50000
MAX_OUTPUT_FILE_SIZE = 25 * 1024 * 1024
MAX_SOURCE_LINKS = 5000
MAX_UNIQUE_SOURCES = 250
MAX_LINK_FILE_SIZE = 1024 * 1024
MAX_GITHUB_API_REFS = 200
GITHUB_API_WORKERS = 8
MAX_REDIRECTS = 5
MAX_HOST_CONSECUTIVE_FAIL = 3
HOST_MAX_CONCURRENT = 3
CACHE_DIR = "cache"
REPORT_DIR = "reports"
STALE_MAX_AGE_DAYS = 7
MIN_VALID_RATIO = 0.70
MIN_OUTPUT_COUNT = 100
OUTPUT_KEEP_RATIO = 0.85
MAX_DELETE_RATIO = 0.10
MAX_GROWTH_RATIO = 1.00
MAX_STALE_RATIO = 0.50
GROUP_DEADLINE = 90

ACCEL_HOSTS = ("gh-proxy.com", "v6.gh-proxy.org", "cdn.gh-proxy.org", "ghfast.top",
               "ghproxy.net", "gh.ddlc.top", "ghproxy.cc")

PRIO_NAMES = {0: "MajoSissi 官方 dist", 1: "MajoSissi 官方 source", 2: "w658/creamycake 官方聚合",
              3: "知名三方聚合", 4: "三方独立源", 5: "dist 镜像 fork"}


OUTPUT_FILES = ("all.json", "online.json", "bt.json", "all-name.json", "online-name.json", "bt-name.json")

KNOWN_REGEX_FIELDS = ("matchChannelName", "matchEpisodeSortFromName", "matchNestedUrl", "matchVideoUrl")
SELECTOR_FIELDS = ("selectLists", "selectNames", "selectLinks", "selectEpisodes", "selectEpisodeLinks",
                   "selectChannelNames", "selectEpisodeLists", "selectEpisodesFromList",
                   "selectEpisodeLinksFromList", "selectCovers")
KNOWN_BOOL_FIELDS = ("searchUseOnlyFirstWord", "searchRemoveSpecial", "filterByEpisodeSort",
                     "filterBySubjectName", "preferShorterName", "preferShortest",
                     "distinguishSubjectName", "distinguishChannelName", "enableNestedUrl",
                     "scanDomMediaUrls", "scanInlineScriptUrls")
KNOWN_INT_FIELDS = ("searchUseSubjectNamesCount", "requestInterval", "searchCacheTtl")
KNOWN_STRING_LIST_FIELDS = ("onlySupportsPlayers",)
KNOWN_OBJECT_FIELDS = ("selectorSubjectFormatA", "selectorSubjectFormatIndexed",
                       "selectorSubjectFormatJsonPathIndexed", "selectorChannelFormatFlattened",
                       "selectorChannelFormatNoChannel", "selectMedia", "matchVideo",
                       "addHeadersToVideo")
KNOWN_PLAIN_STRING_FIELDS = ("rawBaseUrl", "subjectFormatId", "channelFormatId",
                             "defaultResolution", "defaultSubtitleLanguage", "cookies",
                             "referer", "userAgent")

MAX_LEN_NAME = 200
MAX_LEN_DESC = 1000
MAX_LEN_SELECTOR = 500
MAX_LEN_REGEX = 500
MAX_UNIQUE_REGEXES = 5000
MAX_TOTAL_REGEX_CHARS = 1024 * 1024
MAX_LEN_URL = 8192


GITIGNORE_CONTENT = "cache/\nreports/\ndist/.tmp-*\ndist.bak-*\ndist.new-*\n.update_sources.lock\n__pycache__/\n*.pyc\n"
def ensure_gitignore():
    if not os.path.exists(".gitignore"):
        try:
            with open(".gitignore", "w", encoding="utf-8") as f:
                f.write(GITIGNORE_CONTENT)
        except Exception as e:
            print(f"⚠️ .gitignore 写入失败: {e}", file=sys.stderr)


_run_lock_handle = None


def acquire_run_lock(path: str = ".update_sources.lock"):
    global _run_lock_handle
    if _run_lock_handle is not None:
        return
    flags = os.O_RDWR | os.O_CREAT
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    try:
        fd = os.open(path, flags, 0o600)
        handle = os.fdopen(fd, "r+", encoding="utf-8")
    except OSError as exc:
        raise RuntimeError("运行锁文件无法安全打开") from exc
    try:
        try:
            import fcntl
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except ImportError:
            import msvcrt
            handle.seek(0)
            if handle.read(1) == "":
                handle.write("0")
                handle.flush()
            handle.seek(0)
            msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
    except (BlockingIOError, OSError):
        handle.close()
        raise RuntimeError("已有另一个更新进程正在运行")
    handle.seek(0)
    handle.truncate()
    handle.write(str(os.getpid()))
    handle.flush()
    _run_lock_handle = handle


def sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def sha256_json(obj) -> str:
    return hashlib.sha256(json.dumps(obj, ensure_ascii=False, sort_keys=True, allow_nan=False).encode("utf-8")).hexdigest()


UINT_MAX = 2**32 - 1
_IPISH_CHARS = "0123456789.abcdefx:"


def safe_tier(t):
    if isinstance(t, bool):
        return None
    if isinstance(t, int):
        return t if 0 <= t <= UINT_MAX else None
    if isinstance(t, float):
        if t.is_integer() and 0 <= t <= UINT_MAX:
            return int(t)
        return None
    if isinstance(t, str) and t.strip().isdigit():
        try:
            v = int(t)
        except (ValueError, OverflowError):
            return None
        return v if 0 <= v <= UINT_MAX else None
    return None


def tier_rank_of(t):
    return tier_sort_value(t)


TIER_SORT_MAP = {0: 0, 1: 1, 2: 3, 3: 4, 4: 5, 5: 6, 6: 7}


def tier_sort_value(t):
    t = safe_tier(t)
    if t is None:
        return 2
    return TIER_SORT_MAP.get(t, t + 1)


def safe_channel_tier(v):
    if isinstance(v, bool):
        return None
    if isinstance(v, int):
        return v if 0 <= v <= UINT_MAX else None
    if isinstance(v, float):
        if v.is_integer() and 0 <= v <= UINT_MAX:
            return int(v)
        return None
    if isinstance(v, str) and v.strip().isdigit():
        try:
            vv = int(v)
        except (ValueError, OverflowError):
            return None
        return vv if 0 <= vv <= UINT_MAX else None
    return None


def is_private_ip(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    return (not ip.is_global or ip.is_loopback or ip.is_link_local or ip.is_private
            or ip.is_reserved or ip.is_multicast or ip.is_unspecified
            or (ip.version == 6 and ip.is_site_local))


def is_literal_private_host(host: str) -> bool:
    h = host.strip().lower().rstrip(".")
    if not h:
        return True
    if h == "localhost":
        return True
    looks_hex = (
        h.startswith("0x")
        and len(h) > 2
        and all(ch in "0123456789abcdef" for ch in h[2:])
    )
    looks_numeric = (
        (any(ch.isdigit() for ch in h) and all(ch in _IPISH_CHARS for ch in h))
        or looks_hex
        or ":" in h
    )
    try:
        ipaddress.ip_address(h)
    except ValueError:
        return looks_numeric
    return is_private_ip(h)


def _has_control_chars(value: str) -> bool:
    return any(ord(ch) < 32 or ord(ch) == 127 for ch in value)


_dns_rotation = {}
_dns_rotation_lock = threading.Lock()
_dns_slots = threading.BoundedSemaphore(DNS_MAX_OUTSTANDING)


def _bounded_getaddrinfo(host: str, deadline: float | None = None):
    wait = DNS_TIMEOUT
    if deadline is not None:
        wait = min(wait, max(0.0, deadline - time.monotonic()))
    if wait <= 0:
        return None, "dns-timeout"
    slot_started = time.monotonic()
    if not _dns_slots.acquire(timeout=wait):
        return None, "dns-timeout"
    wait -= time.monotonic() - slot_started
    if wait <= 0:
        _dns_slots.release()
        return None, "dns-timeout"
    result = {}
    done = threading.Event()

    def resolve():
        try:
            result["infos"] = socket.getaddrinfo(host, None)
        except Exception as exc:
            result["error"] = exc
        finally:
            done.set()
            _dns_slots.release()

    try:
        threading.Thread(target=resolve, daemon=True).start()
    except Exception:
        _dns_slots.release()
        return None, "dns-fail"
    if not done.wait(wait):
        return None, "dns-timeout"
    infos = result.get("infos")
    return (infos, None) if infos else (None, "dns-fail")


def _choose_public_ip(host: str, infos):
    public_ipv4 = []
    public_ipv6 = []
    for info in infos:
        ip = info[4][0]
        if is_private_ip(ip):
            continue
        target = public_ipv4 if ipaddress.ip_address(ip).version == 4 else public_ipv6
        if ip not in target:
            target.append(ip)
    public_ips = public_ipv4 or public_ipv6
    if not public_ips:
        return None
    with _dns_rotation_lock:
        index = _dns_rotation.get(host, 0)
        _dns_rotation[host] = index + 1
    return public_ips[index % len(public_ips)]


def check_url_safety(url: str, deadline: float | None = None) -> tuple[str | None, str | None]:
    if not url:
        return "empty-url", None
    if not isinstance(url, str) or _has_control_chars(url):
        return "control-char", None
    if len(url) > MAX_LEN_URL:
        return "too-long", None
    try:
        u = urlsplit(url)
    except ValueError:
        return "unparseable", None
    if u.scheme not in ("http", "https"):
        return "bad-scheme", None
    if u.username is not None or u.password is not None:
        return "userinfo", None
    try:
        port = u.port
    except ValueError:
        return "bad-port", None
    if port == 0:
        return "bad-port", None
    host = (u.hostname or "").lower().rstrip(".")
    if not host:
        return "no-host", None
    if is_literal_private_host(host):
        return "private-host", None
    infos, dns_error = _bounded_getaddrinfo(host, deadline)
    if dns_error:
        return dns_error, None
    ip = _choose_public_ip(host, infos)
    if ip is None:
        return "private-ip", None
    return None, ip


def url_shallow_ok(u) -> tuple[bool, str | None]:
    if not isinstance(u, str):
        return False, "not-string"
    if not u:
        return False, "empty"
    if len(u) > MAX_LEN_URL:
        return False, "too-long"
    if _has_control_chars(u):
        return False, "control-char"
    if u.startswith("["):
        match = re.match(r"^\[[A-Za-z0-9_.-]{1,64}\]/", u)
        if not match:
            return False, "bad-bracket"
        suffix = u[match.end() - 1:]
        if suffix.startswith("//") or "\\" in suffix or any(part == ".." for part in suffix.split("/")):
            return False, "bad-bracket-path"
        return True, None
    try:
        p = urlsplit(u)
    except (ValueError, TypeError, AttributeError):
        return False, "unparseable"
    if p.scheme not in ("http", "https"):
        return False, "bad-scheme"
    if p.username is not None or p.password is not None:
        return False, "userinfo"
    try:
        port = p.port
    except ValueError:
        return False, "bad-port"
    if port == 0:
        return False, "bad-port"
    host = (p.hostname or "").lower().rstrip(".")
    if not host:
        return False, "no-host"
    if is_literal_private_host(host):
        return False, "private-ip"
    return True, None


class GitHubRef:
    __slots__ = ("owner", "repo", "ref", "path")

    def __init__(self, owner, repo, ref, path):
        self.owner, self.repo, self.ref, self.path = owner, repo, ref, path

    def raw_url(self):
        return (f"https://raw.githubusercontent.com/{self.owner}/{self.repo}/{self.ref}/{self.path}")


def fold_ref(ref: str) -> str:
    return "main" if ref == "refs/heads/main" else ref


def parse_github_raw(url: str):
    u = urlsplit(url)
    if (u.hostname or "").lower().rstrip(".") != "raw.githubusercontent.com" or u.port not in (None, 443):
        return None
    parts = [p for p in u.path.split("/") if p]
    if len(parts) < 4:
        return None
    owner, repo = parts[0], parts[1]
    if parts[2] == "refs" and len(parts) >= 6 and parts[3] in ("heads", "tags"):
        ref = "/".join(parts[2:5])
        path = "/".join(parts[5:])
    elif parts[2] == "refs":
        return None
    else:
        ref = parts[2]
        path = "/".join(parts[3:])
    return GitHubRef(owner, repo, fold_ref(ref), path)


def parse_github_com(url: str):
    u = urlsplit(url)
    if (u.hostname or "").lower().rstrip(".") != "github.com" or u.port not in (None, 443):
        return None
    parts = [p for p in u.path.split("/") if p]
    if len(parts) < 3:
        return None
    if parts[2] == "raw" and len(parts) >= 4:
        if parts[3] == "refs" and len(parts) >= 7 and parts[4] in ("heads", "tags"):
            ref = "/".join(parts[3:6])
            path = "/".join(parts[6:])
        elif parts[3] == "refs":
            return None
        else:
            ref = parts[3]
            path = "/".join(parts[4:])
        return GitHubRef(parts[0], parts[1], fold_ref(ref), path) if path else None
    if parts[2] == "blob" and len(parts) >= 4:
        if parts[3] == "refs" and len(parts) >= 7 and parts[4] in ("heads", "tags"):
            ref = "/".join(parts[3:6])
            path = "/".join(parts[6:])
        elif parts[3] == "refs":
            return None
        else:
            ref = parts[3]
            path = "/".join(parts[4:])
        return GitHubRef(parts[0], parts[1], fold_ref(ref), path) if path else None
    return None


def parse_jsdelivr(url: str):
    u = urlsplit(url)
    if (u.hostname or "").lower().rstrip(".") != "cdn.jsdelivr.net" or u.port not in (None, 443):
        return None
    m = re.match(r"^/gh/([^/@]+)/([^/@]+)@(.+)$", u.path)
    if not m:
        return None
    owner, repo, rest = m.group(1), m.group(2), m.group(3)
    if rest.startswith("refs/"):
        rm = re.match(r"^(refs/(?:heads|tags)/[^/]+)/(.+)$", rest)
        if rm:
            return GitHubRef(owner, repo, fold_ref(rm.group(1)), rm.group(2))
        return None
    if "/" not in rest:
        return None
    ref, path = rest.split("/", 1)
    return GitHubRef(owner, repo, fold_ref(ref), path)


MAX_PROXY_NESTING = 2


def normalize(url: str) -> str:
    u = url.strip()
    if len(u) > MAX_LEN_URL:
        raise ValueError(f"链接过长: {len(u)}")
    if _has_control_chars(u):
        raise ValueError(f"链接包含控制字符: {repr(u[:60])}")
    if is_bad_protocol(u):
        raise ValueError(f"非法协议: {u}")
    parsed = urlsplit(u)
    if parsed.scheme != "https":
        raise ValueError(f"上游配置链接必须使用 HTTPS: {u[:60]}")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError(f"链接不得包含用户信息: {u[:60]}")
    try:
        initial_port = parsed.port
    except ValueError as exc:
        raise ValueError(f"链接端口非法: {u[:60]}") from exc
    if initial_port == 0:
        raise ValueError(f"链接端口非法: {u[:60]}")
    peeled = 0
    while True:
        for p in (parse_jsdelivr, parse_github_com, parse_github_raw):
            gr = p(u)
            if gr:
                return gr.raw_url()
        up = urlsplit(u)
        host = (up.hostname or "").lower().rstrip(".")
        if host in ACCEL_HOSTS:
            if up.port not in (None, 443):
                raise ValueError(f"代理链接端口非法: {u[:60]}")
            raw_rest = None
            raw_matched = False
            for prefix in ("/raw.githubusercontent.com/", "/https://raw.githubusercontent.com/"):
                if up.path.startswith(prefix):
                    raw_matched = True
                    raw_rest = up.path[len(prefix):]
                    break
            if raw_matched:
                if not raw_rest:
                    raise ValueError(f"代理链接缺少文件 path: {url[:60]}")
                peeled += 1
                if peeled > MAX_PROXY_NESTING:
                    raise ValueError(f"代理嵌套过深（> {MAX_PROXY_NESTING} 层）: {url[:60]}")
                u = f"https://raw.githubusercontent.com/{raw_rest}"
                continue
            if up.path.startswith("/https://github.com/"):
                peeled += 1
                if peeled > MAX_PROXY_NESTING:
                    raise ValueError(f"代理嵌套过深（> {MAX_PROXY_NESTING} 层）: {url[:60]}")
                u = "https://github.com/" + up.path[len("/https://github.com/"):]
                continue
        break
    if host in ACCEL_HOSTS:
        raise ValueError(f"代理链接结构非法: {u[:60]}")
    if host in ("cdn.jsdelivr.net", "raw.githubusercontent.com", "github.com"):
        raise ValueError(f"{host} 链接结构非法（缺文件 path 段？）: {u[:60]}")
    if up.scheme not in ("http", "https") or not up.hostname:
        raise ValueError(f"非 http(s) 链接: {u[:60]}")
    if is_literal_private_host(up.hostname):
        raise ValueError(f"上游配置链接不得使用非公网地址: {u[:60]}")
    try:
        port = up.port
    except ValueError as exc:
        raise ValueError(f"链接端口非法: {u[:60]}") from exc
    clean_host = up.hostname.lower().rstrip(".")
    netloc = f"[{clean_host}]" if ":" in clean_host else clean_host
    if port is not None and not (up.scheme == "https" and port == 443):
        netloc += f":{port}"
    return urlunsplit((up.scheme, netloc, up.path, up.query, ""))


def is_bad_protocol(url: str) -> bool:
    return urlsplit(url).scheme.lower() not in ("http", "https", "")


def host_rank(url: str) -> int:
    host = (urlsplit(url).hostname or "").lower().rstrip(".")
    if host == "raw.githubusercontent.com":
        return 0
    if host == "cdn.jsdelivr.net":
        return 1
    if host == "github.com":
        return 2
    if host in ACCEL_HOSTS:
        return 3
    return 4


def classify_priority(canon: str) -> int:
    gr = parse_github_raw(canon)
    if gr:
        key = f"{gr.owner}/{gr.repo}".lower()
        if key == "majosissi/animeko-source":
            if gr.path.startswith("dist/"):
                return 0
            if gr.path.startswith("source/"):
                return 1
        if key in ("crazybunqnq/animeko-sources", "zen-guo/animeko-sources",
                   "luckyrabbitfeet/animeko-source", "saber-yz/animeko-source",
                   "761218728/animeko-source"):
            return 3
        if key in ("llimeslice/animeko-source", "lklbjn/animeko-source",
                   "heibu01/animeko-source", "lingjueding0726/animeko-source",
                   "mophy-chun/animeko-source", "2016yyy/animeko-source",
                   "becausemadoka/animeko-source"):
            return 5
        return 4
    up = urlsplit(canon)
    host = (up.hostname or "").lower().rstrip(".")
    if host == "gitee.com" and up.path.startswith("/w658/"):
        return 2
    if host == "sub.creamycake.org":
        return 2
    return 4


def is_core_official(canon: str) -> bool:
    gr = parse_github_raw(canon)
    return bool(gr and gr.owner.lower() == "majosissi" and gr.repo.lower() == "animeko-source"
                and gr.path in ("dist/all.json", "dist/online.json", "dist/bt.json"))


FILE_ORDER = {"dist/all.json": 0, "dist/online.json": 1, "dist/bt.json": 2}


def file_order_key(canon: str) -> int:
    gr = parse_github_raw(canon)
    if gr and gr.path.startswith("dist/"):
        return FILE_ORDER.get(gr.path, 3)
    return 3


def extract(obj):
    if isinstance(obj, dict):
        if "exportedMediaSourceDataList" in obj:
            edsl = obj["exportedMediaSourceDataList"]
            return edsl.get("mediaSources") if isinstance(edsl, dict) and isinstance(edsl.get("mediaSources"), list) else None
        if "mediaSources" in obj:
            return obj["mediaSources"] if isinstance(obj["mediaSources"], list) else None
    if isinstance(obj, list):
        return obj
    return None


def url_of(m):
    a = m.get("arguments")
    if not isinstance(a, dict):
        return ""
    sc = a.get("searchConfig")
    if not isinstance(sc, dict):
        return ""
    value = sc.get("searchUrl")
    return value if isinstance(value, str) and value else ""


def _reject_json_constant(value):
    raise ValueError(f"非法 JSON 常量: {value}")


def _strict_json_float(value):
    number = float(value)
    if not math.isfinite(number):
        raise ValueError(f"非有限 JSON 数字: {value}")
    return number


def _strict_json_object(pairs):
    obj = {}
    for key, value in pairs:
        if key in obj:
            raise ValueError(f"JSON 对象键重复: {key}")
        obj[key] = value
    return obj


def load_json_file(path: str):
    with open(path, encoding="utf-8-sig") as f:
        return json.load(f, parse_constant=_reject_json_constant, parse_float=_strict_json_float,
                         object_pairs_hook=_strict_json_object)


def load_json_bytes(data: bytes):
    for enc in ("utf-8-sig", "utf-8"):
        try:
            text = data.decode(enc)
        except UnicodeDecodeError:
            continue
        try:
            obj = json.loads(text, parse_constant=_reject_json_constant,
                             parse_float=_strict_json_float,
                             object_pairs_hook=_strict_json_object)
        except Exception:
            continue
        ms = extract(obj)
        if isinstance(ms, list):
            return obj
    try:
        obj = json.loads(data.decode("gbk"), parse_constant=_reject_json_constant,
                         parse_float=_strict_json_float,
                         object_pairs_hook=_strict_json_object)
    except Exception:
        pass
    else:
        ms = extract(obj)
        if isinstance(ms, list):
            return obj
    raise ValueError("无法解析 JSON（UTF-8/GBK 编码探测+结构校验均失败）")


def migrate_top_level_tier(item):
    it = copy.deepcopy(item)
    raw_args = it.get("arguments")
    if not isinstance(raw_args, dict):
        return it
    args = dict(raw_args)
    marker = object()
    top_tier = it.pop("tier", marker)
    if "tier" not in args and top_tier is not marker:
        args["tier"] = top_tier
    t = safe_tier(args.get("tier"))
    if t is None:
        args.pop("tier", None)
    else:
        args["tier"] = t
    it["arguments"] = args
    return it


def normalize_regex_named_groups(s: str) -> str:
    if "?P<" not in s:
        return s
    out = []
    i = 0
    in_class = False
    while i < len(s):
        if s[i] == "\\" and i + 1 < len(s):
            out.append(s[i:i + 2])
            i += 2
            continue
        if s[i] == "[":
            in_class = True
        elif s[i] == "]" and in_class:
            in_class = False
        if not in_class and s.startswith("(?P<", i):
            match = re.match(r"\(\?P<([A-Za-z_][A-Za-z0-9_]*)>", s[i:])
            if match:
                out.append(f"(?<{match.group(1)}>")
                i += match.end()
                continue
        out.append(s[i])
        i += 1
    return "".join(out)


def normalize_known_regex_fields(obj):
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            if k in KNOWN_REGEX_FIELDS and isinstance(v, str):
                out[k] = normalize_regex_named_groups(v)
            else:
                out[k] = normalize_known_regex_fields(v)
        return out
    if isinstance(obj, list):
        return [normalize_known_regex_fields(v) for v in obj]
    return obj


def normalize_item(item):
    m = migrate_top_level_tier(item)
    raw_args = m.get("arguments")
    if not isinstance(raw_args, dict):
        return m
    args = normalize_known_regex_fields(raw_args)
    search_config = args.get("searchConfig")
    can_migrate_url = False
    if isinstance(search_config, dict):
        can_migrate_url = "searchUrl" not in search_config or search_config.get("searchUrl") == ""
    elif search_config is None:
        search_config = {}
        can_migrate_url = True
    if isinstance(search_config, dict):
        if can_migrate_url:
            legacy_candidates = (search_config.get("rssUrl"), args.get("rssUrl"), args.get("searchUrl"))
            for legacy_url in legacy_candidates:
                if isinstance(legacy_url, str) and legacy_url:
                    search_config["searchUrl"] = legacy_url
                    break
        args["searchConfig"] = search_config
    args.setdefault("description", "")
    args.setdefault("iconUrl", "")
    ct = args.get("channelTiers")
    if isinstance(ct, dict):
        normalized = {}
        for channel, value in ct.items():
            tier = safe_channel_tier(value)
            normalized[str(channel)] = value if tier is None else tier
        args["channelTiers"] = normalized
    m["arguments"] = args
    return m


ALLOWED_FACTORY = ("web-selector", "rss")
SUPPORTED_VERSIONS = {
    "web-selector": {1, 2},
    "rss": {1},
}


def validate_item(m) -> tuple[bool, list[str]]:
    problems = []
    if not isinstance(m, dict):
        return False, ["条目非 dict"]
    factory_id = m.get("factoryId")
    version = m.get("version")
    if factory_id not in ALLOWED_FACTORY:
        problems.append(f"factoryId={factory_id!r} 不受支持")
    if isinstance(version, bool) or not isinstance(version, int):
        problems.append("version 非整数")
    elif factory_id in SUPPORTED_VERSIONS and version not in SUPPORTED_VERSIONS[factory_id]:
        problems.append(f"{factory_id} 不支持 version={version!r}")
    a = m.get("arguments")
    if not isinstance(a, dict):
        problems.append("arguments 非 dict")
        return False, problems
    name = a.get("name")
    if not isinstance(name, str) or not name.strip():
        problems.append("name 缺失/为空")
    elif len(name) > MAX_LEN_NAME:
        problems.append(f"name 超长: {len(name)}")
    desc = a.get("description")
    if not isinstance(desc, str):
        problems.append("description 缺失或非字符串")
    elif len(desc) > MAX_LEN_DESC:
        problems.append("description 超长")
    icon = a.get("iconUrl")
    if not isinstance(icon, str):
        problems.append("iconUrl 缺失或非字符串")
    elif icon:
        ok_icon, err_icon = url_shallow_ok(icon)
        if not ok_icon:
            problems.append(f"iconUrl 非法({err_icon}): {icon[:60]}")
    sc = a.get("searchConfig")
    if not isinstance(sc, dict):
        problems.append("searchConfig 非 dict")
    u = url_of(m)
    ok_u, err_u = url_shallow_ok(u)
    if not ok_u:
        problems.append(f"searchUrl/rssUrl 非法({err_u}): {u[:80]}")
    def check_lengths(obj):
        if isinstance(obj, dict):
            for k, v in obj.items():
                if k in KNOWN_REGEX_FIELDS:
                    if not isinstance(v, str):
                        problems.append(f"正则字段非字符串 {name}: {k}")
                    elif len(v) > MAX_LEN_REGEX:
                        problems.append(f"正则超长 {name}: {k} {len(v)}")
                elif k in SELECTOR_FIELDS:
                    if not isinstance(v, str):
                        problems.append(f"选择器字段非字符串 {name}: {k}")
                    elif len(v) > MAX_LEN_SELECTOR:
                        problems.append(f"选择器超长 {name}: {k} {len(v)}")
                elif k in KNOWN_BOOL_FIELDS:
                    if not isinstance(v, bool):
                        problems.append(f"布尔字段类型非法 {name}: {k}")
                elif k in KNOWN_INT_FIELDS:
                    if isinstance(v, bool) or not isinstance(v, int) or v < 0:
                        problems.append(f"整数字段类型或范围非法 {name}: {k}")
                    elif k == "searchUseSubjectNamesCount" and v < 1:
                        problems.append(f"searchUseSubjectNamesCount 小于 1: {name}")
                elif k in KNOWN_STRING_LIST_FIELDS:
                    if not isinstance(v, list) or any(not isinstance(x, str) for x in v):
                        problems.append(f"字符串列表字段类型非法 {name}: {k}")
                elif k in KNOWN_OBJECT_FIELDS:
                    if not isinstance(v, dict):
                        problems.append(f"对象字段类型非法 {name}: {k}")
                    else:
                        check_lengths(v)
                elif k in KNOWN_PLAIN_STRING_FIELDS:
                    if not isinstance(v, str):
                        problems.append(f"字符串字段类型非法 {name}: {k}")
                    elif len(v) > MAX_LEN_URL:
                        problems.append(f"字符串字段超长 {name}: {k}")
                else:
                    check_lengths(v)
        elif isinstance(obj, list):
            for v in obj:
                check_lengths(v)
    check_lengths(sc)
    t = a.get("tier")
    if t is not None and safe_tier(t) is None:
        problems.append(f"tier 非法: {t!r}")
    ct = a.get("channelTiers")
    if ct is not None and not isinstance(ct, dict):
        problems.append("channelTiers 非 dict")
    elif isinstance(ct, dict):
        for ch, v in ct.items():
            if safe_channel_tier(v) is None:
                problems.append(f"channelTier {ch}={v!r} 非法")
    return len(problems) == 0, problems


def cache_path(canon: str) -> str:
    os.makedirs(CACHE_DIR, exist_ok=True)
    return os.path.join(CACHE_DIR, hashlib.sha256(canon.encode()).hexdigest() + ".json")


def load_cache(canon: str):
    p = cache_path(canon)
    if not os.path.exists(p):
        return None
    try:
        if os.path.getsize(p) > MAX_RESP_SIZE * 3:
            return None
        c = load_json_file(p)
        if not isinstance(c, dict) or c.get("canon") != canon:
            return None
        ts = c.get("ts")
        if isinstance(ts, bool) or not isinstance(ts, (int, float)) or not math.isfinite(ts):
            return None
        age = time.time() - ts
        if age < -300 or age > STALE_MAX_AGE_DAYS * 86400:
            return None
        for field in ("etag", "last_modified"):
            value = c.get(field)
            if value is not None and (not isinstance(value, str) or len(value) > MAX_LEN_URL
                                      or _has_control_chars(value)):
                return None
        validator_url = c.get("validator_url")
        if validator_url is not None and (not isinstance(validator_url, str)
                                          or len(validator_url) > MAX_LEN_URL
                                          or _has_control_chars(validator_url)):
            return None
        encoded = c.get("data_gz_b64")
        if not isinstance(encoded, str) or not encoded:
            return None
        compressed = base64.b64decode(encoded, validate=True)
        with gzip.GzipFile(fileobj=io.BytesIO(compressed)) as gz:
            data = gz.read(MAX_RESP_SIZE + 1)
        if not data or len(data) > MAX_RESP_SIZE or sha256_bytes(data) != c.get("sha256"):
            return None
        c["data"] = data
        return c
    except Exception:
        return None


def save_cache(canon: str, data: bytes, meta: dict, url: str):
    p = cache_path(canon)
    payload = {
        "canon": canon,
        "ts": time.time(),
        "sha256": sha256_bytes(data),
        "etag": meta.get("etag"),
        "last_modified": meta.get("last_modified"),
        "validator_url": url,
        "data_gz_b64": base64.b64encode(gzip.compress(data)).decode("ascii"),
    }
    tmp = p + ".tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(payload, f, allow_nan=False)
        os.replace(tmp, p)
    except Exception:
        try:
            if os.path.exists(tmp):
                os.remove(tmp)
        except Exception:
            pass


def touch_cache(canon: str):
    p = cache_path(canon)
    try:
        c = load_cache(canon)
        if c is None:
            return
        c.pop("data", None)
        c["ts"] = time.time()
        tmp = p + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(c, f, allow_nan=False)
        os.replace(tmp, p)
    except Exception:
        pass




class _PinnedHTTPSConnection(HTTPSConnection):

    def __init__(self, *args, pinned_ip=None, **kwargs):
        self._pinned_ip = pinned_ip
        super().__init__(*args, **kwargs)

    def _new_conn(self):
        if self._pinned_ip:
            try:
                sock = urllib3.util.connection.create_connection(
                    (self._pinned_ip, self.port),
                    self.timeout,
                    source_address=self.source_address,
                    socket_options=self.socket_options,
                )
            except socket.gaierror as e:
                raise urllib3.exceptions.NameResolutionError(self.host, self, e) from e
            except TimeoutError as e:
                raise urllib3.exceptions.ConnectTimeoutError(self, f"pinned {self._pinned_ip}:{self.port} timeout") from e
            except OSError as e:
                raise urllib3.exceptions.NewConnectionError(self, f"pinned {self._pinned_ip}:{self.port} failed") from e
            sys.audit("http.client.connect", self, self.host, self.port)
            return sock
        return super()._new_conn()


class _PinnedHTTPConnection(HTTPConnection):

    def __init__(self, *args, pinned_ip=None, **kwargs):
        self._pinned_ip = pinned_ip
        super().__init__(*args, **kwargs)

    def _new_conn(self):
        if self._pinned_ip:
            try:
                sock = urllib3.util.connection.create_connection(
                    (self._pinned_ip, self.port),
                    self.timeout,
                    source_address=self.source_address,
                    socket_options=self.socket_options,
                )
            except socket.gaierror as e:
                raise urllib3.exceptions.NameResolutionError(self.host, self, e) from e
            except TimeoutError as e:
                raise urllib3.exceptions.ConnectTimeoutError(self, f"pinned {self._pinned_ip}:{self.port} timeout") from e
            except OSError as e:
                raise urllib3.exceptions.NewConnectionError(self, f"pinned {self._pinned_ip}:{self.port} failed") from e
            return sock
        return super()._new_conn()


class _PinnedHTTPSConnectionPool(HTTPSConnectionPool):
    ConnectionCls = _PinnedHTTPSConnection

    def __init__(self, host, port=None, pinned_ip=None, **kwargs):
        kwargs["pinned_ip"] = pinned_ip
        super().__init__(host, port=port, **kwargs)


class _PinnedHTTPConnectionPool(HTTPConnectionPool):
    ConnectionCls = _PinnedHTTPConnection

    def __init__(self, host, port=None, pinned_ip=None, **kwargs):
        kwargs["pinned_ip"] = pinned_ip
        super().__init__(host, port=port, **kwargs)


class _PinnedPoolManager(PoolManager):
    def __init__(self, pinned_ip=None, **kwargs):
        self._pinned_ip = pinned_ip
        super().__init__(**kwargs)
        self.pool_classes_by_scheme = self.pool_classes_by_scheme.copy()
        self.pool_classes_by_scheme["https"] = _PinnedHTTPSConnectionPool
        self.pool_classes_by_scheme["http"] = _PinnedHTTPConnectionPool

    def _new_pool(self, scheme, host, port, request_context=None):
        context = (request_context.copy() if request_context is not None
                   else self.connection_pool_kw.copy())
        context["pinned_ip"] = self._pinned_ip
        return super()._new_pool(scheme, host, port, context)


class PinnedIPAdapter(HTTPAdapter):

    def __init__(self, pinned_ip, *args, **kwargs):
        self._pinned_ip = pinned_ip
        super().__init__(*args, **kwargs)

    def init_poolmanager(self, connections, maxsize, block=False, **pool_kwargs):
        self.poolmanager = _PinnedPoolManager(
            pinned_ip=self._pinned_ip,
            num_pools=connections, maxsize=maxsize, block=block, **pool_kwargs)


_pinned_tls = threading.local()


def get_pinned_session(host: str, ip: str) -> requests.Session:
    cache = getattr(_pinned_tls, "sessions", None)
    if cache is None:
        cache = _pinned_tls.sessions = {}
    key = f"{host}:{ip}"
    s = cache.get(key)
    if s is None:
        s = requests.Session()
        s.trust_env = os.environ.get("ALLOW_ENV_PROXY") == "1"
        s.mount("https://", PinnedIPAdapter(ip, pool_connections=2, pool_maxsize=2, max_retries=0))
        s.mount("http://", PinnedIPAdapter(ip, pool_connections=2, pool_maxsize=2, max_retries=0))
        cache[key] = s
    return s


_host_fail = {}
_host_lock = threading.Lock()
_host_sems: dict[str, threading.Semaphore] = {}


def host_semaphore(host: str) -> threading.Semaphore:
    with _host_lock:
        s = _host_sems.get(host)
        if s is None:
            s = threading.Semaphore(HOST_MAX_CONCURRENT)
            _host_sems[host] = s
        return s


def host_circuit_broken(host: str) -> bool:
    with _host_lock:
        return _host_fail.get(host, 0) >= MAX_HOST_CONSECUTIVE_FAIL


def host_success(host: str):
    with _host_lock:
        _host_fail[host] = 0


def host_fail(host: str):
    with _host_lock:
        _host_fail[host] = _host_fail.get(host, 0) + 1


def looks_like_html(head: bytes) -> bool:
    low = head[:256].lower().lstrip()
    if not low.startswith(b"<"):
        return False
    return (low.startswith(b"<!doctype") or low.startswith(b"<html")
            or low.startswith(b"<head") or low.startswith(b"<body"))


def fetch_url(url: str, cache_meta: dict | None, deadline: float):
    meta = {"url": url, "status": None, "error": None, "redirects": [], "latency": None}
    current = url
    redirect_count = 0
    t0 = time.monotonic()
    try:
        while redirect_count <= MAX_REDIRECTS:
            if time.monotonic() > deadline:
                meta["error"] = "deadline"
                return None, meta
            parsed = urlsplit(current)
            hop_host = (parsed.hostname or "").lower().rstrip(".")
            if host_circuit_broken(hop_host):
                meta["error"] = "circuit-open"
                meta["redirects"].append(current)
                return None, meta
            if parsed.scheme not in ("http", "https") or not hop_host:
                meta["error"] = "bad-scheme-or-host"
                meta["redirects"].append(current)
                return None, meta
            if is_literal_private_host(hop_host):
                meta["error"] = "private-host"
                meta["redirects"].append(current)
                return None, meta
            data, hop_meta, location = single_hop(current, cache_meta, deadline)
            if hop_meta.get("status") is not None:
                meta["status"] = hop_meta["status"]
            meta["latency"] = round(time.monotonic() - t0, 3)
            if hop_meta.get("final_url"):
                meta["final_url"] = hop_meta["final_url"]
            if hop_meta.get("size"):
                meta["size"] = hop_meta["size"]
            if hop_meta.get("sha256"):
                meta["sha256"] = hop_meta["sha256"]
            if hop_meta.get("etag") is not None:
                meta["etag"] = hop_meta["etag"]
            if hop_meta.get("last_modified") is not None:
                meta["last_modified"] = hop_meta["last_modified"]
            if hop_meta.get("not_modified"):
                meta["not_modified"] = True
            if data is not None:
                meta["redirects"].append(current)
                return data, meta
            if location is not None:
                redirect_count += 1
                meta["redirects"].append(current)
                next_url = urljoin(current, location)
                if urlsplit(current).scheme == "https" and urlsplit(next_url).scheme != "https":
                    meta["error"] = "redirect-downgrade"
                    meta["redirects"].append(next_url)
                    return None, meta
                current = next_url
                continue
            meta["error"] = hop_meta.get("error") or "unknown"
            meta["redirects"].append(current)
            return None, meta
        meta["error"] = "too-many-redirects"
        return None, meta
    except Exception as e:
        meta["error"] = f"unexpected:{e!r}"
        return None, meta


def single_hop(current: str, cache_meta, deadline: float):
    host = (urlsplit(current).hostname or "").lower().rstrip(".")
    meta = {"status": None, "error": None}
    if host_circuit_broken(host):
        meta["error"] = "circuit-open"
        return None, meta, None
    sem = host_semaphore(host)
    slot_wait = min(10.0, max(0.0, deadline - time.monotonic()))
    if slot_wait <= 0 or not sem.acquire(timeout=slot_wait):
        meta["error"] = "host-slot-timeout"
        return None, meta, None
    try:
        ua = UA_DEFAULT
        ua_switched = False
        retry_attempt = 0
        MAX_RETRIES_PER_URL = 3
        while retry_attempt < MAX_RETRIES_PER_URL:
            if time.monotonic() > deadline:
                meta["error"] = "deadline"
                return None, meta, None
            err, pinned_ip = check_url_safety(current, deadline)
            if err:
                if err in ("dns-fail", "dns-timeout"):
                    host_fail(host)
                meta["error"] = err
                return None, meta, None
            sess = get_pinned_session(host, pinned_ip)
            meta["error"] = None
            headers = {"User-Agent": ua}
            if cache_meta and cache_meta.get("validator_url") == current:
                if cache_meta.get("etag"):
                    headers["If-None-Match"] = cache_meta["etag"]
                if cache_meta.get("last_modified"):
                    headers["If-Modified-Since"] = cache_meta["last_modified"]
            try:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    meta["error"] = "deadline"
                    return None, meta, None
                request_timeout = (min(TIMEOUT[0], max(0.001, remaining)),
                                   min(TIMEOUT[1], max(0.001, remaining)))
                with sess.get(current, timeout=request_timeout, headers=headers,
                              allow_redirects=False, stream=True) as r:
                    meta["status"] = r.status_code
                    meta["final_url"] = r.url
                    if r.status_code < 500 and r.status_code != 429:
                        host_success(host)
                    if r.status_code in (301, 302, 303, 307, 308):
                        location = r.headers.get("Location")
                        if not location:
                            meta["error"] = "redirect-without-location"
                            return None, meta, None
                        return None, meta, urljoin(current, location)
                    if r.status_code == 304:
                        sent_validator = "If-None-Match" in headers or "If-Modified-Since" in headers
                        if sent_validator and cache_meta and cache_meta.get("data"):
                            meta["not_modified"] = True
                            return cache_meta["data"], meta, None
                        meta["error"] = ("http-304-no-validator" if not sent_validator
                                         else "http-304-no-cache")
                        return None, meta, None
                    if r.status_code == 403:
                        if not ua_switched:
                            ua_switched = True
                            ua = UA_FALLBACK
                            continue
                        meta["error"] = "http-403"
                        return None, meta, None
                    if r.status_code == 404:
                        meta["error"] = "http-404"
                        return None, meta, None
                    if r.status_code in (400, 401, 402, 405, 406, 408, 409, 410, 411, 412,
                                         413, 415, 416, 417, 418, 421, 422, 423, 424, 425,
                                         426, 428, 431, 451):
                        meta["error"] = f"http-{r.status_code}"
                        return None, meta, None
                    if r.status_code == 429 or r.status_code >= 500:
                        wait = parse_retry_after(r.headers.get("Retry-After"),
                                                 default=min(1.5 * (2 ** retry_attempt), 15))
                        retry_attempt += 1
                        if time.monotonic() + wait > deadline or retry_attempt >= MAX_RETRIES_PER_URL:
                            host_fail(host)
                            meta["error"] = f"http-{r.status_code}"
                            return None, meta, None
                        time.sleep(wait)
                        continue
                    if r.status_code != 200:
                        meta["error"] = f"http-{r.status_code}"
                        return None, meta, None
                    cl = r.headers.get("Content-Length")
                    if cl and cl.isdigit() and int(cl) > MAX_RESP_SIZE:
                        meta["error"] = "too-large-header"
                        return None, meta, None
                    chunks = []
                    size = 0
                    for chunk in r.iter_content(64 * 1024):
                        if time.monotonic() > deadline:
                            meta["error"] = "deadline-during-body"
                            return None, meta, None
                        if not chunk:
                            continue
                        size += len(chunk)
                        if size > MAX_RESP_SIZE:
                            meta["error"] = "too-large"
                            return None, meta, None
                        chunks.append(chunk)
                    data = b"".join(chunks)
                    if not data:
                        meta["error"] = "empty"
                        return None, meta, None
                    if looks_like_html(data):
                        meta["error"] = "html"
                        return None, meta, None
                    host_success(host)
                    meta["size"] = size
                    meta["sha256"] = sha256_bytes(data)
                    meta["etag"] = r.headers.get("ETag")
                    meta["last_modified"] = r.headers.get("Last-Modified")
                    return data, meta, None
            except requests.exceptions.Timeout as e:
                meta["error"] = f"timeout:{type(e).__name__}"
                retry_attempt += 1
                if time.monotonic() + 1.0 > deadline or retry_attempt >= MAX_RETRIES_PER_URL:
                    host_fail(host)
                    return None, meta, None
                time.sleep(1.0)
                continue
            except requests.exceptions.SSLError:
                meta["error"] = "tls"
                host_fail(host)
                return None, meta, None
            except requests.exceptions.ConnectionError:
                meta["error"] = "dns-or-conn"
                retry_attempt += 1
                if time.monotonic() + 1.0 > deadline or retry_attempt >= MAX_RETRIES_PER_URL:
                    host_fail(host)
                    return None, meta, None
                time.sleep(1.0)
                continue
            except (requests.exceptions.ChunkedEncodingError,
                    requests.exceptions.ContentDecodingError) as e:
                meta["error"] = f"body-transfer:{type(e).__name__}"
                retry_attempt += 1
                if time.monotonic() + 1.0 > deadline or retry_attempt >= MAX_RETRIES_PER_URL:
                    host_fail(host)
                    return None, meta, None
                time.sleep(1.0)
                continue
            except Exception as e:
                detail = str(e).replace("\r", " ").replace("\n", " ")[:200]
                meta["error"] = f"other:{type(e).__name__}:{detail}"
                return None, meta, None
        meta["error"] = meta.get("error") or "exhausted"
        return None, meta, None
    finally:
        sem.release()


def parse_retry_after(value: str | None, default: float) -> float:
    if not value:
        return default
    v = value.strip()
    if v.isdigit():
        try:
            return min(int(v), 15)
        except (ValueError, OverflowError):
            return default
    try:
        from email.utils import parsedate_to_datetime
        dt = parsedate_to_datetime(v)
        if dt:
            wait = (dt - datetime_now()).total_seconds()
            return min(max(wait, 0), 15)
    except Exception:
        pass
    return default


def datetime_now():
    import datetime
    return datetime.datetime.now(datetime.timezone.utc)


def fetch_group_worker(canon: str, urls: list[str], cache_meta):
    deadline = time.monotonic() + GROUP_DEADLINE
    last_meta = None
    for u in urls:
        data, meta = fetch_url(u, cache_meta, deadline)
        last_meta = meta
        if data is not None:
            return data, meta
        err = meta.get("error") or ""
        if "deadline" in err:
            break
    return None, last_meta


def clean_links(data) -> list[str]:
    result = []
    for value in data:
        if not isinstance(value, str):
            continue
        value = value.strip()
        if not value or value.startswith("#"):
            continue
        result.append(value)
        if len(result) > MAX_SOURCE_LINKS:
            raise ValueError(f"上游链接过多：超过 {MAX_SOURCE_LINKS}")
    return result


def read_links():
    for name in ("all_animeko_links.txt", "canonical_links.json"):
        if os.path.exists(name):
            if os.path.getsize(name) > MAX_LINK_FILE_SIZE:
                raise ValueError(f"上游链接文件过大：{name}")
            if name.endswith(".json"):
                data = load_json_file(name)
            else:
                with open(name, encoding="utf-8-sig") as f:
                    data = [ln.strip() for ln in f]
            if not isinstance(data, list):
                raise ValueError(f"上游链接文件必须是列表：{name}")
            if data:
                links = clean_links(data)
                for link in links:
                    try:
                        normalize(link)
                    except ValueError:
                        continue
                    return links
    raise FileNotFoundError(
        "缺少包含有效 HTTPS 链接的 all_animeko_links.txt / canonical_links.json"
    )


def resolve_commit_shas(canons: list[str]) -> tuple[dict[str, str], dict[str, str]]:
    out: dict[str, str] = {}
    status: dict[str, str] = {}
    parsed = {}
    ref_info = {}
    repo_refs: dict[tuple, tuple] = {}
    token = os.environ.get("GITHUB_TOKEN")
    for canon in canons:
        gr = parse_github_raw(canon)
        parsed[canon] = gr
        if not gr:
            out[canon] = canon
            status[canon] = "not-github"
            continue
        key = (gr.owner.lower(), gr.repo.lower(), gr.ref)
        ref_info.setdefault(key, (gr.owner, gr.repo, gr.ref))
        if re.fullmatch(r"[0-9a-fA-F]{40}", gr.ref):
            repo_refs[key] = (gr.ref.lower(), "already-sha")

    def resolve_one(info):
        owner, repo, ref = info
        hdrs = {"User-Agent": UA_DEFAULT, "Accept": "application/vnd.github+json"}
        if token:
            hdrs["Authorization"] = f"Bearer {token}"
        try:
            with requests.Session() as api_session:
                api_session.trust_env = os.environ.get("ALLOW_ENV_PROXY") == "1"
                owner_q = quote(unquote(owner), safe="")
                repo_q = quote(unquote(repo), safe="")
                ref_q = quote(unquote(ref), safe="")
                r = api_session.get(
                    f"https://api.github.com/repos/{owner_q}/{repo_q}/commits/{ref_q}",
                    timeout=(5, 10), headers=hdrs, allow_redirects=False)
            if r.status_code == 200:
                candidate_sha = r.json().get("sha")
                if isinstance(candidate_sha, str) and re.fullmatch(r"[0-9a-fA-F]{40}", candidate_sha):
                    return candidate_sha.lower(), "resolved"
                return ref, "api-invalid-response"
            if r.status_code in (403, 429):
                return ref, "api-rate-limited"
            if r.status_code == 404:
                return ref, "ref-not-found"
            return ref, f"api-http-{r.status_code}"
        except Exception:
            return ref, "api-error"

    unresolved = sorted((key, info) for key, info in ref_info.items() if key not in repo_refs)
    allowed = unresolved[:MAX_GITHUB_API_REFS]
    for key, info in unresolved[MAX_GITHUB_API_REFS:]:
        repo_refs[key] = (info[2], "api-limit-skipped")
    if allowed:
        with ThreadPoolExecutor(max_workers=min(GITHUB_API_WORKERS, len(allowed))) as ex:
            futures = {ex.submit(resolve_one, info): key for key, info in allowed}
            for future in as_completed(futures):
                key = futures[future]
                try:
                    repo_refs[key] = future.result()
                except Exception:
                    repo_refs[key] = (ref_info[key][2], "api-error")

    for canon in canons:
        gr = parsed[canon]
        if not gr:
            continue
        key = (gr.owner.lower(), gr.repo.lower(), gr.ref)
        ref, st = repo_refs[key]
        status[canon] = st
        out[canon] = (f"https://raw.githubusercontent.com/{gr.owner}/{gr.repo}/"
                      f"{quote(unquote(ref), safe='/')}/{quote(unquote(gr.path), safe='/')}")
    return out, status




def _dir_hash(d: str) -> str:
    h = hashlib.sha256()
    for fn in OUTPUT_FILES:
        p = os.path.join(d, fn)
        name = fn.encode("utf-8")
        h.update(len(name).to_bytes(4, "big"))
        h.update(name)
        if os.path.isfile(p):
            size = os.path.getsize(p)
            h.update(b"\x01")
            h.update(size.to_bytes(8, "big"))
            read_size = 0
            with open(p, "rb") as f:
                while True:
                    chunk = f.read(1024 * 1024)
                    if not chunk:
                        break
                    read_size += len(chunk)
                    h.update(chunk)
            if read_size != size:
                raise RuntimeError(f"哈希期间文件大小变化: {p}")
        else:
            h.update(b"\x00")
    return h.hexdigest()


def _write_json_limited(path: str, obj, limit: int):
    encoder = json.JSONEncoder(ensure_ascii=False, indent=2, allow_nan=False)
    total = 0
    with open(path, "wb") as f:
        for chunk in encoder.iterencode(obj):
            data = chunk.encode("utf-8")
            total += len(data)
            if total > limit:
                raise ValueError(f"JSON 输出超过 {limit} 字节")
            f.write(data)


def _output_size_problems(d: str) -> list[str]:
    problems = []
    for fn in OUTPUT_FILES:
        p = os.path.join(d, fn)
        if os.path.exists(p):
            size = os.path.getsize(p)
            if size > MAX_OUTPUT_FILE_SIZE:
                problems.append(f"{fn} 过大：{size} > {MAX_OUTPUT_FILE_SIZE}")
    return problems


def _output_dir_structurally_valid(d: str) -> bool:
    if not os.path.isdir(d):
        return False
    try:
        for fn in OUTPUT_FILES:
            p = os.path.join(d, fn)
            if not os.path.isfile(p) or os.path.getsize(p) > MAX_OUTPUT_FILE_SIZE:
                return False
            obj = load_json_file(p)
            if not isinstance(obj, dict):
                return False
            exported = obj.get("exportedMediaSourceDataList")
            ms = exported.get("mediaSources") if isinstance(exported, dict) else None
            if not isinstance(ms, list) or not ms:
                return False
        return True
    except Exception:
        return False


def _output_dir_valid(d: str) -> bool:
    if not _output_dir_structurally_valid(d):
        return False
    try:
        outputs = {}
        for fn in OUTPUT_FILES:
            obj = load_json_file(os.path.join(d, fn))
            outputs[fn] = obj["exportedMediaSourceDataList"]["mediaSources"]
        problems, _ = validate_outputs(outputs)
        return not problems
    except Exception:
        return False


def _metadata_ok(d: str, output_hash: str | None, counts: dict) -> bool:
    try:
        latest = load_json_file(os.path.join(d, "latest.json"))
        source_base = latest.get("source_base_commit", "")
        return (
            os.path.isfile(os.path.join(d, "log"))
            and latest.get("output_sha256") == output_hash
            and latest.get("counts") == counts
            and (source_base == "" or bool(re.fullmatch(r"[0-9a-fA-F]{40}", source_base)))
        )
    except Exception:
        return False


def _count_guard_problems(old_counts: dict, new_counts: dict) -> list[str]:
    problems = []
    for fn in OUTPUT_FILES:
        old_n = old_counts.get(fn, new_counts.get(fn, 0))
        new_n = new_counts.get(fn, 0)
        if not old_n:
            continue
        floor = (max(MIN_OUTPUT_COUNT, int(old_n * OUTPUT_KEEP_RATIO)) if fn == "all.json"
                 else int(old_n * OUTPUT_KEEP_RATIO))
        if new_n < floor:
            problems.append(f"[P0-2] {fn} 条目异常减少 {old_n} -> {new_n}（下限 {floor}），拒绝覆盖")
        if (old_n - new_n) / old_n > MAX_DELETE_RATIO:
            problems.append(f"[P0-2] {fn} 删除比例 {old_n} -> {new_n} 超 {MAX_DELETE_RATIO:.0%}，拒绝覆盖")
        if (new_n - old_n) / old_n > MAX_GROWTH_RATIO:
            problems.append(f"[P0-2] {fn} 增长比例 {old_n} -> {new_n} 超 {MAX_GROWTH_RATIO:.0%}，拒绝覆盖")
    return problems


def _remove_path(path: str):
    try:
        if os.path.isdir(path) and not os.path.islink(path):
            shutil.rmtree(path)
        else:
            os.remove(path)
    except FileNotFoundError:
        pass


def _content_guard_problems(old_outputs: dict, new_outputs: dict) -> list[str]:
    problems = []
    for fn in OUTPUT_FILES:
        old_ms = old_outputs.get(fn)
        new_ms = new_outputs.get(fn)
        if not isinstance(old_ms, list) or not isinstance(new_ms, list):
            continue
        name_mode = fn.endswith("-name.json")
        def identities(items):
            out = set()
            for item in items:
                if not isinstance(item, dict):
                    continue
                args = item.get("arguments")
                if not isinstance(args, dict):
                    continue
                fid = item.get("factoryId")
                name = args.get("name")
                if not isinstance(fid, str) or not isinstance(name, str):
                    continue
                out.add((fid, name) if name_mode else (fid, name, url_of(item)))
            return out
        old_keys = identities(old_ms)
        new_keys = identities(new_ms)
        if not old_keys:
            continue
        removed = len(old_keys - new_keys)
        if removed / len(old_keys) > MAX_DELETE_RATIO:
            problems.append(f"[P0-2] {fn} 旧键删除 {removed}/{len(old_keys)} 超 {MAX_DELETE_RATIO:.0%}，拒绝覆盖")
    return problems


def _recover_stale_backup():
    import glob
    for newdir in sorted(glob.glob("dist.new-*")):
        _remove_path(newdir)
    backups = glob.glob("dist.bak-*")
    dist_valid = _output_dir_valid("dist")
    valid_backups = [bak for bak in backups if _output_dir_valid(bak)]
    if valid_backups and not dist_valid:
        chosen = max(valid_backups, key=os.path.getmtime)
        print(f"  ⚠️ 检测到上次原子 swap 未完成，从备份恢复: {chosen}")
        if os.path.lexists("dist"):
            _remove_path("dist")
        os.rename(chosen, "dist")
        dist_valid = True
    if dist_valid:
        for bak in backups:
            if os.path.lexists(bak):
                _remove_path(bak)
    return dist_valid


def main():
    try:
        acquire_run_lock()
    except RuntimeError as e:
        sys.exit(str(e))
    start = time.time()

    def _early_abort(reason):
        os.makedirs(REPORT_DIR, exist_ok=True)
        report = {
            "ts": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
            "duration_s": round(time.time() - start, 1),
            "aborted_reason": reason,
            "phase": "startup",
        }
        with open(os.path.join(REPORT_DIR, "latest.json"), "w", encoding="utf-8") as f:
            json.dump(report, f, ensure_ascii=False, indent=1, allow_nan=False)
        print(f"⛔ 已中止并落盘报告（{REPORT_DIR}/latest.json）：{reason}")
        raise SystemExit(reason)

    try:
        old_dist_valid = _recover_stale_backup()
        ensure_gitignore()
    except Exception as exc:
        _early_abort(f"启动恢复失败: {type(exc).__name__}: {exc}")

    def _save_abort_report(reason):
        os.makedirs(REPORT_DIR, exist_ok=True)
        report = {
            "ts": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
            "duration_s": round(time.time() - start, 1),
            "aborted_reason": reason,
            "links_total": len(links),
            "groups": len(groups),
            "valid_sources_fresh": len(fresh_valid_canons),
            "valid_sources_stale": len(stale_valid_canons),
            "valid_ratio": round(ratio, 3),
            "stale_ratio": round(stale_ratio, 3),
            "core_official_fresh": core_fresh,
            "snapshot_status": sha_status,
            "stale_reasons": stale_reasons,
            "stale_failures": stale_failures,
            "failed": failed,
            "parsed_fail": parsed_fail,
            "fetched_summary": {"ok": len(ok), "failed": len(failed),
                                "stale_fallback": len(stale_reasons),
                                "fresh_bytes": fresh_bytes, "cache_bytes": cache_bytes},
        }
        with open(os.path.join(REPORT_DIR, "latest.json"), "w", encoding="utf-8") as f:
            json.dump(report, f, ensure_ascii=False, indent=1, allow_nan=False)
        print(f"⛔ 已中止并落盘报告（{REPORT_DIR}/latest.json）：{reason}")

    def _abort(reason):
        _save_abort_report(reason)
        sys.exit(reason)

    try:
        links = read_links()
    except Exception as exc:
        _early_abort(f"上游链接读取失败: {type(exc).__name__}: {exc}")
    groups: dict[str, list[str]] = {}
    for ln in links:
        try:
            canon = normalize(ln)
        except ValueError:
            print(f"跳过非法链接: {ln}")
            continue
        groups.setdefault(canon, [])
        if ln not in groups[canon]:
            groups[canon].append(ln)
    for k in groups:
        groups[k].sort(key=host_rank)
    if len(groups) > MAX_UNIQUE_SOURCES:
        _early_abort(f"唯一上游过多：{len(groups)} > {MAX_UNIQUE_SOURCES}")

    print(f"抓取 {len(groups)} 个唯一聚合源（共 {sum(len(v) for v in groups.values())} 条链接）...")

    sha_map, sha_status = resolve_commit_shas(list(groups.keys()))
    rate_limited = [c for c, s in sha_status.items() if s == "api-rate-limited"]
    if rate_limited:
        print(f"⚠️ GitHub API 限额（{len(rate_limited)} 个源回退 ref）：{rate_limited[:3]}...")

    ok: dict[str, tuple[bytes, dict]] = {}
    failed: dict[str, dict] = {}
    cache_metas: dict[str, dict] = {}
    canons_sorted = sorted(groups.keys())
    candidates = []
    fresh_valid_canons = set()
    stale_valid_canons = set()
    stale_reasons: dict[str, str] = {}
    stale_failures: dict[str, dict] = {}
    parsed_fail = []
    pending_cache_updates = []
    ratio = 0.0
    stale_ratio = 0.0
    core_fresh = False
    cache_bytes = 0
    fresh_bytes = 0
    cache_budget_exceeded = False
    fetch_budget_exceeded = False

    def fetch_batch(batch: list[str]):
        nonlocal cache_bytes, fresh_bytes, cache_budget_exceeded, fetch_budget_exceeded
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
            futs = {}
            for canon in batch:
                cache_meta = load_cache(canon)
                if cache_meta and cache_meta.get("data"):
                    size = len(cache_meta["data"])
                    if cache_bytes + size > MAX_TOTAL_INPUT_SIZE:
                        cache_meta = None
                        cache_budget_exceeded = True
                    else:
                        cache_bytes += size
                cache_metas[canon] = cache_meta
                pinned = sha_map.get(canon)
                urls = []
                if pinned and pinned != canon:
                    urls.append(pinned)
                if canon not in urls:
                    urls.append(canon)
                for u in groups[canon]:
                    if u not in urls:
                        urls.append(u)
                futs[ex.submit(fetch_group_worker, canon, urls, cache_meta)] = canon
            for fut in as_completed(futs):
                canon = futs.pop(fut)
                try:
                    data, meta = fut.result()
                except Exception as exc:
                    failed[canon] = {"error": f"worker-exception:{exc!r}"}
                    continue
                if data is not None:
                    size = len(data)
                    if fetch_budget_exceeded or fresh_bytes + size > MAX_TOTAL_INPUT_SIZE:
                        fetch_budget_exceeded = True
                        failed[canon] = {"error": "total-input-too-large", "size": size}
                        for pending in futs:
                            pending.cancel()
                    else:
                        fresh_bytes += size
                        ok[canon] = (data, meta)
                else:
                    failed[canon] = meta

    fetch_batch(canons_sorted)
    if cache_budget_exceeded:
        print(f"⚠️ 缓存输入累计超过 {MAX_TOTAL_INPUT_SIZE} 字节，超出部分已忽略")
    if fetch_budget_exceeded:
        _abort(f"网络输入累计超过 {MAX_TOTAL_INPUT_SIZE} 字节，拒绝继续解析")

    for canon in canons_sorted:
        if canon in ok:
            data, meta = ok[canon]
            seg, chosen = choose_fresh_or_stale(
                fresh_data=data,
                stale_data=(cache_metas.get(canon) or {}).get("data"),
                canon=canon, parsed_fail=parsed_fail)
            if chosen == "fresh":
                candidates.extend(seg)
                fresh_valid_canons.add(canon)
                if not meta.get("not_modified"):
                    pending_cache_updates.append(("save", canon, data, meta,
                                                  meta.get("final_url") or meta.get("url")))
                else:
                    pending_cache_updates.append(("touch", canon, None, None, None))
            elif chosen == "stale":
                candidates.extend(seg)
                stale_valid_canons.add(canon)
                stale_reasons[canon] = "fresh-invalid-using-stale-cache"
                stale_failures[canon] = {"error": "fresh-invalid", "fetch": meta}
                print(f"  fresh 无效→缓存兜底: {canon}")
            else:
                failed[canon] = {"error": "fresh-invalid-no-valid"}
        else:
            cache = cache_metas.get(canon)
            if cache and cache.get("data"):
                seg, chosen = choose_fresh_or_stale(
                    fresh_data=None,
                    stale_data=cache["data"],
                    canon=canon, parsed_fail=parsed_fail)
                if chosen == "stale":
                    candidates.extend(seg)
                    stale_valid_canons.add(canon)
                    stale_reasons[canon] = "network-fail-using-stale-cache"
                    stale_failures[canon] = failed.get(canon) or {"error": "unknown"}
                    failed.pop(canon, None)
                    print(f"  缓存兜底: {canon}")
                else:
                    failed[canon] = {"error": "stale-cache-invalid"}
            else:
                failed[canon] = failed.get(canon, {"error": "no-data-no-cache"})

    valid_total = len(fresh_valid_canons) + len(stale_valid_canons)
    ratio = valid_total / max(len(groups), 1)
    stale_ratio = (len(stale_valid_canons) / valid_total) if valid_total else 0.0
    print(f"有效上游 {valid_total}/{len(groups)}（{ratio:.0%}；fresh {len(fresh_valid_canons)} / stale {len(stale_valid_canons)}）")

    core_fresh = any(is_core_official(c) for c in fresh_valid_canons)
    if len(candidates) > MAX_TOTAL_CANDIDATES:
        _abort(f"候选条目过多：{len(candidates)} > {MAX_TOTAL_CANDIDATES}")
    if not core_fresh:
        _abort("[3] 核心官方源（MajoSissi dist）无 fresh 有效数据，拒绝覆盖产物")
    if stale_ratio > MAX_STALE_RATIO:
        _abort(f"[21] stale 占比 {stale_ratio:.0%} 超上限 {MAX_STALE_RATIO:.0%}，拒绝覆盖产物")
    if ratio < MIN_VALID_RATIO:
        _abort(f"[P0-2] 有效上游率 {ratio:.0%} < {MIN_VALID_RATIO:.0%}，拒绝覆盖现有产物")

    sel_full = build_merged(candidates, "full")
    sel_name = build_merged(candidates, "name")
    sel_full = enrich_channel_tiers(sel_full, candidates)
    sel_name = enrich_channel_tiers(sel_name, candidates, "name")

    def split(ordered):
        items = [rec["item"] for _, rec in ordered]
        online = [m for m in items if m.get("factoryId") != "rss"]
        bt = [m for m in items if m.get("factoryId") == "rss"]
        return items, online, bt

    of_full = split(sort_merged(sel_full, "full"))
    of_name = split(sort_merged(sel_name, "name"))

    outputs = {
        "all.json": of_full[0],
        "online.json": of_full[1],
        "bt.json": of_full[2],
        "all-name.json": of_name[0],
        "online-name.json": of_name[1],
        "bt-name.json": of_name[2],
    }

    problems_out, _regex_mode = validate_outputs(outputs)
    if problems_out:
        _abort("产物校验失败:\n  " + "\n  ".join(problems_out))

    old_counts = {}
    old_outputs = {}
    for fn in OUTPUT_FILES:
        oldp = os.path.join("dist", fn)
        if old_dist_valid and os.path.exists(oldp):
            try:
                if os.path.getsize(oldp) > MAX_OUTPUT_FILE_SIZE:
                    raise ValueError("旧产物过大")
                old_ms = load_json_file(oldp)["exportedMediaSourceDataList"]["mediaSources"]
                old_counts[fn] = len(old_ms)
                old_outputs[fn] = old_ms
            except Exception:
                old_counts[fn] = 0
    new_counts = {fn: len(v) for fn, v in outputs.items()}
    guard_problems = (_count_guard_problems(old_counts, new_counts)
                      + _content_guard_problems(old_outputs, outputs))
    if guard_problems:
        _abort("\n".join(guard_problems))


    newdir = f"dist.new-{os.getpid()}"
    if os.path.lexists(newdir):
        _remove_path(newdir)
    os.makedirs(newdir, exist_ok=True)
    try:
        for fn, ms_list in outputs.items():
            _write_json_limited(
                os.path.join(newdir, fn),
                {"exportedMediaSourceDataList": {"mediaSources": ms_list}},
                MAX_OUTPUT_FILE_SIZE,
            )
    except Exception as exc:
        shutil.rmtree(newdir, ignore_errors=True)
        _abort(f"产物序列化失败或过大: {type(exc).__name__}: {exc}")
    size_problems = _output_size_problems(newdir)
    if size_problems:
        shutil.rmtree(newdir, ignore_errors=True)
        _abort("产物文件过大:\n  " + "\n  ".join(size_problems))
    try:
        for fn in OUTPUT_FILES:
            load_json_file(os.path.join(newdir, fn))
        old_hash = _dir_hash("dist") if old_dist_valid else None
        new_hash = _dir_hash(newdir)
    except Exception as exc:
        _remove_path(newdir)
        _abort(f"产物写后校验失败: {type(exc).__name__}: {exc}")
    changed_any = not (old_hash and old_hash == new_hash and _metadata_ok("dist", old_hash, new_counts))
    if not changed_any:
        shutil.rmtree(newdir, ignore_errors=True)
        print("产物无变化，跳过提交")
    else:
        updated = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())
        source_base_commit = os.environ.get("GITHUB_SHA", "")
        if not re.fullmatch(r"[0-9a-fA-F]{40}", source_base_commit):
            source_base_commit = ""
        try:
            with open(os.path.join(newdir, "log"), "w", encoding="utf-8") as f:
                f.write(updated + chr(10))
            with open(os.path.join(newdir, "latest.json"), "w", encoding="utf-8") as f:
                json.dump({
                    "updated": updated,
                    "source_base_commit": source_base_commit.lower(),
                    "output_sha256": new_hash,
                    "counts": new_counts,
                }, f, ensure_ascii=False, indent=1, allow_nan=False)
        except Exception as exc:
            _remove_path(newdir)
            _abort(f"产物元数据写入失败: {type(exc).__name__}: {exc}")
        old_existed = os.path.lexists("dist")
        bak = f"dist.bak-{os.getpid()}"
        try:
            if os.path.lexists(bak):
                raise FileExistsError(f"备份路径已存在: {bak}")
            if old_existed:
                os.rename("dist", bak)
            os.rename(newdir, "dist")
        except Exception as exc:
            if old_existed and os.path.lexists(bak) and not os.path.lexists("dist"):
                try:
                    os.rename(bak, "dist")
                except Exception:
                    pass
            if os.path.lexists(newdir):
                _remove_path(newdir)
            _abort(f"产物原子 swap 失败: {type(exc).__name__}: {exc}")
        print("产物已更新（目录原子 swap 完成）")
        if os.path.lexists(bak):
            _remove_path(bak)
    if os.path.lexists(newdir):
        _remove_path(newdir)
    for action, canon, data, meta, validator_url in pending_cache_updates:
        if action == "save":
            save_cache(canon, data, meta, validator_url)
        else:
            touch_cache(canon)
    os.makedirs(REPORT_DIR, exist_ok=True)
    err_cats = {}
    for c, m in ok.items():
        if c in stale_reasons or c in failed:
            continue
        e = m[1].get("error") or "ok"
        err_cats[e] = err_cats.get(e, 0) + 1
    for c, m in failed.items():
        e = m.get("error") or "unknown"
        err_cats[e.split("(")[0].strip()] = err_cats.get(e.split("(")[0].strip(), 0) + 1
    for reason in set(stale_reasons.values()):
        n = sum(1 for v in stale_reasons.values() if v == reason)
        err_cats[reason] = err_cats.get(reason, 0) + n
    all_valid_canons = fresh_valid_canons | stale_valid_canons
    prio_dist = {PRIO_NAMES[p]: 0 for p in PRIO_NAMES}
    for c in all_valid_canons:
        p = classify_priority(c)
        if p in PRIO_NAMES:
            prio_dist[PRIO_NAMES[p]] += 1
    legacy_v1, http_sources = [], []
    for m in outputs["all.json"]:
        a = m.get("arguments") or {}
        sc = a.get("searchConfig") or {}
        if m.get("factoryId") == "web-selector" and m.get("version") == 1:
            legacy_v1.append(a.get("name"))
        def _is_http(v):
            return isinstance(v, str) and v.startswith("http://")
        if _is_http(sc.get("searchUrl")) or _is_http(sc.get("rssUrl")) or _is_http(a.get("rssUrl")):
            http_sources.append(a.get("name"))
    report = {
        "ts": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
        "duration_s": round(time.time() - start, 1),
        "aborted_reason": None,
        "links_total": len(links),
        "groups": len(groups),
        "valid_sources_fresh": len(fresh_valid_canons),
        "valid_sources_stale": len(stale_valid_canons),
        "stale_reasons": stale_reasons,
        "stale_failures": stale_failures,
        "valid_ratio": round(ratio, 3),
        "stale_ratio": round(stale_ratio, 3),
        "core_official_fresh": core_fresh,
        "snapshot_status": sha_status,
        "outputs": new_counts,
        "input_bytes": {"fresh": fresh_bytes, "cache": cache_bytes},
        "changed": changed_any,
        "priority_dist": prio_dist,
        "error_categories": err_cats,
        "legacy_version1_sources": legacy_v1,
        "http_sources": http_sources,
        "fetched": {
            **{c: {"size": m[1].get("size"), "sha256": m[1].get("sha256"),
                   "etag": m[1].get("etag"), "status": m[1].get("status"),
                   "error": m[1].get("error"), "cached": c in stale_reasons,
                   "stale_reason": stale_reasons.get(c),
                   "upstream_failure": stale_failures.get(c),
                   "not_modified": m[1].get("not_modified"),
                   "latency": m[1].get("latency"),
                   "redirects": m[1].get("redirects")}
               for c, m in ok.items()},
            **{c: {"cached": True, "stale_reason": r, "error": "stale-cache",
                   "upstream_failure": stale_failures.get(c)}
               for c, r in stale_reasons.items() if c not in ok}},

        "failed": failed,
        "parsed_fail": parsed_fail,
    }
    with open(os.path.join(REPORT_DIR, "latest.json"), "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=1, allow_nan=False)
    print(f"报告: {REPORT_DIR}/latest.json")
    print(f"优先级分布: {prio_dist}")
    print(f"错误分类: {err_cats}")
    if legacy_v1:
        print(f"⚠️ 旧版 version=1 在线源: {legacy_v1}")
    if http_sources:
        print(f"⚠️ HTTP 搜索源（仅标记，不改配置）: {http_sources}")
    if failed:
        print(f"失败 {len(failed)} 个上游: {list(failed)[:8]}...")


def try_parse(data: bytes, canon: str, parsed_fail: list | None = None) -> tuple[list, bool]:
    try:
        obj = load_json_bytes(data)
    except Exception as e:
        if parsed_fail is not None:
            parsed_fail.append((canon, f"json:{e}"))
        return [], False
    ms = extract(obj)
    if not isinstance(ms, list):
        if parsed_fail is not None:
            parsed_fail.append((canon, "no-mediaSources"))
        return [], False
    if len(ms) > MAX_ITEMS_PER_SOURCE:
        if parsed_fail is not None:
            parsed_fail.append((canon, f"too-many-items:{len(ms)}"))
        return [], False
    out = []
    valid = 0
    for index, m in enumerate(ms):
        if not isinstance(m, dict):
            continue
        try:
            m2 = normalize_item(m)
            ok_flag, problems = validate_item(m2)
        except Exception as exc:
            if parsed_fail is not None:
                parsed_fail.append((canon, f"item-{index}-exception:{type(exc).__name__}"))
            continue
        if not ok_flag:
            continue
        args = m2.get("arguments") or {}
        name = args.get("name")
        if not name:
            continue
        u = url_of(m2)
        key = (m2.get("factoryId", "?"), name, u)
        quality = (classify_priority(canon), tier_rank_of(args.get("tier")), file_order_key(canon))
        rank = (quality, canon, u, sha256_json(m2))
        out.append((rank, key, m2, canon))
        valid += 1
    if valid == 0:
        if parsed_fail is not None:
            parsed_fail.append((canon, "no-valid-items"))
        return [], False
    valid_ratio = valid / len(ms)
    if valid_ratio < MIN_SOURCE_ITEM_VALID_RATIO:
        if parsed_fail is not None:
            parsed_fail.append((canon, f"valid-items-ratio-too-low:{valid}/{len(ms)}"))
        return [], False
    if valid < len(ms) and parsed_fail is not None:
        parsed_fail.append((canon, f"partial-invalid-items:{len(ms) - valid}/{len(ms)}"))
    return out, True


def choose_fresh_or_stale(fresh_data, stale_data, canon, parsed_fail=None):
    if fresh_data is not None:
        seg, valid = try_parse(fresh_data, canon, parsed_fail)
        if valid:
            return seg, "fresh"
    if stale_data is not None:
        seg, valid = try_parse(stale_data, canon, parsed_fail)
        if valid:
            return seg, "stale"
    return [], "invalid"


def build_merged(candidates: list, mode: str) -> dict:
    selected = {}
    for rank, key, m, canon in candidates:
        k = key if mode == "full" else (key[0], key[1])
        if k not in selected or rank < selected[k]["rank"]:
            selected[k] = {"item": m, "origin": canon, "rank": rank}
    return selected


def enrich_channel_tiers(merged: dict, candidates: list, mode: str = "full") -> dict:
    by_key = {}
    for rank, key, m, canon in candidates:
        k = key if mode == "full" else (key[0], key[1])
        by_key.setdefault(k, []).append((rank, m))
    out = {}
    for key, rec in merged.items():
        m2 = copy.deepcopy(rec["item"])
        args = m2.get("arguments") or {}
        if not args.get("channelTiers"):
            sc = args.get("searchConfig") or {}
            core = {kk: v for kk, v in sc.items()}
            for _, cand in sorted(by_key.get(key, []), key=lambda pair: pair[0]):
                ca = cand.get("arguments") or {}
                ct = ca.get("channelTiers")
                if not isinstance(ct, dict) or not ct:
                    continue
                if all(safe_channel_tier(v) is not None for v in ct.values()):
                    csc = ca.get("searchConfig") or {}
                    if core == {kk: v for kk, v in csc.items()}:
                        args["channelTiers"] = ct
                        break
        out[key] = {"item": m2, "origin": rec["origin"], "rank": rec["rank"]}
    return out


def sort_merged(selected: dict, mode: str):
    ordered = sorted(selected.items(), key=lambda it: (
        1 if it[1]["item"].get("factoryId") == "rss" else 0,
        tier_sort_value((it[1]["item"].get("arguments") or {}).get("tier")),
        classify_priority(it[1]["origin"]),
        it[0][1] if mode == "name" else (it[0][1], it[0][2])))
    return ordered


def collect_known_regex_fields(obj, out: list[str]):
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k in KNOWN_REGEX_FIELDS and isinstance(v, str):
                out.append(v)
            else:
                collect_known_regex_fields(v, out)
    elif isinstance(obj, list):
        for v in obj:
            collect_known_regex_fields(v, out)


def java_check_regexes(regexes: list[str]) -> tuple[list[str], str]:
    if not regexes:
        return [], "java"
    if len(regexes) > MAX_UNIQUE_REGEXES or sum(len(regex) for regex in regexes) > MAX_TOTAL_REGEX_CHARS:
        return ["正则总量超过资源上限"], "limit"
    try:
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            data_p = os.path.join(td, "regexes.txt")
            with open(data_p, "w", encoding="utf-8") as f:
                for rx in regexes:
                    f.write(base64.b64encode(rx.encode("utf-8")).decode() + "\n")
            java_src = os.path.join(td, "RegexCheck.java")
            with open(java_src, "w", encoding="utf-8") as f:
                f.write('''import java.util.*;import java.util.regex.*;import java.nio.file.*;import java.util.Base64;
public class RegexCheck { public static void main(String[] a) throws Exception {
  int fail=0;
  for (String ln : Files.readAllLines(Path.of(a[0]))) {
    String rx = new String(Base64.getDecoder().decode(ln.trim()), java.nio.charset.StandardCharsets.UTF_8);
    try { Pattern.compile(rx); } catch (Exception e) { System.out.println("FAIL: "+rx+" :: "+e.getMessage()); fail++; }
  }
  if (fail>0) { System.out.println(fail+" regex failed"); System.exit(1); }
  System.out.println("OK"); }}''')
            java_exe = shutil.which("java")
            if not java_exe:
                raise FileNotFoundError("java")
            r = subprocess.run([java_exe, java_src, data_p], capture_output=True, text=True, timeout=30, check=False)
            if r.returncode != 0:
                fails = [line for line in r.stdout.splitlines() if line.startswith("FAIL")]
                return ([f[5:] for f in fails] if fails else [r.stdout.strip() or "java-check-failed"]), "java"
            return [], "java"
    except FileNotFoundError:
        return ["Java 运行时不可用"], "unavailable"
    except Exception as exc:
        return [f"Java 校验器执行失败: {type(exc).__name__}"], "unavailable"


def validate_outputs(outputs: dict[str, list]) -> tuple[list[str], str]:
    problems = []
    missing = [fn for fn in OUTPUT_FILES if fn not in outputs]
    if missing:
        problems.append(f"缺少产物: {missing}")
        return problems, "n/a"
    bad_types = False
    for fn in OUTPUT_FILES:
        ms = outputs[fn]
        if not isinstance(ms, list):
            problems.append(f"{fn} mediaSources 非列表")
            bad_types = True
        elif not ms:
            problems.append(f"{fn} 为空")
    if bad_types:
        return problems, "n/a"

    def keyset(ms):
        return {(m.get("factoryId"), (m.get("arguments") or {}).get("name"), url_of(m)) for m in ms}
    def namekeyset(ms):
        return {(m.get("factoryId"), (m.get("arguments") or {}).get("name")) for m in ms}

    allk = keyset(outputs["all.json"])
    onlinek = keyset(outputs["online.json"])
    btk = keyset(outputs["bt.json"])
    if len(allk) != len(outputs["all.json"]):
        problems.append("all.json 存在 (factoryId,name,url) 重复")
    if len(onlinek) != len(outputs["online.json"]):
        problems.append("online.json 存在重复")
    if len(btk) != len(outputs["bt.json"]):
        problems.append("bt.json 存在重复")
    if allk != (onlinek | btk):
        problems.append("all 键集合 != online ∪ bt")
    if onlinek & btk:
        problems.append("online 与 bt 键集合有交集")
    if outputs["all.json"] != outputs["online.json"] + outputs["bt.json"]:
        problems.append("all.json 内容或顺序 != online.json + bt.json")
    if any(m.get("factoryId") == "rss" for m in outputs["online.json"]):
        problems.append("online.json 含 rss 条目")
    if any(m.get("factoryId") != "rss" for m in outputs["bt.json"]):
        problems.append("bt.json 含非 rss 条目")

    an_full = keyset(outputs["all-name.json"])
    on_full = keyset(outputs["online-name.json"])
    bn_full = keyset(outputs["bt-name.json"])
    an = namekeyset(outputs["all-name.json"])
    on = namekeyset(outputs["online-name.json"])
    bn = namekeyset(outputs["bt-name.json"])
    if len(an) != len(outputs["all-name.json"]):
        problems.append("all-name.json 存在 (factoryId,name) 重复")
    if len(on) != len(outputs["online-name.json"]):
        problems.append("online-name.json 存在 (factoryId,name) 重复")
    if len(bn) != len(outputs["bt-name.json"]):
        problems.append("bt-name.json 存在 (factoryId,name) 重复")
    if an != (on | bn):
        problems.append("all-name 键集合 != online-name ∪ bt-name")
    if on & bn:
        problems.append("online-name 与 bt-name 键集合有交集")
    if not an_full <= allk or not on_full <= onlinek or not bn_full <= btk:
        problems.append("name 产物含不在对应完整产物中的键")
    if outputs["all-name.json"] != outputs["online-name.json"] + outputs["bt-name.json"]:
        problems.append("all-name.json 内容或顺序 != online-name.json + bt-name.json")
    if any(m.get("factoryId") == "rss" for m in outputs["online-name.json"]):
        problems.append("online-name.json 含 rss 条目")
    if any(m.get("factoryId") != "rss" for m in outputs["bt-name.json"]):
        problems.append("bt-name.json 含非 rss 条目")

    for fn, ms in outputs.items():
        for m in ms:
            valid, issues = validate_item(m)
            if not valid:
                for iss in issues[:3]:
                    problems.append(f"{fn} 内 {((m.get('arguments') or {}).get('name'))} Schema: {iss}")
                continue
            a = m.get("arguments") or {}
            if a.get("tier") is not None and safe_tier(a.get("tier")) is None:
                problems.append(f"{fn} 内 {a.get('name')} tier 非法")
            if "tier" in m:
                problems.append(f"{fn} 内 {a.get('name')} tier 仍在顶层")
            ct = a.get("channelTiers")
            if isinstance(ct, dict) and any(safe_channel_tier(v) is None for v in ct.values()):
                problems.append(f"{fn} 内 {a.get('name')} channelTiers 值非法")

    regexes = []
    for fn, ms in outputs.items():
        for m in ms:
            collect_known_regex_fields((m.get("arguments") or {}).get("searchConfig") or {}, regexes)
    regexes = list(dict.fromkeys(regexes))
    jfails, jmode = java_check_regexes(regexes)
    if jmode == "python":
        for f_ in jfails:
            problems.append(f"正则(降级Python)失败: {f_}")
    else:
        for f_ in jfails:
            problems.append(f"Java 正则校验失败: {f_[:120]}")
    return problems, jmode


def run_selftests():
    import unittest
    from unittest import mock

    def write_valid_output_dir(directory, label):
        web = {"factoryId": "web-selector", "version": 2,
               "arguments": {"name": f"W{label}", "description": "", "iconUrl": "",
                             "searchConfig": {"searchUrl": f"https://w{label}.com"}}}
        rss = {"factoryId": "rss", "version": 1,
               "arguments": {"name": f"R{label}", "description": "", "iconUrl": "",
                             "searchConfig": {"searchUrl": f"https://r{label}.com/rss"}}}
        values = {
            "all.json": [web, rss], "online.json": [web], "bt.json": [rss],
            "all-name.json": [web, rss], "online-name.json": [web], "bt-name.json": [rss],
        }
        os.makedirs(directory, exist_ok=True)
        for fn, media_sources in values.items():
            with open(os.path.join(directory, fn), "w", encoding="utf-8") as f:
                json.dump({"exportedMediaSourceDataList": {"mediaSources": media_sources}}, f)

    class T(unittest.TestCase):
        def setUp(self):
            self._safety_patcher = mock.patch(
                __name__ + ".check_url_safety", return_value=(None, "93.184.216.34"))
            self._safety_patcher.start()
            self._fail_snapshot = dict(_host_fail)
            self._sems_snapshot = dict(_host_sems)

        def tearDown(self):
            self._safety_patcher.stop()
            _host_fail.clear()
            _host_fail.update(self._fail_snapshot)
            _host_sems.clear()
            _host_sems.update(self._sems_snapshot)

        def test_dependency_version_parser(self):
            self.assertEqual(_dependency_version("2.33.0"), (2, 33))
            self.assertEqual(_dependency_version("2.7.0.dev1"), (2, 7))
            self.assertIsNone(_dependency_version("unknown"))

        def test_tier0_not_99(self):
            self.assertEqual(tier_rank_of(0), 0)
            self.assertEqual(tier_rank_of(None), 2)

        def test_jsdelivr_to_raw(self):
            self.assertEqual(
                normalize("https://cdn.jsdelivr.net/gh/MajoSissi/animeko-source@main/dist/all.json"),
                "https://raw.githubusercontent.com/MajoSissi/animeko-source/main/dist/all.json")

        def test_refs_heads_main_folded(self):
            a = normalize("https://raw.githubusercontent.com/SZMY-haruhi/haruhi/refs/heads/main/haruhiAni.json")
            b = normalize("https://cdn.jsdelivr.net/gh/SZMY-haruhi/haruhi@main/haruhiAni.json")
            c = normalize("https://cdn.jsdelivr.net/gh/SZMY-haruhi/haruhi@refs/heads/main/haruhiAni.json")
            self.assertEqual(a, b)
            self.assertEqual(a, c)

        def test_github_com_raw_refs_heads(self):
            a = normalize("https://github.com/o/r/raw/refs/heads/main/dist/all.json")
            b = normalize("https://raw.githubusercontent.com/o/r/main/dist/all.json")
            self.assertEqual(a, b)

        def test_github_com_blob_refs_heads(self):
            a = normalize("https://github.com/o/r/blob/refs/heads/main/dist/all.json")
            b = normalize("https://raw.githubusercontent.com/o/r/main/dist/all.json")
            self.assertEqual(a, b)
            c = normalize("https://github.com/o/r/blob/main/dist/all.json")
            self.assertEqual(c, b)

        def test_proxy_prefix(self):
            self.assertEqual(
                normalize("https://gh-proxy.com/raw.githubusercontent.com/MajoSissi/animeko-source/main/dist/all.json"),
                "https://raw.githubusercontent.com/MajoSissi/animeko-source/main/dist/all.json")

        def test_bad_protocol_rejected(self):
            with self.assertRaises(ValueError):
                normalize("file:///etc/passwd")
            with self.assertRaises(ValueError):
                normalize("http://example.com/source.json")

        def test_generic_url_canonicalization(self):
            self.assertEqual(normalize("HTTPS://EXAMPLE.com.:443/x.json?a=1#fragment"),
                             "https://example.com/x.json?a=1")
            self.assertEqual(
                normalize("https://raw.githubusercontent.com./o/r/main/x.json"),
                "https://raw.githubusercontent.com/o/r/main/x.json",
            )
            self.assertEqual(
                normalize("https://gh-proxy.com./https://raw.githubusercontent.com/o/r/main/x.json"),
                "https://raw.githubusercontent.com/o/r/main/x.json",
            )
            for value in ("https://example.com:99999/x.json", "https://example.com:0/x.json",
                          "https://raw.githubusercontent.com:444/o/r/main/x.json"):
                with self.assertRaises(ValueError, msg=value):
                    normalize(value)
            self.assertEqual(url_shallow_ok("https://example.com:99999/x")[1], "bad-port")
            self.assertEqual(url_shallow_ok("https://example.com:0/x")[1], "bad-port")

        def test_host_rank_raw_first(self):
            self.assertLess(host_rank("https://raw.githubusercontent.com/a/b/main/x.json"),
                            host_rank("https://cdn.jsdelivr.net/gh/a/b@main/x.json"))

        def test_literal_private_ip_rejected(self):
            for u in ("http://10.0.0.1/x", "http://192.168.1.1/x", "http://169.254.169.254/x",
                      "http://[fd00::1]/x", "http://127.0.0.1/x"):
                ok_f, err = url_shallow_ok(u)
                self.assertFalse(ok_f, u)
                self.assertEqual(err, "private-ip")

        def test_public_ip_allowed(self):
            ok_f, _ = url_shallow_ok("https://8.8.8.8/x")
            self.assertTrue(ok_f)

        def test_private_ip_detected(self):
            self.assertTrue(is_private_ip("127.0.0.1"))
            self.assertTrue(is_private_ip("fd00::1"))
            self.assertFalse(is_private_ip("8.8.8.8"))

        def _resp(self, status=200, body=b"{}", headers=None):
            r = mock.MagicMock()
            r.status_code = status
            r.url = "https://raw.githubusercontent.com/a/b/main/x.json"
            r.history = []
            r.headers = headers or {}
            r.iter_content.return_value = [body] if body else []
            ctx = mock.MagicMock()
            ctx.__enter__.return_value = r
            ctx.__exit__.return_value = False
            return ctx

        @mock.patch.object(requests.Session, "get")
        def test_redirect_to_private_blocked_before_request(self, mget):
            r302 = self._resp(302, b"", headers={"Location": "http://127.0.0.1/evil"})
            mget.return_value = r302
            data, meta = fetch_url("https://raw.githubusercontent.com/a/b/main/x.json", None,
                                   time.monotonic() + 30)
            self.assertIsNone(data)
            self.assertIn(meta.get("error"), ("private-host", "redirect-private-host", "redirect-downgrade"))
            self.assertEqual(mget.call_count, 1)

        @mock.patch.object(requests.Session, "get")
        def test_https_redirect_downgrade_rejected(self, mget):
            mget.return_value = self._resp(302, b"", headers={"Location": "http://example.com/source.json"})
            data, meta = fetch_url("https://raw.githubusercontent.com/a/b/main/x.json", None,
                                   time.monotonic() + 30)
            self.assertIsNone(data)
            self.assertEqual(meta["error"], "redirect-downgrade")
            self.assertEqual(mget.call_count, 1)

        @mock.patch.object(requests.Session, "get")
        def test_html_200_rejected(self, mget):
            mget.return_value = self._resp(200, b"<html><head><title>captcha</title></head></html>")
            data, meta = fetch_url("https://raw.githubusercontent.com/a/b/main/x.json", None,
                                   time.monotonic() + 30)
            self.assertIsNone(data)
            self.assertEqual(meta["error"], "html")

        @mock.patch.object(requests.Session, "get")
        def test_response_size_header_rejected(self, mget):
            mget.return_value = self._resp(200, b"{}", headers={"Content-Length": str(MAX_RESP_SIZE + 1)})
            data, meta = fetch_url("https://raw.githubusercontent.com/a/b/main/x.json", None,
                                   time.monotonic() + 30)
            self.assertIsNone(data)
            self.assertEqual(meta["error"], "too-large-header")

        @mock.patch.object(requests.Session, "get")
        def test_response_stream_size_rejected(self, mget):
            mget.return_value = self._resp(200, b"x" * (MAX_RESP_SIZE + 1))
            data, meta = fetch_url("https://raw.githubusercontent.com/a/b/main/x.json", None,
                                   time.monotonic() + 30)
            self.assertIsNone(data)
            self.assertEqual(meta["error"], "too-large")

        @mock.patch.object(requests.Session, "get")
        def test_etag_304_returns_cache(self, mget):
            r = self._resp(304, b"")
            mget.return_value = r
            cache_meta = {"etag": '"abc"', "validator_url": "https://raw.githubusercontent.com/a/b/main/x.json",
                          "data": b'{"x":1}'}
            data, meta = fetch_url("https://raw.githubusercontent.com/a/b/main/x.json", cache_meta,
                                   time.monotonic() + 30)
            self.assertEqual(data, b'{"x":1}')
            self.assertTrue(meta.get("not_modified"))

        @mock.patch.object(requests.Session, "get")
        def test_unsolicited_304_without_validator_rejected(self, mget):
            mget.return_value = self._resp(304, b"")
            cache_meta = {"validator_url": "https://raw.githubusercontent.com/a/b/main/x.json",
                          "data": b'{"x":1}'}
            data, meta = fetch_url("https://raw.githubusercontent.com/a/b/main/x.json", cache_meta,
                                   time.monotonic() + 30)
            self.assertIsNone(data)
            self.assertEqual(meta["error"], "http-304-no-validator")

        @mock.patch.object(requests.Session, "get")
        def test_etag_not_sent_across_mirror(self, mget):
            r = self._resp(200, b'{"exportedMediaSourceDataList":{"mediaSources":[]}}')
            mget.return_value = r
            cache_meta = {"etag": '"abc"', "validator_url": "https://other.example/x",
                          "data": b'{"x":1}'}
            fetch_url("https://raw.githubusercontent.com/a/b/main/x.json", cache_meta,
                      time.monotonic() + 30)
            sent_headers = mget.call_args.kwargs.get("headers") or mget.call_args[1].get("headers") or {}
            self.assertNotIn("If-None-Match", sent_headers)

        @mock.patch.object(requests.Session, "get")
        def test_404_not_circuit_break(self, mget):
            host = "raw.githubusercontent.com"
            _host_fail[host] = 0
            mget.return_value = self._resp(404, b"nope")
            data, meta = fetch_url(f"https://{host}/a/b/main/x.json", None, time.monotonic() + 30)
            self.assertIsNone(data)
            self.assertEqual(_host_fail[host], 0)

        @mock.patch.object(requests.Session, "get")
        def test_400_401_451_not_circuit_break(self, mget):
            host = "raw.githubusercontent.com"
            for code in (400, 401, 451):
                _host_fail[host] = 0
                mget.return_value = self._resp(code, b"")
                data, meta = fetch_url(f"https://{host}/a/b/main/x.json", None, time.monotonic() + 30)
                self.assertIsNone(data)
                self.assertEqual(_host_fail[host], 0, f"code {code} 不应熔断")

        @mock.patch.object(requests.Session, "get")
        def test_429_backoff_retry(self, mget):
            r429 = self._resp(429, b"", headers={"Retry-After": "0"})
            r200 = self._resp(200, b'{"exportedMediaSourceDataList":{"mediaSources":[]}}')
            mget.side_effect = [r429, r200]
            with mock.patch.object(time, "sleep"):
                data, _ = fetch_url("https://raw.githubusercontent.com/a/b/main/x.json", None,
                                    time.monotonic() + 30)
            self.assertIsNotNone(data)

        def test_schema_url_check(self):
            ok_f, probs = validate_item({"factoryId": "web-selector", "version": 2,
                                         "arguments": {"name": "X", "description": "", "iconUrl": "",
                                                       "searchConfig": {"searchUrl": "http://x.com/?wd={keyword}"}}})
            self.assertTrue(ok_f)
            ok_f2, _ = validate_item({"factoryId": "web-selector", "version": 2,
                                      "arguments": {"name": "X", "description": "", "iconUrl": "",
                                                    "searchConfig": {"searchUrl": "ftp://x.com"}}})
            self.assertFalse(ok_f2)

        def test_tier_not_modified_by_protocol(self):
            item = {"factoryId": "web-selector", "version": 2,
                    "arguments": {"name": "H源", "searchConfig": {"searchUrl": "http://x.com/?wd={keyword}"}}}
            m2 = normalize_item(item)
            self.assertNotIn("tier", m2["arguments"])

        def test_validate_missing_files(self):
            probs, _ = validate_outputs({"all.json": []})
            self.assertTrue(any("缺少产物" in p for p in probs))
            probs2, _ = validate_outputs({"all.json": [], "online.json": [], "bt.json": []})
            self.assertTrue(any("缺少产物" in p for p in probs2))
            malformed = {fn: {} for fn in OUTPUT_FILES}
            probs3, mode = validate_outputs(malformed)
            self.assertEqual(mode, "n/a")
            self.assertTrue(any("非列表" in p for p in probs3))

        def test_outputs_set_equality(self):
            def mk(fid, name, url):
                return {"factoryId": fid,
                        "version": 1 if fid == "rss" else 2,
                        "arguments": {"name": name, "description": "", "iconUrl": "",
                                      "searchConfig": {"searchUrl": url}}}
            onl = [mk("web-selector", f"O{i}", f"https://o{i}.com") for i in range(3)]
            bt = [mk("rss", f"B{i}", f"https://r{i}.xml") for i in range(2)]
            allms = onl + bt
            out = {"all.json": allms, "online.json": onl, "bt.json": bt,
                   "all-name.json": allms, "online-name.json": onl, "bt-name.json": bt}
            self.assertEqual(validate_outputs(out)[0], [])
            bad = {"all.json": allms, "online.json": bt + onl[:1], "bt.json": onl[1:],
                   "all-name.json": allms, "online-name.json": bt + onl[:1], "bt-name.json": onl[1:]}
            self.assertTrue(any("rss" in p or "集合" in p or "交集" in p for p in validate_outputs(bad)[0]))
            altered = copy.deepcopy(out)
            altered["online.json"][0] = copy.deepcopy(altered["online.json"][0])
            altered["online.json"][0]["arguments"]["description"] = "changed"
            self.assertTrue(any("内容或顺序" in p for p in validate_outputs(altered)[0]))
            rogue = copy.deepcopy(out)
            rogue_item = copy.deepcopy(rogue["online-name.json"][0])
            rogue_item["arguments"]["searchConfig"]["searchUrl"] = "https://rogue.example"
            rogue["online-name.json"] = list(rogue["online-name.json"])
            rogue["all-name.json"] = list(rogue["all-name.json"])
            rogue["online-name.json"][0] = rogue_item
            rogue["all-name.json"][0] = rogue_item
            self.assertTrue(any("对应完整产物" in p for p in validate_outputs(rogue)[0]))

        def test_duplicate_detected(self):
            ms = [{"factoryId": "web-selector", "version": 2,
                   "arguments": {"name": "X", "searchConfig": {"searchUrl": "https://x.com"}}}]
            out = {"all.json": ms + ms, "online.json": ms + ms, "bt.json": [],
                   "all-name.json": ms + ms, "online-name.json": ms + ms, "bt-name.json": []}
            self.assertTrue(any("重复" in p for p in validate_outputs(out)[0]))

        def test_merge_keeps_origin(self):
            def mk(fid, name, url, tier):
                return {"factoryId": fid, "version": 2,
                        "arguments": {"name": name, "tier": tier, "searchConfig": {"searchUrl": url}}}
            c1 = "https://raw.githubusercontent.com/MajoSissi/animeko-source/main/dist/all.json"
            c2 = "https://raw.githubusercontent.com/CrazyBunQnQ/animeko-sources/main/animeko.json"
            cands = [
                ((3, 2, 0), ("web-selector", "X", "https://x.com"), mk("web-selector", "X", "https://x.com", 2), c2),
                ((0, 2, 0), ("web-selector", "X", "https://x.com"), mk("web-selector", "X", "https://x.com", 2), c1),
            ]
            sel = build_merged(cands, "full")
            self.assertEqual(sel[("web-selector", "X", "https://x.com")]["origin"], c1)

        def test_channel_tier_enrichment_deterministic(self):
            key = ("web-selector", "X", "https://x.com")
            base = {"factoryId": "web-selector", "version": 2,
                    "arguments": {"name": "X", "description": "", "iconUrl": "",
                                  "searchConfig": {"searchUrl": "https://x.com"}}}
            a = copy.deepcopy(base)
            b = copy.deepcopy(base)
            a["arguments"]["channelTiers"] = {"A": 1}
            b["arguments"]["channelTiers"] = {"B": 2}
            merged = {key: {"item": base, "origin": "o", "rank": (0,)}}
            first = [((2,), key, b, "b"), ((1,), key, a, "a")]
            second = list(reversed(first))
            out1 = enrich_channel_tiers(merged, first)[key]["item"]["arguments"]["channelTiers"]
            out2 = enrich_channel_tiers(merged, second)[key]["item"]["arguments"]["channelTiers"]
            self.assertEqual(out1, {"A": 1})
            self.assertEqual(out1, out2)
            empty = copy.deepcopy(base)
            empty["arguments"]["channelTiers"] = {}
            merged_empty = {key: {"item": empty, "origin": "o", "rank": (0,)}}
            out3 = enrich_channel_tiers(merged_empty, first)[key]["item"]["arguments"]["channelTiers"]
            self.assertEqual(out3, {"A": 1})

        def test_cache_roundtrip(self):
            import tempfile
            td = tempfile.mkdtemp()
            old = CACHE_DIR
            globals()["CACHE_DIR"] = td
            try:
                canon = "https://raw.githubusercontent.com/a/b/main/x.json"
                save_cache(canon, b'{"a":1}', {"etag": "x"}, "https://raw.githubusercontent.com/a/b/main/x.json")
                c = load_cache(canon)
                self.assertEqual(c["data"], b'{"a":1}')
                self.assertEqual(c["validator_url"], "https://raw.githubusercontent.com/a/b/main/x.json")
            finally:
                globals()["CACHE_DIR"] = old
                shutil.rmtree(td, ignore_errors=True)

        def test_cache_future_timestamp_rejected(self):
            import tempfile
            td = tempfile.mkdtemp()
            old = CACHE_DIR
            globals()["CACHE_DIR"] = td
            try:
                canon = "https://raw.githubusercontent.com/a/b/main/x.json"
                save_cache(canon, b'{"a":1}', {}, canon)
                p = cache_path(canon)
                with open(p, encoding="utf-8") as f:
                    c = json.load(f)
                c["ts"] = time.time() + 3600
                with open(p, "w", encoding="utf-8") as f:
                    json.dump(c, f)
                self.assertIsNone(load_cache(canon))
            finally:
                globals()["CACHE_DIR"] = old
                shutil.rmtree(td, ignore_errors=True)

        def test_cache_decompression_limit(self):
            import tempfile
            td = tempfile.mkdtemp()
            old = CACHE_DIR
            globals()["CACHE_DIR"] = td
            try:
                canon = "https://raw.githubusercontent.com/a/b/main/x.json"
                data = b"x" * (MAX_RESP_SIZE + 1)
                payload = {"canon": canon, "ts": time.time(), "sha256": sha256_bytes(data),
                           "data_gz_b64": base64.b64encode(gzip.compress(data)).decode("ascii")}
                with open(cache_path(canon), "w", encoding="utf-8") as f:
                    json.dump(payload, f)
                self.assertIsNone(load_cache(canon))
            finally:
                globals()["CACHE_DIR"] = old
                shutil.rmtree(td, ignore_errors=True)

        def test_percent_encoded_path_not_double_encoded(self):
            gr = parse_github_raw("https://raw.githubusercontent.com/cxay666/ani-yuan/main/%E6%B5%8B%E8%AF%95.json")
            self.assertIsNotNone(gr)
            out = (f"https://raw.githubusercontent.com/{gr.owner}/{gr.repo}/"
                   f"{quote(unquote(gr.ref), safe='/')}/{quote(unquote(gr.path), safe='/')}")
            self.assertIn("%E6%B5%8B%E8%AF%95.json", out)
            self.assertNotIn("%25E6", out)

        def test_deterministic_hash(self):
            a = {"x": [1, 2], "n": "中文"}
            b = {"n": "中文", "x": [1, 2]}
            self.assertEqual(sha256_json(a), sha256_json(b))

        def test_read_links_from_txt(self):
            import tempfile
            d = tempfile.mkdtemp()
            cwd = os.getcwd()
            try:
                os.chdir(d)
                with open("all_animeko_links.txt", "w", encoding="utf-8") as f:
                    f.write("\n".join(f"https://raw.githubusercontent.com/o{i}/r{i}/main/x.json"
                                      for i in range(120)))
                    f.write("\n# 注释行\n\n")
                links = read_links()
                self.assertEqual(len(links), 120)
                self.assertTrue(all(link.startswith("https://") for link in links))
            finally:
                os.chdir(cwd)
                shutil.rmtree(d, ignore_errors=True)

        def test_invalid_text_falls_back_to_json_links(self):
            import tempfile
            d = tempfile.mkdtemp()
            cwd = os.getcwd()
            try:
                os.chdir(d)
                with open("all_animeko_links.txt", "w", encoding="utf-8") as f:
                    f.write("# only comments\n\nnot-a-url\n")
                expected = "https://raw.githubusercontent.com/o/r/main/x.json"
                with open("canonical_links.json", "w", encoding="utf-8") as f:
                    json.dump([expected], f)
                self.assertEqual(read_links(), [expected])
            finally:
                os.chdir(cwd)
                shutil.rmtree(d, ignore_errors=True)

        def test_read_links_missing_file_raises(self):
            with mock.patch.object(os.path, "exists", return_value=False):
                with self.assertRaises(FileNotFoundError):
                    read_links()

        def test_safe_tier(self):
            self.assertEqual(safe_tier("2"), 2)
            self.assertEqual(safe_tier(9), 9)
            self.assertIsNone(safe_tier(True))
            self.assertIsNone(safe_tier(-1))
            self.assertIsNone(safe_tier(2**32))

        def test_length_limits_enforced(self):
            item = {"factoryId": "web-selector", "version": 2,
                    "arguments": {"name": "X",
                                  "searchConfig": {"matchChannelName": "a" * (MAX_LEN_REGEX + 10)}}}
            ok_f, probs = validate_item(item)
            self.assertFalse(ok_f)
            self.assertTrue(any("超长" in p for p in probs))

        def test_nonstandard_loopback_forms_rejected(self):
            for host in ("2130706433", "0177.0.0.1", "0x7f000001", "127.1"):
                self.assertTrue(is_literal_private_host(host), host)

        def test_url_shallow_ok_non_string(self):
            ok_f, err = url_shallow_ok(["https://example.com"])
            self.assertFalse(ok_f)
            self.assertEqual(err, "not-string")
            ok_f, err = url_shallow_ok(12345)
            self.assertFalse(ok_f)
            self.assertEqual(err, "not-string")

        def test_bracket_template_restricted(self):
            self.assertTrue(url_shallow_ok("[config.api.public_base]/search?q={keyword}")[0])
            for value in ("[x]javascript:alert(1)", "[x]//evil", "[x]/../evil", "[x]/a\\b", "[]/x"):
                self.assertFalse(url_shallow_ok(value)[0], value)

        def test_version_bool_rejected(self):
            item = {"factoryId": "web-selector", "version": True,
                    "arguments": {"name": "X", "searchConfig": {"searchUrl": "https://x.com"}}}
            ok_f, probs = validate_item(item)
            self.assertFalse(ok_f)
            self.assertTrue(any("version" in p for p in probs))
            item2 = {"factoryId": "rss", "version": 2,
                     "arguments": {"name": "X", "searchConfig": {"searchUrl": "https://x.com/rss"}}}
            ok_f2, probs2 = validate_item(item2)
            self.assertFalse(ok_f2)
            self.assertTrue(any("不支持 version" in p for p in probs2))

        def test_clean_links_filters(self):
            out = clean_links(["https://a.com", 123, None, "  ", "# 注释", "https://b.com"])
            self.assertEqual(out, ["https://a.com", "https://b.com"])
            with self.assertRaises(ValueError):
                clean_links([f"https://x{i}.com" for i in range(MAX_SOURCE_LINKS + 1)])

        def test_links_json_must_be_list(self):
            import tempfile
            d = tempfile.mkdtemp()
            cwd = os.getcwd()
            try:
                os.chdir(d)
                with open("canonical_links.json", "w", encoding="utf-8") as f:
                    json.dump({"url": "https://example.com"}, f)
                with self.assertRaises(ValueError):
                    read_links()
            finally:
                os.chdir(cwd)
                shutil.rmtree(d, ignore_errors=True)

        def test_try_parse_bad_item_does_not_crash(self):
            ms = [
                {"factoryId": "web-selector", "version": 2,
                 "arguments": {"name": "好1", "searchConfig": {"searchUrl": "https://good1.com/?wd={keyword}"}}},
                {"factoryId": "web-selector", "version": 2,
                 "arguments": {"name": "坏", "searchConfig": {"searchUrl": ["不是字符串"]}}},
                {"factoryId": "web-selector", "version": 2,
                 "arguments": {"name": "好2", "searchConfig": {"searchUrl": "https://good2.com/?wd={keyword}"}}},
            ]
            body = json.dumps({"exportedMediaSourceDataList": {"mediaSources": ms}}).encode()
            seg, valid = try_parse(body, "https://raw.githubusercontent.com/a/b/main/x.json", [])
            self.assertTrue(valid)
            names = [s[2]["arguments"]["name"] for s in seg]
            self.assertIn("好1", names)
            self.assertIn("好2", names)
            self.assertNotIn("坏", names)

        def test_choose_fresh_or_stale(self):
            canon = "https://raw.githubusercontent.com/a/b/main/x.json"
            good = b'{"exportedMediaSourceDataList":{"mediaSources":[' \
                   b'{"factoryId":"web-selector","version":2,' \
                   b'"arguments":{"name":"X","searchConfig":{"searchUrl":"https://x.com/?wd={keyword}"}}}]}}'
            bad = b"<html>not json"
            seg, ch = choose_fresh_or_stale(good, None, canon)
            self.assertEqual(ch, "fresh")
            self.assertTrue(len(seg) >= 1)
            seg, ch = choose_fresh_or_stale(bad, good, canon)
            self.assertEqual(ch, "stale")
            seg, ch = choose_fresh_or_stale(bad, bad, canon)
            self.assertEqual(ch, "invalid")
            self.assertEqual(seg, [])

        def test_source_tier_uint_supported(self):
            self.assertEqual(safe_tier(6), 6)
            self.assertEqual(safe_tier(9), 9)
            self.assertEqual(tier_sort_value(5), 6)
            self.assertEqual(tier_sort_value(6), 7)
            self.assertEqual(tier_sort_value(None), 2)
            self.assertEqual(tier_sort_value(1), 1)

        def test_fresh_invalid_no_valid_items(self):
            seg, valid = try_parse(b"<html>not json", "https://raw.githubusercontent.com/a/b/main/x.json")
            self.assertFalse(valid)
            self.assertEqual(seg, [])
            seg2, valid2 = try_parse(b'{"exportedMediaSourceDataList":{"mediaSources":[]}}',
                                     "https://raw.githubusercontent.com/a/b/main/x.json")
            self.assertFalse(valid2)

        def test_core_fresh_logic(self):
            canon = "https://raw.githubusercontent.com/MajoSissi/animeko-source/main/dist/all.json"
            self.assertTrue(is_core_official(canon))
            self.assertTrue(is_core_official("https://raw.githubusercontent.com/majosissi/ANIMEKO-SOURCE/main/dist/all.json"))
            self.assertFalse(is_core_official("https://raw.githubusercontent.com/CrazyBunQnQ/animeko-sources/main/animeko.json"))
            self.assertFalse(is_core_official(
                "https://raw.githubusercontent.com/MajoSissi/animeko-source/main/dist/unrelated.json"))
            fresh_valid = set()
            seg, valid = try_parse(b'{"exportedMediaSourceDataList":{"mediaSources":[]}}', canon)
            if valid:
                fresh_valid.add(canon)
            self.assertFalse(any(is_core_official(c) for c in fresh_valid))

        @mock.patch.object(requests.Session, "get")
        def test_body_deadline_during_read(self, mget):
            def slow_iter(*_args):
                yield b"chunk1"
                time.sleep(0.05)
                yield b"chunk2"
            ctx = self._resp(200, b"")
            ctx.__enter__.return_value.iter_content.side_effect = slow_iter
            mget.return_value = ctx
            deadline = time.monotonic() + 0.01
            data, meta = fetch_url("https://raw.githubusercontent.com/a/b/main/x.json", None, deadline)
            self.assertIsNone(data)
            self.assertEqual(meta["error"], "deadline-during-body")

        @mock.patch.object(requests.Session, "get")
        def test_cross_host_hop_respects_circuit(self, mget):
            _host_fail["example.org"] = 100
            ctx = self._resp(302, b"", headers={"Location": "https://example.org/evil"})
            mget.return_value = ctx
            data, meta = fetch_url("https://raw.githubusercontent.com/a/b/main/x.json", None,
                                   time.monotonic() + 30)
            self.assertIsNone(data)
            self.assertEqual(meta["error"], "circuit-open")
            self.assertEqual(mget.call_count, 1)

        @mock.patch.object(requests.Session, "get")
        def test_response_closed_via_with(self, mget):
            ctx = self._resp(404, b"nope")
            mget.return_value = ctx
            fetch_url("https://raw.githubusercontent.com/a/b/main/x.json", None, time.monotonic() + 30)
            ctx.__exit__.assert_called_once()

        def test_proxy_https_raw_prefix(self):
            self.assertEqual(
                normalize("https://gh-proxy.com/https://raw.githubusercontent.com/MajoSissi/animeko-source/main/dist/all.json"),
                "https://raw.githubusercontent.com/MajoSissi/animeko-source/main/dist/all.json")
            self.assertEqual(
                normalize("https://ghfast.top/https://raw.githubusercontent.com/o/r/main/x.json"),
                "https://raw.githubusercontent.com/o/r/main/x.json")

        def test_garbage_line_rejected(self):
            for bad in ("这不是一个链接", "//example.com/x", "ftp://bad/x", "x.com/noscheme"):
                with self.assertRaises(ValueError, msg=repr(bad)):
                    normalize(bad)

        def test_url_userinfo_rejected(self):
            with self.assertRaises(ValueError):
                normalize("https://user:secret@example.com/x.json")
            self.assertEqual(url_shallow_ok("https://user:secret@example.com/x")[1], "userinfo")

        def test_url_control_chars_rejected(self):
            value = "https://example.com/x\r\nX-Test: injected"
            with self.assertRaises(ValueError):
                normalize(value)
            self.assertEqual(url_shallow_ok(value)[1], "control-char")

        def test_url_length_limited(self):
            value = "https://example.com/" + "a" * MAX_LEN_URL
            with self.assertRaises(ValueError):
                normalize(value)
            self.assertEqual(url_shallow_ok(value)[1], "too-long")

        def test_proxy_nesting_limit_real(self):
            with mock.patch(__name__ + ".MAX_PROXY_NESTING", 0):
                with self.assertRaises(ValueError):
                    normalize("https://gh-proxy.com/https://github.com/o/r/raw/main/dist/all.json")

        @mock.patch.object(requests.Session, "get")
        def test_error_cleared_after_retry_success(self, mget):
            body = b'{"exportedMediaSourceDataList":{"mediaSources":[]}}'
            mget.side_effect = [requests.exceptions.ConnectionError("flap"), self._resp(200, body)]
            with mock.patch.object(time, "sleep"):
                data, meta, _ = single_hop("https://raw.githubusercontent.com/a/b/main/x.json",
                                           None, time.monotonic() + 10)
            self.assertIsNotNone(data)
            self.assertIsNone(meta["error"])
            self.assertEqual(_host_fail.get("raw.githubusercontent.com", 0), 0)

        @mock.patch.object(requests.Session, "get")
        def test_chunked_body_error_retried(self, mget):
            bad = self._resp(200, b"")
            bad.__enter__.return_value.iter_content.side_effect = requests.exceptions.ChunkedEncodingError("cut")
            good = self._resp(200, b'{}')
            mget.side_effect = [bad, good]
            with mock.patch.object(time, "sleep"):
                data, meta, _ = single_hop("https://raw.githubusercontent.com/a/b/main/x.json",
                                           None, time.monotonic() + 10)
            self.assertEqual(data, b'{}')
            self.assertIsNone(meta["error"])
            self.assertEqual(mget.call_count, 2)

        @mock.patch.object(requests.Session, "get")
        def test_connection_retry_rechecks_and_rotates_dns(self, mget):
            body = b'{"exportedMediaSourceDataList":{"mediaSources":[]}}'
            check_url_safety.side_effect = [(None, "93.184.216.34"), (None, "1.1.1.1")]
            mget.side_effect = [requests.exceptions.ConnectionError("first-ip-down"), self._resp(200, body)]
            with mock.patch.object(time, "sleep"):
                data, meta, _ = single_hop("https://raw.githubusercontent.com/a/b/main/x.json",
                                           None, time.monotonic() + 10)
            self.assertEqual(data, body)
            self.assertIsNone(meta["error"])
            self.assertEqual(check_url_safety.call_count, 2)

        @mock.patch.object(requests.Session, "get")
        def test_exhausted_retries_count_one_host_failure(self, mget):
            mget.side_effect = [self._resp(503, b"") for _ in range(3)]
            with mock.patch.object(time, "sleep"):
                data, meta, _ = single_hop("https://raw.githubusercontent.com/a/b/main/x.json",
                                           None, time.monotonic() + 10)
            self.assertIsNone(data)
            self.assertEqual(meta["error"], "http-503")
            self.assertEqual(_host_fail.get("raw.githubusercontent.com", 0), 1)

        def test_touch_cache_refreshes_ts(self):
            import tempfile
            td = tempfile.mkdtemp()
            old = CACHE_DIR
            globals()["CACHE_DIR"] = td
            try:
                canon = "https://raw.githubusercontent.com/a/b/main/x.json"
                save_cache(canon, b'{"a":1}', {"etag": "x"}, canon)
                p = cache_path(canon)
                with open(p, encoding="utf-8") as f:
                    c = json.load(f)
                old_ts = time.time() - 86400
                c["ts"] = old_ts
                with open(p, "w", encoding="utf-8") as f:
                    json.dump(c, f)
                self.assertIsNotNone(load_cache(canon))
                touch_cache(canon)
                c2 = load_cache(canon)
                self.assertIsNotNone(c2)
                self.assertGreater(c2["ts"], old_ts)
                self.assertEqual(c2["data"], b'{"a":1}')
                self.assertEqual(c2["etag"], "x")
                c2.pop("data", None)
                c2["ts"] = time.time() - (STALE_MAX_AGE_DAYS + 1) * 86400
                with open(p, "w", encoding="utf-8") as f:
                    json.dump(c2, f)
                touch_cache(canon)
                self.assertIsNone(load_cache(canon))
            finally:
                globals()["CACHE_DIR"] = old
                shutil.rmtree(td, ignore_errors=True)

        def test_refs_without_path_rejected(self):
            self.assertIsNone(parse_github_raw("https://raw.githubusercontent.com/o/r/refs/heads/main"))
            self.assertIsNone(parse_github_com("https://github.com/o/r/raw/refs/heads/main"))
            self.assertIsNone(parse_github_com("https://github.com/o/r/blob/refs/tags/v1"))

        def test_mixed_hex_octet_loopback_rejected(self):
            for host in ("0x7f.0.0.1", "0x7f.1", "0x7f.0.0.001"):
                self.assertTrue(is_literal_private_host(host), host)
            ok_f, _ = url_shallow_ok("http://0x7f.0.0.1/x")
            self.assertFalse(ok_f)
            self.assertTrue(url_shallow_ok("https://sub1.example.com/x")[0])
            self.assertTrue(url_shallow_ok("https://8.8.8.8/x")[0])

        def test_float_tier_coerced(self):
            self.assertEqual(safe_tier(2.0), 2)
            self.assertEqual(safe_tier(0.0), 0)
            self.assertIsNone(safe_tier(2.5))
            self.assertIsNone(safe_tier(-1.0))
            self.assertEqual(safe_channel_tier(5.0), 5)
            self.assertIsNone(safe_channel_tier(2.5))

        def test_jsdelivr_no_path_rejected(self):
            self.assertIsNone(parse_jsdelivr("https://cdn.jsdelivr.net/gh/o/r@main"))
            gr = parse_jsdelivr("https://cdn.jsdelivr.net/gh/o/r@main/x.json")
            self.assertIsNotNone(gr)
            self.assertEqual(gr.path, "x.json")
            for bad in ("https://cdn.jsdelivr.net/gh/o/r@main",
                        "https://raw.githubusercontent.com/o/r/main"):
                with self.assertRaises(ValueError):
                    normalize(bad)

        def test_channel_tiers_reports_all_invalid(self):
            item = {"factoryId": "web-selector", "version": 2,
                    "arguments": {"name": "X", "searchConfig": {"searchUrl": "https://x.com"},
                                  "channelTiers": {"a": "bad", "b": 99e99, "c": -3}}}
            ok_f, probs = validate_item(item)
            self.assertFalse(ok_f)
            ct_probs = [p for p in probs if "channelTier" in p]
            self.assertEqual(len(ct_probs), 3)

        def test_channel_tiers_normalized_to_int(self):
            item = {"factoryId": "web-selector", "version": 2,
                    "arguments": {"name": "X", "searchConfig": {"searchUrl": "https://x.com"},
                                  "channelTiers": {"a": "5", "b": 6.0, "c": 7}}}
            out = normalize_item(item)
            self.assertEqual(out["arguments"]["channelTiers"], {"a": 5, "b": 6, "c": 7})

        def test_named_group_conversion_ignores_literals(self):
            self.assertEqual(normalize_regex_named_groups(r"(?P<ep>\d+)"), r"(?<ep>\d+)")
            self.assertEqual(normalize_regex_named_groups(r"\(?P<literal>"), r"\(?P<literal>")
            self.assertEqual(normalize_regex_named_groups(r"[(?P<literal>]"), r"[(?P<literal>]")
            self.assertEqual(normalize_regex_named_groups(r"\\(?P<ep>\d+)"), r"\\(?<ep>\d+)")

        def test_legacy_url_fields_migrated_to_search_url(self):
            legacy = {"factoryId": "rss", "version": 1,
                      "arguments": {"name": "R", "description": "", "iconUrl": "",
                                    "searchConfig": {"rssUrl": "https://x.com/rss"}}}
            self.assertFalse(validate_item(legacy)[0])
            normalized = normalize_item(legacy)
            self.assertEqual(normalized["arguments"]["searchConfig"]["searchUrl"],
                             "https://x.com/rss")
            self.assertTrue(validate_item(normalized)[0])
            malformed = copy.deepcopy(legacy)
            malformed["arguments"]["searchConfig"]["searchUrl"] = []
            self.assertFalse(validate_item(normalize_item(malformed))[0])

        def test_required_text_fields_normalized(self):
            item = {"factoryId": "web-selector", "version": 2,
                    "arguments": {"name": "X", "searchConfig": {"searchUrl": "https://x.com"}}}
            self.assertFalse(validate_item(item)[0])
            out = normalize_item(item)
            self.assertEqual(out["arguments"]["description"], "")
            self.assertEqual(out["arguments"]["iconUrl"], "")
            self.assertTrue(validate_item(out)[0])

        def test_pinned_connection_timeout_mapping(self):
            for cls, port in ((_PinnedHTTPSConnection, 443), (_PinnedHTTPConnection, 80)):
                conn = cls("example.com", port=port, pinned_ip="93.184.216.34", timeout=1)
                with mock.patch.object(urllib3.util.connection, "create_connection",
                                       side_effect=socket.timeout("timed out")):
                    with self.assertRaises(urllib3.exceptions.ConnectTimeoutError):
                        conn._new_conn()

        def test_pinned_pool_preserves_request_tls_context(self):
            import ssl
            context = ssl.create_default_context()
            manager = _PinnedPoolManager(pinned_ip="93.184.216.34", num_pools=1, maxsize=1)
            pool = manager._new_pool(
                "https", "example.com", 443,
                {"scheme": "https", "host": "example.com", "port": 443,
                 "ssl_context": context, "cert_reqs": "CERT_REQUIRED"},
            )
            try:
                self.assertIsInstance(pool, _PinnedHTTPSConnectionPool)
                self.assertIs(pool.conn_kw["ssl_context"], context)
                self.assertEqual(pool.conn_kw["pinned_ip"], "93.184.216.34")
                self.assertEqual(pool.cert_reqs, "CERT_REQUIRED")
            finally:
                manager.clear()

        def test_pinned_session_ignores_env_proxy_by_default(self):
            old = getattr(_pinned_tls, "sessions", None)
            _pinned_tls.sessions = {}
            try:
                with mock.patch.dict(os.environ, {}, clear=True):
                    session = get_pinned_session("example.com", "93.184.216.34")
                    self.assertFalse(session.trust_env)
                    session.close()
            finally:
                if old is None:
                    try:
                        delattr(_pinned_tls, "sessions")
                    except AttributeError:
                        pass
                else:
                    _pinned_tls.sessions = old

        def test_validate_malformed_output_fails_cleanly(self):
            import tempfile
            d = tempfile.mkdtemp()
            try:
                os.makedirs(os.path.join(d, "dist"))
                with open(os.path.join(d, "dist", OUTPUT_FILES[0]), "w", encoding="utf-8") as f:
                    f.write("not-json")
                result = subprocess.run([sys.executable, os.path.abspath(__file__), "--validate"],
                                        cwd=d, capture_output=True, text=True, check=False)
                self.assertEqual(result.returncode, 1)
                self.assertIn("产物读取失败", result.stdout)
                self.assertNotIn("Traceback", result.stderr)
            finally:
                shutil.rmtree(d, ignore_errors=True)

        def test_unknown_cli_argument_rejected(self):
            result = subprocess.run([sys.executable, os.path.abspath(__file__), "--unknown"],
                                    capture_output=True, text=True, check=False)
            self.assertEqual(result.returncode, 2)
            self.assertIn("未知参数", result.stderr)

        @unittest.skipUnless(hasattr(os, "O_NOFOLLOW") and hasattr(os, "symlink"), "需要 O_NOFOLLOW")
        def test_process_lock_rejects_symlink(self):
            import tempfile
            global _run_lock_handle
            td = tempfile.mkdtemp()
            target = os.path.join(td, "target")
            link = os.path.join(td, "lock")
            old = _run_lock_handle
            _run_lock_handle = None
            try:
                with open(target, "w", encoding="utf-8") as f:
                    f.write("keep")
                os.symlink(target, link)
                with self.assertRaises(RuntimeError):
                    acquire_run_lock(link)
                with open(target, encoding="utf-8") as f:
                    self.assertEqual(f.read(), "keep")
            finally:
                _run_lock_handle = old
                shutil.rmtree(td, ignore_errors=True)

        def test_process_lock_blocks_second_process(self):
            import tempfile
            global _run_lock_handle
            td = tempfile.mkdtemp()
            path = os.path.join(td, "lock")
            old = _run_lock_handle
            _run_lock_handle = None
            try:
                acquire_run_lock(path)
                root = os.path.dirname(os.path.abspath(__file__))
                code = ("import sys;sys.path.insert(0," + repr(root) + ");import update_sources as u;"
                        "\ntry:u.acquire_run_lock(" + repr(path) + ")"
                        "\nexcept RuntimeError:raise SystemExit(3)"
                        "\nraise SystemExit(0)")
                result = subprocess.run([sys.executable, "-c", code], check=False)
                self.assertEqual(result.returncode, 3)
            finally:
                if _run_lock_handle is not None:
                    _run_lock_handle.close()
                _run_lock_handle = old
                shutil.rmtree(td, ignore_errors=True)

        def test_recover_removes_stale_newdir(self):
            import tempfile
            d = tempfile.mkdtemp()
            cwd = os.getcwd()
            try:
                os.chdir(d)
                os.makedirs("dist.new-123")
                _recover_stale_backup()
                self.assertFalse(os.path.exists("dist.new-123"))
            finally:
                os.chdir(cwd)
                shutil.rmtree(d, ignore_errors=True)

        def test_metadata_validation(self):
            import tempfile
            d = tempfile.mkdtemp()
            try:
                counts = {fn: i for i, fn in enumerate(OUTPUT_FILES)}
                with open(os.path.join(d, "log"), "w", encoding="utf-8") as f:
                    f.write("now\n")
                with open(os.path.join(d, "latest.json"), "w", encoding="utf-8") as f:
                    json.dump({"output_sha256": "abc", "counts": counts}, f)
                self.assertTrue(_metadata_ok(d, "abc", counts))
                self.assertFalse(_metadata_ok(d, "wrong", counts))
                with open(os.path.join(d, "latest.json"), "w", encoding="utf-8") as f:
                    json.dump({"output_sha256": "abc", "counts": counts,
                               "source_base_commit": "not-a-sha"}, f)
                self.assertFalse(_metadata_ok(d, "abc", counts))
                os.remove(os.path.join(d, "log"))
                self.assertFalse(_metadata_ok(d, "abc", counts))
            finally:
                shutil.rmtree(d, ignore_errors=True)

        def test_count_guard_covers_name_outputs(self):
            old = {fn: 100 for fn in OUTPUT_FILES}
            new = dict(old)
            new["all-name.json"] = 80
            problems = _count_guard_problems(old, new)
            self.assertTrue(any("all-name.json" in p for p in problems))
            new["all-name.json"] = 90
            self.assertFalse(_count_guard_problems(old, new))
            grown = dict(old)
            grown["all.json"] = 200
            self.assertFalse(_count_guard_problems(old, grown))
            grown["all.json"] = 201
            self.assertTrue(any("增长比例" in p for p in _count_guard_problems(old, grown)))

        def test_content_guard_detects_same_count_replacement(self):
            def mk(i):
                return {"factoryId": "web-selector", "version": 2,
                        "arguments": {"name": f"X{i}", "description": "", "iconUrl": "",
                                      "searchConfig": {"searchUrl": f"https://x{i}.com"}}}
            old = [mk(i) for i in range(100)]
            exact = old[10:] + [mk(i) for i in range(100, 110)]
            over = old[11:] + [mk(i) for i in range(100, 111)]
            self.assertFalse(_content_guard_problems({"all.json": old}, {"all.json": exact}))
            problems = _content_guard_problems({"all.json": old}, {"all.json": over})
            self.assertTrue(any("all.json" in p for p in problems))
            replaced = [mk(i) for i in range(100, 200)]
            problems = _content_guard_problems({"all-name.json": old}, {"all-name.json": replaced})
            self.assertTrue(any("all-name.json" in p for p in problems))

        @mock.patch.object(requests, "Session")
        def test_github_api_ignores_env_proxy_by_default(self, session_cls):
            api = mock.MagicMock()
            response = mock.MagicMock()
            response.status_code = 404
            api.get.return_value = response
            session_cls.return_value.__enter__.return_value = api
            resolve_commit_shas(["https://raw.githubusercontent.com/o/r/main/x.json"])
            self.assertFalse(api.trust_env)

        @mock.patch.object(requests, "Session")
        def test_github_api_invalid_sha_rejected(self, session_cls):
            api = mock.MagicMock()
            response = mock.MagicMock()
            response.status_code = 200
            response.json.return_value = {"sha": "not-a-sha"}
            api.get.return_value = response
            session_cls.return_value.__enter__.return_value = api
            canon = "https://raw.githubusercontent.com/o/r/main/x.json"
            out, status = resolve_commit_shas([canon])
            self.assertEqual(status[canon], "api-invalid-response")
            self.assertEqual(out[canon], canon)

        @mock.patch.object(requests, "Session")
        def test_github_api_case_insensitive_repo_dedup(self, session_cls):
            api = mock.MagicMock()
            response = mock.MagicMock()
            response.status_code = 200
            response.json.return_value = {"sha": "a" * 40}
            api.get.return_value = response
            session_cls.return_value.__enter__.return_value = api
            a = "https://raw.githubusercontent.com/Owner/Repo/main/a.json"
            b = "https://raw.githubusercontent.com/owner/repo/main/b.json"
            out, status = resolve_commit_shas([a, b])
            self.assertEqual(session_cls.call_count, 1)
            self.assertEqual(status[a], "resolved")
            self.assertEqual(status[b], "resolved")
            self.assertIn("/" + "a" * 40 + "/", out[a])

        @mock.patch.object(requests, "Session")
        def test_abbreviated_sha_is_resolved(self, session_cls):
            api = mock.MagicMock()
            response = mock.MagicMock()
            response.status_code = 200
            response.json.return_value = {"sha": "b" * 40}
            api.get.return_value = response
            session_cls.return_value.__enter__.return_value = api
            canon = "https://raw.githubusercontent.com/o/r/abcdef1/x.json"
            out, status = resolve_commit_shas([canon])
            self.assertEqual(status[canon], "resolved")
            self.assertIn("/" + "b" * 40 + "/", out[canon])

        @mock.patch.object(requests, "Session")
        def test_github_api_resolution_cap(self, session_cls):
            api = mock.MagicMock()
            response = mock.MagicMock()
            response.status_code = 404
            api.get.return_value = response
            session_cls.return_value.__enter__.return_value = api
            canons = [f"https://raw.githubusercontent.com/o{i}/r/main/x.json" for i in range(3)]
            with mock.patch(__name__ + ".MAX_GITHUB_API_REFS", 1):
                _, status = resolve_commit_shas(canons)
            self.assertEqual(session_cls.call_count, 1)
            self.assertEqual(sum(v == "api-limit-skipped" for v in status.values()), 2)

        def test_nonfinite_json_rejected(self):
            canon = "https://raw.githubusercontent.com/a/b/main/x.json"
            for constant in ("NaN", "Infinity", "-Infinity", "1e9999", "-1e9999"):
                body = ("{\"exportedMediaSourceDataList\":{\"mediaSources\":["
                        "{\"factoryId\":\"web-selector\",\"version\":2,"
                        "\"arguments\":{\"name\":\"X\",\"searchConfig\":{"
                        "\"searchUrl\":\"https://x.com\",\"x\":" + constant + "}}}]}}")
                seg, valid = try_parse(body.encode(), canon)
                self.assertFalse(valid)
                self.assertEqual(seg, [])

        def test_malformed_export_wrapper_not_bypassed(self):
            obj = {"exportedMediaSourceDataList": None, "mediaSources": [{"x": 1}]}
            self.assertIsNone(extract(obj))
            with self.assertRaises(ValueError):
                load_json_bytes(json.dumps(obj).encode())

        def test_duplicate_json_keys_rejected(self):
            canon = "https://raw.githubusercontent.com/a/b/main/x.json"
            body = (b'{"exportedMediaSourceDataList":{"mediaSources":['
                    b'{"factoryId":"web-selector","version":2,"arguments":{'
                    b'"name":"X","name":"Y","description":"","iconUrl":"",'
                    b'"searchConfig":{"searchUrl":"https://x.com"}}}]}}')
            failures = []
            seg, valid = try_parse(body, canon, failures)
            self.assertFalse(valid)
            self.assertEqual(seg, [])
            self.assertTrue(any("JSON" in str(x) for x in failures))

        def test_source_item_limit(self):
            body = json.dumps({"exportedMediaSourceDataList": {
                "mediaSources": [None] * (MAX_ITEMS_PER_SOURCE + 1)}}).encode()
            failures = []
            seg, valid = try_parse(body, "https://raw.githubusercontent.com/a/b/main/x.json", failures)
            self.assertFalse(valid)
            self.assertEqual(seg, [])
            self.assertTrue(any("too-many-items" in str(x) for x in failures))

        def test_source_item_valid_ratio(self):
            good = {"factoryId": "web-selector", "version": 2,
                    "arguments": {"name": "X", "description": "", "iconUrl": "",
                                  "searchConfig": {"searchUrl": "https://x.com"}}}
            canon = "https://raw.githubusercontent.com/a/b/main/x.json"
            failures = []
            low = [good] * 49 + [None] * 51
            body = json.dumps({"exportedMediaSourceDataList": {"mediaSources": low}}).encode()
            seg, valid = try_parse(body, canon, failures)
            self.assertFalse(valid)
            self.assertEqual(seg, [])
            self.assertTrue(any("valid-items-ratio-too-low" in str(x) for x in failures))
            edge = [good] * 50 + [None] * 50
            body = json.dumps({"exportedMediaSourceDataList": {"mediaSources": edge}}).encode()
            seg, valid = try_parse(body, canon, [])
            self.assertTrue(valid)
            self.assertEqual(len(seg), 50)

        def test_streaming_output_limit(self):
            import tempfile
            d = tempfile.mkdtemp()
            try:
                obj = {"x": "中文" * 100}
                expected = json.dumps(obj, ensure_ascii=False, indent=2, allow_nan=False).encode("utf-8")
                p = os.path.join(d, "ok.json")
                _write_json_limited(p, obj, len(expected))
                with open(p, "rb") as f:
                    self.assertEqual(f.read(), expected)
                with self.assertRaises(ValueError):
                    _write_json_limited(os.path.join(d, "large.json"), obj, len(expected) - 1)
                self.assertLessEqual(os.path.getsize(os.path.join(d, "large.json")), len(expected) - 1)
            finally:
                shutil.rmtree(d, ignore_errors=True)

        def test_output_file_size_limit(self):
            import tempfile
            d = tempfile.mkdtemp()
            try:
                with open(os.path.join(d, OUTPUT_FILES[0]), "wb") as f:
                    f.truncate(MAX_OUTPUT_FILE_SIZE + 1)
                self.assertTrue(_output_size_problems(d))
            finally:
                shutil.rmtree(d, ignore_errors=True)

        def test_dir_hash_frames_files(self):
            import tempfile
            d1 = tempfile.mkdtemp()
            d2 = tempfile.mkdtemp()
            try:
                with open(os.path.join(d1, OUTPUT_FILES[0]), "wb") as f:
                    f.write(b"ab")
                with open(os.path.join(d1, OUTPUT_FILES[1]), "wb") as f:
                    f.write(b"c")
                with open(os.path.join(d2, OUTPUT_FILES[0]), "wb") as f:
                    f.write(b"a")
                with open(os.path.join(d2, OUTPUT_FILES[1]), "wb") as f:
                    f.write(b"bc")
                self.assertNotEqual(_dir_hash(d1), _dir_hash(d2))
            finally:
                shutil.rmtree(d1, ignore_errors=True)
                shutil.rmtree(d2, ignore_errors=True)

        def test_recover_prefers_newest_complete_backup(self):
            import tempfile
            d = tempfile.mkdtemp()
            cwd = os.getcwd()
            try:
                os.chdir(d)
                for i in (1, 2):
                    bak = f"dist.bak-{i}"
                    write_valid_output_dir(bak, i)
                    os.utime(bak, (i, i))
                with mock.patch("builtins.print"):
                    _recover_stale_backup()
                restored = load_json_file(os.path.join("dist", OUTPUT_FILES[0]))
                self.assertEqual(extract(restored)[0]["arguments"]["name"], "W2")
                self.assertFalse(os.path.exists("dist.bak-1"))
                self.assertFalse(os.path.exists("dist.bak-2"))
            finally:
                os.chdir(cwd)
                shutil.rmtree(d, ignore_errors=True)

        def test_regex_aggregate_limit(self):
            with mock.patch(__name__ + ".MAX_UNIQUE_REGEXES", 1):
                failures, mode = java_check_regexes(["a", "b"])
            self.assertEqual(mode, "limit")
            self.assertTrue(failures)
            with mock.patch(__name__ + ".MAX_TOTAL_REGEX_CHARS", 1):
                failures, mode = java_check_regexes(["ab"])
            self.assertEqual(mode, "limit")
            self.assertTrue(failures)

        def test_java_validation_fails_closed(self):
            with mock.patch.object(shutil, "which", return_value=None):
                failures, mode = java_check_regexes([".*"])
            self.assertEqual(mode, "unavailable")
            self.assertTrue(failures)

        def test_non_global_addresses_rejected(self):
            for ip in ("100.64.0.1", "100.127.255.254", "::ffff:100.64.0.1"):
                self.assertTrue(is_private_ip(ip), ip)
                self.assertTrue(is_literal_private_host(ip), ip)
            with self.assertRaises(ValueError):
                normalize("https://100.64.0.1/source.json")

        def test_cache_nonstandard_and_incomplete_rejected(self):
            import tempfile
            td = tempfile.mkdtemp()
            old = CACHE_DIR
            globals()["CACHE_DIR"] = td
            canon = "https://raw.githubusercontent.com/a/b/main/x.json"
            try:
                p = cache_path(canon)
                data = b'{}'
                base = {"canon": canon, "ts": time.time(), "sha256": sha256_bytes(data),
                        "data_gz_b64": base64.b64encode(gzip.compress(data)).decode("ascii")}
                for value in (float("nan"), float("inf"), float("-inf")):
                    payload = dict(base)
                    payload["ts"] = value
                    with open(p, "w", encoding="utf-8") as f:
                        json.dump(payload, f)
                    self.assertIsNone(load_cache(canon))
                payload = dict(base)
                payload.pop("data_gz_b64")
                with open(p, "w", encoding="utf-8") as f:
                    json.dump(payload, f)
                self.assertIsNone(load_cache(canon))
            finally:
                globals()["CACHE_DIR"] = old
                shutil.rmtree(td, ignore_errors=True)

        def test_arguments_pair_list_not_coerced(self):
            item = {"factoryId": "web-selector", "version": 2,
                    "arguments": [["name", "X"], ["description", ""], ["iconUrl", ""],
                                  ["searchConfig", {"searchUrl": "https://x.com"}]]}
            normalized = normalize_item(item)
            self.assertIsInstance(normalized["arguments"], list)
            self.assertFalse(validate_item(normalized)[0])

        def test_duplicate_top_level_tier_removed(self):
            item = {"factoryId": "web-selector", "version": 2, "tier": 9,
                    "arguments": {"name": "X", "description": "", "iconUrl": "", "tier": 1,
                                  "searchConfig": {"searchUrl": "https://x.com"}}}
            normalized = normalize_item(item)
            self.assertNotIn("tier", normalized)
            self.assertEqual(normalized["arguments"]["tier"], 1)

        def test_pathless_github_links_rejected(self):
            for value in ("https://github.com/o/r/blob/main", "https://github.com/o/r/raw/main",
                          "https://gh-proxy.com/raw.githubusercontent.com/",
                          "https://gh-proxy.com/https://example.com/x.json",
                          "https://gh-proxy.com/https://raw.githubusercontent.com/o/r/main"):
                with self.assertRaises(ValueError, msg=value):
                    normalize(value)

        def test_selector_and_regex_types_checked(self):
            base = {"factoryId": "web-selector", "version": 2,
                    "arguments": {"name": "X", "description": "", "iconUrl": "",
                                  "searchConfig": {"searchUrl": "https://x.com"}}}
            for field in SELECTOR_FIELDS + KNOWN_REGEX_FIELDS:
                item = copy.deepcopy(base)
                item["arguments"]["searchConfig"][field] = 123
                self.assertFalse(validate_item(item)[0], field)

        def test_known_search_config_field_types(self):
            base = {"factoryId": "web-selector", "version": 2,
                    "arguments": {"name": "X", "description": "", "iconUrl": "",
                                  "searchConfig": {"searchUrl": "https://x.com"}}}
            cases = [
                (KNOWN_BOOL_FIELDS[0], 1),
                (KNOWN_INT_FIELDS[0], True),
                (KNOWN_INT_FIELDS[1], -1),
                (KNOWN_STRING_LIST_FIELDS[0], ["mpv", 3]),
                (KNOWN_OBJECT_FIELDS[0], []),
                (KNOWN_PLAIN_STRING_FIELDS[0], 3),
            ]
            for field, value in cases:
                item = copy.deepcopy(base)
                item["arguments"]["searchConfig"][field] = value
                self.assertFalse(validate_item(item)[0], field)
            item = copy.deepcopy(base)
            item["arguments"]["searchConfig"]["searchUseSubjectNamesCount"] = 0
            self.assertFalse(validate_item(item)[0])

        def test_retry_after_huge_integer_safe(self):
            self.assertEqual(parse_retry_after("9" * 10000, 1.25), 1.25)

        def test_public_dns_addresses_rotate(self):
            host = "multi.example"
            infos = [
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.1", 0)),
                (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("2606:4700:4700::1111", 0, 0, 0)),
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0)),
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("1.1.1.1", 0)),
                (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0)),
            ]
            with _dns_rotation_lock:
                _dns_rotation.pop(host, None)
            self.assertEqual(_choose_public_ip(host, infos), "93.184.216.34")
            self.assertEqual(_choose_public_ip(host, infos), "1.1.1.1")
            self.assertEqual(_choose_public_ip(host, infos), "93.184.216.34")

        def test_dns_resolution_respects_deadline(self):
            release = threading.Event()

            def blocked(*_args):
                release.wait(1)
                return []

            try:
                with mock.patch.object(socket, "getaddrinfo", side_effect=blocked):
                    started = time.monotonic()
                    infos, error = _bounded_getaddrinfo("example.com", started + 0.01)
                    elapsed = time.monotonic() - started
                self.assertIsNone(infos)
                self.assertEqual(error, "dns-timeout")
                self.assertLess(elapsed, 0.1)
            finally:
                release.set()

        def test_dns_outstanding_limit_respects_deadline(self):
            slots = threading.BoundedSemaphore(0)
            with mock.patch(__name__ + "._dns_slots", slots), \
                 mock.patch.object(socket, "getaddrinfo") as resolver:
                infos, error = _bounded_getaddrinfo("example.com", time.monotonic() + 0.01)
            self.assertIsNone(infos)
            self.assertEqual(error, "dns-timeout")
            resolver.assert_not_called()

        def test_host_slot_wait_respects_deadline(self):
            sem = mock.MagicMock()
            sem.acquire.return_value = False
            with mock.patch(__name__ + ".host_semaphore", return_value=sem):
                data, meta, location = single_hop("https://example.com/x", None,
                                                  time.monotonic() + 0.01)
            self.assertIsNone(data)
            self.assertIsNone(location)
            self.assertEqual(meta["error"], "host-slot-timeout")
            self.assertLessEqual(sem.acquire.call_args.kwargs["timeout"], 0.02)

        @mock.patch.object(requests.Session, "get")
        def test_request_timeout_respects_deadline(self, mget):
            mget.return_value = self._resp(200, b'{}')
            deadline = time.monotonic() + 0.05
            data, _, _ = single_hop("https://example.com/x", None, deadline)
            self.assertEqual(data, b'{}')
            timeout = mget.call_args.kwargs["timeout"]
            self.assertLessEqual(timeout[0], 0.05)
            self.assertLessEqual(timeout[1], 0.05)

        def test_first_generation_absolute_minimum(self):
            low = {fn: 1 for fn in OUTPUT_FILES}
            low["all.json"] = MIN_OUTPUT_COUNT - 1
            self.assertTrue(_count_guard_problems({}, low))
            low["all.json"] = MIN_OUTPUT_COUNT
            self.assertFalse(_count_guard_problems({}, low))

        def test_aborted_output_does_not_poison_cache(self):
            import tempfile
            d = tempfile.mkdtemp()
            cwd = os.getcwd()
            canon = "https://raw.githubusercontent.com/MajoSissi/animeko-source/main/dist/all.json"
            items = []
            for i in range(MIN_OUTPUT_COUNT - 1):
                fid = "rss" if i == 0 else "web-selector"
                items.append({"factoryId": fid, "version": 1 if fid == "rss" else 2,
                              "arguments": {"name": f"X{i}", "description": "", "iconUrl": "",
                                            "searchConfig": {
                                                "searchUrl":
                                                    f"https://x{i}.com"}}})
            body = json.dumps({"exportedMediaSourceDataList": {"mediaSources": items}}).encode()
            save = mock.MagicMock()
            touch = mock.MagicMock()
            try:
                os.chdir(d)
                with open("all_animeko_links.txt", "w", encoding="utf-8") as f:
                    f.write(canon + "\n")
                with mock.patch(__name__ + ".acquire_run_lock"), \
                     mock.patch(__name__ + "._recover_stale_backup"), \
                     mock.patch(__name__ + ".resolve_commit_shas",
                                return_value=({canon: canon}, {canon: "resolved"})), \
                     mock.patch(__name__ + ".load_cache", return_value=None), \
                     mock.patch(__name__ + ".fetch_group_worker",
                                return_value=(body, {"url": canon, "final_url": canon})), \
                     mock.patch(__name__ + ".save_cache", save), \
                     mock.patch(__name__ + ".touch_cache", touch), \
                     mock.patch("builtins.print"):
                    with self.assertRaises(SystemExit):
                        main()
                save.assert_not_called()
                touch.assert_not_called()
            finally:
                os.chdir(cwd)
                shutil.rmtree(d, ignore_errors=True)

        def test_swap_failure_keeps_cache_unmodified(self):
            import tempfile
            d = tempfile.mkdtemp()
            cwd = os.getcwd()
            canon = "https://raw.githubusercontent.com/MajoSissi/animeko-source/main/dist/all.json"
            items = []
            for i in range(MIN_OUTPUT_COUNT):
                fid = "rss" if i == 0 else "web-selector"
                items.append({"factoryId": fid, "version": 1 if fid == "rss" else 2,
                              "arguments": {"name": f"S{i}", "description": "", "iconUrl": "",
                                            "searchConfig": {
                                                "searchUrl":
                                                    f"https://s{i}.com"}}})
            body = json.dumps({"exportedMediaSourceDataList": {"mediaSources": items}}).encode()
            save = mock.MagicMock()
            try:
                os.chdir(d)
                with open("all_animeko_links.txt", "w", encoding="utf-8") as f:
                    f.write(canon + "\n")
                real_rename = os.rename

                def fail_newdir(src, dst):
                    if str(src).startswith("dist.new-") and dst == "dist":
                        raise OSError("injected-swap-failure")
                    return real_rename(src, dst)

                with mock.patch(__name__ + ".acquire_run_lock"), \
                     mock.patch(__name__ + ".resolve_commit_shas",
                                return_value=({canon: canon}, {canon: "resolved"})), \
                     mock.patch(__name__ + ".load_cache", return_value=None), \
                     mock.patch(__name__ + ".fetch_group_worker",
                                return_value=(body, {"url": canon, "final_url": canon})), \
                     mock.patch(__name__ + ".save_cache", save), \
                     mock.patch.object(os, "rename", side_effect=fail_newdir), \
                     mock.patch("builtins.print"):
                    with self.assertRaises(SystemExit):
                        main()
                save.assert_not_called()
                self.assertFalse(os.path.exists("dist"))
                report = load_json_file(os.path.join("reports", "latest.json"))
                self.assertIn("原子 swap 失败", report["aborted_reason"])
            finally:
                os.chdir(cwd)
                shutil.rmtree(d, ignore_errors=True)

        def test_unique_source_limit_before_network(self):
            import tempfile
            d = tempfile.mkdtemp()
            cwd = os.getcwd()
            resolve = mock.MagicMock()
            try:
                os.chdir(d)
                with open("all_animeko_links.txt", "w", encoding="utf-8") as f:
                    for i in range(MAX_UNIQUE_SOURCES + 1):
                        f.write(f"https://raw.githubusercontent.com/o{i}/r/main/x.json\n")
                with mock.patch(__name__ + ".acquire_run_lock"), \
                     mock.patch(__name__ + "._recover_stale_backup"), \
                     mock.patch(__name__ + ".resolve_commit_shas", resolve), \
                     mock.patch("builtins.print"):
                    with self.assertRaises(SystemExit):
                        main()
                resolve.assert_not_called()
                self.assertFalse(os.path.exists("dist"))
                report = load_json_file(os.path.join("reports", "latest.json"))
                self.assertEqual(report["phase"], "startup")
            finally:
                os.chdir(cwd)
                shutil.rmtree(d, ignore_errors=True)

        def test_total_input_budget_aborts_before_parsing(self):
            import tempfile
            d = tempfile.mkdtemp()
            cwd = os.getcwd()
            a = "https://raw.githubusercontent.com/MajoSissi/animeko-source/main/dist/all.json"
            b = "https://raw.githubusercontent.com/o/r/main/x.json"
            item = {"factoryId": "web-selector", "version": 2,
                    "arguments": {"name": "X", "description": "", "iconUrl": "",
                                  "searchConfig": {"searchUrl": "https://x.com"}}}
            body = json.dumps({"exportedMediaSourceDataList": {"mediaSources": [item]}}).encode()
            save = mock.MagicMock()
            try:
                os.chdir(d)
                with open("all_animeko_links.txt", "w", encoding="utf-8") as f:
                    f.write(a + "\n" + b + "\n")
                mapping = {a: a, b: b}
                statuses = {a: "resolved", b: "resolved"}
                with mock.patch(__name__ + ".acquire_run_lock"), \
                     mock.patch(__name__ + "._recover_stale_backup"), \
                     mock.patch(__name__ + ".resolve_commit_shas", return_value=(mapping, statuses)), \
                     mock.patch(__name__ + ".load_cache", return_value=None), \
                     mock.patch(__name__ + ".fetch_group_worker",
                                return_value=(body, {"url": a, "final_url": a})), \
                     mock.patch(__name__ + ".save_cache", save), \
                     mock.patch(__name__ + ".MAX_TOTAL_INPUT_SIZE", len(body)), \
                     mock.patch("builtins.print"):
                    with self.assertRaises(SystemExit):
                        main()
                save.assert_not_called()
                report = load_json_file(os.path.join("reports", "latest.json"))
                self.assertIn("网络输入累计超过", report["aborted_reason"])
                self.assertEqual(report["fetched_summary"]["fresh_bytes"], len(body))
            finally:
                os.chdir(cwd)
                shutil.rmtree(d, ignore_errors=True)

        def test_invalid_old_dist_does_not_block_regeneration(self):
            import tempfile
            d = tempfile.mkdtemp()
            cwd = os.getcwd()
            canon = "https://raw.githubusercontent.com/MajoSissi/animeko-source/main/dist/all.json"
            items = []
            for i in range(MIN_OUTPUT_COUNT):
                fid = "rss" if i == 0 else "web-selector"
                items.append({"factoryId": fid, "version": 1 if fid == "rss" else 2,
                              "arguments": {"name": f"N{i}", "description": "", "iconUrl": "",
                                            "searchConfig": {
                                                "searchUrl":
                                                    f"https://n{i}.com"}}})
            body = json.dumps({"exportedMediaSourceDataList": {"mediaSources": items}}).encode()
            try:
                os.chdir(d)
                os.makedirs("dist")
                for fn in OUTPUT_FILES:
                    with open(os.path.join("dist", fn), "w", encoding="utf-8") as f:
                        json.dump({"exportedMediaSourceDataList": {"mediaSources": [fn] * 500}}, f)
                with open("all_animeko_links.txt", "w", encoding="utf-8") as f:
                    f.write(canon + "\n")
                with mock.patch(__name__ + ".acquire_run_lock"), \
                     mock.patch(__name__ + ".resolve_commit_shas",
                                return_value=({canon: canon}, {canon: "resolved"})), \
                     mock.patch(__name__ + ".load_cache", return_value=None), \
                     mock.patch(__name__ + ".fetch_group_worker",
                                return_value=(body, {"url": canon, "final_url": canon})), \
                     mock.patch(__name__ + ".save_cache"), \
                     mock.patch("builtins.print"):
                    main()
                restored = extract(load_json_file(os.path.join("dist", "all.json")))
                self.assertEqual(len(restored), MIN_OUTPUT_COUNT)
                self.assertTrue(_output_dir_valid("dist"))
            finally:
                os.chdir(cwd)
                shutil.rmtree(d, ignore_errors=True)

        def test_recover_ignores_schema_invalid_backup(self):
            import tempfile
            d = tempfile.mkdtemp()
            cwd = os.getcwd()
            try:
                os.chdir(d)
                os.makedirs("dist.bak-1")
                for fn in OUTPUT_FILES:
                    with open(os.path.join("dist.bak-1", fn), "w", encoding="utf-8") as f:
                        json.dump({"exportedMediaSourceDataList": {"mediaSources": [fn]}}, f)
                with mock.patch("builtins.print"):
                    _recover_stale_backup()
                self.assertFalse(os.path.exists("dist"))
                self.assertTrue(os.path.exists("dist.bak-1"))
            finally:
                os.chdir(cwd)
                shutil.rmtree(d, ignore_errors=True)

        def test_recover_replaces_corrupt_complete_dist(self):
            import tempfile
            d = tempfile.mkdtemp()
            cwd = os.getcwd()
            try:
                os.chdir(d)
                os.makedirs("dist")
                for fn in OUTPUT_FILES:
                    with open(os.path.join("dist", fn), "w", encoding="utf-8") as f:
                        f.write("not-json")
                write_valid_output_dir("dist.bak-1", "backup")
                with mock.patch("builtins.print"):
                    _recover_stale_backup()
                restored = extract(load_json_file(os.path.join("dist", OUTPUT_FILES[0])))
                self.assertEqual(restored[0]["arguments"]["name"], "Wbackup")
                self.assertFalse(os.path.exists("dist.bak-1"))
            finally:
                os.chdir(cwd)
                shutil.rmtree(d, ignore_errors=True)

    suite = unittest.defaultTestLoader.loadTestsFromTestCase(T)
    print(f"selftests: {suite.countTestCases()}")
    runner = unittest.TextTestRunner(verbosity=1)
    result = runner.run(suite)
    sys.exit(0 if result.wasSuccessful() else 1)


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--test":
        run_selftests()
    elif len(sys.argv) > 1 and sys.argv[1] == "--validate":
        size_problems = _output_size_problems("dist")
        if size_problems:
            print("❌ 产物文件过大：", size_problems)
            sys.exit(1)
        out = {}
        try:
            for fn in OUTPUT_FILES:
                p = os.path.join("dist", fn)
                if os.path.exists(p):
                    out[fn] = load_json_file(p)["exportedMediaSourceDataList"]["mediaSources"]
        except Exception as exc:
            print(f"❌ 产物读取失败: {type(exc).__name__}: {exc}")
            sys.exit(1)
        missing = [fn for fn in OUTPUT_FILES if fn not in out]
        if missing:
            print("❌ 缺少产物:", missing)
            sys.exit(1)
        problems, regex_mode = validate_outputs(out)
        if problems:
            print("❌ 校验失败：")
            for p_ in problems[:30]:
                print("  -", p_)
            sys.exit(1)
        print(f"✅ 校验通过（正则模式: {regex_mode}）")
    elif len(sys.argv) > 1:
        print(f"未知参数: {sys.argv[1]}", file=sys.stderr)
        sys.exit(2)
    else:
        main()
