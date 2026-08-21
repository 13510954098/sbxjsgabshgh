#!/usr/bin/env python3

from __future__ import annotations

import base64
import copy
import gzip
import hashlib
import ipaddress
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlsplit, urljoin, quote, unquote

try:
    import requests
    from requests.adapters import HTTPAdapter
    import urllib3
    from urllib3.connection import HTTPConnection, HTTPSConnection
    from urllib3.connectionpool import HTTPConnectionPool, HTTPSConnectionPool
    from urllib3.poolmanager import PoolManager
except ImportError:
    sys.exit("缺少依赖 requests：请先 `pip install requests==2.32.5`")
try:
    from packaging.version import Version
    if Version(requests.__version__) < Version("2.32"):
        print(f"⚠️ requests 版本 {requests.__version__} 低于推荐 2.32，建议升级")
except Exception:
    try:
        nums = [int(x) for x in requests.__version__.split(".")[:2] if x.isdigit()]
        if len(nums) == 2 and tuple(nums) < (2, 32):
            print(f"⚠️ requests 版本 {requests.__version__} 低于推荐 2.32，建议升级")
    except Exception:
        pass

UA_DEFAULT = ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 "
              "(KHTML, like Gecko) Version/17.0 Safari/605.1.15")
UA_FALLBACK = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
               "(KHTML, like Gecko) Chrome/124.0 Safari/537.36")
TIMEOUT = (5, 20)
MAX_WORKERS = 12
MAX_RESP_SIZE = 5 * 1024 * 1024
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
                   "selectEpisodeLinksFromList")

MAX_LEN_NAME = 200
MAX_LEN_DESC = 1000
MAX_LEN_SELECTOR = 500
MAX_LEN_REGEX = 500


GITIGNORE_CONTENT = "cache/\nreports/\ndist/.tmp-*\ndist.bak-*\ndist.new-*\n__pycache__/\n*.pyc\n"
def ensure_gitignore():
    if not os.path.exists(".gitignore"):
        try:
            with open(".gitignore", "w", encoding="utf-8") as f:
                f.write(GITIGNORE_CONTENT)
        except Exception as e:
            print(f"⚠️ .gitignore 写入失败: {e}", file=sys.stderr)


def sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def sha256_json(obj) -> str:
    return hashlib.sha256(json.dumps(obj, ensure_ascii=False, sort_keys=True).encode("utf-8")).hexdigest()


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
        v = int(t)
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
        vv = int(v)
        return vv if 0 <= vv <= UINT_MAX else None
    return None


def is_private_ip(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    return (ip.is_loopback or ip.is_link_local or ip.is_private or ip.is_reserved
            or ip.is_multicast or (ip.version == 6 and ip.is_site_local))


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
        ip = ipaddress.ip_address(h)
    except ValueError:
        return looks_numeric
    return (
        ip.is_loopback or ip.is_link_local or ip.is_private or ip.is_reserved
        or ip.is_multicast or (ip.version == 6 and ip.is_site_local)
    )


def check_url_safety(url: str) -> tuple[str | None, str | None]:
    if not url:
        return "empty-url", None
    try:
        u = urlsplit(url)
    except ValueError:
        return "unparseable", None
    if u.scheme not in ("http", "https"):
        return "bad-scheme", None
    host = (u.hostname or "").lower().rstrip(".")
    if not host:
        return "no-host", None
    if is_literal_private_host(host):
        return "private-host", None
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        return "dns-fail", None
    for info in infos:
        ip = info[4][0]
        if not is_private_ip(ip):
            return None, ip
    return f"private-ip", None


def url_shallow_ok(u) -> tuple[bool, str | None]:
    if not isinstance(u, str):
        return False, "not-string"
    if not u:
        return False, "empty"
    if u.startswith("["):
        if re.match(r"^\[[^\[\]/]{1,32}\]", u):
            return True, None
        return False, "bad-bracket"
    try:
        p = urlsplit(u)
    except (ValueError, TypeError, AttributeError):
        return False, "unparseable"
    if p.scheme not in ("http", "https"):
        return False, "bad-scheme"
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
    if u.hostname != "raw.githubusercontent.com":
        return None
    parts = [p for p in u.path.split("/") if p]
    if len(parts) < 4:
        return None
    owner, repo = parts[0], parts[1]
    if parts[2] == "refs" and len(parts) >= 6:
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
    if u.hostname != "github.com":
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
        return GitHubRef(parts[0], parts[1], fold_ref(ref), path)
    if parts[2] == "blob" and len(parts) >= 4:
        if parts[3] == "refs" and len(parts) >= 7 and parts[4] in ("heads", "tags"):
            ref = "/".join(parts[3:6])
            path = "/".join(parts[6:])
        elif parts[3] == "refs":
            return None
        else:
            ref = parts[3]
            path = "/".join(parts[4:])
        return GitHubRef(parts[0], parts[1], fold_ref(ref), path)
    return None


def parse_jsdelivr(url: str):
    u = urlsplit(url)
    if u.hostname != "cdn.jsdelivr.net":
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
    if is_bad_protocol(u):
        raise ValueError(f"非法协议: {u}")
    peeled = 0
    while True:
        for p in (parse_jsdelivr, parse_github_com, parse_github_raw):
            gr = p(u)
            if gr:
                return gr.raw_url()
        up = urlsplit(u)
        host = (up.hostname or "").lower()
        if host in ACCEL_HOSTS:
            for prefix in ("/raw.githubusercontent.com/", "/https://raw.githubusercontent.com/"):
                if up.path.startswith(prefix):
                    rest = up.path[len(prefix):]
                    if rest:
                        return f"https://raw.githubusercontent.com/{rest}"
            if up.path.startswith("/https://github.com/"):
                peeled += 1
                if peeled > MAX_PROXY_NESTING:
                    raise ValueError(f"代理嵌套过深（> {MAX_PROXY_NESTING} 层）: {url[:60]}")
                u = "https://github.com/" + up.path[len("/https://github.com/"):]
                continue
        break
    if host in ("cdn.jsdelivr.net", "raw.githubusercontent.com"):
        raise ValueError(f"{host} 链接结构非法（缺文件 path 段？）: {u[:60]}")
    if up.scheme not in ("http", "https") or not up.hostname:
        raise ValueError(f"非 http(s) 链接: {u[:60]}")
    return u


def is_bad_protocol(url: str) -> bool:
    return urlsplit(url).scheme.lower() not in ("http", "https", "")


def host_rank(url: str) -> int:
    host = (urlsplit(url).hostname or "").lower()
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
        key = f"{gr.owner}/{gr.repo}"
        if key == "MajoSissi/animeko-source":
            if gr.path.startswith("dist/"):
                return 0
            if gr.path.startswith("source/"):
                return 1
        if key in ("CrazyBunQnQ/animeko-sources", "ZEN-GUO/animeko-sources",
                   "LuckyRabbitFeet/animeko-source", "saber-yz/Animeko-Source",
                   "761218728/Animeko-Source"):
            return 3
        if key in ("llimeslice/animeko-source", "lklbjn/animeko-source",
                   "heibu01/animeko-source", "lingjueding0726/animeko-source",
                   "mophy-chun/animeko-source", "2016YYy/animeko-source",
                   "becausemadoka/animeko-source"):
            return 5
        return 4
    up = urlsplit(canon)
    host = (up.hostname or "").lower()
    if host == "gitee.com" and up.path.startswith("/w658/"):
        return 2
    if host == "sub.creamycake.org":
        return 2
    return 4


def is_core_official(canon: str) -> bool:
    gr = parse_github_raw(canon)
    return bool(gr and gr.owner == "MajoSissi" and gr.repo == "animeko-source" and gr.path.startswith("dist/"))


FILE_ORDER = {"dist/all.json": 0, "dist/online.json": 1, "dist/bt.json": 2}


def file_order_key(canon: str) -> int:
    gr = parse_github_raw(canon)
    if gr and gr.path.startswith("dist/"):
        return FILE_ORDER.get(gr.path, 3)
    return 3


def extract(obj):
    if isinstance(obj, dict):
        edsl = obj.get("exportedMediaSourceDataList")
        if isinstance(edsl, dict) and isinstance(edsl.get("mediaSources"), list):
            return edsl["mediaSources"]
        if isinstance(obj.get("mediaSources"), list):
            return obj["mediaSources"]
    if isinstance(obj, list):
        return obj
    return None


def url_of(m):
    a = m.get("arguments")
    if not isinstance(a, dict):
        return ""
    sc = a.get("searchConfig")
    if not isinstance(sc, dict):
        sc = {}
    fid = m.get("factoryId")
    if fid == "rss":
        candidates = (sc.get("rssUrl"), a.get("rssUrl"), sc.get("searchUrl"), a.get("searchUrl"))
    else:
        candidates = (sc.get("searchUrl"), sc.get("rssUrl"), a.get("rssUrl"), a.get("searchUrl"))
    for value in candidates:
        if isinstance(value, str) and value:
            return value
    return ""


def load_json_bytes(data: bytes):
    for enc in ("utf-8-sig", "utf-8"):
        try:
            text = data.decode(enc)
        except UnicodeDecodeError:
            continue
        try:
            obj = json.loads(text)
        except Exception:
            continue
        ms = extract(obj)
        if isinstance(ms, list):
            return obj
    try:
        obj = json.loads(data.decode("gbk"))
    except Exception:
        pass
    else:
        ms = extract(obj)
        if isinstance(ms, list):
            return obj
    raise ValueError("无法解析 JSON（UTF-8/GBK 编码探测+结构校验均失败）")


def migrate_top_level_tier(item):
    it = copy.deepcopy(item)
    args = dict(it.get("arguments") or {})
    if "tier" not in args and "tier" in it:
        args["tier"] = it.pop("tier")
    t = safe_tier(args.get("tier"))
    if t is None:
        args.pop("tier", None)
    else:
        args["tier"] = t
    it["arguments"] = args
    return it


def normalize_regex_named_groups(s: str) -> str:
    if "?P<" in s:
        return re.sub(r"\(\?P<([A-Za-z_][A-Za-z0-9_]*)>", r"(?<\1>", s)
    return s


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
    m["arguments"] = normalize_known_regex_fields(m.get("arguments") or {})
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
    if desc is not None and not isinstance(desc, str):
        problems.append("description 非字符串")
    elif isinstance(desc, str) and len(desc) > MAX_LEN_DESC:
        problems.append("description 超长")
    icon = a.get("iconUrl")
    if icon is not None and not isinstance(icon, str):
        problems.append("iconUrl 非字符串")
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
                if k in KNOWN_REGEX_FIELDS and isinstance(v, str) and len(v) > MAX_LEN_REGEX:
                    problems.append(f"正则超长 {name}: {k} {len(v)}")
                elif k in SELECTOR_FIELDS and isinstance(v, str) and len(v) > MAX_LEN_SELECTOR:
                    problems.append(f"选择器超长 {name}: {k} {len(v)}")
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
        with open(p, encoding="utf-8") as f:
            c = json.load(f)
        age = time.time() - c.get("ts", 0)
        if age > STALE_MAX_AGE_DAYS * 86400:
            return None
        if c.get("data_gz_b64"):
            data = gzip.decompress(base64.b64decode(c["data_gz_b64"]))
            if sha256_bytes(data) != c.get("sha256"):
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
            json.dump(payload, f)
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
        with open(p, encoding="utf-8") as f:
            c = json.load(f)
        c["ts"] = time.time()
        tmp = p + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(c, f)
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
            except urllib3.exceptions.SocketTimeout as e:
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
            except urllib3.exceptions.SocketTimeout as e:
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

    def _new_pool(self, scheme, host, port, request_context=None):
        if scheme == "https":
            return _PinnedHTTPSConnectionPool(host, port, pinned_ip=self._pinned_ip, **self.connection_pool_kw)
        if scheme == "http":
            return _PinnedHTTPConnectionPool(host, port, pinned_ip=self._pinned_ip, **self.connection_pool_kw)
        return super()._new_pool(scheme, host, port, request_context)


class PinnedIPAdapter(HTTPAdapter):

    def __init__(self, pinned_ip, *args, **kwargs):
        self._pinned_ip = pinned_ip
        super().__init__(*args, **kwargs)

    def init_poolmanager(self, connections, maxsize, block=False):
        self.poolmanager = _PinnedPoolManager(
            pinned_ip=self._pinned_ip,
            num_pools=connections, maxsize=maxsize, block=block)


_pinned_tls = threading.local()


def get_pinned_session(host: str, ip: str) -> requests.Session:
    cache = getattr(_pinned_tls, "sessions", None)
    if cache is None:
        cache = _pinned_tls.sessions = {}
    key = f"{host}:{ip}"
    s = cache.get(key)
    if s is None:
        s = requests.Session()
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
                current = urljoin(current, location)
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
    if not sem.acquire(timeout=10):
        meta["error"] = "host-slot-timeout"
        return None, meta, None
    try:
        err, pinned_ip = check_url_safety(current)
        if err:
            if err == "dns-fail":
                host_fail(host)
            meta["error"] = err
            return None, meta, None
        sess = get_pinned_session(host, pinned_ip)
        ua = UA_DEFAULT
        ua_switched = False
        retry_attempt = 0
        MAX_RETRIES_PER_URL = 3
        while retry_attempt < MAX_RETRIES_PER_URL:
            if time.monotonic() > deadline:
                meta["error"] = "deadline"
                return None, meta, None
            meta["error"] = None
            headers = {"User-Agent": ua}
            if cache_meta and cache_meta.get("validator_url") == current:
                if cache_meta.get("etag"):
                    headers["If-None-Match"] = cache_meta["etag"]
                if cache_meta.get("last_modified"):
                    headers["If-Modified-Since"] = cache_meta["last_modified"]
            try:
                with sess.get(current, timeout=TIMEOUT, headers=headers,
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
                        if cache_meta and cache_meta.get("data"):
                            meta["not_modified"] = True
                            return cache_meta["data"], meta, None
                        meta["error"] = "http-304-no-cache"
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
                        host_fail(host)
                        wait = parse_retry_after(r.headers.get("Retry-After"),
                                                 default=min(1.5 * (2 ** retry_attempt), 15))
                        retry_attempt += 1
                        if time.monotonic() + wait > deadline or retry_attempt >= MAX_RETRIES_PER_URL:
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
                host_fail(host)
                retry_attempt += 1
                if time.monotonic() + 1.0 > deadline:
                    return None, meta, None
                time.sleep(1.0)
                continue
            except requests.exceptions.SSLError:
                meta["error"] = "tls"
                host_fail(host)
                return None, meta, None
            except requests.exceptions.ConnectionError:
                meta["error"] = "dns-or-conn"
                host_fail(host)
                retry_attempt += 1
                if time.monotonic() + 1.0 > deadline:
                    return None, meta, None
                time.sleep(1.0)
                continue
            except Exception as e:
                meta["error"] = f"other:{type(e).__name__}"
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
        return min(int(v), 15)
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
    return result


def read_links():
    for name in ("all_animeko_links.txt", "canonical_links.json"):
        if os.path.exists(name):
            with open(name, encoding="utf-8") as f:
                data = json.load(f) if name.endswith(".json") else [ln.strip() for ln in f]
            if data:
                return clean_links(data)
    raise FileNotFoundError(
        "缺少 all_animeko_links.txt / canonical_links.json —— 请把抓取链接文件放到本目录"
    )


def resolve_commit_shas(canons: list[str]) -> tuple[dict[str, str], dict[str, str]]:
    out: dict[str, str] = {}
    status: dict[str, str] = {}
    repo_refs: dict[tuple, tuple] = {}
    token = os.environ.get("GITHUB_TOKEN")
    for canon in canons:
        gr = parse_github_raw(canon)
        if not gr:
            out[canon] = canon
            status[canon] = "not-github"
            continue
        key = (gr.owner, gr.repo, gr.ref)
        if key not in repo_refs:
            sha = None
            st = "unresolved"
            if re.fullmatch(r"[0-9a-f]{7,40}", gr.ref):
                sha = gr.ref
                st = "already-sha"
            else:
                hdrs = {"User-Agent": UA_DEFAULT, "Accept": "application/vnd.github+json"}
                if token:
                    hdrs["Authorization"] = f"Bearer {token}"
                try:
                    r = requests.get(
                        f"https://api.github.com/repos/{gr.owner}/{gr.repo}/commits/{quote(unquote(gr.ref), safe='')}",
                        timeout=(5, 10), headers=hdrs)
                    if r.status_code == 200:
                        sha = r.json().get("sha")
                        st = "resolved"
                    elif r.status_code == 403:
                        st = "api-rate-limited"
                    elif r.status_code == 429:
                        st = "api-rate-limited"
                    elif r.status_code == 404:
                        st = "ref-not-found"
                    else:
                        st = f"api-http-{r.status_code}"
                except Exception:
                    st = "api-error"
            repo_refs[key] = (sha or gr.ref, st)
        ref, st = repo_refs[key]
        status[canon] = st
        out[canon] = (f"https://raw.githubusercontent.com/{gr.owner}/{gr.repo}/"
                      f"{quote(unquote(ref), safe='/')}/{quote(unquote(gr.path), safe='/')}")
    return out, status




def _dir_hash(d: str) -> str:
    h = hashlib.sha256()
    for fn in OUTPUT_FILES:
        p = os.path.join(d, fn)
        if os.path.exists(p):
            with open(p, "rb") as f:
                h.update(f.read())
    return h.hexdigest()


def _recover_stale_backup():
    import glob
    for bak in sorted(glob.glob("dist.bak-*")):
        if not os.path.exists("dist") or not all(os.path.exists(os.path.join("dist", fn)) for fn in OUTPUT_FILES):
            print(f"  ⚠️ 检测到上次原子 swap 未完成，从备份恢复: {bak}")
            if os.path.exists("dist"):
                shutil.rmtree("dist", ignore_errors=True)
            os.rename(bak, "dist")
        else:
            shutil.rmtree(bak, ignore_errors=True)


def main():
    _recover_stale_backup()
    start = time.time()
    ensure_gitignore()

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
            "failed": failed,
            "parsed_fail": parsed_fail,
            "fetched_summary": {"ok": len(ok), "failed": len(failed),
                                "stale_fallback": len(stale_reasons)},
        }
        with open(os.path.join(REPORT_DIR, "latest.json"), "w", encoding="utf-8") as f:
            json.dump(report, f, ensure_ascii=False, indent=1)
        print(f"⛔ 已中止并落盘报告（{REPORT_DIR}/latest.json）：{reason}")

    def _abort(reason):
        _save_abort_report(reason)
        sys.exit(reason)

    links = read_links()
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

    print(f"抓取 {len(groups)} 个唯一聚合源（共 {sum(len(v) for v in groups.values())} 条链接）...")

    sha_map, sha_status = resolve_commit_shas(list(groups.keys()))
    rate_limited = [c for c, s in sha_status.items() if s == "api-rate-limited"]
    if rate_limited:
        print(f"⚠️ GitHub API 限额（{len(rate_limited)} 个源回退 ref）：{rate_limited[:3]}...")

    ok: dict[str, tuple[bytes, dict]] = {}
    failed: dict[str, dict] = {}
    cache_metas: dict[str, dict] = {}
    canons_sorted = sorted(groups.keys())

    def fetch_batch(batch: list[str]):
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
            futs = {}
            for canon in batch:
                cache_meta = load_cache(canon)
                cache_metas[canon] = cache_meta
                pinned = sha_map.get(canon)
                urls = []
                if pinned and pinned != canon:
                    urls.append(pinned)
                for u in groups[canon]:
                    if u not in urls:
                        urls.append(u)
                futs[ex.submit(fetch_group_worker, canon, urls, cache_meta)] = canon
            for fut in as_completed(futs):
                canon = futs[fut]
                try:
                    data, meta = fut.result()
                except Exception as exc:
                    failed[canon] = {"error": f"worker-exception:{exc!r}"}
                    continue
                if data is not None:
                    ok[canon] = (data, meta)
                else:
                    failed[canon] = meta

    fetch_batch(canons_sorted)

    candidates = []
    fresh_valid_canons = set()
    stale_valid_canons = set()
    stale_reasons: dict[str, str] = {}
    parsed_fail = []

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
                    save_cache(canon, data, meta, meta.get("final_url") or meta.get("url"))
                else:
                    touch_cache(canon)
            elif chosen == "stale":
                candidates.extend(seg)
                stale_valid_canons.add(canon)
                stale_reasons[canon] = "fresh-invalid-using-stale-cache"
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
    for fn in OUTPUT_FILES:
        oldp = os.path.join("dist", fn)
        if os.path.exists(oldp):
            try:
                with open(oldp, encoding="utf-8") as _f:
                    old_counts[fn] = len(json.load(_f)["exportedMediaSourceDataList"]["mediaSources"])
            except Exception:
                old_counts[fn] = 0
    new_counts = {fn: len(v) for fn, v in outputs.items()}
    for fn in ("all.json", "online.json", "bt.json"):
        old_n = old_counts.get(fn, new_counts[fn])
        if old_n:
            floor = (max(MIN_OUTPUT_COUNT, int(old_n * OUTPUT_KEEP_RATIO)) if fn == "all.json"
                     else int(old_n * OUTPUT_KEEP_RATIO))
            if new_counts[fn] < floor:
                _abort(f"[P0-2] {fn} 条目异常减少 {old_n} -> {new_counts[fn]}（下限 {floor}），拒绝覆盖")
            if (old_n - new_counts[fn]) / old_n > MAX_DELETE_RATIO:
                _abort(f"[P0-2] {fn} 删除比例 {old_n} -> {new_counts[fn]} 超 {MAX_DELETE_RATIO:.0%}，拒绝覆盖")


    newdir = f"dist.new-{os.getpid()}"
    if os.path.exists(newdir):
        shutil.rmtree(newdir, ignore_errors=True)
    os.makedirs(newdir, exist_ok=True)
    for fn, ms_list in outputs.items():
        with open(os.path.join(newdir, fn), "w", encoding="utf-8") as f:
            json.dump({"exportedMediaSourceDataList": {"mediaSources": ms_list}},
                      f, ensure_ascii=False, indent=2)
    for fn in OUTPUT_FILES:
        with open(os.path.join(newdir, fn), encoding="utf-8") as f:
            json.load(f)
    old_hash = _dir_hash("dist") if os.path.exists("dist") else None
    new_hash = _dir_hash(newdir)
    changed_any = not (old_hash and old_hash == new_hash)
    if not changed_any:
        shutil.rmtree(newdir, ignore_errors=True)
        print("产物无变化，跳过提交")
    else:
        old_existed = os.path.exists("dist")
        bak = f"dist.bak-{os.getpid()}"
        if old_existed:
            os.rename("dist", bak)
        else:
            os.makedirs(bak, exist_ok=True)
        try:
            os.rename(newdir, "dist")
        except Exception:
            if old_existed:
                os.rename(bak, "dist")
            else:
                if os.path.exists("dist"):
                    shutil.rmtree("dist", ignore_errors=True)
            raise
        with open(os.path.join("dist", "log"), "w", encoding="utf-8") as f:
            f.write(time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()) + chr(10))
        with open(os.path.join("dist", "latest.json"), "w", encoding="utf-8") as f:
            json.dump({
                "updated": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
                "source_base_commit": os.environ.get("GITHUB_SHA", ""),
                "output_sha256": _dir_hash("dist"),
                "counts": {fn: len(v) for fn, v in outputs.items()},
            }, f, ensure_ascii=False, indent=1)
        print("产物已更新（目录原子 swap 完成）")
        if os.path.exists(bak):
            shutil.rmtree(bak, ignore_errors=True)
    if os.path.exists(newdir):
        shutil.rmtree(newdir, ignore_errors=True)
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
        "valid_ratio": round(ratio, 3),
        "stale_ratio": round(stale_ratio, 3),
        "core_official_fresh": core_fresh,
        "snapshot_status": sha_status,
        "outputs": new_counts,
        "changed": changed_any,
        "priority_dist": prio_dist,
        "error_categories": err_cats,
        "legacy_version1_sources": legacy_v1,
        "http_sources": http_sources,
        "fetched": {
            **{c: {"size": m[1].get("size"), "sha256": m[1].get("sha256"),
                   "etag": m[1].get("etag"), "status": m[1].get("status"),
                   "error": m[1].get("error"), "cached": c in stale_reasons,
                   "not_modified": m[1].get("not_modified"),
                   "latency": m[1].get("latency"),
                   "redirects": m[1].get("redirects")}
               for c, m in ok.items()},
            **{c: {"cached": True, "stale_reason": r, "error": "stale-cache"}
               for c, r in stale_reasons.items() if c not in ok}},

        "failed": failed,
        "parsed_fail": parsed_fail,
    }
    with open(os.path.join(REPORT_DIR, "latest.json"), "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=1)
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
    if valid == 0 and parsed_fail is not None:
        parsed_fail.append((canon, "no-valid-items"))
    return out, valid > 0


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
        by_key.setdefault(k, []).append(m)
    out = {}
    for key, rec in merged.items():
        m2 = copy.deepcopy(rec["item"])
        args = m2.get("arguments") or {}
        if "channelTiers" not in args:
            sc = args.get("searchConfig") or {}
            core = {kk: v for kk, v in sc.items()}
            for cand in by_key.get(key, []):
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
            r = subprocess.run(["java", java_src, data_p], capture_output=True, text=True, timeout=30)
            if r.returncode != 0:
                fails = [l for l in r.stdout.splitlines() if l.startswith("FAIL")]
                return ([f[5:] for f in fails] if fails else [r.stdout.strip() or "java-check-failed"]), "java"
            return [], "java"
    except FileNotFoundError:
        return fallback_python_regex(regexes), "python"
    except Exception:
        return fallback_python_regex(regexes), "python"


def fallback_python_regex(regexes: list[str]) -> list[str]:
    fails = []
    for rx in regexes:
        py_rx = re.sub(r"\(\?<([A-Za-z_][A-Za-z0-9_]*)>", r"(?P<\1>", rx)
        try:
            re.compile(py_rx)
        except re.error as e:
            fails.append(f"{e!r} @ {rx[:60]}")
    return fails


def validate_outputs(outputs: dict[str, list]) -> tuple[list[str], str]:
    problems = []
    missing = [fn for fn in OUTPUT_FILES if fn not in outputs]
    if missing:
        problems.append(f"缺少产物: {missing}")
        return problems, "n/a"
    for fn, ms in outputs.items():
        if not ms:
            problems.append(f"{fn} 为空")

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
    if any(m.get("factoryId") == "rss" for m in outputs["online.json"]):
        problems.append("online.json 含 rss 条目")
    if any(m.get("factoryId") != "rss" for m in outputs["bt.json"]):
        problems.append("bt.json 含非 rss 条目")

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
            self.assertIn(meta.get("error"), ("private-host", "redirect-private-host"))
            self.assertEqual(mget.call_count, 1)

        @mock.patch.object(requests.Session, "get")
        def test_html_200_rejected(self, mget):
            mget.return_value = self._resp(200, b"<html><head><title>captcha</title></head></html>")
            data, meta = fetch_url("https://raw.githubusercontent.com/a/b/main/x.json", None,
                                   time.monotonic() + 30)
            self.assertIsNone(data)
            self.assertEqual(meta["error"], "html")

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
                                         "arguments": {"name": "X",
                                                       "searchConfig": {"searchUrl": "http://x.com/?wd={keyword}"}}})
            self.assertTrue(ok_f)
            ok_f2, _ = validate_item({"factoryId": "web-selector", "version": 2,
                                      "arguments": {"name": "X",
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

        def test_outputs_set_equality(self):
            def mk(fid, name, url):
                return {"factoryId": fid,
                        "version": 1 if fid == "rss" else 2,
                        "arguments": {"name": name,
                                      "searchConfig": {"rssUrl" if fid == "rss" else "searchUrl": url}}}
            onl = [mk("web-selector", f"O{i}", f"https://o{i}.com") for i in range(3)]
            bt = [mk("rss", f"B{i}", f"https://r{i}.xml") for i in range(2)]
            allms = onl + bt
            out = {"all.json": allms, "online.json": onl, "bt.json": bt,
                   "all-name.json": allms, "online-name.json": onl, "bt-name.json": bt}
            self.assertEqual(validate_outputs(out)[0], [])
            bad = {"all.json": allms, "online.json": bt + onl[:1], "bt.json": onl[1:],
                   "all-name.json": allms, "online-name.json": bt + onl[:1], "bt-name.json": onl[1:]}
            self.assertTrue(any("rss" in p or "集合" in p or "交集" in p for p in validate_outputs(bad)[0]))

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

        def test_cache_roundtrip(self):
            import tempfile, shutil
            td = tempfile.mkdtemp()
            try:
                old = CACHE_DIR
                globals()["CACHE_DIR"] = td
                canon = "https://raw.githubusercontent.com/a/b/main/x.json"
                save_cache(canon, b'{"a":1}', {"etag": "x"}, "https://raw.githubusercontent.com/a/b/main/x.json")
                c = load_cache(canon)
                self.assertEqual(c["data"], b'{"a":1}')
                self.assertEqual(c["validator_url"], "https://raw.githubusercontent.com/a/b/main/x.json")
                globals()["CACHE_DIR"] = old
            finally:
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
                self.assertTrue(all(l.startswith("https://") for l in links))
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

        def test_version_bool_rejected(self):
            item = {"factoryId": "web-selector", "version": True,
                    "arguments": {"name": "X", "searchConfig": {"searchUrl": "https://x.com"}}}
            ok_f, probs = validate_item(item)
            self.assertFalse(ok_f)
            self.assertTrue(any("version" in p for p in probs))
            item2 = {"factoryId": "rss", "version": 2,
                     "arguments": {"name": "X", "searchConfig": {"rssUrl": "https://x.com/rss"}}}
            ok_f2, probs2 = validate_item(item2)
            self.assertFalse(ok_f2)
            self.assertTrue(any("不支持 version" in p for p in probs2))

        def test_clean_links_filters(self):
            out = clean_links(["https://a.com", 123, None, "  ", "# 注释", "https://b.com"])
            self.assertEqual(out, ["https://a.com", "https://b.com"])

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
            self.assertFalse(is_core_official("https://raw.githubusercontent.com/CrazyBunQnQ/animeko-sources/main/animeko.json"))
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
                c["ts"] = time.time() - (STALE_MAX_AGE_DAYS + 1) * 86400
                with open(p, "w", encoding="utf-8") as f:
                    json.dump(c, f)
                self.assertIsNone(load_cache(canon))
                touch_cache(canon)
                c2 = load_cache(canon)
                self.assertIsNotNone(c2)
                self.assertEqual(c2["data"], b'{"a":1}')
                self.assertEqual(c2["etag"], "x")
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

    suite = unittest.defaultTestLoader.loadTestsFromTestCase(T)
    print(f"selftests: {suite.countTestCases()}")
    runner = unittest.TextTestRunner(verbosity=1)
    result = runner.run(suite)
    sys.exit(0 if result.wasSuccessful() else 1)


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--test":
        run_selftests()
    elif len(sys.argv) > 1 and sys.argv[1] == "--validate":
        out = {}
        for fn in OUTPUT_FILES:
            p = os.path.join("dist", fn)
            if os.path.exists(p):
                with open(p, encoding="utf-8") as _f:
                    out[fn] = json.load(_f)["exportedMediaSourceDataList"]["mediaSources"]
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
    else:
        main()
