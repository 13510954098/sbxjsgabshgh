#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Animeko 聚合源自动更新脚本 v9（修复 v8 复审发现的问题）
============================================
版本历史（代码含 v5~v8 全部修复，本注释已同步）：

v5（按《v4 上传前复审》19 项）：
  1  手动重定向：allow_redirects=False + 循环，每个 Location 在发请求前 check_url_safety
  2  fresh 网络数据解析失败/零有效条目 → 回退 stale cache
  3  core_fresh 只依据 fresh+valid canonical（fresh_valid_canons）
  4  parse_jsdelivr 正确处理 @refs/heads/<branch>/<path>、@refs/tags/<tag>/<path>
  5  url_shallow_ok 拒绝字面私网/环回/链路本地/保留 IP（ipaddress）
  6  非 5xx/429 的 HTTP 状态不触发 host 熔断
  7  删除 HTTP 自动降 tier 4（只报告标记，不修改任何源配置）
  8  iter_content() 循环内检查 deadline
  9  ETag/Last-Modified 只在 validator_url == 当前请求 URL 时发送（不跨镜像）
  10 quote(unquote(path)) / quote(unquote(ref)) 防二次编码
  11 GitHub API 403/429/失败 → snapshot_status 记录
  12 DNS 失败计入 host 熔断
  13 validate_outputs 任一产物缺失 → 跳过全部集合检查
  14 集合校验比 key 集合（all==online∪bt、交集∅、name 三件套同）
  15 MAX_LEN_SELECTOR / MAX_LEN_REGEX 实际生效
  16 java_check_regexes 返回模式状态，--validate 如实输出 Java 或 Python fallback
  17 测试数量以 suite.countTestCases() 的运行结果为准
  18 build_merged 移为模块级函数
  19 补齐关键测试（@refs/heads/main 归组、fresh坏JSON→stale、core_fresh、
     重定向私网阻止、400/401/451不熔断、percent path、ETag跨镜像、集合相等…）

v6（按《v5 上传前复审》19 项）：
  1  所有响应 with 关闭（不泄漏连接）
  2  每跳独立 host：semaphore/circuit/健康统计归属当前 host（single_hop）
  3  条件头按当前 URL 重构（validator_url == current 才发）
  4  redirect_count 与 retry_attempt 分离
  5  429/5xx 按 retry_attempt 指数退避（1.5*2^n，上限 15s），Retry-After 支持整数秒/HTTP-date
  6  source tier 改 UInt 范围（0..2^32-1），排序 t>=2 → t+1
  7  --validate 对每个条目执行完整 validate_item
  8  DNS rebinding 威胁模型在文档如实说明（v9 已闭环为固定 IP 连接）
  9  字面 IP 非标准数字形式拒绝
  10 缓存加载校验 SHA-256
  11 Retry-After 支持 HTTP-date
  12 parse_jsdelivr 注释如实（仅保证 refs/heads/main）
  13 body deadline 限制如实说明
  14 selftests 数量动态输出
  15 补测试（fresh坏JSON、core_fresh、body deadline、跨host熔断、响应关闭、tier>4）
  16 配套文件全部提供

v7（按《v6 上传前复审》8 项）：
  1  非标准数字 IP 绕过：is_literal_private_host 用 ipaddress，数字型失败一律拒绝
  2  safe_channel_tier 限 UInt（0..2^32-1）
  3  去重/排序 tier 统一：tier_rank_of 复用 tier_sort_value（未标记=fallback(2)）
  4  DNS 熔断检查移到 DNS 查询前
  5  host 健康与数据有效性分离（<500 且非 429 即 host_success）
  6  两个 mock 嵌套 context 修正
  7  测试数量说明不再写死
  8  choose_fresh_or_stale 提取为模块级函数 + 真单元测试

v8（按《v7 上传前复审》7 项）：
  1  非字符串 URL 防护：url_shallow_ok 拒 not-string；url_of 逐值检查；iconUrl 非字符串报错
  2  单条异常不拖垮任务：try_parse 内每条 try/except（item-N-exception 记录后跳过）
  3  version 组合校验：拒 bool；web-selector∈{1,2}、rss∈{1}
  4  0x 数字地址收紧（仅 0x 后全为合法 hex 才算）
  5  body deadline 测试 mock check_url_safety（不依赖真实 DNS）
  6  测试数量说明不写死
  7  clean_links 过滤非字符串/空/注释（防畸形配置文件）

v8 附加（拆分）：
  - 抓取链接已外置到 all_animeko_links.txt（162 条），脚本优先读它；
    缺失时明确报错。加源/删源只改 txt，不用动脚本。

v9（修复 v8 复审）：
  1  加速链补识别 '/https://raw.githubusercontent.com/' 前缀（原只认 '/raw.githubusercontent.com/'，
     漏一种常见写法导致同一上游裂成两个 canon 组：重复抓取、有效率统计失真、缓存分裂）
  2  meta["error"] 粘滞：重试循环每轮开头重置——重试后成功的源不再被报告误标为失败
  3  自测离线化：fetch 相关用例统一 mock check_url_safety（不再依赖真实 DNS）；
     links 用例改为临时目录里的合成文件（不再依赖部署数据 all_animeko_links.txt）
  4  parse_jsdelivr 删除 v8 的"显式拒绝"死代码（守卫写在 split 之后永不可达），如实说明
     jsdelivr 语法无法消歧含斜杠的 branch/tag，此类链接请改用 40 位 commit sha
  5  normalize 两重修正：嵌套剥壳上限真实生效（peeled 计数）；兜底分支要求可解析出
     http(s) scheme + hostname（垃圾行/无 scheme 行不再被收编为独立 group、污染有效率分母）
  6  parse_github_raw / parse_github_com：refs 但缺 path 段时返回 None（不再静默误切）
  7  304 not_modified 时 touch_cache 刷新 ts——长期 304 不再导致 stale 兜底 7 天后过期失效
  8  url_shallow_ok 收窄 '[' 豁免：仅放行"方括号占位符开头"，其余畸形串照旧结构校验
  9  Timeout/ConnectionError 重试与 429 分支一致：sleep 前预检 deadline
  10 报告 http_sources 同时检查 rssUrl（RSS 源的 http:// 不再漏报）

配套文件（部署只需 3 个）：update_sources.py + all_animeko_links.txt + .github/workflows/update.yml。
说明：requirements 依赖检查与 .gitignore 自动生成已内嵌脚本；README/LICENSE 为可选附加，非必需。

安全与限制说明：
- DNS rebinding：已闭环——check_url_safety 解析并校验 IP 后，请求经 PinnedIPAdapter
  直接连接到该固定 IP（SNI/Host 仍用原 hostname），requests 不再二次解析 DNS，
  不存在两次解析不一致的 rebinding 窗口。GitHub API 等受信域名走普通请求。
- body deadline：iter_content 循环内检查单调时钟，但若服务器长时间不发下一个 chunk，
  会先等 requests 读超时（20s），deadline 非绝对实时。
- 目录原子 swap：os.rename 整体替换（同一文件系统内核级原子），步骤间有短暂空窗但无新/旧混合状态
  但 Actions 中最终 git commit 本身是原子的。
"""

# 需要 Python 3.10+（PEP 604/585 注解）。__future__ 使注解在解析期不报错，
# 但运行时类型仍需 3.10+。
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
# [合一] 内嵌依赖版本检查（替代独立 requirements.txt）
try:
    from packaging.version import Version
    if Version(requests.__version__) < Version("2.32"):
        print(f"⚠️ requests 版本 {requests.__version__} 低于推荐 2.32，建议升级")
except Exception:
    # packaging 不可用时降级为简单数字比较
    try:
        nums = [int(x) for x in requests.__version__.split(".")[:2] if x.isdigit()]
        if len(nums) == 2 and tuple(nums) < (2, 32):
            print(f"⚠️ requests 版本 {requests.__version__} 低于推荐 2.32，建议升级")
    except Exception:
        pass

# ---------------- 配置 ----------------
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
# JSONPATH_FIELDS = ("selectLinks", "selectNames")  # 未使用——selectLinks/selectNames 已在 SELECTOR_FIELDS 中，长度校验已覆盖

MAX_LEN_NAME = 200
MAX_LEN_DESC = 1000
MAX_LEN_SELECTOR = 500      # [15]
MAX_LEN_REGEX = 500         # [15]


# [合一] 启动时确保 .gitignore 存在（替代独立文件；已存在则不覆盖）
GITIGNORE_CONTENT = "cache/\nreports/\ndist/.tmp-*\ndist.bak-*\ndist.new-*\n__pycache__/\n*.pyc\n"
def ensure_gitignore():
    if not os.path.exists(".gitignore"):
        try:
            with open(".gitignore", "w", encoding="utf-8") as f:
                f.write(GITIGNORE_CONTENT)
        except Exception as e:
            # [修] 不静默吞异常
            print(f"⚠️ .gitignore 写入失败: {e}", file=sys.stderr)


# ---------------- 小工具 ----------------
def sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def sha256_json(obj) -> str:
    return hashlib.sha256(json.dumps(obj, ensure_ascii=False, sort_keys=True).encode("utf-8")).hexdigest()


UINT_MAX = 2**32 - 1  # [6] Animeko MediaSourceTier 底层是 UInt，无 0~4 上限


def safe_tier(t):
    """[6] 接受 0..2^32-1 的非负整数（拒绝 bool/负数/非数字）。"""
    if isinstance(t, bool):
        return None
    if isinstance(t, int):
        return t if 0 <= t <= UINT_MAX else None
    if isinstance(t, str) and t.strip().isdigit():
        v = int(t)
        return v if 0 <= v <= UINT_MAX else None
    return None


def tier_rank_of(t):
    """[3] 去重/质量排名与最终显示排序统一：直接复用 tier_sort_value
    （None→2 fallback 位于 1 与显式 2 之间；t>=2 → t+1）。"""
    return tier_sort_value(t)


# [低3] tier → 排序值 显式映射（官方 MediaSourceTier 语义：越小越靠前）
#   0 → 0
#   1 → 1
#   (未标记) → 2   ← fallback 插在 1 和显式 2 之间（客户端把未标记当"正常"源）
#   2 → 3,  3 → 4,  4 → 5,  5 → 6, …（显式 tier 整体后移一档，给 fallback 让位）
TIER_SORT_MAP = {0: 0, 1: 1, 2: 3, 3: 4, 4: 5, 5: 6, 6: 7}


def tier_sort_value(t):
    """[6] 排序用：按 TIER_SORT_MAP 映射；未标记(None)=2（fallback 位于 1 和显式 2 之间）；
    t≥2 时 t→t+1（保持官方"越小越靠前"语义）。"""
    t = safe_tier(t)
    if t is None:
        return 2
    return TIER_SORT_MAP.get(t, t + 1)  # 超过映射表的大值也保持 t+1 语义


def safe_channel_tier(v):
    """channelTier 值域：0..2^32-1 的非负整数（与 source tier 同类型 UInt；
    真实数据中 5/6 表示备用线路）。拒绝 bool/负数/超上限/非数字。"""
    if isinstance(v, bool):
        return None
    if isinstance(v, int):
        return v if 0 <= v <= UINT_MAX else None
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
    """[5] hostname 本身是 IP 字面量时的私网判定。"""
    h = host.strip().lower().rstrip(".")
    if not h:
        return True
    if h == "localhost":
        return True
    # 数字型地址：纯数字/数字+点/0x 十六进制（仅当 0x 后全为合法 hex 字符）/IPv6
    looks_hex = (
        h.startswith("0x")
        and len(h) > 2
        and all(ch in "0123456789abcdef" for ch in h[2:])
    )
    looks_numeric = (
        all(ch.isdigit() or ch == "." for ch in h)
        or looks_hex
        or ":" in h
    )
    try:
        ip = ipaddress.ip_address(h)
    except ValueError:
        # 数字形式但不是标准 IP（2130706433、0177.0.0.1、0x7f000001、127.1）→ 一律拒绝
        return looks_numeric
    return (
        ip.is_loopback or ip.is_link_local or ip.is_private or ip.is_reserved
        or ip.is_multicast or (ip.version == 6 and ip.is_site_local)
    )


def check_url_safety(url: str) -> tuple[str | None, str | None]:
    """[1][12] URL 安全 + DNS rebinding 闭环：scheme + hostname（含字面 IP 私网检查）
    + DNS 解析 IP（私网拒绝）。
    返回 (错误原因或 None, 已校验的 IPv4 地址或 None)。
    - 通过：返回 (None, ip)——ip 是已确认非私网的地址，供连接固定使用
    - 失败：返回 (原因, None)"""
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
    # 选第一个非私网地址；若全部私网 → 拒绝
    for info in infos:
        ip = info[4][0]
        if not is_private_ip(ip):
            return None, ip
    return f"private-ip", None


def url_shallow_ok(u) -> tuple[bool, str | None]:
    """[5][12] 浅层 URL 校验：模板占位符放行；scheme+hostname；字面 IP 私网拒绝。
    非字符串输入直接拒绝（防畸形上游崩溃）。不做 DNS 深检。"""
    if not isinstance(u, str):
        return False, "not-string"
    if not u:
        return False, "empty"
    if u.startswith("["):
        # [v9:8] 仅放行"方括号占位符开头"的模板（如 [keyword]...）；任意 '[' 开头串不再放行
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


# ---------------- URL 归一化 / 解析 ----------------
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
        return None  # [v9:6] refs 但缺 path 段 → 不误切（ref 会是 "refs" 这种垃圾）
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
        # [修7] 正确处理 refs/heads/<branch>/<path>：ref 可能是多段（如 refs/heads/main），
        #       不能简单把 parts[3:-1] 全当 ref
        if parts[3] == "refs" and len(parts) >= 7 and parts[4] in ("heads", "tags"):
            ref = "/".join(parts[3:6])   # refs/heads/main
            path = "/".join(parts[6:])   # dist/all.json
        elif parts[3] == "refs":
            return None  # [v9:6] refs 但结构不合法 → 不误切
        else:
            ref = parts[3]
            path = "/".join(parts[4:])
        return GitHubRef(parts[0], parts[1], fold_ref(ref), path)
    if parts[2] == "blob" and len(parts) >= 4:
        # [修] blob 多段 ref（refs/heads/<branch>/<path>）与 raw 分支对齐
        if parts[3] == "refs" and len(parts) >= 7 and parts[4] in ("heads", "tags"):
            ref = "/".join(parts[3:6])
            path = "/".join(parts[6:])
        elif parts[3] == "refs":
            return None  # [v9:6] 同上
        else:
            ref = parts[3]
            path = "/".join(parts[4:])
        return GitHubRef(parts[0], parts[1], fold_ref(ref), path)
    return None


def parse_jsdelivr(url: str):
    """[4] 处理 @main、@refs/heads/<branch>/<path>、@refs/tags/<tag>/<path>。
    [v9:4] 如实测述：含斜杠的非 refs/ branch/tag（如 @feature/x/...）jsdelivr 语法本身无法消歧，
    按"第一个 / 前为 ref"切分（可能错切）——此类上游请改用 40 位 commit sha。"""
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
        return None  # refs/ 但结构不合法
    if "/" in rest:
        # [v9:4] 含斜杠的 branch/tag（如 @feature/x/path）在 jsdelivr 语法中无法消歧，
        #        v8 原打算"显式拒绝"但守卫写在 split 之后是死代码——如实说明：
        #        按"第一个 / 前为 ref"切分，可能与预期不符 → 此类链接应改用 40 位 commit sha。
        ref, path = rest.split("/", 1)
        return GitHubRef(owner, repo, fold_ref(ref), path)
    return GitHubRef(owner, repo, fold_ref(rest), "")


MAX_PROXY_NESTING = 2  # [修] 代理嵌套剥壳深度上限


def normalize(url: str) -> str:
    """[v9:5] 迭代剥壳，嵌套上限真实生效（peeled 计数，替代 v8 的不可达 ValueError）。
    [v9:1] 加速链同时识别 '/raw.githubusercontent.com/' 与 '/https://raw.githubusercontent.com/'。
    [v9:5] 兜底分支要求可解析出 http(s) scheme + hostname——垃圾行不再被收编为独立 group。"""
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
    # [v9:5] 兜底线：必须是个能解析的 http(s) URL
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


# ---------------- 解析 ----------------
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
    """[修] 按 factoryId 区分取值顺序：rss 优先 rssUrl，web-selector 优先 searchUrl，
    避免 rss 条目的占位 searchUrl 被错误优先返回。"""
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
    """[修] 编码探测：UTF-8 严格优先（绝大多数上游是 UTF-8），GBK 仅作兜底。
    每次解码后都做 JSON 解析 + extract() 结构校验，乱码解出的无结构内容不会误判成功。
    不引入 chardet（避免额外依赖），UTF-8 严格解码已覆盖绝大多数真实数据。"""
    # 1) UTF-8（含 BOM）严格优先——errors="strict" 保证字节序列必须是合法 UTF-8
    for enc in ("utf-8-sig", "utf-8"):
        try:
            text = data.decode(enc)  # strict 默认，非法字节直接抛 UnicodeDecodeError
        except UnicodeDecodeError:
            continue
        try:
            obj = json.loads(text)
        except Exception:
            continue
        ms = extract(obj)
        if isinstance(ms, list):
            return obj
    # 2) GBK 兜底（老站可能用 GBK）——同样要求结构校验
    try:
        obj = json.loads(data.decode("gbk"))
    except Exception:
        pass
    else:
        ms = extract(obj)
        if isinstance(ms, list):
            return obj
    raise ValueError("无法解析 JSON（UTF-8/GBK 编码探测+结构校验均失败）")


# ---------------- 规范化 + Schema 校验 ----------------
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
SUPPORTED_VERSIONS = {  # [3] 组合校验
    "web-selector": {1, 2},
    "rss": {1},
}


def validate_item(m) -> tuple[bool, list[str]]:
    """[12][15] Schema 校验：类型/URL(浅层)/长度(选择器/正则/JSONPath)/tier/channelTiers。"""
    problems = []
    if not isinstance(m, dict):
        return False, ["条目非 dict"]
    factory_id = m.get("factoryId")
    version = m.get("version")
    if factory_id not in ALLOWED_FACTORY:
        problems.append(f"factoryId={factory_id!r} 不受支持")
    # [3] version 拒绝布尔（isinstance(True,int)==True）；组合校验
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
    elif icon:  # 空 iconUrl 放行（很多源没有图标）
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
    # [15] 长度限制：已知正则 / 选择器 / JSONPath
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
                break
    return len(problems) == 0, problems


# ---------------- 缓存 ----------------
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
            # [10] 校验缓存自身 SHA-256，不匹配视为损坏
            if sha256_bytes(data) != c.get("sha256"):
                return None
            c["data"] = data
        return c
    except Exception:
        return None


def save_cache(canon: str, data: bytes, meta: dict, url: str):
    """[6][9][20] 只在有效解析后调用；保存 validator_url（ETag 不跨镜像）。"""
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
    """[v9:7] 304 not_modified 时只刷新缓存时间戳（数据/校验器不动）。
    避免上游长期 304 时 stale 兜底因 ts 超过 STALE_MAX_AGE_DAYS 而过期失效。"""
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


# ---------------- 抓取（[1][6][8][9][12]） ----------------
_tls = threading.local()


class _PinnedHTTPSConnection(HTTPSConnection):
    """[高1] DNS rebinding 闭环：socket 连接到"已校验的固定 IP"，
    但保留 self._dns_host（原 hostname）用于 SNI / 证书校验 / Host 头。"""

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
    """HTTP 版同款固定 IP 连接。"""

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
    """urllib3 2.x：pinned_ip 经 **conn_kw 自动传给连接类。"""
    ConnectionCls = _PinnedHTTPSConnection

    def __init__(self, host, port=None, pinned_ip=None, **kwargs):
        kwargs["pinned_ip"] = pinned_ip  # 进 **conn_kw → self.conn_kw["pinned_ip"]
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
    """[高1] 把连接固定到已校验的 IP（DNS rebinding 防护）。"""

    def __init__(self, pinned_ip, *args, **kwargs):
        self._pinned_ip = pinned_ip
        super().__init__(*args, **kwargs)

    def init_poolmanager(self, connections, maxsize, block=False):
        self.poolmanager = _PinnedPoolManager(
            pinned_ip=self._pinned_ip,
            num_pools=connections, maxsize=maxsize, block=block)


def get_session():
    s = getattr(_tls, "session", None)
    if s is None:
        s = requests.Session()
        # 注意：不要设置 s.max_redirects = 0 —— requests 在 allow_redirects=False 时
        # 仍会因 max_redirects=0 抛 TooManyRedirects（已知怪癖）；手动循环自带限制。
        # 默认适配器不固定 IP（用于 GitHub API 等受信调用）；抓取走固定 IP 专用 session
        s.mount("https://", HTTPAdapter(pool_connections=4, pool_maxsize=4, max_retries=0))
        s.mount("http://", HTTPAdapter(pool_connections=4, pool_maxsize=4, max_retries=0))
        _tls.session = s
    return s


# 注：get_session() 定义在 L891，v9 已改为全量走固定 IP 连接，该函数未调用——保留以供未来本地调试用。


# [高1] 每个 host+IP 一个固定 IP 的专用 session（thread-local，与 _tls 一致，避免多线程共享）
_pinned_tls = threading.local()


def get_pinned_session(host: str, ip: str) -> requests.Session:
    """返回把该 host 固定到已校验 IP 的 session（DNS rebinding 闭环；线程本地缓存）。"""
    cache = getattr(_pinned_tls, "sessions", None)
    if cache is None:
        cache = _pinned_tls.sessions = {}
    key = f"{host}:{ip}"
    s = cache.get(key)
    if s is None:
        s = requests.Session()
        # 注意：不能设 s.max_redirects = 0 —— requests 在 allow_redirects=False 时
        # 仍会因 max_redirects=0 抛 TooManyRedirects；手动重定向循环自带限制
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
    """[修8] 只在内容开头就是 HTML 标记时才拒绝（避免合法 JSON 前 256 字节
    恰好含 <html/<head 字样被误杀）。"""
    low = head[:256].lower().lstrip()
    if not low.startswith(b"<"):
        return False
    return (low.startswith(b"<!doctype") or low.startswith(b"<html")
            or low.startswith(b"<head") or low.startswith(b"<body"))


def fetch_url(url: str, cache_meta: dict | None, deadline: float):
    """[1][2][4][5] 手动重定向循环：每跳独立 host semaphore/circuit/健康统计；
    每个 Location 在发请求前校验；redirect 次数与 retry 次数分离。"""
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
            # [4] circuit 检查在 DNS 查询之前（熔断后不再重复解析失效域名）
            if host_circuit_broken(hop_host):
                meta["error"] = "circuit-open"
                meta["redirects"].append(current)
                return None, meta
            # scheme/hostname/字面私网 IP 浅检（DNS 深检由 single_hop 统一做一次，
            # 返回已校验 IP 供固定连接使用——避免 DNS 打两遍）
            if parsed.scheme not in ("http", "https") or not hop_host:
                meta["error"] = "bad-scheme-or-host"
                meta["redirects"].append(current)
                return None, meta
            if is_literal_private_host(hop_host):
                meta["error"] = "private-host"
                meta["redirects"].append(current)
                return None, meta
            data, hop_meta, location = single_hop(current, cache_meta, deadline)
            # 汇总 hop 状态
            if hop_meta.get("status") is not None:
                meta["status"] = hop_meta["status"]  # [修] 避免 None 覆盖上一跳真实状态
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
            # 非重定向失败
            meta["error"] = hop_meta.get("error") or "unknown"
            meta["redirects"].append(current)
            return None, meta
        meta["error"] = "too-many-redirects"
        return None, meta
    except Exception as e:
        meta["error"] = f"unexpected:{e!r}"
        return None, meta


def single_hop(current: str, cache_meta, deadline: float):
    """[1][2][3][4][5] 单次请求：独立 host 锁/熔断/健康；with 关闭响应；
    条件头按当前 URL 重构（validator_url 匹配才发）；redirect 次数与 retry 分离；
    429/5xx 按 retry_attempt 指数退避（支持 Retry-After 整数秒或 HTTP-date）。
    返回 (data|None, meta, redirect_location|None)。"""
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
        # [高1] DNS rebinding 闭环：用固定到已校验 IP 的 session 发请求
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
            meta["error"] = None  # [v9:2] 重试迭代开头重置上一轮的错误，防止 error 粘滞
            #                      #      （成功后 report 的 error_categories 不再误报）
            # [3] 每跳重构条件头：validator_url 必须等于当前 URL
            headers = {"User-Agent": ua}
            if cache_meta and cache_meta.get("validator_url") == current:
                if cache_meta.get("etag"):
                    headers["If-None-Match"] = cache_meta["etag"]
                if cache_meta.get("last_modified"):
                    headers["If-Modified-Since"] = cache_meta["last_modified"]
            try:
                with sess.get(current, timeout=TIMEOUT, headers=headers,
                              allow_redirects=False, stream=True) as r:  # [1] with 关闭
                    meta["status"] = r.status_code
                    meta["final_url"] = r.url
                    # [5] 能正常收到非服务故障响应 → host 网络是通的，清零熔断
                    # （数据层问题如 304/403/404/HTML/过大在下面分别处理，不混淆）
                    if r.status_code < 500 and r.status_code != 429:
                        host_success(host)
                    # 重定向
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
                            continue  # 换 UA 重试（不占 retry_attempt）
                        meta["error"] = "http-403"
                        return None, meta, None
                    if r.status_code == 404:
                        meta["error"] = "http-404"  # 文件级错误，不熔断
                        return None, meta, None
                    if r.status_code in (400, 401, 402, 405, 406, 408, 409, 410, 411, 412,
                                         413, 415, 416, 417, 418, 421, 422, 423, 424, 425,
                                         426, 428, 431, 451):
                        meta["error"] = f"http-{r.status_code}"  # [6] 不熔断
                        return None, meta, None
                    if r.status_code == 429 or r.status_code >= 500:
                        host_fail(host)  # [8] 服务级错误计入当前 host 熔断
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
                    # 200：大小限制 + 流式读取（[8] body 内查 deadline）
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
                    host_success(host)  # 网络层成功才清零当前 host 熔断
                    meta["size"] = size
                    meta["sha256"] = sha256_bytes(data)
                    meta["etag"] = r.headers.get("ETag")
                    meta["last_modified"] = r.headers.get("Last-Modified")
                    return data, meta, None
            except requests.exceptions.Timeout as e:
                meta["error"] = f"timeout:{type(e).__name__}"
                host_fail(host)
                retry_attempt += 1
                if time.monotonic() + 1.0 > deadline:  # [v9:9] 与 429 分支一致，预检再睡
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
                if time.monotonic() + 1.0 > deadline:  # [v9:9] 同上
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
    """[11] Retry-After 支持整数秒和 HTTP-date。"""
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
        # [修2] 除 deadline 外的所有错误（404/redirect/dns/熔断/429/5xx/超时…）
        #       都继续试下一个镜像——镜像列表在 host 故障/限流时才该发挥作用；
        #       每组已有 GROUP_DEADLINE 总预算兜底，不会无限循环
        if "deadline" in err:
            break
    return None, last_meta


def clean_links(data) -> list[str]:
    """[7] 过滤非字符串/空/注释行，防畸形配置文件崩溃。"""
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


# ---------------- commit 快照 [10][11] ----------------
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
        # [10] 防二次编码：先 unquote 再 quote
        out[canon] = (f"https://raw.githubusercontent.com/{gr.owner}/{gr.repo}/"
                      f"{quote(unquote(ref), safe='/')}/{quote(unquote(gr.path), safe='/')}")
    return out, status


# ---------------- 主流程 ----------------


def _dir_hash(d: str) -> str:
    """计算 dist/ 目录 6 个产物的整体哈希，用于判断是否有实质变化。"""
    h = hashlib.sha256()
    for fn in OUTPUT_FILES:
        p = os.path.join(d, fn)
        if os.path.exists(p):
            with open(p, "rb") as f:
                h.update(f.read())
    return h.hexdigest()


def _recover_stale_backup():
    """启动恢复：检测上次原子 swap 中途崩溃残留的 dist.bak-* 目录。
    若当前 dist/ 不存在或不完整，从 bak 恢复；否则清理 bak。"""
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
    canons_sorted = sorted(groups.keys())

    def fetch_batch(batch: list[str]):
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
            futs = {}
            for canon in batch:
                cache_meta = load_cache(canon)
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

    # ---------------- 解析 + 有效统计（[2][3]） ----------------
    candidates = []
    fresh_valid_canons = set()
    stale_valid_canons = set()
    stale_reasons: dict[str, str] = {}  # [修] stale 回退原因（数据被采用，不算失败）
    parsed_fail = []

    for canon in canons_sorted:
        if canon in ok:
            data, meta = ok[canon]
            # [修1] fresh 数据与上次有效缓存都传入：fresh 有效→采用并刷缓存；
            #       fresh 无效（坏 JSON/零有效条目）→ 自动回退 stale 缓存。
            #       （meta["cached"] 恒为 falsy，原条件判断是冗余死逻辑，已移除）
            seg, chosen = choose_fresh_or_stale(
                fresh_data=data,
                stale_data=(load_cache(canon) or {}).get("data"),
                canon=canon, parsed_fail=parsed_fail)
            if chosen == "fresh":
                candidates.extend(seg)
                fresh_valid_canons.add(canon)
                if not meta.get("not_modified"):
                    save_cache(canon, data, meta, meta.get("final_url") or meta.get("url"))
                else:
                    touch_cache(canon)  # [v9:7] 304 命中也刷新 ts，保住 stale 兜底时效
            elif chosen == "stale":
                candidates.extend(seg)
                stale_valid_canons.add(canon)
                stale_reasons[canon] = "fresh-invalid-using-stale-cache"  # [修] 不进 failed
                print(f"  fresh 无效→缓存兜底: {canon}")
            else:
                failed[canon] = {"error": "fresh-invalid-no-valid"}
        else:
            # 网络失败 → stale-if-error
            cache = load_cache(canon)
            if cache and cache.get("data"):
                seg, chosen = choose_fresh_or_stale(
                    fresh_data=None,
                    stale_data=cache["data"],
                    canon=canon, parsed_fail=parsed_fail)
                if chosen == "stale":
                    candidates.extend(seg)
                    stale_valid_canons.add(canon)
                    stale_reasons[canon] = "network-fail-using-stale-cache"  # [修] 不进 failed
                    failed.pop(canon, None)  # [修] fetch_batch 已写入 failed，需移除避免重复计数
                    print(f"  缓存兜底: {canon}")
                else:
                    failed[canon] = {"error": "stale-cache-invalid"}
            else:
                failed[canon] = failed.get(canon, {"error": "no-data-no-cache"})

    valid_total = len(fresh_valid_canons) + len(stale_valid_canons)
    ratio = valid_total / max(len(groups), 1)
    stale_ratio = (len(stale_valid_canons) / valid_total) if valid_total else 0.0
    print(f"有效上游 {valid_total}/{len(groups)}（{ratio:.0%}；fresh {len(fresh_valid_canons)} / stale {len(stale_valid_canons)}）")

    # [3] core_fresh 只依据 fresh+valid canonical
    core_fresh = any(is_core_official(c) for c in fresh_valid_canons)
    if not core_fresh:
        sys.exit("[3] 核心官方源（MajoSissi dist）无 fresh 有效数据，拒绝覆盖产物")
    if stale_ratio > MAX_STALE_RATIO:
        sys.exit(f"[21] stale 占比 {stale_ratio:.0%} 超上限 {MAX_STALE_RATIO:.0%}，拒绝覆盖产物")
    if ratio < MIN_VALID_RATIO:
        sys.exit(f"[P0-2] 有效上游率 {ratio:.0%} < {MIN_VALID_RATIO:.0%}，拒绝覆盖现有产物")

    # ---------------- 确定性合并（[18] 模块级函数） ----------------
    sel_full = build_merged(candidates, "full")
    sel_name = build_merged(candidates, "name")
    sel_full = enrich_channel_tiers(sel_full, candidates)
    sel_name = enrich_channel_tiers(sel_name, candidates, "name")  # [修] name 模式也补上 channelTiers，避免 *-name.json 丢失备用线路

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
        sys.exit("产物校验失败:\n  " + "\n  ".join(problems_out))

    # ---------------- 保护：条目数与删除比例 ----------------
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
                sys.exit(f"[P0-2] {fn} 条目异常减少 {old_n} -> {new_counts[fn]}（下限 {floor}），拒绝覆盖")
            if (old_n - new_counts[fn]) / old_n > MAX_DELETE_RATIO:
                sys.exit(f"[P0-2] {fn} 删除比例 {old_n} -> {new_counts[fn]} 超 {MAX_DELETE_RATIO:.0%}，拒绝覆盖")


    # ---------------- 写入（目录原子 swap：os.rename 整体替换） ----------------
    # 同一文件系统下 os.rename() 是内核级原子操作。流程：
    #   1) 写 6 产物到 dist.new-{pid}/ + 校验
    #   2) os.rename("dist", "dist.bak-{pid}")   ← 原子：旧目录整体移走
    #      （此刻到步骤 3 之间，dist/ 短暂不存在。订阅者可能看到 404/空目录。
    #       但 Actions 的 git commit 本身是原子的——步骤 3 成功后 commit 才会提交，
    #       所以 CI 场景下无人会看到这个空窗。本地如需避免，可用上层卷快照。）
    #   3) os.rename("dist.new-{pid}", "dist")    ← 原子：新目录整体就位
    #      （自此 dist/ 里 6 个文件全是新的，没有半新半旧混合状态）
    #   4) 写辅助文件（log / latest.json）→ 删 dist.bak-{pid}
    # 在 main() 开头已调用 _recover_stale_backup()，此处不再重复
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
    # ---------------- 结构化报告 ----------------
    os.makedirs(REPORT_DIR, exist_ok=True)
    # [修] stale 回退的源已在主循环单独记录（stale_reasons），不进 failed；
    #      报告按原因归类，不重复计数
    err_cats = {}
    for c, m in ok.items():
        if c in stale_reasons or c in failed:
            continue  # [修] fresh 无效且无缓存的源在 failed 里，不重复计数
        e = m[1].get("error") or "ok"
        err_cats[e] = err_cats.get(e, 0) + 1
    for c, m in failed.items():
        e = m.get("error") or "unknown"
        err_cats[e.split("(")[0].strip()] = err_cats.get(e.split("(")[0].strip(), 0) + 1
    for reason in set(stale_reasons.values()):
        n = sum(1 for v in stale_reasons.values() if v == reason)
        err_cats[reason] = err_cats.get(reason, 0) + n
    # [修] 覆盖所有有效源（fresh + stale）：网络失败走 stale 兜底的源不在 ok，也要统计
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
        # [修] searchUrl 与 rssUrl 分别检查，or 链会遮蔽 http 协议；
        #      且非字符串值（畸形上游）不能调 .startswith —— 先 isinstance 防崩
        def _is_http(v):
            return isinstance(v, str) and v.startswith("http://")
        if _is_http(sc.get("searchUrl")) or _is_http(sc.get("rssUrl")) or _is_http(a.get("rssUrl")):
            http_sources.append(a.get("name"))
    report = {
        "ts": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
        "duration_s": round(time.time() - start, 1),
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
            # [修] 网络失败走 stale 的源：不在 ok，用 stale_reasons 补记录
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


# ---------------- 解析辅助（模块级，可测 [15]） ----------------
def try_parse(data: bytes, canon: str, parsed_fail: list | None = None) -> tuple[list, bool]:
    """返回 (candidates 片段, 是否有有效条目)。坏 JSON/无结构/零有效条目 → ([], False)。"""
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
        try:  # [2] 单条异常不拖垮整个任务
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
    """[8] fresh 优先；fresh 无效（坏 JSON/零有效条目）→ stale；都无效 → ([], "invalid")。"""
    if fresh_data is not None:
        seg, valid = try_parse(fresh_data, canon, parsed_fail)
        if valid:
            return seg, "fresh"
    if stale_data is not None:
        seg, valid = try_parse(stale_data, canon, parsed_fail)
        if valid:
            return seg, "stale"
    return [], "invalid"


# ---------------- 合并（模块级，[18] 可测） ----------------
def build_merged(candidates: list, mode: str) -> dict:
    """[7][18] 确定性合并：保留选中来源 origin。"""
    selected = {}
    for rank, key, m, canon in candidates:
        k = key if mode == "full" else (key[0], key[1])
        if k not in selected or rank < selected[k]["rank"]:
            selected[k] = {"item": m, "origin": canon, "rank": rank}
    return selected


def enrich_channel_tiers(merged: dict, candidates: list, mode: str = "full") -> dict:
    """[修] 增加 mode 参数：name 模式下 merged 的 key 是二元组 (fid, name)，
    by_key 必须用同样的键长匹配，否则查不到 → 上一版对 sel_name 的调用是无效操作。"""
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


# ---------------- 产物校验（[13][14][15][16]） ----------------
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
    """[16] 返回 (失败列表, 模式)。java 可用 → "java"；否则降级 Python → "python"。"""
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
    """[13][14] 缺任一文件即跳过集合检查；集合校验比 key 集合。"""
    problems = []
    missing = [fn for fn in OUTPUT_FILES if fn not in outputs]
    if missing:
        problems.append(f"缺少产物: {missing}")
        return problems, "n/a"  # [13] 缺文件就不做集合检查；返回值与正常分支一致
    for fn, ms in outputs.items():
        if not ms:
            problems.append(f"{fn} 为空")

    # [14] key 集合校验（all/online/bt）
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

    # name 三件套
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
            # [7] 对每个条目执行完整 Schema 校验
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
    return problems, jmode  # [修] 正则模式随返回值传递，不再用全局可变字典


# ---------------- 内嵌自动测试（数量以运行结果为准） ----------------
def run_selftests():
    import unittest
    from unittest import mock

    class T(unittest.TestCase):
        # [v9:3] 自测离线化：所有用例统一 mock check_url_safety——fetch 链路不再依赖真实 DNS；
        #        快照 host 熔断/并发全局状态，避免用例间污染
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

        # --- [1] tier ---
        def test_tier0_not_99(self):
            self.assertEqual(tier_rank_of(0), 0)
            self.assertEqual(tier_rank_of(None), 2)  # [3] 与最终排序统一：未标记 = fallback(2)

        # --- URL 归一化 ---
        def test_jsdelivr_to_raw(self):
            self.assertEqual(
                normalize("https://cdn.jsdelivr.net/gh/MajoSissi/animeko-source@main/dist/all.json"),
                "https://raw.githubusercontent.com/MajoSissi/animeko-source/main/dist/all.json")

        def test_refs_heads_main_folded(self):  # [4]
            a = normalize("https://raw.githubusercontent.com/SZMY-haruhi/haruhi/refs/heads/main/haruhiAni.json")
            b = normalize("https://cdn.jsdelivr.net/gh/SZMY-haruhi/haruhi@main/haruhiAni.json")
            c = normalize("https://cdn.jsdelivr.net/gh/SZMY-haruhi/haruhi@refs/heads/main/haruhiAni.json")
            self.assertEqual(a, b)
            self.assertEqual(a, c)

        def test_github_com_raw_refs_heads(self):  # [修7] github.com raw refs/heads 路径
            a = normalize("https://github.com/o/r/raw/refs/heads/main/dist/all.json")
            b = normalize("https://raw.githubusercontent.com/o/r/main/dist/all.json")
            self.assertEqual(a, b)

        def test_github_com_blob_refs_heads(self):  # [修] blob 多段 ref
            a = normalize("https://github.com/o/r/blob/refs/heads/main/dist/all.json")
            b = normalize("https://raw.githubusercontent.com/o/r/main/dist/all.json")
            self.assertEqual(a, b)
            # 普通 blob 也正常
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

        # --- [5] 私网 IP ---
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

        # --- 手动重定向 [1] ---
        def _resp(self, status=200, body=b"{}", headers=None):
            """返回可 `with` 的上下文 mock：sess.get() 返回 ctx，`with ctx as r` 拿到响应。"""
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
            """[1] 重定向到 127.0.0.1 在发请求前被阻止（手动重定向逐跳检查）。"""
            r302 = self._resp(302, b"", headers={"Location": "http://127.0.0.1/evil"})
            mget.return_value = r302
            data, meta = fetch_url("https://raw.githubusercontent.com/a/b/main/x.json", None,
                                   time.monotonic() + 30)
            self.assertIsNone(data)
            # 私网跳转在第二跳请求前被 check_url_safety 拦截
            self.assertIn(meta.get("error"), ("private-host", "redirect-private-host"))
            self.assertEqual(mget.call_count, 1)  # 第二个 hop 不会发出请求

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
        def test_etag_not_sent_across_mirror(self, mget):  # [9]
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
        def test_400_401_451_not_circuit_break(self, mget):  # [6]
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

        def test_tier_not_modified_by_protocol(self):  # [7]
            item = {"factoryId": "web-selector", "version": 2,
                    "arguments": {"name": "H源", "searchConfig": {"searchUrl": "http://x.com/?wd={keyword}"}}}
            m2 = normalize_item(item)
            self.assertNotIn("tier", m2["arguments"])  # HTTP 不再自动降级

        def test_validate_missing_files(self):  # [13]
            probs, _ = validate_outputs({"all.json": []})
            self.assertTrue(any("缺少产物" in p for p in probs))
            # 缺 all-name 时不应 KeyError
            probs2, _ = validate_outputs({"all.json": [], "online.json": [], "bt.json": []})
            self.assertTrue(any("缺少产物" in p for p in probs2))

        def test_outputs_set_equality(self):  # [14]
            def mk(fid, name, url):
                return {"factoryId": fid,
                        "version": 1 if fid == "rss" else 2,  # [3] 组合校验
                        "arguments": {"name": name,
                                      "searchConfig": {"rssUrl" if fid == "rss" else "searchUrl": url}}}
            onl = [mk("web-selector", f"O{i}", f"https://o{i}.com") for i in range(3)]
            bt = [mk("rss", f"B{i}", f"https://r{i}.xml") for i in range(2)]
            allms = onl + bt
            out = {"all.json": allms, "online.json": onl, "bt.json": bt,
                   "all-name.json": allms, "online-name.json": onl, "bt-name.json": bt}
            self.assertEqual(validate_outputs(out)[0], [])
            # 错误分组（数量对但内容不对）应被检出
            bad = {"all.json": allms, "online.json": bt + onl[:1], "bt.json": onl[1:],
                   "all-name.json": allms, "online-name.json": bt + onl[:1], "bt-name.json": onl[1:]}
            self.assertTrue(any("rss" in p or "集合" in p or "交集" in p for p in validate_outputs(bad)[0]))

        def test_duplicate_detected(self):
            ms = [{"factoryId": "web-selector", "version": 2,
                   "arguments": {"name": "X", "searchConfig": {"searchUrl": "https://x.com"}}}]
            out = {"all.json": ms + ms, "online.json": ms + ms, "bt.json": [],
                   "all-name.json": ms + ms, "online-name.json": ms + ms, "bt-name.json": []}
            self.assertTrue(any("重复" in p for p in validate_outputs(out)[0]))

        def test_merge_keeps_origin(self):  # [18]
            def mk(fid, name, url, tier):
                return {"factoryId": fid, "version": 2,
                        "arguments": {"name": name, "tier": tier, "searchConfig": {"searchUrl": url}}}
            c1 = "https://raw.githubusercontent.com/MajoSissi/animeko-source/main/dist/all.json"   # prio 0
            c2 = "https://raw.githubusercontent.com/CrazyBunQnQ/animeko-sources/main/animeko.json"  # prio 3
            cands = [
                ((3, 2, 0), ("web-selector", "X", "https://x.com"), mk("web-selector", "X", "https://x.com", 2), c2),
                ((0, 2, 0), ("web-selector", "X", "https://x.com"), mk("web-selector", "X", "https://x.com", 2), c1),
            ]
            sel = build_merged(cands, "full")
            self.assertEqual(sel[("web-selector", "X", "https://x.com")]["origin"], c1)  # 官方优先

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

        def test_percent_encoded_path_not_double_encoded(self):  # [10]
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
            # [v9:3] 用临时目录里的合成链接文件验证加载逻辑，不依赖部署数据文件
            import tempfile
            d = tempfile.mkdtemp()
            cwd = os.getcwd()
            try:
                os.chdir(d)
                with open("all_animeko_links.txt", "w", encoding="utf-8") as f:
                    f.write("\n".join(f"https://raw.githubusercontent.com/o{i}/r{i}/main/x.json"
                                      for i in range(120)))
                    f.write("\n# 注释行\n\n")  # 顺带验证 clean_links 过滤
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
            self.assertEqual(safe_tier(9), 9)  # [6] UInt 范围
            self.assertIsNone(safe_tier(True))
            self.assertIsNone(safe_tier(-1))
            self.assertIsNone(safe_tier(2**32))

        def test_length_limits_enforced(self):  # [15]
            item = {"factoryId": "web-selector", "version": 2,
                    "arguments": {"name": "X",
                                  "searchConfig": {"matchChannelName": "a" * (MAX_LEN_REGEX + 10)}}}
            ok_f, probs = validate_item(item)
            self.assertFalse(ok_f)
            self.assertTrue(any("超长" in p for p in probs))

        def test_nonstandard_loopback_forms_rejected(self):  # [1] 非标准数字环回
            for host in ("2130706433", "0177.0.0.1", "0x7f000001", "127.1"):
                self.assertTrue(is_literal_private_host(host), host)

        def test_url_shallow_ok_non_string(self):  # [1] 非字符串 URL
            ok_f, err = url_shallow_ok(["https://example.com"])
            self.assertFalse(ok_f)
            self.assertEqual(err, "not-string")
            ok_f, err = url_shallow_ok(12345)
            self.assertFalse(ok_f)
            self.assertEqual(err, "not-string")

        def test_version_bool_rejected(self):  # [3]
            item = {"factoryId": "web-selector", "version": True,
                    "arguments": {"name": "X", "searchConfig": {"searchUrl": "https://x.com"}}}
            ok_f, probs = validate_item(item)
            self.assertFalse(ok_f)
            self.assertTrue(any("version" in p for p in probs))
            # 组合校验：rss version=2 不支持
            item2 = {"factoryId": "rss", "version": 2,
                     "arguments": {"name": "X", "searchConfig": {"rssUrl": "https://x.com/rss"}}}
            ok_f2, probs2 = validate_item(item2)
            self.assertFalse(ok_f2)
            self.assertTrue(any("不支持 version" in p for p in probs2))

        def test_clean_links_filters(self):  # [7]
            out = clean_links(["https://a.com", 123, None, "  ", "# 注释", "https://b.com"])
            self.assertEqual(out, ["https://a.com", "https://b.com"])

        def test_try_parse_bad_item_does_not_crash(self):  # [2] 单条异常不影响整体
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

        def test_choose_fresh_or_stale(self):  # [8] fresh/stale 选择流程
            canon = "https://raw.githubusercontent.com/a/b/main/x.json"
            good = b'{"exportedMediaSourceDataList":{"mediaSources":[' \
                   b'{"factoryId":"web-selector","version":2,' \
                   b'"arguments":{"name":"X","searchConfig":{"searchUrl":"https://x.com/?wd={keyword}"}}}]}}'
            bad = b"<html>not json"
            # fresh 有效 → fresh
            seg, ch = choose_fresh_or_stale(good, None, canon)
            self.assertEqual(ch, "fresh")
            self.assertTrue(len(seg) >= 1)
            # fresh 坏 → stale 有效
            seg, ch = choose_fresh_or_stale(bad, good, canon)
            self.assertEqual(ch, "stale")
            # 都坏 → invalid
            seg, ch = choose_fresh_or_stale(bad, bad, canon)
            self.assertEqual(ch, "invalid")
            self.assertEqual(seg, [])

        def test_source_tier_uint_supported(self):  # [6] 源级 tier 支持 >4
            self.assertEqual(safe_tier(6), 6)
            self.assertEqual(safe_tier(9), 9)
            self.assertEqual(tier_sort_value(5), 6)
            self.assertEqual(tier_sort_value(6), 7)
            self.assertEqual(tier_sort_value(None), 2)
            self.assertEqual(tier_sort_value(1), 1)

        def test_fresh_invalid_no_valid_items(self):  # [15] 坏 JSON → 无有效条目
            seg, valid = try_parse(b"<html>not json", "https://raw.githubusercontent.com/a/b/main/x.json")
            self.assertFalse(valid)
            self.assertEqual(seg, [])
            seg2, valid2 = try_parse(b'{"exportedMediaSourceDataList":{"mediaSources":[]}}',
                                     "https://raw.githubusercontent.com/a/b/main/x.json")
            self.assertFalse(valid2)

        def test_core_fresh_logic(self):  # [15] 核心官方源判定
            canon = "https://raw.githubusercontent.com/MajoSissi/animeko-source/main/dist/all.json"
            self.assertTrue(is_core_official(canon))
            self.assertFalse(is_core_official("https://raw.githubusercontent.com/CrazyBunQnQ/animeko-sources/main/animeko.json"))
            # 坏 fresh 官方源不应进入 fresh_valid_canons（try_parse 返回 False）
            fresh_valid = set()
            seg, valid = try_parse(b'{"exportedMediaSourceDataList":{"mediaSources":[]}}', canon)
            if valid:
                fresh_valid.add(canon)
            self.assertFalse(any(is_core_official(c) for c in fresh_valid))

        @mock.patch.object(requests.Session, "get")
        def test_body_deadline_during_read(self, mget):  # [15] body 期间 deadline（safety 已由 setUp mock）
            def slow_iter(*_args):  # iter_content(chunk_size) 会把参数传给 side_effect
                yield b"chunk1"
                time.sleep(0.05)
                yield b"chunk2"
            ctx = self._resp(200, b"")
            ctx.__enter__.return_value.iter_content.side_effect = slow_iter
            mget.return_value = ctx
            deadline = time.monotonic() + 0.01  # 足够短，但跳过 DNS 检查
            data, meta = fetch_url("https://raw.githubusercontent.com/a/b/main/x.json", None, deadline)
            self.assertIsNone(data)
            self.assertEqual(meta["error"], "deadline-during-body")

        @mock.patch.object(requests.Session, "get")
        def test_cross_host_hop_respects_circuit(self, mget):  # [15] 重定向到熔断 host 被拦截
            _host_fail["example.org"] = 100
            ctx = self._resp(302, b"", headers={"Location": "https://example.org/evil"})
            mget.return_value = ctx
            data, meta = fetch_url("https://raw.githubusercontent.com/a/b/main/x.json", None,
                                   time.monotonic() + 30)
            self.assertIsNone(data)
            self.assertEqual(meta["error"], "circuit-open")
            self.assertEqual(mget.call_count, 1)  # 第二跳在请求前被 circuit 拦截

        @mock.patch.object(requests.Session, "get")
        def test_response_closed_via_with(self, mget):  # [15] 响应用 with 关闭
            ctx = self._resp(404, b"nope")
            mget.return_value = ctx
            fetch_url("https://raw.githubusercontent.com/a/b/main/x.json", None, time.monotonic() + 30)
            ctx.__exit__.assert_called_once()

        # ---------------- v9 回归用例 ----------------
        def test_proxy_https_raw_prefix(self):  # [v9:1] 带 https:// 前缀的代理 raw 链接
            self.assertEqual(
                normalize("https://gh-proxy.com/https://raw.githubusercontent.com/MajoSissi/animeko-source/main/dist/all.json"),
                "https://raw.githubusercontent.com/MajoSissi/animeko-source/main/dist/all.json")
            self.assertEqual(
                normalize("https://ghfast.top/https://raw.githubusercontent.com/o/r/main/x.json"),
                "https://raw.githubusercontent.com/o/r/main/x.json")

        def test_garbage_line_rejected(self):  # [v9:5] 垃圾行/无 scheme 行不再成 group
            for bad in ("这不是一个链接", "//example.com/x", "ftp://bad/x", "x.com/noscheme"):
                with self.assertRaises(ValueError, msg=repr(bad)):
                    normalize(bad)

        def test_proxy_nesting_limit_real(self):  # [v9:5] 嵌套上限真实生效
            with mock.patch(__name__ + ".MAX_PROXY_NESTING", 0):
                with self.assertRaises(ValueError):
                    normalize("https://gh-proxy.com/https://github.com/o/r/raw/main/dist/all.json")

        @mock.patch.object(requests.Session, "get")
        def test_error_cleared_after_retry_success(self, mget):  # [v9:2] error 不粘滞
            body = b'{"exportedMediaSourceDataList":{"mediaSources":[]}}'
            mget.side_effect = [requests.exceptions.ConnectionError("flap"), self._resp(200, body)]
            with mock.patch.object(time, "sleep"):
                data, meta, _ = single_hop("https://raw.githubusercontent.com/a/b/main/x.json",
                                           None, time.monotonic() + 10)
            self.assertIsNotNone(data)
            self.assertIsNone(meta["error"])

        def test_touch_cache_refreshes_ts(self):  # [v9:7] 304 路径刷 ts，过期缓存复活
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
                c["ts"] = time.time() - (STALE_MAX_AGE_DAYS + 1) * 86400  # 人为拨到过期
                with open(p, "w", encoding="utf-8") as f:
                    json.dump(c, f)
                self.assertIsNone(load_cache(canon))
                touch_cache(canon)
                c2 = load_cache(canon)
                self.assertIsNotNone(c2)
                self.assertEqual(c2["data"], b'{"a":1}')
                self.assertEqual(c2["etag"], "x")  # 数据/校验器原样保留
            finally:
                globals()["CACHE_DIR"] = old
                shutil.rmtree(td, ignore_errors=True)

        def test_refs_without_path_rejected(self):  # [v9:6] refs 缺 path 段不误切
            self.assertIsNone(parse_github_raw("https://raw.githubusercontent.com/o/r/refs/heads/main"))
            self.assertIsNone(parse_github_com("https://github.com/o/r/raw/refs/heads/main"))
            self.assertIsNone(parse_github_com("https://github.com/o/r/blob/refs/tags/v1"))

    suite = unittest.defaultTestLoader.loadTestsFromTestCase(T)
    print(f"selftests: {suite.countTestCases()}")  # [14] 数量以运行结果为准
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
