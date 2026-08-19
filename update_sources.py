#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Animeko 聚合源自动更新脚本
==========================
抓取 all_animeko_links.txt 里所有聚合源（镜像自动归组、坏链自动换镜像），
解析出数据源后按 (factoryId, 名称, 搜索URL) 去重，择优排序，生成：
    dist/all.json  dist/online.json  dist/bt.json          （全量：同名不同配置全保留）
    dist/all-name.json dist/online-name.json dist/bt-name.json （备选：同名只留最优）
输出文件可直接作为 Animeko 订阅链接。

可本地手动运行，也可由 .github/workflows/update.yml 定时自动运行。
"""
import json
import os
import re
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import requests
except ImportError:
    sys.exit("缺少依赖 requests：请先 `pip install requests`")

UA = [
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36",
    "curl/8.0",
]
TIMEOUT = 30
MAX_WORKERS = 12

ACCEL_PREFIXES = [
    "https://gh-proxy.com/", "https://v6.gh-proxy.org/", "https://cdn.gh-proxy.org/",
    "https://ghfast.top/", "https://ghproxy.net/", "https://gh.ddlc.top/",
    "https://ghproxy.cc/",
    # 以下前缀已失效（2026-08 实测，见 Animeko_所有链接整合_2026-08-17.txt），不再尝试：
    # "https://ghproxy.link/", "https://mirror.ghproxy.com/",
]

PRIO_NAMES = {0: "MajoSissi 官方 dist", 1: "MajoSissi 官方 source", 2: "w658/creamycake 官方聚合",
              3: "知名三方聚合", 4: "三方独立源", 5: "dist 镜像 fork"}


# ---------- URL 归一化：把各种镜像统一成 canonical 以便归组 ----------
def normalize(url: str) -> str:
    u = url.strip()
    changed = True
    while changed:
        changed = False
        for p in ACCEL_PREFIXES:
            if u.startswith(p):
                u = u[len(p):]
                u = u if u.startswith("http") else "https://" + u
                changed = True
    m = re.match(r"^https://github\.com/([^/]+/[^/]+)/raw/(.+)$", u)
    if m:
        return f"https://raw.githubusercontent.com/{m.group(1)}/{m.group(2)}"
    m = re.match(r"^https://cdn\.jsdelivr\.net/gh/([^/@]+/[^/@]+)@([^/]+)/(.+)$", u)
    if m:
        ref = m.group(2)
        if ref.startswith("refs/heads/"):
            ref = ref[len("refs/heads/"):]
        return f"https://raw.githubusercontent.com/{m.group(1)}/{ref}/{m.group(3)}"
    return u


# ---------- 来源优先级（官方优先，用于排序） ----------
def classify_priority(canon: str) -> int:
    u = canon
    if "MajoSissi/animeko-source/main/dist/" in u:
        return 0
    if "MajoSissi/animeko-source/main/source/" in u:
        return 1
    if u.startswith("https://gitee.com/w658/") or u.startswith("https://sub.creamycake.org/"):
        return 2
    for marker in ("CrazyBunQnQ/", "ZEN-GUO/", "LuckyRabbitFeet/", "saber-yz/", "761218728/"):
        if marker in u:
            return 3
    for marker in ("llimeslice/", "lklbjn/", "heibu01/", "lingjueding0726/",
                   "mophy-chun/", "2016YYy/", "becausemadoka/"):
        if marker in u:
            return 5
    return 4


FILE_ORDER = {"dist/all.json": 0, "dist/online.json": 1, "dist/bt.json": 2}


def file_order_key(canon: str) -> int:
    m = re.search(r"/dist/([^/]+\.json)$", canon)
    return FILE_ORDER.get(m.group(1), 3) if m else 3


# ---------- 解析 ----------
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
    a = m.get("arguments") or {}
    sc = a.get("searchConfig") or {}
    return sc.get("searchUrl") or sc.get("rssUrl") or a.get("rssUrl") or a.get("searchUrl") or ""


def tier_rank(t):
    try:
        return int(t)
    except (TypeError, ValueError):
        return 99


def load_json_bytes(data: bytes):
    for enc in ("utf-8-sig", "utf-8", "gbk"):
        try:
            return json.loads(data.decode(enc))
        except Exception:
            continue
    raise ValueError("无法解析 JSON")


# ---------- 抓取 ----------
def fetch_one(url: str):
    """逐个 UA 尝试，直到拿到 200 且非空。"""
    for ua in UA:
        try:
            r = requests.get(url, timeout=TIMEOUT, headers={"User-Agent": ua}, allow_redirects=True)
            if r.status_code == 200 and r.text.strip():
                return r.content
        except Exception:
            pass
    return None


def fetch_group(urls, retries: int = 2):
    """按顺序尝试一组镜像 URL；整组失败则等待后重试，最多 retries 轮。"""
    for attempt in range(retries):
        for u in urls:
            d = fetch_one(u)
            if d is not None:
                return d
        if attempt < retries - 1:
            time.sleep(1.5)
    return None


def read_links():
    """优先读 all_animeko_links.txt，缺失时用 canonical_links.json 兜底。"""
    for name in ("all_animeko_links.txt", "canonical_links.json"):
        if os.path.exists(name):
            with open(name, encoding="utf-8") as f:
                data = json.load(f) if name.endswith(".json") else [ln.strip() for ln in f]
            if data:
                return [ln for ln in data if ln]
    raise FileNotFoundError("缺少 all_animeko_links.txt / canonical_links.json")


# ---------- 主流程 ----------
def main():
    links = read_links()
    groups: dict[str, list[str]] = {}
    for ln in links:
        canon = normalize(ln)
        groups.setdefault(canon, [])
        if ln not in groups[canon]:
            groups[canon].append(ln)
    for k in groups:
        groups[k].sort(key=lambda u: (
            0 if "raw.githubusercontent.com" in u else
            1 if "cdn.jsdelivr.net" in u else 2))

    print(f"抓取 {len(groups)} 个唯一聚合源（共 {len(links)} 条链接）...")

    ok, failed = {}, {}
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        futs = {ex.submit(fetch_group, urls): canon for canon, urls in groups.items()}
        for fut in as_completed(futs):
            canon = futs[fut]
            data = fut.result()
            if data is not None:
                ok[canon] = data
            else:
                failed[canon] = groups[canon]

    print(f"成功 {len(ok)} / {len(groups)}" + (f"，失败 {len(failed)}: {list(failed)}" if failed else ""))

    ratio = len(ok) / max(len(groups), 1)
    if ratio < 0.5:
        sys.exit(f"成功率过低（{len(ok)}/{len(groups)}），为保护现有 dist 文件本次不更新")

    # ---------- 合并 ----------
    candidates = []
    for canon, data in ok.items():
        try:
            obj = load_json_bytes(data)
        except Exception:
            continue
        for m in extract(obj) or []:
            if not isinstance(m, dict):
                continue
            args = m.get("arguments")
            if not isinstance(args, dict) or not args.get("name"):
                continue
            fid = m.get("factoryId", "?")
            quality = (classify_priority(canon), tier_rank(args.get("tier")), file_order_key(canon))
            candidates.append((quality, (fid, args["name"], url_of(m)), m, canon))

    def enrich_channel_tiers(merged):
        """择优增强：对每个 (fid,名称,URL)，若存在核心搜索配置一致、且带【非空】channelTiers 的版本，则合并该字段。
        不新增条目、不改变名称/链接/选择器，只补 per-channel 质量分级。"""
        by_key = {}
        for q, k, m, canon in candidates:
            by_key.setdefault(k, []).append(m)
        for key, m in merged.items():
            args = m.get("arguments") or {}
            if "channelTiers" in args:
                continue
            sc = args.get("searchConfig") or {}
            core = {kk: v for kk, v in sc.items() if kk != "channelTiers"}
            for cand in by_key.get(key, []):
                ca = cand.get("arguments") or {}
                ct = ca.get("channelTiers")
                if not isinstance(ct, dict) or not ct:
                    continue
                if ca.get("name") != args.get("name"):
                    continue
                csc = ca.get("searchConfig") or {}
                ccore = {kk: v for kk, v in csc.items() if kk != "channelTiers"}
                if core == ccore:
                    args["channelTiers"] = ct
                    break
        return merged

    def merge_and_dump(mode):
        # mode: 'full' -> (fid,name,url) 全保留 ; 'name' -> (fid,name) 去重
        best, origin = {}, {}
        for q, k, m, canon in candidates:
            key = k if mode == "full" else (k[0], k[1])
            if key not in best or q < best[key]:
                best[key] = q
                origin[key] = canon
        merged = {}
        for q, k, m, canon in candidates:
            key = k if mode == "full" else (k[0], k[1])
            if key in best and q == best[key]:
                merged[key] = m
        if mode == "full":
            merged = enrich_channel_tiers(merged)
        # 排序规则（对齐 Animeko 官方 MediaSourceTier 语义，见 open-ani/animeko
        # MediaSelectorSourceTierSortTest：tier 0→1→未标记→2→3→4，默认偏好在线源在前、BT 殿后）:
        #   1) 类型: 在线(web-selector) 在前, BT(rss) 殿后
        #   2) tier: 0 → 1 → 未标记 → 2 → 3 → 4
        #   3) 来源优先级（官方优先）
        #   4) 名称、URL
        def tier_mid(t):
            if t is None:
                return 2
            return {0: 0, 1: 1, 2: 3, 3: 4, 4: 5}.get(int(t), 6)
        ordered = sorted(merged.items(), key=lambda it: (
            1 if it[1].get("factoryId") == "rss" else 0,
            tier_mid((it[1].get("arguments") or {}).get("tier")),
            classify_priority(origin[it[0]]),
            it[0][1] if mode == "name" else (it[0][1], it[0][2])))
        online = [m for k, m in ordered if k[0] != "rss"]
        bt = [m for k, m in ordered if k[0] == "rss"]
        tag = "" if mode == "full" else "-name"
        for ms_list, name in (([m for _, m in ordered], f"dist/all{tag}.json"),
                              (online, f"dist/online{tag}.json"),
                              (bt, f"dist/bt{tag}.json")):
            with open(name, "w", encoding="utf-8") as f:
                json.dump({"exportedMediaSourceDataList": {"mediaSources": ms_list}},
                          f, ensure_ascii=False, indent=2)
        return len(merged), len(online), len(bt)

    os.makedirs("dist", exist_ok=True)
    t_full = merge_and_dump("full")
    t_name = merge_and_dump("name")
    print(f"dist/all.json        = {t_full[0]} 个（在线 {t_full[1]} + BT {t_full[2]}）")
    print(f"dist/all-name.json   = {t_name[0]} 个（在线 {t_name[1]} + BT {t_name[2]}）")

    # 更新时间日志（照 MajoSissi 的 log 文件）
    with open("log", "w", encoding="utf-8") as f:
        f.write(time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()) + "\n")
    print("log 已更新")


if __name__ == "__main__":
    main()
