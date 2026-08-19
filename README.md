# Animeko 聚合数据源（自动更新版）

抓取 `all_animeko_links.txt` 中的全部聚合源（去镜像后 77 个），解析、去重、择优排序后生成 Animeko 可订阅的 JSON，并通过 **GitHub Actions 每 4 小时自动更新**。

## 产物

| 文件 | 内容 | 数量 |
|---|---|---|
| `dist/all.json` | 在线 + BT（`factoryId,名称,URL` 去重，同名不同配置全保留） | 207 |
| `dist/online.json` / `dist/bt.json` | 按在线 / BT 拆分 | 189 / 18 |
| `dist/all-name.json` | 备选：按 `factoryId,名称` 去重（同名只留最优版） | 164 |
| `dist/online-name.json` / `dist/bt-name.json` | 按在线 / BT 拆分 | 148 / 16 |

排序（择优靠前）：来源优先级（MajoSissi 官方 dist → source → w658/creamycake → 知名三方 → 独立源 → fork）→ tier（0→1→2→3→4→未标记）→ 名称。

## 部署（约 2 分钟）

1. 在 GitHub 新建一个仓库（Public 即可），把本目录所有文件推上去：
   ```bash
   git init
   git add -A
   git commit -m "init"
   git branch -M main
   git remote add origin https://github.com/<你的用户名>/<仓库名>.git
   git push -u origin main
   ```
2. 打开仓库 **Actions** 页 → 确认 `Update Sources` 工作流已出现（首次推送会自动运行一次，也可点 **Run workflow** 手动触发）。
3. 等第一次运行完成后，订阅链接就用：
   ```
   https://raw.githubusercontent.com/<你的用户名>/<仓库名>/main/dist/all.json
   ```
   国内网络可在后面加加速前缀，例如：
   ```
   https://gh-proxy.com/https://raw.githubusercontent.com/<你的用户名>/<仓库名>/main/dist/all.json
   https://cdn.jsdelivr.net/gh/<你的用户名>/<仓库名>@main/dist/all.json
   ```
   > 注意：jsDelivr 有 CDN 缓存（约 12 小时），用 jsDelivr 链接的话更新会延迟；`raw.githubusercontent.com` 链接即时生效。

## 定时与手动

- 默认每 4 小时自动更新（`.github/workflows/update.yml` 里的 `cron` 可改，如 `0 */6 * * *` 为每 6 小时）。
- 想立即更新：仓库 Actions 页 → Update Sources → **Run workflow**。
- 想增删源：直接编辑 `all_animeko_links.txt`（新增一行一个链接，镜像会自动归组去重）→ 手动运行一次即可。

## 本地运行（可选）

不依赖 GitHub 也能用：装了 Python 3 + requests 后直接
```bash
pip install requests
python update_sources.py
```
脚本会实时抓取、重新生成 `dist/` 下的文件。用系统定时任务（cron / 计划任务）调度它即可。

## 更新日志

见根目录 `log` 文件（最近一次更新时间，UTC）。
