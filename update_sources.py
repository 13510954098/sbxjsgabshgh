name: Update Animeko Sources

on:
  # 定时运行：每 6 小时一次（UTC）
  schedule:
    - cron: '0 */6 * * *'
  # 手动触发
  workflow_dispatch:
  # 推送脚本或链接文件时触发
  push:
    branches:
      - main
    paths:
      - 'update_sources.py'
      - 'all_animeko_links.txt'
      - '.github/workflows/update.yml'

# 最小权限：仅允许写入仓库内容用于提交产物
permissions:
  contents: write

# 防止并发运行导致的目录 swap 冲突
concurrency:
  group: update-sources
  cancel-in-progress: false

jobs:
  update:
    runs-on: ubuntu-latest
    timeout-minutes: 30

    steps:
      # 1) 检出仓库
      - name: Checkout repository
        uses: actions/checkout@v4
        with:
          fetch-depth: 1

      # 2) 安装 Python
      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'   # 脚本要求 3.10+

      # 3) 安装 Java（脚本用 java 校验正则；缺失会自动降级 Python，但装上更严格）
      - name: Set up Java
        uses: actions/setup-java@v4
        with:
          distribution: 'temurin'
          java-version: '21'

      # 4) 安装 Python 依赖
      - name: Install dependencies
        run: |
          python -m pip install --upgrade pip
          pip install "requests==2.32.5" packaging

      # 5) 运行内嵌自测（失败则中止，避免带病更新）
      - name: Run self-tests
        run: python update_sources.py --test

      # 6) 抓取并生成产物
      - name: Update sources
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}   # 提升 GitHub API 限额，减少 ref 回退
        run: python update_sources.py

      # 7) 校验产物（正则等），失败则中止提交
      - name: Validate outputs
        run: python update_sources.py --validate

      # 8) 提交变更（仅当 dist/ 有实际改动时）
      - name: Commit and push changes
        run: |
          git config --local user.name "github-actions[bot]"
          git config --local user.email "41898282+github-actions[bot]@users.noreply.github.com"

          # 只跟踪 dist/ 产物目录（cache/、reports/ 已被 .gitignore 忽略）
          git add dist/

          if git diff --cached --quiet; then
            echo "✅ 无变更，跳过提交"
          else
            git commit -m "chore: auto-update animeko sources $(date -u '+%Y-%m-%d %H:%M UTC')"
            git push
          fi

      # 9) 上传报告作为构建产物（便于排查，保留 7 天）
      - name: Upload report artifact
        if: always()   # 即使前面失败也上传，方便诊断
        uses: actions/upload-artifact@v4
        with:
          name: reports
          path: reports/
          retention-days: 7
