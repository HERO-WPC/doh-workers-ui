# 恢复指南（仓库布局 · 快照 · 回滚 · 发布前检查）

> 本项目有**两个 git 仓库**，共用同一个工作区：
> - **主仓库 `.git`** → `origin` = GitHub `HERO-WPC/doh-workers-ui`（**会公开**）
> - **本地专属仓库 `.git-local`** → **无 remote，永不 push**（逆向工具 / 抓取产物 / 内部文档）

## 1. 两个仓库的分工

| 仓库 | 位置 | remote | 内容 |
|---|---|---|---|
| 主仓库 | `.git`（父目录） | GitHub `HERO-WPC/doh-workers-ui` | worker-doh 源码（`src/` `public/` `test/`）+ `tools/` 优选工具 + `docs/` |
| 本地专属 | `.git-local`（父目录） | **无** | `itdog/` `kkce/` `tcptest/` `tcping/` 逆向工具与逆向文档、根目录抓取产物、内部方案与开发记录 |

要点：

- `tools/` 现在**随主仓库一起公开**（以前是独立的不带 remote 的仓库）。
- 真实 DoH 域名 / DoH 路径 / 面板登录路径 / zone id **不在源码里**：它们只存在于被忽略的
  `tools/.monitor.env`，源码里是 `your-` 开头的占位符。`monitor.py`、`daily_test_dns.py`
  启动时会硬校验，占位符一律拒绝启动（它们是写 DNS 的进程）。
- 主仓库 `.gitignore` 把本地专属内容全部排除，所以 `git add -A` 不会误加它们。

## 2. 本地专属仓库怎么用

```powershell
tools\git-local.bat status                 # 本地专属内容的改动
tools\git-local.bat log --oneline
tools\git-local.bat add itdog              # 加白名单文件(包装脚本自动带 -f)
tools\git-local.bat commit -m "<说明>"
```

> 为什么必须带 `-f`：两个仓库共用一个工作区，git 只认工作区里的 `.gitignore`，
> 而主仓库已经把"不发布"的文件标成 ignored；ignore 只能加不能减，所以只能强制添加。
> **绝不要** `add -f .` 或 `add -f -A` —— 那会把 `tools/monitor.db`（38 MB）、
> `.cf-token`、`.monitor.env` 一起加进来。只加明确路径。

主仓库日常操作就是普通 git：

```powershell
git status
git add -A
git commit -m "<说明>"
```

## 3. 常用恢复操作

```powershell
# 历史
git log --oneline -- tools/monitor.py
git show 95796e3 --stat

# 单文件回滚
git checkout <提交或标签> -- tools/monitor.py

# 整体回滚（推荐 revert：生成反向提交，保留历史）
git revert HEAD

# 本地专属内容的回滚
tools\git-local.bat checkout HEAD~1 -- itdog/itdog_api.py
```

### 归档分支

`re-archive-20261001` 保存着"逆向工具还在主仓库里"的那 9 个提交（`1f14af0`）。
**它绝不能 push**（内容就是不想公开的那些）。`git push --all` / `--mirror` 会泄漏它 —— 只推 main：

```powershell
git push origin main        # 唯一安全的推送方式
```

## 4. 离线快照（bundle）：`.git` 被误删也能救回

```powershell
# 主仓库
git bundle create "D:\桌面\doh-workers-ui\tools\_diagnostics\snapshots\main-$(Get-Date -Format yyyyMMdd-HHmm).bundle" --all
git bundle verify <bundle>
git clone <bundle> main-restore

# 本地专属仓库（.git-local 没有 remote，快照就是唯一异地副本）
git --git-dir=.git-local --work-tree=. bundle create "D:\桌面\doh-workers-ui\tools\_diagnostics\snapshots\local-$(Get-Date -Format yyyyMMdd-HHmm).bundle" --all
```

已有快照（都放在被忽略的 `tools/_diagnostics/snapshots/`）：

| 快照 | 内容 |
|---|---|
| `main-repo-20261001-1609.bundle` | 主仓库完整历史（含拆分前的 9 个提交） |
| `tools-20261001-1609.bundle`、`tools-20261001-1623.bundle` | 旧 tools 独立仓库完整历史（含脱敏那次提交） |

> `tools/.git` 已按"并入主仓库"处理并删除，它的历史只存在于上面两个 tools bundle 里。

## 5. 数据与密钥：**不在 git 里，需单独备份**

| 文件 | 说明 |
|---|---|
| `tools/monitor.db`（38 MB） | 运行数据；`*.db` 已忽略。回滚用 `tools/monitor.db.bak-*`（**先停 monitor** 再覆盖） |
| `tools/.cf-token`、`tools/.cf-tunnel-token` | Cloudflare 凭据 |
| `.dev.vars`（父目录） | `CLOUDFLARE_API_TOKEN` 等 |
| `tools/monitor-token.txt` | 面板登录密钥（访问 `/<AUTH_PATH>` 用） |
| `tools/.monitor.env` | **部署标识**：DoH 域名 / DoH 路径 / 面板登录路径 / 监控域名 / zone id（模板 `.monitor.env.example`）。丢了它 monitor 会拒绝启动 |
| `tools/cloudflared.exe`（52 MB） | 二进制，已忽略 |

> 这些文件**只有本机一份**。要做到"整机可恢复"，需另行加密备份到别的介质。

## 6. 发布前检查（每次 push 前）

1. 只看公开内容：`git ls-tree --name-only HEAD` 应只有 worker-doh + `tools/`（无 `itdog/` `kkce/` `tcptest/` `tcping/`）。
2. 敏感串自查：把 `.git/hooks/pre-commit` 里的模式，外加 `tools/.monitor.env` 里的
   真实域名 / DoH 路径 / 面板路径，一起对着 `git diff --cached` 跑一遍。钩子只覆盖
   几类最常见的泄漏，**不会**自动发现"新写死的域名"，所以这步是人工兜底。
   （本文件刻意不写出这些真实值 —— 否则文档自己就成了泄漏源。）

3. 确认私有文件仍被忽略：`git check-ignore -v tools/.monitor.env tools/monitor.db tools/.cf-token`。
4. 推之前先跑测试：`node .\node_modules\vitest\vitest.mjs run`。

## 7. 改完脚本后的推荐动作

```powershell
node .\node_modules\vitest\vitest.mjs run          # 231 个用例
git add -A
git commit -m "<说明>"                              # pre-commit 钩子会拦真实域名/路径/密钥
git tag -a "stable-$(Get-Date -Format yyyy-MM-dd)" -m "<说明>"
git bundle create "D:\桌面\doh-workers-ui\tools\_diagnostics\snapshots\main-$(Get-Date -Format yyyyMMdd-HHmm).bundle" --all
```

改完 `monitor.py` 必须重启进程才生效（`tools\monitor-start.bat`；它就是按完整参数启动的脚本）：

```powershell
Stop-Process -Id (Get-CimInstance Win32_Process -Filter "Name='pythonw.exe'" | Where-Object { $_.CommandLine -like '*monitor.py*' }).ProcessId -Force
Start-Sleep 3
cmd /c "tools\monitor-start.bat"
# 验证: 8080 在听 / 命令行参数齐全 / monitor.log 无 "[env] 启动中止" 与 "依赖自检失败"
```

## 8. 启动 / 看门狗

- 启动：`tools\monitor-start.bat`（域名等参数来自 `tools/.monitor.env`，不在命令行里）
- 部署自检（不启动任何探测）：`python tools\monitor.py --check-env`
- 看门狗：计划任务 `doh-monitor-watchdog` 每 5 分钟检查一次；`tools\monitor-watchdog.ps1`
  - 维护时想故意停 monitor：建 `tools\.watchdog-pause`（删掉即恢复）
  - 日志：`tools\monitor-watchdog.log`
