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
  - **不弹窗**：任务是 `wscript.exe //B tools\monitor-watchdog-hidden.vbs`，由 VBS 以
    窗口样式 0 拉起 powershell。原先任务直接跑 `powershell.exe -File ...`，而任务
    是 InteractiveToken（用户会话内），于是每 5 分钟闪一个控制台窗口。
    改任务动作的方法（导出的 XML 是 UTF-8，写回用 UTF-16）：

    ```powershell
    cmd /c "schtasks /query /tn doh-monitor-watchdog /xml > $env:TEMP\wd.xml"
    # 把 <Command> 改成 wscript.exe，<Arguments> 改成 //B "…\monitor-watchdog-hidden.vbs"
    schtasks /create /tn doh-monitor-watchdog /xml $env:TEMP\wd-new.xml /f
    ```
  - 缺 `tools/.monitor.env` 时看门狗会记一行原因并**拒绝拉起**（避免每 5 分钟空转失败）。

## 9. Linux（Arch）部署 —— 2026-10-07 已实际迁移过一次

`monitor.py` 本身没有任何 Windows 调用，跨平台；要换的只是"运维外壳"。

### 9.1 现役部署（Arch 备机：`<备机 IP>`，用户 `<用户名>`，仓库 `~/doh-workers-ui`）

| 组件 | 位置 | 说明 |
|---|---|---|
| monitor 服务 | `/etc/systemd/system/doh-monitor.service` | `User=<用户名>`，`ExecStart=tools/linux/start-monitor.sh`；`Restart=on-failure`；**`KillSignal=SIGINT`**（走 Ctrl+C 路径 → 正常关闭并合并 SQLite WAL） |
| 看门狗 | `doh-monitor-watchdog.service` + `.timer` | 每 5 分钟跑 `tools/linux/watchdog.py`（**User=root**，因为要 `systemctl restart`）；逻辑与 Windows 的 ps1 一致：进程/端口/HTTP 三级判据，连续 3 次异常才重启 |
| 隧道 | `/etc/systemd/system/cloudflared.service` | `cloudflared service install <token>`，token 取自 `tools/.cf-tunnel-token`；对外域名 `<面板域名>`（隧道 CNAME，见 CF zone） |
| 启动参数 | `tools/linux/start-monitor.sh` | 等价于 Windows 的 `monitor-start.bat`（真实域名等仍在 `tools/.monitor.env`，不在命令行） |

安装 / 卸载：

```bash
bash tools/linux/install.sh              # 装单元 + 开机自启（需要 sudo，会提示密码）
bash tools/linux/install.sh --no-start   # 只装文件
bash tools/linux/install.sh --uninstall
# SSH 里没有 TTY 时用: SUDO_PW='...' bash tools/linux/install.sh

sudo systemctl restart doh-monitor        # 改完 start-monitor.sh 后
journalctl -u doh-monitor -f              # 实时日志(也可以 tail -f tools/monitor.log)
systemctl list-timers doh-monitor-watchdog.timer
```

### 9.2 从 Windows 搬一台新机器（本次实操过的流程）

1. **先停旧的 monitor**，否则两边会抢同一批 DNS A 记录：
   ```powershell
   Stop-Process -Id <monitor PID> -Force
   schtasks /change /tn doh-monitor-watchdog /disable      # 否则 5 分钟后又被拉起
   ```
2. **合并 SQLite WAL**（强杀进程后遗留，直接拷会不一致；也可拷 `.db` + `-wal` + `-shm` 三个一起）：
   ```powershell
   python -c "import sqlite3;c=sqlite3.connect(r'tools\monitor.db');print(c.execute('PRAGMA wal_checkpoint(TRUNCATE)').fetchone());c.execute('PRAGMA journal_mode=DELETE');c.close()"
   ```
3. **打包**（`node_modules` / `cloudflared.exe` / db 备份 / `.tmp` / 测试抓包都不必带）：
   ```powershell
   cd D:\桌面
   tar -czf doh-migrate.tgz `
     --exclude=doh-workers-ui/node_modules --exclude=doh-workers-ui/.wrangler `
     --exclude=doh-workers-ui/.tmp --exclude=doh-workers-ui/tools/cloudflared.exe `
     --exclude=doh-workers-ui/tools/monitor.db.bak-* --exclude=doh-workers-ui/tools/monitor-stdout.log `
     --exclude=doh-workers-ui/kkce/saved/mtr-*.json --exclude=*/__pycache__ doh-workers-ui
   ```
   → 实测 27 MB（完整目录 642 MB，其中 node_modules 227 MB、cloudflared.exe 52 MB）。
4. **传过去解包**（`scp`/SFTP 均可），然后：
   ```bash
   cd ~/doh-workers-ui
   git checkout -- .            # 消掉 CRLF/LF 噪声(根目录没有 .gitattributes, 只有 tools/ 有)
   python3 tools/monitor.py --check-env        # 私有配置自检, 必须先过
   SUDO_PW='...' bash tools/linux/install.sh   # 装服务
   ```
5. **隧道**：`sudo cloudflared service install "$(cat tools/.cf-tunnel-token)"`，然后
   `curl "https://<面板域名>/api/best?n=1&key=$(cat tools/monitor-token.txt)"`
   看返回的 `pid` 是不是新机器上的 monitor PID。
6. **退役旧机器**（管理员 PowerShell）：
   ```powershell
   Stop-Service Cloudflared -Force; Set-Service Cloudflared -StartupType Disabled
   # 本机 monitor 保持停止 + doh-monitor-watchdog 保持 Disabled
   ```

### 9.3 换机时容易踩的坑

- **`.git-local` 没有 remote**：只 clone GitHub 会丢掉 itdog/kkce/tcptest/tcping 和内部文档 →
  用 `git bundle` 或整目录打包带走（全量 tar 天然包含它）。
- **`tools/.proxy`**：Windows 上指向本机 SOCKS5（`127.0.0.1:10808`）作 CF API 回落。
  新机器没有这个代理就把文件改名（`tools/.proxy.from-windows`）留档；`monitor.py` 与
  `daily_test_dns.py` 都是"**直连优先，配了代理才回落**"，没代理也能跑。
- **`cloudflared.exe` 不能带走**：Arch 上 `pacman -S cloudflared`（本次实测已预装）。
- **`node_modules` 不能带走**：含 Windows 原生二进制，`npm i` 重装。
- **Python 依赖只有 `websockets`**（Arch: `pacman -S python-websockets`），其余全是标准库；
  语法只需 3.8+。
- **别两边同时跑 monitor**（同一域名 A 记录会被互相覆盖）；也**别让两个 cloudflared 连接器
  指向不同后端**（一个转发到已停的 8080 会导致面板时好时坏）。
