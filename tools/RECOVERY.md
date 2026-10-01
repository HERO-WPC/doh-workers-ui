# 恢复指南（git 配置 · 快照 · 回滚）

> `tools/` 是**独立的纯本地 git 仓库**，刻意不配置 remote。
> 原因见 `.gitignore` 顶部：`monitor.py` 的 argparse 默认值里含**真实 DoH 域名 / DoH 路径 / 面板登录路径**，
> 在公开仓库里等同凭据；要发布必须先脱敏（把这些值移到被忽略的配置文件，源码只留占位符）。

## 1. 两个仓库的分工

| 仓库 | 位置 | remote | 内容 |
|---|---|---|---|
| 主仓库 | `.git`（父目录） | `origin` = GitHub `HERO-WPC/doh-workers-ui` | Worker/面板源码（`src/` `public/` `test/`）、逆向文档（`itdog/` `tcptest/` `kkce/`） |
| tools 仓库 | `tools/.git` | **无（纯本地）** | 生产脚本：`monitor.py`、`daily_test_dns.py`、`monitor-start.bat`、`monitor-watchdog.ps1`、`*.mjs` |

`tools/` 被主仓库 `.gitignore` 忽略，所以两者不会互相干扰。

## 2. 常用恢复操作

```powershell
# 历史
git -C tools log --oneline
git -C tools show a399014 --stat          # 某次提交改了什么
git -C tools diff HEAD~1 -- monitor.py

# 单文件回滚到某个提交/标签
git -C tools checkout stable-2026-10-01 -- monitor.py

# 整体回滚（推荐用 revert：生成反向提交，保留历史）
git -C tools revert HEAD
# 危险操作（丢弃之后的提交，仅在明确知道后果时用）
# git -C tools reset --hard HEAD~1
```

## 3. 离线快照（bundle）：`.git` 被误删也能救回

```powershell
# 生成（已放在被忽略的 _diagnostics/snapshots/ 下）
git -C tools bundle create "D:\桌面\doh-workers-ui\tools\_diagnostics\snapshots\tools-$(Get-Date -Format yyyyMMdd-HHmm).bundle" --all

# 校验 / 从快照恢复出完整仓库
git -C tools bundle verify <bundle 路径>
git clone <bundle 路径> tools-restore
```

## 4. 数据与密钥：**不在 git 里，需单独备份**

| 文件 | 说明 |
|---|---|
| `tools/monitor.db`（38 MB） | 运行数据；`*.db` 已忽略。回滚用 `tools/monitor.db.bak-*`（**先停 monitor** 再覆盖） |
| `tools/.cf-token`、`tools/.cf-tunnel-token` | Cloudflare 凭据 |
| `.dev.vars`（父目录） | `CLOUDFLARE_API_TOKEN` 等 |
| `tools/monitor-token.txt` | 面板登录密钥（访问 `/<AUTH_PATH>` 用） |
| `tools/.monitor.env` | **部署标识**：DoH 域名 / DoH 路径 / 面板登录路径 / 监控域名 / zone id。源码里只有 `your-` 占位符，真实值只在这里（模板 `.monitor.env.example`）。丢了这个文件 monitor 会拒绝启动（防写错 DNS） |
| `tools/cloudflared.exe`（52 MB） | 二进制，已忽略 |

> 这些文件**只有本机一份**。要做到"整机可恢复"，需另行加密备份到别的介质。

## 5. 改完生产脚本后的推荐动作

```powershell
git -C tools add -A
git -C tools commit -m "<说明>"
git -C tools tag -a "stable-$(Get-Date -Format yyyy-MM-dd)" -m "<说明>"
git -C tools bundle create "D:\桌面\doh-workers-ui\tools\_diagnostics\snapshots\tools-$(Get-Date -Format yyyyMMdd-HHmm).bundle" --all
```

## 6. 启动 / 看门狗（与恢复相关的运维修正）

- 启动：`tools\monitor-start.bat`（参数已补全，含 `--ntprxx-patrol`）
- 看门狗：计划任务 `doh-monitor-watchdog` 每 5 分钟检查一次；`tools\monitor-watchdog.ps1`
  - 维护时想故意停 monitor：建 `tools\.watchdog-pause`（删掉即恢复）
  - 日志：`tools\monitor-watchdog.log`
