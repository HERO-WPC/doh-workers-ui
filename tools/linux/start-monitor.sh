#!/bin/bash
# DoH monitor 启动脚本 —— 与 Windows 的 tools/monitor-start.bat 等价。
#
# systemd 用它做 ExecStart; 也可以手动前台跑(此时 Ctrl+C 就是优雅退出)。
#
# 约定:
#   * 真实域名 / DoH 路径 / 面板路径 / zone id 全部来自 tools/.monitor.env,
#     不要写进这里的命令行(否则会进 git)。
#   * --monitor-domains / --ntprxx-domain 不传, 默认值就是 .monitor.env 里的。
#   * 改完参数要重启服务: sudo systemctl restart doh-monitor
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
cd "$REPO"

if [ ! -f tools/.monitor.env ]; then
    echo "[start-monitor] 缺少 tools/.monitor.env —— monitor.py 会拒绝启动" >&2
    echo "[start-monitor] 模板: tools/.monitor.env.example" >&2
    exit 1
fi

exec python3 tools/monitor.py \
    --count 8 \
    --interval 600 \
    --pool-interval 7200 \
    --itdog --itdog-top 35 --itdog-port 443 --itdog-weight 0.5 \
    --itdog-hours 5 --itdog-sleep 28 --itdog-max-age 48 \
    --upgrade-score-gain 3.0 --min-samples 24 --min-availability 90 \
    --min-serve-hours 4 --hysteresis 5.0 \
    --ntprxx-patrol --ntprxx-threshold 95 --ntprxx-hours 3 \
    --ntprxx-sleep 28 --ntprxx-keep 3
