#!/bin/bash
# 安装 DoH monitor 的 systemd 单元(tools/linux/*.service|*.timer -> /etc/systemd/system)。
#
# 用法:
#   bash tools/linux/install.sh            # 安装 + 开机自启
#   bash tools/linux/install.sh --no-start # 只安装文件, 不启动
#   bash tools/linux/install.sh --uninstall
#
# 单元里的 @REPO@ / @USER@ 会在安装时替换成本机实际路径与用户
# (需要 sudo —— 会提示输入密码)。
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
RUN_USER="${SUDO_USER:-$(id -un)}"
UNIT_DIR=/etc/systemd/system
UNITS=(doh-monitor.service doh-monitor-watchdog.service doh-monitor-watchdog.timer)

# sudo 助手: 交互式会正常提示; 非交互(SSH 无 TTY)时用 SUDO_PW 环境变量喂密码。
#   例: SUDO_PW='...' bash tools/linux/install.sh
run_sudo() {
    if [ -n "${SUDO_PW:-}" ]; then
        echo "$SUDO_PW" | sudo -S -p '' "$@"
    else
        sudo "$@"
    fi
}

if [ ! -f "$REPO/tools/.monitor.env" ]; then
    echo "!! 缺少 $REPO/tools/.monitor.env —— 先按 tools/.monitor.env.example 建好" >&2
    exit 1
fi

if [ "${1:-}" = "--uninstall" ]; then
    for u in "${UNITS[@]}"; do
        run_sudo systemctl disable --now "$u" 2>/dev/null || true
        run_sudo rm -f "$UNIT_DIR/$u"
        echo "  已移除 $UNIT_DIR/$u"
    done
    run_sudo systemctl daemon-reload
    echo "卸载完成(monitor.db / .monitor.env / 密钥不受影响)"
    exit 0
fi

echo "安装目标: REPO=$REPO USER=$RUN_USER"
for u in "${UNITS[@]}"; do
    tmp="$(mktemp)"
    sed -e "s|@REPO@|$REPO|g" -e "s|@USER@|$RUN_USER|g" "$HERE/$u" > "$tmp"
    run_sudo install -m 0644 "$tmp" "$UNIT_DIR/$u"
    rm -f "$tmp"
    echo "  已安装 $UNIT_DIR/$u"
done
chmod +x "$HERE/start-monitor.sh" "$HERE/watchdog.py" 2>/dev/null || true

run_sudo systemctl daemon-reload

if [ "${1:-}" = "--no-start" ]; then
    echo "已安装(未启动)。手动: sudo systemctl start doh-monitor"
    exit 0
fi

run_sudo systemctl enable --now doh-monitor.service
run_sudo systemctl enable --now doh-monitor-watchdog.timer
sleep 3
echo
echo "=== 状态 ==="
systemctl --no-pager --lines=0 status doh-monitor.service | head -6 || true
systemctl --no-pager list-timers doh-monitor-watchdog.timer --all | head -3 || true
echo
echo "看日志: journalctl -u doh-monitor -f      或   tail -f tools/monitor.log"
