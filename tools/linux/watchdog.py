#!/usr/bin/env python3
"""DoH monitor 看门狗 —— Windows 版 tools/monitor-watchdog.ps1 的跨平台移植。

由 systemd timer 每 5 分钟调用一次(doh-monitor-watchdog.timer)。

判据(三级, 逐级更严):
  1) 进程: 有 `python3 ... monitor.py` 在跑吗
  2) 端口: 127.0.0.1:8080 能连上吗(等价于"在监听")
  3) 健康: 对 http://127.0.0.1:8080/ 发一次请求(未认证返回 401 也算"活着" = 服务在应答)

动作:
  * 无进程 且 无监听            -> systemctl start(兜底; 正常应由 systemd Restart= 负责)
  * 有进程 但 无监听/不响应      -> 记一次异常; 连续 3 次(约 15 分钟)才判定卡死:
                                   systemctl restart(卡死不会触发 Restart=on-failure)
  * 正常                        -> 清零异常计数

开关: tools/.watchdog-pause 存在则只记一行日志并跳过(维护用)。
日志: tools/monitor-watchdog.log(超 1MB 轮转为 .1)

需要 root(用 systemctl 控制 doh-monitor.service)—— unit 里已设 User=root。
"""
import os
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
TOOLS = os.path.join(REPO, "tools")
LOG = os.path.join(TOOLS, "monitor-watchdog.log")
COUNT = os.path.join(TOOLS, ".watchdog-badcount")
PAUSE = os.path.join(TOOLS, ".watchdog-pause")
SERVICE = "doh-monitor.service"
HOST, PORT = "127.0.0.1", 8080


def log(msg):
    line = "%s %s" % (time.strftime("%m-%d %H:%M:%S"), msg)
    try:
        if os.path.exists(LOG) and os.path.getsize(LOG) > 1024 * 1024:
            os.replace(LOG, LOG + ".1")
        with open(LOG, "a", encoding="utf-8") as fh:
            fh.write(line + "\n")
    except OSError:
        pass
    print(line, flush=True)


def monitor_procs():
    """返回 monitor.py 进程的 PID 列表(排除本脚本自身)。"""
    try:
        out = subprocess.run(["pgrep", "-f", r"monitor\.py"],
                             capture_output=True, text=True, timeout=10).stdout
    except (OSError, subprocess.SubprocessError):
        return []
    pids = []
    for s in out.split():
        try:
            pids.append(int(s))
        except ValueError:
            pass
    return [p for p in pids if p != os.getpid()]


def port_open():
    try:
        with socket.create_connection((HOST, PORT), timeout=4):
            return True
    except OSError:
        return False


def health_ok():
    """拿到 HTTP 应答(含 401)就算活着。"""
    try:
        urllib.request.urlopen("http://%s:%d/" % (HOST, PORT), timeout=6)
        return True
    except urllib.error.HTTPError:
        return True
    except Exception:
        return False


def systemctl(action):
    try:
        r = subprocess.run(["systemctl", action, SERVICE], capture_output=True,
                           text=True, timeout=60)
        if r.returncode != 0:
            log("  systemctl %s 失败: %s" % (action, (r.stderr or r.stdout).strip()[:200]))
        return r.returncode == 0
    except (OSError, subprocess.SubprocessError) as e:
        log("  systemctl %s 异常: %s" % (action, e))
        return False


def main():
    if os.path.exists(PAUSE):
        log("已暂停(存在 .watchdog-pause), 跳过本次检查")
        return 0

    pids = monitor_procs()
    listen = port_open()
    alive = health_ok() if listen else False

    if pids and listen and alive:
        if os.path.exists(COUNT):
            os.remove(COUNT)
        log("正常: monitor 在跑 (PID %s), 8080 监听且应答" % ",".join(map(str, pids)))
        return 0

    if not pids and not listen:
        log("唤醒: 拉起 monitor (无进程且 8080 未监听)")
        systemctl("start")
        return 0

    bad = 0
    if os.path.exists(COUNT):
        try:
            bad = int(open(COUNT, encoding="utf-8").read().strip() or 0)
        except (OSError, ValueError):
            bad = 0
    bad += 1
    try:
        with open(COUNT, "w", encoding="utf-8") as fh:
            fh.write(str(bad))
    except OSError:
        pass
    log("异常第 %d 次: 进程 %d 个, 8080 监听=%s, 健康=%s" % (bad, len(pids), listen, alive))

    if bad >= 3:
        log("连续 3 次异常 -> 判定卡死, 重启服务")
        systemctl("restart")
        try:
            os.remove(COUNT)
        except OSError:
            pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
