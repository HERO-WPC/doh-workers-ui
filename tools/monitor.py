#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
优选 IP 在线率监控服务(Windows 本机 · 纯监控展示 + 失效自动换 IP)。

功能:
- 每隔 --interval 秒(默认 600)对 IP 池(tools/ips-latest.csv)做一轮真实 DoH 探测
  (每 IP 同时记录:TCP 握手耗时、端到端总耗时)
- 🌐 域名整体探针:每轮额外走一次系统 DNS 解析的真实用户路径
- 历史数据存 SQLite(保留 30 天),WebUI 展示在线率/延迟曲线
- DNS 中某 IP 连续失败 ≥2 轮 → 自动测候选池 → 经 CF API 换新 IP
- 每 --sweep-hours 小时对整个候选文件做一次全量复测并刷新 DNS

纯标准库,无第三方依赖。直连探测与 API 访问,不走系统代理。
"""

import argparse
import base64
import contextlib
import hmac
import http.client
import json
import os
import re
import secrets
import socket
import sqlite3
import sys
import ssl
import threading
import time
import urllib.parse
import urllib.request
import concurrent.futures
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# ---------------------------------------------------------------------------
# 配置
# ---------------------------------------------------------------------------

BASE = os.path.dirname(os.path.abspath(__file__))

# ---------------------------------------------------------------------------
# 本地私有部署标识:真实 DoH 域名 / DoH 路径 / 面板登录路径 / 被监控域名
# 一律不写进源码 —— 它们在公开仓库里等同于凭据。真实值放 tools/.monitor.env
# (已 gitignore),源码里只有 "your-" 开头的占位符。
#
# 注意:占位符只是为了让 --help / --dry-run 之类能跑起来;真正启动前有硬校验
# (见下面 _env_guard),占位值一律拒绝启动 —— 本进程会写 DNS,用错域名不可逆。
# ---------------------------------------------------------------------------

_ENV_PATH = os.path.join(BASE, ".monitor.env")
_PLACEHOLDER = "your-"          # 所有占位符统一前缀,便于校验与人工识别
ENV = {}


def _load_env(path):
    """读 KEY=VALUE 形式的本地配置文件;文件不存在/无权限时返回空 dict。"""
    data = {}
    try:
        with open(path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                data[k.strip()] = v.strip().strip('"').strip("'")
    except OSError:
        pass
    return data


ENV = _load_env(_ENV_PATH)


def env(key, fallback):
    """取本地私有配置(也可用同名环境变量覆盖);都没有则用占位符。"""
    return os.environ.get(key) or ENV.get(key) or fallback


def _is_placeholder(val):
    """空值, 或以 your- 开头的占位符(路径类占位符前面带 /, 故先剥掉 /)。"""
    s = str(val or "").strip()
    if not s:
        return True
    return s.lstrip("/").startswith(_PLACEHOLDER)


# ---------------------------------------------------------------------------
# 安全日志:pythonw 下 stdout 为 None、或父进程管道关闭后写入会抛 Broken pipe。
# 直接 print 会杀死探测线程(曾导致探测静默停止),故统一走 log():
# 始终落盘 tools/monitor.log,同时尽力输出到 stdout。
# ---------------------------------------------------------------------------

_LOG_PATH = os.path.join(BASE, "monitor.log")
_log_fh = None

def _log_file():
    global _log_fh
    if _log_fh is None:
        try:
            if os.path.exists(_LOG_PATH) and os.path.getsize(_LOG_PATH) > 2 * 1024 * 1024:
                os.replace(_LOG_PATH, _LOG_PATH + ".1")
            _log_fh = open(_LOG_PATH, "a", buffering=1, encoding="utf-8")
        except OSError:
            _log_fh = False
    return _log_fh

def log(*args):
    msg = " ".join(str(a) for a in args)
    try:
        sys.stdout.write(msg + chr(10))
        sys.stdout.flush()
    except Exception:
        pass
    fh = _log_file()
    if fh:
        try:
            fh.write(datetime.now().strftime("%m-%d %H:%M:%S") + " " + msg + chr(10))
        except Exception:
            pass

AP = argparse.ArgumentParser(description="优选 IP 在线率监控")
AP.add_argument("--interval", type=int, default=600, help="高频探测间隔秒:域名端到端 + DNS 在线 IP(默认 600,10 分钟)")
AP.add_argument("--pool-interval", type=int, default=7200, help="池内全部 IP 探测间隔秒(默认 7200,2 小时;域名失效时立即触发一次)")
AP.add_argument("--upgrade-score-gain", type=float, default=3.0,
                help="择优替换的评分差阈值:候选评分须比 DNS 最差者高这么多分才替换(默认 3.0)")
AP.add_argument("--port", type=int, default=8080, help="Web 端口(默认 8080)")
AP.add_argument("--host", default="0.0.0.0", help="Web 监听地址")
AP.add_argument("--pool", default=os.path.join(BASE, "ips-latest.csv"), help="IP 池文件")
AP.add_argument("--db", default=os.path.join(BASE, "monitor.db"), help="SQLite 文件")
AP.add_argument("--timeout", type=int, default=5000, help="单次探测超时毫秒")
AP.add_argument("--doh-host", default=env("DOH_HOST", "your-doh-domain.example"),
                help="DoH 域名(默认取 tools/.monitor.env 的 DOH_HOST)")
AP.add_argument("--doh-path", default=env("DOH_PATH", "/your-doh-path/dns-query"),
                help="DoH 路径(默认取 tools/.monitor.env 的 DOH_PATH)")
AP.add_argument("--no-auto-sync", action="store_true", help="关闭自动换 IP(默认开)")
AP.add_argument("--count", type=int, default=5, help="DNS 保持的 A 记录数(默认 5)")
AP.add_argument("--fail-threshold", type=int, default=2, help="DNS 中 IP 连续失败 N 轮才换(默认 2)")
AP.add_argument("--candidates", default=os.path.join(BASE, "ips-candidates.txt"), help="候选 IP 文件(换 IP 时才测活)")
AP.add_argument("--sweep-hours", type=float, default=8, help="全量复测间隔小时(0=关闭,默认 8)")
AP.add_argument("--auth-path", default=env("AUTH_PATH", "your-auth-path"),
                help="面板登录路径(访问 /<路径> 即种 Cookie 进入;越难猜越安全;"
                     "默认取 tools/.monitor.env 的 AUTH_PATH)")
AP.add_argument("--peer-health-url", default="",
                help="对端(主机)健康检查 URL;可访问时本机让出 DNS 写权(双机热备防冲突)。备份机上配置。")

# ---- itdog 全国评测(可选) ----
AP.add_argument("--itdog", action="store_true",
                help="启用 itdog 全国(305节点) TCP 评测,与本地评分融合(需 pip install websockets;默认关)")
AP.add_argument("--itdog-top", type=int, default=35,
                help="itdog 评测的 top N 个 IP(从可用池按本地评分取前 N,默认 35)")
AP.add_argument("--itdog-hours", type=float, default=24,
                help="itdog 评测周期(小时,默认 24;0=只跑一次后停)")
AP.add_argument("--itdog-sleep", type=float, default=28,
                help="itdog 任务间节流秒(防频率风控,默认 28)")
AP.add_argument("--itdog-break-after", type=int, default=3,
                help="itdog 连续被拦(验证码/可疑任务)多少次后, 本轮剩余 IP 直接走回退源(默认 3)")
AP.add_argument("--itdog-min-nodes", type=int, default=100,
                help="itdog 返回的 check_node_num 低于此值视为被拦(实测被拦时只给 39 个节点且不推结果), 直接跳过 WS")
AP.add_argument("--itdog-weight", type=float, default=0.5,
                help="itdog 分在综合评分中的权重(0=全本机, 1=全 itdog, 默认 0.5)")
AP.add_argument("--itdog-port", type=int, default=443, help="itdog tcping 端口(默认 443)")
AP.add_argument("--itdog-rankfile", default=os.path.join(BASE, "itdog-rank.json"),
                help="itdog 综合评分排行输出文件(默认 tools/itdog-rank.json)")
AP.add_argument("--itdog-max-age", type=float, default=48,
                help="itdog 全国数据最大有效小时数(默认 48);过后按线性衰减 freshness")

# ---- 评分分层/资格/防抖 ----
AP.add_argument("--min-samples", type=int, default=24,
                help="主动升级所需 24h 样本数(默认 24;样本不足无升级资格)")
AP.add_argument("--min-availability", type=float, default=90.0,
                help="主动升级所需 24h 在线率下限(百分比,默认 90)")
AP.add_argument("--min-serve-hours", type=float, default=4,
                help="当前 DNS IP 最短服役小时数,期间不被主动择优替换(默认 4;死亡替换不受限)")
AP.add_argument("--hysteresis", type=float, default=5.0,
                help="防抖加码:候选若是 2 小时内刚被撤下的 IP(见 FLAP_WINDOW), 换回门槛额外加这么多分(默认 5)")
AP.add_argument("--monitor-domains", default=env("MONITOR_DOMAINS", "your-domain.example"),
                help="域名监控列表, 逗号分隔(默认取 tools/.monitor.env 的 MONITOR_DOMAINS); "
                     "每 --interval 检测一次域名端到端 + 全国 itdog")

# ---- 反代 IP 巡检(独立于上面 DoH 主域的 DNS) ----
AP.add_argument("--ntprxx-patrol", action="store_true",
                help="启用反代域名的 A 记录巡检: 任一 IP 全国连通率低于 --ntprxx-threshold 就从池内 itdog 最优候选替换(默认关)")
AP.add_argument("--ntprxx-domain", default=env("NTPRXX_DOMAIN", "your-domain.example"),
                help="巡检域名(默认取 tools/.monitor.env 的 NTPRXX_DOMAIN)")
AP.add_argument("--ntprxx-zone", default=env("CF_ZONE_ID", ""),
                help="该域名所在 zone id(默认取 tools/.monitor.env 的 CF_ZONE_ID;留空=按域名自动匹配 token 可见的 zone)")
AP.add_argument("--ntprxx-threshold", type=float, default=95.0,
                help="全国连通率低于此值判为问题 IP 并替换(默认 95)")
AP.add_argument("--ntprxx-hours", type=float, default=3.0,
                help="巡检周期小时(默认 3; 0=只在启动后跑一次)")
AP.add_argument("--ntprxx-sleep", type=float, default=28.0,
                help="逐个 IP 之间的节流秒(默认 28, 防 itdog 频率风控)")
AP.add_argument("--ntprxx-keep", type=int, default=3, help="保持的 A 记录条数(默认 3)")
AP.add_argument("--ntprxx-align", action="store_true",
                help="启动先做一次'对齐 itdog 最优 N 个'(即使当前 IP 全健康, 也按 itdog 分整体重选)")
AP.add_argument("--ntprxx-dry-run", action="store_true", help="只检测/只打印计划, 不写 DNS")
AP.add_argument("--check-env", action="store_true",
                help="只打印私有配置(tools/.monitor.env)的解析结果并退出, 不会启动探测/服务(部署前自检)")

ARGS = AP.parse_args()


def _env_guard():
    """启动硬校验:涉及 DNS 写入 / 面板身份的参数不允许还是占位符。

    本进程会写真实 DNS 记录。一旦带着占位域名或占位面板路径跑起来,后果不可逆
    (改错别人的域名、面板入口退化成可猜),所以宁可拒绝启动,也不要"带病运行"。
    """
    bad = []
    # ① 核心身份:空 与 占位符 都拒绝
    for opt, val, key in (("--doh-host", ARGS.doh_host, "DOH_HOST"),
                          ("--doh-path", ARGS.doh_path, "DOH_PATH"),
                          ("--auth-path", ARGS.auth_path, "AUTH_PATH")):
        if _is_placeholder(val):
            bad.append((opt, key))
    # ② 域名监控:显式留空 = 明确关闭(允许);占位符 = 配置没填(拒绝)
    if str(ARGS.monitor_domains or "").strip() and _is_placeholder(ARGS.monitor_domains):
        bad.append(("--monitor-domains", "MONITOR_DOMAINS"))
    # ③ 反代巡检域名:只在启用巡检时要求
    if ARGS.ntprxx_patrol and _is_placeholder(ARGS.ntprxx_domain):
        bad.append(("--ntprxx-domain", "NTPRXX_DOMAIN"))

    if not bad:
        return
    log("[env] !! 启动中止: 下列参数仍是占位符或为空, 拒绝启动(本进程会写 DNS)")
    for opt, key in bad:
        log(f"[env]    {opt}  <- 请在 .monitor.env 里设置 {key}=<真实值>")
    if not os.path.exists(_ENV_PATH):
        log(f"[env] !! 配置文件不存在: {_ENV_PATH}")
        log("[env]    模板见 tools/.monitor.env.example")
    log("[env] 真实域名/DoH 路径/面板路径 等同凭据, 不要写回源码或提交进仓库。")
    sys.exit(1)


_env_guard()

# ---- 部署自检: 打印私有配置解析结果后退出(不启动任何探测/服务/线程) ----
if ARGS.check_env:
    log(f"[env] 配置文件: {_ENV_PATH} " + ("(存在)" if os.path.exists(_ENV_PATH) else "(不存在)"))
    for _k in ("DOH_HOST", "DOH_PATH", "AUTH_PATH", "MONITOR_DOMAINS",
               "NTPRXX_DOMAIN", "CF_ZONE_ID"):
        _v = ENV.get(_k)
        log(f"[env]   {_k} = " + (_v if _v else "<空>")
            + "  [" + ("来自配置文件" if _v else "未设置") + "]")
    log(f"[env] 解析结果: DoH = https://{ARGS.doh_host}{ARGS.doh_path}")
    log(f"[env]           面板入口 = /{ARGS.auth_path.strip('/')}")
    log(f"[env]           监控域名 = {ARGS.monitor_domains or '<已关闭>'}")
    log(f"[env]           巡检域名 = {ARGS.ntprxx_domain} (patrol="
        f"{'on' if ARGS.ntprxx_patrol else 'off'}, zone={ARGS.ntprxx_zone or '<自动匹配>'})")
    sys.exit(0)

# itdog 第三方库 websockets 可用性(拿到 ARGS 后判定真正开关)
try:
    import websockets  # noqa: F401
    _HAS_WS = True
except Exception:
    _HAS_WS = False
ITDOG_ENABLED = bool(ARGS.itdog and _HAS_WS)
# itdog 客户端依赖自检结果(仅 main() 启动时可写): 非 None 表示 itdog/ 目录缺失或
# itdog_api.py 不可导入。用于面板明确告警, 避免"线程在跑、每 24h 只留一行异常日志、
# 页面照旧显示历史数据"的静默瘫痪。
_ITDOG_LOAD_ERROR = None
if ARGS.itdog and not _HAS_WS:
    print("[itdog] --itdog 已指定但未安装 websockets,功能未启用(pip install websockets)",
          file=sys.stderr)

DOH_HOST = ARGS.doh_host
DOH_PATH = ARGS.doh_path
DNS_NAME = DOH_HOST
# 全部 IP 失效时的 CNAME 兜底目标(公共 CF 优选域名,恢复后自动切回 A 记录)
FALLBACK_CNAME = "cf.877774.xyz"
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/152.0.0.0 Safari/537.36")

# 预编码 DoH 查询:example.com A(TXID 0x1a2b, RD=1)
DOH_QUERY = bytes.fromhex("1a2b" + "0100" + "0001" + "0000" + "0000" + "0000" +
                          "07" + "6578616d706c65" + "03" + "636f6d" + "00" +
                          "0001" + "0001")

TLS_CTX = ssl.create_default_context()

DAY = 86400
DOMAIN_LABEL = "域名整体(端到端)"
RETENTION_DAYS = 30
LIVE_POOL_MAX = 60
UPGRADE_COOLDOWN = 600      # 择优替换最小间隔(秒):每轮(10 分钟)最多换 1 个
FLAP_WINDOW = 7200          # "刚撤下的 IP 不许立刻换回"的防抖窗口(秒,2 小时)

AUTH_PATH = "/" + ARGS.auth_path.strip("/")

IPV4_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")

# 访问密钥:首次启动自动生成(用于公网访问鉴权,如经 Cloudflare Tunnel 暴露)
AUTH_FILE = os.path.join(BASE, "monitor-token.txt")
if os.path.exists(AUTH_FILE):
    AUTH_TOKEN = open(AUTH_FILE, encoding="utf-8").read().strip() or None
else:
    AUTH_TOKEN = secrets.token_hex(16)
    open(AUTH_FILE, "w").write(AUTH_TOKEN)
    # 注意:日志里不打印登录路径与密钥(日志页会展示给已登录用户,
    # 且日志文件本身可能被读取);首次启动只提示已生成。
    log(f"[monitor] 访问密钥已生成,保存在 {os.path.basename(AUTH_FILE)}"
        f"(登录路径见启动参数 --auth-path,或从本地命令历史/部署记录获取)")

# ---------------------------------------------------------------------------
# 数据库
# ---------------------------------------------------------------------------

_db_local = threading.local()


def _new_conn():
    conn = sqlite3.connect(ARGS.db, timeout=15)
    # busy_timeout 让并发写(探测线程 vs 面板查询)自己排队,而不是立刻抛
    # "database is locked"。synchronous=NORMAL 在 WAL 下已足够安全(D),
    # 且省掉每次提交的 fsync。
    conn.execute("PRAGMA busy_timeout=15000")
    conn.execute("PRAGMA synchronous=NORMAL")
    return conn


@contextlib.contextmanager
def db():
    """每个线程复用一条连接(而不是每次调用都新开)。

    旧实现有两个问题,面板加载时被放大成秒级:
      1. 每次 db() 都 sqlite3.connect + PRAGMA journal_mode=WAL —— 一次
         /api/stats 要开上千条连接,每次都要重新协商 journal mode;
      2. `with conn` 在 sqlite3 里只是"事务"上下文,并不会关闭连接 ——
         那些连接全靠 GC 回收,等于每请求泄漏上千个句柄。

    WAL 是持久化在库文件里的属性,现在只在 db_init() 设置一次。
    """
    conn = getattr(_db_local, "conn", None)
    if conn is None:
        conn = _new_conn()
        _db_local.conn = conn
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise


def db_init():
    with db() as c:
        # WAL 只需设一次:它是库文件的持久属性,之后所有连接自动继承。
        c.execute("PRAGMA journal_mode=WAL")
        c.execute("""CREATE TABLE IF NOT EXISTS probes(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT NOT NULL,
            ts INTEGER NOT NULL,
            ok INTEGER NOT NULL,
            latency_ms INTEGER,
            tcp_ms INTEGER,
            reason TEXT
        )""")
        c.execute("CREATE INDEX IF NOT EXISTS idx_probes_ip_ts ON probes(ip, ts)")
        # itdog 全国评测结果(每 IP 一条最新;历史可留,取最新)
        c.execute("""CREATE TABLE IF NOT EXISTS itdog_scores(
            ip TEXT NOT NULL,
            ts INTEGER NOT NULL,
            success_rate REAL,
            median_rtt REAL,
            p95 REAL,
            nodes INTEGER,
            src TEXT
        )""")
        c.execute("CREATE INDEX IF NOT EXISTS idx_itdog_ip_ts ON itdog_scores(ip, ts)")
        # 节点级明细:每个 (ip, round_ts) 一条;只保留最新一轮(写入时清理旧轮)
        c.execute("""CREATE TABLE IF NOT EXISTS itdog_nodes(
            ip TEXT NOT NULL,
            round_ts INTEGER NOT NULL,
            node_id TEXT NOT NULL,
            isp TEXT,
            city TEXT,
            result TEXT,
            node_ip TEXT
        )""")
        c.execute("CREATE INDEX IF NOT EXISTS idx_itdog_nodes_ip_ts ON itdog_nodes(ip, round_ts)")
        # 域名监控:每域名一条汇总(端到端 + 全国 itdog), 不参与 IP 评分
        c.execute("""CREATE TABLE IF NOT EXISTS domain_status(
            domain TEXT PRIMARY KEY,
            resolve_ip TEXT,
            e2e_ok INTEGER,
            e2e_total INTEGER,
            e2e_latency_ms INTEGER,
            itdog_rate REAL,
            itdog_med_rtt REAL,
            itdog_nodes INTEGER,
            itdog_ts INTEGER,
            itdog_src TEXT,
            last_ts INTEGER
        )""")
        # 域名 itdog 节点明细(每域名最新一轮), 供 /abc 展开查看
        c.execute("""CREATE TABLE IF NOT EXISTS domain_nodes(
            domain TEXT NOT NULL,
            round_ts INTEGER NOT NULL,
            node_id TEXT NOT NULL,
            isp TEXT,
            city TEXT,
            result TEXT,
            node_ip TEXT
        )""")
        c.execute("CREATE INDEX IF NOT EXISTS idx_domain_nodes_d_ts ON domain_nodes(domain, round_ts)")
        c.execute("""CREATE TABLE IF NOT EXISTS meta(
            k TEXT PRIMARY KEY, v TEXT)""")
        for ddl in ("ALTER TABLE probes ADD COLUMN tcp_ms INTEGER",
                    "ALTER TABLE probes ADD COLUMN src TEXT",
                    "ALTER TABLE probes ADD COLUMN warm_ms INTEGER",
                    "ALTER TABLE domain_status ADD COLUMN itdog_src TEXT",
                    # 全国评测的来源: itdog(首选) / tcptest / kkce(回退源)
                    # —— 回退源的节点数与地区口径都和 itdog 不同, 必须能区分
                    "ALTER TABLE itdog_scores ADD COLUMN src TEXT"):
            try:
                c.execute(ddl)
            except sqlite3.OperationalError:
                pass  # 列已存在
        # 常规轮样本索引:延迟均值/评分只取常规轮(排除扫描期受负载污染的样本)
        c.execute("CREATE INDEX IF NOT EXISTS idx_probes_ip_ts_src ON probes(ip, ts, src)")

def db_insert(ip, ok, latency_ms, tcp_ms, reason, src="round", warm_ms=None):
    """落库一条探测记录。src 标记样本来源:
    round = 5 分钟常规轮(用于延迟统计与评分)
    sweep = 全量复测批次  scan = 临时扫描/补位探测(两者只用于在线率与筛选)
    warm_ms = 复用 TLS 会话后的热延迟(模拟客户端长连接体验),测量失败为 None"""
    with db() as c:
        c.execute(
            "INSERT INTO probes(ip, ts, ok, latency_ms, tcp_ms, reason, src, warm_ms) "
            "VALUES(?,?,?,?,?,?,?,?)",
            (ip, int(time.time()), 1 if ok else 0, latency_ms, tcp_ms, reason, src, warm_ms))

def db_itdog_insert(ip, success_rate, median_rtt, p95, nodes, src="itdog"):
    """落库一条全国评测结果。src = itdog / tcptest / kkce(后两者是回退源)。"""
    with db() as c:
        c.execute(
            "INSERT INTO itdog_scores(ip, ts, success_rate, median_rtt, p95, nodes, src) "
            "VALUES(?,?,?,?,?,?,?)",
            (ip, int(time.time()), success_rate, median_rtt, p95, nodes, src))

def db_itdog_nodes_insert(ip, round_ts, node_rows):
    """落库节点级明细;先清掉该 ip 上一轮明细(只保留最新一轮)。"""
    with db() as c:
        c.execute("DELETE FROM itdog_nodes WHERE ip=?", (ip,))
        c.executemany(
            "INSERT INTO itdog_nodes(ip, round_ts, node_id, isp, city, result, node_ip) "
            "VALUES(?,?,?,?,?,?,?)",
            [(ip, round_ts, r["node_id"], r.get("isp", ""), r.get("city", ""),
              r.get("result", ""), r.get("ip", "")) for r in node_rows])

def itdog_nodes_latest(ip):
    """取该 ip 最新一轮的节点明细列表(按 node_id 顺序返回)。"""
    with db() as c:
        row = c.execute("SELECT MAX(round_ts) FROM itdog_nodes WHERE ip=?", (ip,)).fetchone()
        if not row or row[0] is None:
            return []
        round_ts = row[0]
        return [{"node_id": r[0], "isp": r[1], "city": r[2], "result": r[3], "ip": r[4]}
                for r in c.execute(
                    "SELECT node_id, isp, city, result, node_ip FROM itdog_nodes "
                    "WHERE ip=? AND round_ts=? ORDER BY node_id", (ip, round_ts))]

def itdog_history(ip):
    """该 ip 的历史多轮评测(按时间倒序,最新在前)。"""
    with db() as c:
        return [{"ts": r[0], "success_rate": r[1], "median_rtt": r[2],
                 "p95": r[3], "nodes": r[4]}
                for r in c.execute(
                    "SELECT ts, success_rate, median_rtt, p95, nodes "
                    "FROM itdog_scores WHERE ip=? ORDER BY ts DESC", (ip,))]

def itdog_api_payload():
    """供 /api/itdog 与 /itdog 页使用:每个池内 IP 的最新评测 + 历史 + 节点明细。"""
    ips = sorted(load_pool())
    now = int(time.time())
    out = []
    src_count = {}
    for ip in ips:
        s24 = window_stats(ip, now - DAY)
        local = score_ip(s24, s24, s24, consecutive_failures(ip))
        idog = itdog_score(ip)
        # merged 与 score 一致:用 itdog_blend(含 freshness 衰减),而非固定权重
        merged = itdog_blend(local, ip)
        hist = itdog_history(ip)
        latest = itdog_latest(ip)
        if latest:
            latest = dict(latest)
            latest["freshness"] = itdog_freshness(latest.get("ts"))
            s = latest.get("src") or "itdog"
            src_count[s] = src_count.get(s, 0) + 1
        out.append({
            "ip": ip,
            "info": ipinfo_lookup(ip),
            "local_score": local,
            "itdog_score": idog,
            "merged_score": merged,
            "freshness": latest["freshness"] if latest else None,
            "src": (latest or {}).get("src") or None,
            "latest": latest,
            "history": hist,
            "nodes": itdog_nodes_latest(ip) if latest else [],
        })
    out.sort(key=lambda x: -(x["merged_score"] if x["merged_score"] is not None else -1))
    return {
        "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "weight_itdog": ARGS.itdog_weight,
        "itdog_enabled": ITDOG_ENABLED,
        # 依赖自检失败原因(itdog/ 缺失等); 非 None 时页面必须显式告警
        "itdog_error": _ITDOG_LOAD_ERROR,
        "itdog_last": db_meta_get("itdog_last"),
        # itdog 整轮被拦(验证码/可疑任务)时的提示; 空串=正常
        "itdog_blocked": db_meta_get("itdog_blocked"),
        # 各来源的 IP 数: 有回退源时页面要显式提示(回退源的节点数/地区口径与 itdog 不同)
        "src_count": src_count,
        "ips": out,
    }

def db_cleanup():
    cutoff = int(time.time()) - RETENTION_DAYS * DAY
    with db() as c:
        c.execute("DELETE FROM probes WHERE ts < ?", (cutoff,))

IPINFO_FILE = os.path.join(BASE, "ip-info.json")
_ipinfo_cache = {"mtime": None, "data": {}}

def load_ipinfo():
    try:
        mtime = os.path.getmtime(IPINFO_FILE)
    except OSError:
        return {}
    with _pool_lock:
        if _ipinfo_cache["mtime"] == mtime:
            return _ipinfo_cache["data"]
        try:
            data = json.load(open(IPINFO_FILE, encoding="utf-8"))
        except Exception:
            data = {}
        _ipinfo_cache["mtime"] = mtime
        _ipinfo_cache["data"] = data
    return data

def ipinfo_lookup(ip):
    return load_ipinfo().get(ip)

def db_pool_ips():
    with db() as c:
        return [r[0] for r in c.execute("SELECT DISTINCT ip FROM probes")]

def db_meta_get(k):
    with db() as c:
        row = c.execute("SELECT v FROM meta WHERE k=?", (k,)).fetchone()
    return row[0] if row else None

def db_meta_set(k, v):
    with db() as c:
        c.execute("INSERT INTO meta(k,v) VALUES(?,?) "
                  "ON CONFLICT(k) DO UPDATE SET v=excluded.v", (k, v))

# ---------------------------------------------------------------------------
# 池文件(支持纯文本 / CSV,逐行提取第一个 IPv4;mtime 缓存)
# ---------------------------------------------------------------------------

_pool_lock = threading.Lock()
_pool_cache = {"mtime": None, "ips": []}

def load_pool():
    try:
        mtime = os.path.getmtime(ARGS.pool)
    except OSError:
        return []
    with _pool_lock:
        if _pool_cache["mtime"] == mtime:
            return _pool_cache["ips"]
        ips = []
        try:
            with open(ARGS.pool, encoding="utf-8-sig", errors="replace") as f:
                for line in f:
                    m = IPV4_RE.search(line)
                    if m:
                        ips.append(m.group(1))
        except OSError:
            return []
        seen, out = set(), []
        for ip in ips:
            if ip not in seen:
                seen.add(ip)
                out.append(ip)
        _pool_cache["mtime"] = mtime
        _pool_cache["ips"] = out
    return out

# ---------------------------------------------------------------------------
# DoH 探测(直连指定 IP,TLS 证书按域名校验)
# 返回结构化 dict:{"ok", "total_ms", "tcp_ms", "status", "cache", "reason"}
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# 热延迟测量(纯附加:失败一律忽略,绝不影响主探测的 ok/失败判定)
#
# 主探测每次新建 TCP+TLS,得到的是"冷路径"(最坏情况)。真实客户端(AGH 等)
# 复用长连接,后续查询无需再握手。这里在一条 keep-alive 连接上连发两次查询,
# 第二次的耗时即"热"路径延迟,供展示与评分使用。
# ---------------------------------------------------------------------------

def _read_http_response(tls, carry, CRLF):
    """从连接读一个完整 HTTP 响应。返回 (ok, 剩余缓冲)。
    仅接受带 content-length 的非分块响应;其他情况一律放弃热测量。"""
    buf = carry
    sep = buf.find(b"\r\n\r\n")
    while sep < 0:
        chunk = tls.recv(4096)
        if not chunk:
            return False, b""
        buf += chunk
        if len(buf) > 65536:
            return False, b""
        sep = buf.find(b"\r\n\r\n")
    head = buf[:sep].decode("utf-8", "replace")
    rest = buf[sep + 4:]
    m = re.search(r"HTTP/[\d.]+ (\d{3})", head)
    if not m or int(m.group(1)) != 200:
        return False, b""
    if "x-doh-cache" not in head.lower():
        return False, b""
    clen = None
    for line in head.split(CRLF)[1:]:
        if line.lower().startswith("content-length:"):
            try:
                clen = int(line.split(":", 1)[1].strip())
            except ValueError:
                clen = None
    if clen is None:
        return False, b""          # 分块传输/长度未知:不做热测量
    while len(rest) < clen:
        chunk = tls.recv(4096)
        if not chunk:
            return False, b""
        rest += chunk
    body = rest[:clen]
    if len(body) < 12 or not (body[2] & 0x80):
        return False, b""
    return True, rest[clen:]

def _probe_warm(ip):
    """在一条 keep-alive 连接上连发两次查询,返回第二次耗时(热路径)。
    任何异常或对端不支持长连接时返回 None。"""
    CRLF = "\r\n"
    try:
        raw = socket.create_connection((ip, 443), timeout=ARGS.timeout / 1000)
        try:
            tls = TLS_CTX.wrap_socket(raw, server_hostname=DOH_HOST)
        except Exception:
            raw.close()
            return None
        try:
            tls.settimeout(ARGS.timeout / 1000)
            head = (
                f"POST {DOH_PATH} HTTP/1.1{CRLF}"
                f"Host: {DOH_HOST}{CRLF}"
                f"user-agent: {UA}{CRLF}"
                f"content-type: application/dns-message{CRLF}"
                f"accept: application/dns-message{CRLF}"
                f"content-length: {len(DOH_QUERY)}{CRLF}"
                f"connection: keep-alive{CRLF}{CRLF}"
            )
            carry = b""
            # 第一次:预热(不计时)
            tls.sendall(head.encode("ascii") + DOH_QUERY)
            ok, carry = _read_http_response(tls, carry, CRLF)
            if not ok:
                return None
            # 第二次:同一连接上计时
            t0 = time.time()
            tls.sendall(head.encode("ascii") + DOH_QUERY)
            ok, carry = _read_http_response(tls, carry, CRLF)
            if not ok:
                return None
            return int((time.time() - t0) * 1000)
        finally:
            tls.close()
    except Exception:
        return None

def _resolve_doh_ip():
    """解析 DoH 域名,优先取 IPv4 记录。

    域名同时有 A/AAAA 时,系统解析常把 IPv6 排在前面;而本机/主流客户端
    走的是 IPv4 中继,Windows 还可能禁用了 IPv6 —— 端到端探针若取了 v6
    首地址会直接连接失败,被误判为"域名离线"。"""
    try:
        infos = socket.getaddrinfo(DOH_HOST, 443, type=socket.SOCK_STREAM)
    except OSError:
        return None
    for i in infos:
        if i[0] == socket.AF_INET:
            return i[4][0]
    return infos[0][4][0]


def doh_probe(ip, warm=False):
    started = time.time()
    r = {"ip": ip, "ok": False, "total_ms": None, "tcp_ms": None,
         "status": 0, "cache": "-", "reason": "", "warm_ms": None}
    tcp_ms = None
    CRLF = "\r\n"
    try:
        t0 = time.time()
        raw = socket.create_connection((ip, 443), timeout=ARGS.timeout / 1000)
        tcp_ms = int((time.time() - t0) * 1000)
        r["tcp_ms"] = tcp_ms
        try:
            tls = TLS_CTX.wrap_socket(raw, server_hostname=DOH_HOST)
        except Exception:
            # 握手失败(证书不符 / 超时 / 被 RST)时必须显式关掉裸套接字:
            # wrap_socket 抛异常时不会接管 raw 的所有权,不关就泄漏一个 fd。
            # 扫描上千个候选时绝大多数握手都会失败,泄漏几千个 fd 会把进程的
            # nofile 用光,之后连 SQLite 都开不了(表现为持续
            # "unable to open database file",探测循环静默死掉、只留一个空壳服务)。
            raw.close()
            raise
        try:
            head = (
                f"POST {DOH_PATH} HTTP/1.1{CRLF}"
                f"Host: {DOH_HOST}{CRLF}"
                f"user-agent: {UA}{CRLF}"
                f"content-type: application/dns-message{CRLF}"
                f"accept: application/dns-message{CRLF}"
                f"content-length: {len(DOH_QUERY)}{CRLF}"
                f"connection: close{CRLF}{CRLF}"
            )
            tls.sendall(head.encode("ascii") + DOH_QUERY)
            buf = b""
            tls.settimeout(ARGS.timeout / 1000)
            while True:
                chunk = tls.recv(4096)
                if not chunk:
                    break
                buf += chunk
                if len(buf) > 65536:
                    break
        finally:
            tls.close()

        sep = buf.find(b"\r\n\r\n")
        if sep < 0:
            r["reason"] = "无 HTTP 响应"
            return r
        head = buf[:sep].decode("utf-8", "replace")
        body = buf[sep + 4:]
        m = re.search(r"HTTP/[\d.]+ (\d{3})", head)
        r["status"] = int(m.group(1)) if m else 0
        headers = {}
        for line in head.split("\r\n")[1:]:
            i = line.find(":")
            if i > 0:
                headers[line[:i].strip().lower()] = line[i + 1:].strip()
        r["cache"] = headers.get("x-doh-cache", "-")

        if r["status"] != 200:
            r["reason"] = f"HTTP {r['status']}"
        elif "x-doh-cache" not in headers:
            r["reason"] = "缺少 x-doh-cache 头(非本 Worker)"
        elif len(body) < 12 or not (body[2] & 0x80):
            r["reason"] = "响应非 DNS 报文"
        else:
            r["ok"] = True
        r["total_ms"] = int((time.time() - started) * 1000)
        if r["ok"] and warm:
            # 热延迟:纯附加测量,失败为 None,不影响上面的结论
            try:
                r["warm_ms"] = _probe_warm(ip)
            except Exception:
                r["warm_ms"] = None
        return r
    except socket.timeout:
        r["reason"] = "超时"
    except ssl.SSLCertVerificationError:
        r["reason"] = "证书不匹配"
    except OSError as e:
        code = getattr(e, "errno", None) or str(e)
        r["reason"] = ("连接失败" if "10060" in str(code) or "ETIMEDOUT" in str(code)
                       else f"网络错误({code})"[:40])
    except Exception as e:
        r["reason"] = f"异常({type(e).__name__})"
    r["total_ms"] = int((time.time() - started) * 1000)
    return r

# ---------------------------------------------------------------------------
# Cloudflare API(无代理解析器;token: tools/.cf-token)
# ---------------------------------------------------------------------------

_NO_PROXY_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))
_zone_id_cache = None

# ---------------------------------------------------------------------------
# Cloudflare API 访问:直连 + 重试 + 可选 SOCKS5 回落
#
# 国内网络会间歇性 RST 直连 api.cloudflare.com(表现为
# ssl.SSLEOFError / UNEXPECTED_EOF_WHILE_READING)。若持续数分钟,自动换 IP、
# 全量复测、择优替换都会失效。因此:先直连重试,仍失败则回落本地代理。
# 代理地址从环境变量 MONITOR_PROXY 或 tools/.proxy 文件读取(未配置则不启用),
# SOCKS5 握手用标准库 socket 实现,不引入第三方依赖。
# ---------------------------------------------------------------------------

def _proxy_addr():
    """返回 (host, port) 或 None。支持 MONITOR_PROXY=socks5://127.0.0.1:10808。"""
    raw = os.environ.get("MONITOR_PROXY", "").strip()
    if not raw:
        p = os.path.join(BASE, ".proxy")
        if os.path.exists(p):
            try:
                raw = open(p, encoding="utf-8").read().strip()
            except OSError:
                raw = ""
    if not raw:
        return None
    raw = raw.split("://")[-1]
    if ":" not in raw:
        return None
    host, _, port = raw.rpartition(":")
    try:
        return (host.strip("[]") or "127.0.0.1", int(port))
    except ValueError:
        return None


class _Socks5HTTPSConnection(http.client.HTTPSConnection):
    """经 SOCKS5 代理建立 TLS 连接(仅 CONNECT,无认证)。"""

    def __init__(self, *args, proxy=None, **kwargs):
        super().__init__(*args, **kwargs)
        self._proxy = proxy

    def connect(self):
        proxy = self._proxy or ("127.0.0.1", 10808)
        sock = socket.create_connection(proxy, timeout=self.timeout)
        try:
            sock.sendall(bytes([5, 1, 0]))          # VER=5, NMETHODS=1, NOAUTH
            if sock.recv(2) != bytes([5, 0]):
                raise OSError("SOCKS5 协商失败")
            host = self.host
            try:
                ip = socket.inet_aton(host)
                addr = bytes([1]) + ip
            except OSError:
                h = host.encode("idna")
                addr = bytes([3, len(h)]) + h
            sock.sendall(bytes([5, 1, 0]) + addr + self.port.to_bytes(2, "big"))
            resp = sock.recv(10)
            if len(resp) < 2 or resp[1] != 0:
                raise OSError("SOCKS5 CONNECT 失败(code=%s)" % (resp[1] if len(resp) > 1 else "?"))
        except Exception:
            sock.close()
            raise
        try:
            self.sock = self._context.wrap_socket(sock, server_hostname=self.host)
        except Exception:
            # 经代理做 TLS 握手失败时,底层 socket 同样要关掉(否则每次
            # CF API 回落失败都会泄漏一个 fd)
            sock.close()
            raise


class _Socks5HTTPSHandler(urllib.request.HTTPSHandler):
    def __init__(self, proxy):
        super().__init__()
        self._proxy = proxy

    def https_open(self, req):
        return self.do_open(
            lambda *a, **kw: _Socks5HTTPSConnection(*a, proxy=self._proxy, **kw), req)


def _cf_api_via_proxy(method, path, body, proxy):
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}), _Socks5HTTPSHandler(proxy))
    return _cf_api_call(opener, method, path, body)


def _cf_api_call(opener, method, path, body):
    token_path = os.path.join(BASE, ".cf-token")
    token = open(token_path, encoding="utf-8").read().strip()
    req = urllib.request.Request(
        "https://api.cloudflare.com/client/v4" + path,
        data=json.dumps(body).encode("utf-8") if body is not None else None,
        headers={"authorization": f"Bearer {token}",
                 "content-type": "application/json"},
        method=method)
    with opener.open(req, timeout=20) as resp:
        return json.load(resp)


def cf_api(method, path, body=None):
    """调用 CF API:直连最多 3 次(指数退避),仍失败则尝试 SOCKS5 代理。"""
    last = None
    for attempt in range(3):
        try:
            j = _cf_api_call(_NO_PROXY_OPENER, method, path, body)
            break
        except Exception as e:
            last = e
            if attempt < 2:
                time.sleep(1 + attempt * 2)
    else:
        proxy = _proxy_addr()
        if not proxy:
            raise last
        log(f"[cf-api] 直连失败({type(last).__name__}),改用代理 {proxy[0]}:{proxy[1]} 重试")
        j = _cf_api_via_proxy(method, path, body, proxy)
    if not j.get("success"):
        raise RuntimeError("; ".join(str(e.get("message")) for e in j.get("errors", [])))
    return j.get("result")


    token_path = os.path.join(BASE, ".cf-token")
    token = open(token_path, encoding="utf-8").read().strip()
    req = urllib.request.Request(
        "https://api.cloudflare.com/client/v4" + path,
        data=json.dumps(body).encode("utf-8") if body is not None else None,
        headers={"authorization": f"Bearer {token}",
                 "content-type": "application/json"},
        method=method)
    with _NO_PROXY_OPENER.open(req, timeout=20) as resp:
        j = json.load(resp)
    if not j.get("success"):
        raise RuntimeError("; ".join(str(e.get("message")) for e in j.get("errors", [])))
    return j.get("result")

def cf_zone_id():
    global _zone_id_cache
    if _zone_id_cache:
        return _zone_id_cache
    zones = cf_api("GET", "/zones?per_page=50")
    zone = next((z for z in zones
                 if DNS_NAME == z["name"] or DNS_NAME.endswith("." + z["name"])), None)
    if not zone:
        raise RuntimeError("token 无法访问包含该域名的 zone")
    _zone_id_cache = zone["id"]
    return _zone_id_cache

def peer_alive():
    """对端(主监控机)是否在线。备份机上配置了 --peer-health-url 才生效;
    在线时本机拒绝一切 DNS 写操作,保证双机热备不冲突。
    判定标准:对端 HTTP 服务有任何应答(含 302/401)即为存活。"""
    if not ARGS.peer_health_url:
        return False
    try:
        req = urllib.request.Request(ARGS.peer_health_url)
        with _NO_PROXY_OPENER.open(req, timeout=8):
            return True
    except urllib.error.HTTPError:
        return True  # 有 HTTP 应答即存活(401/302 都说明进程在跑)
    except Exception:
        return False

def _yield_to_peer():
    if peer_alive():
        log("[peer] 主监控机在线,本机让出 DNS 写权(仅探测)")
        return True
    return False

def get_dns_records():
    zid = cf_zone_id()
    recs = cf_api("GET", f"/zones/{zid}/dns_records?type=A&name={urllib.parse.quote(DNS_NAME)}&per_page=100")
    return [(r["content"], r["id"]) for r in recs]

def dns_name_records():
    """DNS_NAME 的全部 A/CNAME 记录对象 [{type,content,id}],用于识别兜底状态。"""
    zid = cf_zone_id()
    recs = cf_api("GET", f"/zones/{zid}/dns_records?name={urllib.parse.quote(DNS_NAME)}&per_page=100")
    return [r for r in recs if r["type"] in ("A", "AAAA", "CNAME")]

_dns_cache = {"at": 0.0, "records": None}
_dns_refresh_lock = threading.Lock()
DNS_CACHE_TTL = 300


def _refresh_dns_cache():
    """真的去 CF API 拉一次 A 记录并写进缓存(同时落一份到 meta)。"""
    records = [c for c, _ in get_dns_records()]
    _dns_cache.update(at=time.time(), records=records)
    # 落盘一份"上次已知记录":面板重启后能立刻显示,而不是先空着等 CF API。
    try:
        db_meta_set("dns_records_cache", json.dumps(records))
    except Exception:
        pass
    return records


def _load_dns_cache_from_meta():
    """启动时把上次已知的 A 记录装回内存缓存(标记为过期 -> 会后台刷新)。"""
    try:
        raw = db_meta_get("dns_records_cache")
        recs = json.loads(raw) if raw else None
        if isinstance(recs, list) and recs:
            _dns_cache.update(at=0.0, records=[str(x) for x in recs])
    except Exception:
        pass


def _kick_dns_refresh():
    """起一个后台线程刷新缓存;已有刷新在跑就直接返回(不排队、不堆积)。"""
    if not _dns_refresh_lock.acquire(blocking=False):
        return
    def job():
        try:
            _refresh_dns_cache()
        except Exception as e:
            log(f"[dns] 后台刷新失败: {type(e).__name__}: {e}")
        finally:
            _dns_refresh_lock.release()
    threading.Thread(target=job, daemon=True).start()


def current_dns_records():
    """当前 DNS A 记录(TTL 内直接用缓存;过期则**阻塞**去拉一次)。

    这是 DNS 管理路径用的版本 —— auto_sync/择优/兜底必须拿到真实状态才能
    决定往 DNS 写什么,所以这里允许阻塞。**面板不要用它**,用
    current_dns_records_cached():CF API 在本机经常直连失败、退避 3 次再走
    SOCKS5 代理,实测单次可达 251 秒,足以把页面卡死。
    """
    if time.time() - _dns_cache["at"] < DNS_CACHE_TTL and _dns_cache["records"] is not None:
        return _dns_cache["records"]
    try:
        return _refresh_dns_cache()
    except Exception:
        return _dns_cache["records"] if _dns_cache["records"] is not None else []


def current_dns_records_cached():
    """面板专用:永不阻塞。

    总是立刻返回上次已知的 A 记录;缓存过期就在后台刷新,绝不等待 CF API。
    首次调用(还没有任何数据)返回 [],后台刷完下次就有了。
    """
    if _dns_cache["records"] is None or time.time() - _dns_cache["at"] >= DNS_CACHE_TTL:
        _kick_dns_refresh()
    return _dns_cache["records"] or []

# ---------------------------------------------------------------------------
# 统计聚合
# ---------------------------------------------------------------------------

def pct95(values):
    if not values:
        return None
    srt = sorted(values)
    return srt[min(len(srt) - 1, int(len(srt) * 0.95))]

QUIET_SRC = "COALESCE(src,'round')='round'"


def window_stats(ip, since):
    with db() as c:
        row = c.execute(
            "SELECT COUNT(*), SUM(ok) FROM probes WHERE ip=? AND ts>=?",
            (ip, since)).fetchone()
        total, ok_sum = row[0], row[1] or 0
        quiet = c.execute(
            "SELECT AVG(latency_ms), AVG(tcp_ms), COUNT(*) FROM probes "
            f"WHERE ip=? AND ts>=? AND ok=1 AND {QUIET_SRC}",
            (ip, since)).fetchone()
        avg, avg_tcp, quiet_n = quiet[0], quiet[1], quiet[2] or 0
        if quiet_n == 0:
            # 该窗口还没有常规轮样本(如刚加入池子):回落到全部样本,
            # 宁可显示受污染的延迟,也好过显示空白。
            fallback = c.execute(
                "SELECT AVG(latency_ms), AVG(tcp_ms) FROM probes "
                "WHERE ip=? AND ts>=? AND ok=1", (ip, since)).fetchone()
            avg, avg_tcp = fallback[0], fallback[1]
            lats = [r[0] for r in c.execute(
                "SELECT latency_ms FROM probes WHERE ip=? AND ts>=? AND ok=1",
                (ip, since))]
        else:
            lats = [r[0] for r in c.execute(
                "SELECT latency_ms FROM probes WHERE ip=? AND ts>=? AND ok=1 "
                f"AND {QUIET_SRC}", (ip, since))]
        warms = [r[0] for r in c.execute(
            "SELECT warm_ms FROM probes WHERE ip=? AND ts>=? AND ok=1 "
            f"AND warm_ms IS NOT NULL AND {QUIET_SRC}", (ip, since))]
        tcps = [r[0] for r in c.execute(
            "SELECT tcp_ms FROM probes WHERE ip=? AND ts>=? AND ok=1 "
            f"AND tcp_ms IS NOT NULL AND {QUIET_SRC}", (ip, since))]
    med = None
    if lats:
        srt = sorted(lats)
        mid = len(srt) // 2
        med = srt[mid] if len(srt) % 2 else round((srt[mid - 1] + srt[mid]) / 2)
    med_warm = None
    if warms:
        srt = sorted(warms)
        mid = len(srt) // 2
        med_warm = srt[mid] if len(srt) % 2 else round((srt[mid - 1] + srt[mid]) / 2)
    med_tcp = None
    if tcps:
        srt = sorted(tcps)
        mid = len(srt) // 2
        med_tcp = srt[mid] if len(srt) % 2 else round((srt[mid - 1] + srt[mid]) / 2)
    return {
        "total": total or 0,
        "ok": ok_sum,
        "rate": round(ok_sum / total * 100, 1) if total else None,
        "avg_ms": round(avg) if avg is not None else None,
        # 中位数:不受秒级长尾影响,用于评分与展示(均值仅作参考)
        "med_ms": med,
        # 热延迟中位:复用 TLS 会话后的耗时,更接近客户端长连接体感
        "med_warm_ms": med_warm,
        "avg_tcp": round(avg_tcp) if avg_tcp is not None else None,
        # TCP 握手中位:与其它列同口径(均值易被抽风样本拖高)
        "med_tcp": med_tcp,
        "p95_ms": pct95(lats),
    }

def consecutive_failures(ip):
    with db() as c:
        rows = c.execute(
            "SELECT ok FROM probes WHERE ip=? ORDER BY ts DESC LIMIT 50", (ip,)).fetchall()
    n = 0
    for (ok,) in rows:
        if ok:
            break
        n += 1
    return n

def hourly_series(ip, hours=48):
    now = int(time.time())
    start = now - hours * 3600
    with db() as c:
        rows = c.execute(
            "SELECT ts, ok, latency_ms, tcp_ms, COALESCE(src,'round') FROM probes "
            "WHERE ip=? AND ts>=? ORDER BY ts",
            (ip, start)).fetchall()
    buckets = {}
    for ts, ok, lat, tcp, src in rows:
        h = int(ts // 3600)
        # [total, ok, lat_q, tcp_q, n_q, lat_all, tcp_all, n_all]
        b = buckets.setdefault(h, [0, 0, 0, 0, 0, 0, 0, 0])
        b[0] += 1
        b[1] += ok
        if ok and lat is not None:
            b[5] += lat
            b[7] += 1
            if src == "round":
                b[2] += lat
                b[4] += 1
                if tcp is not None:
                    b[3] += tcp
        elif ok and tcp is not None:
            b[6] += tcp
    out = []
    for h in sorted(buckets):
        total, ok, lat_q, tcp_q, n_q, lat_all, tcp_all, n_all = buckets[h]
        use_q = n_q > 0  # 有常规轮样本就用常规轮,否则用全部(新 IP 曲线不断点)
        lat_sum = lat_q if use_q else lat_all
        tcp_sum = tcp_q if use_q else tcp_all
        denom = n_q if use_q else n_all
        out.append({
            "hour": datetime.fromtimestamp(h * 3600, timezone.utc).astimezone().strftime("%m-%d %H:%M"),
            "total": total, "ok": ok,
            "rate": round(ok / total * 100, 1) if total else None,
            "avg_ms": round(lat_sum / denom) if denom else None,
            "avg_tcp": round(tcp_sum / denom) if denom else None,
        })
    return out

def merged_series(hours):
    """整池合并:所有池内 IP 的逐小时汇总曲线。"""
    now = int(time.time())
    start = now - hours * 3600
    pool = load_pool()
    if not pool:
        return []
    ph = ",".join("?" for _ in pool)
    with db() as c:
        rows = c.execute(
            f"SELECT ts, ok, latency_ms, tcp_ms, COALESCE(src,'round') FROM probes "
            f"WHERE ts>=? AND ip IN ({ph}) ORDER BY ts",
            [start] + pool).fetchall()
    buckets = {}
    for ts, ok, lat, tcp, src in rows:
        h = int(ts // 3600)
        # [total, ok, lat_q, tcp_q, n_q, lat_all, tcp_all, n_all]
        b = buckets.setdefault(h, [0, 0, 0, 0, 0, 0, 0, 0])
        b[0] += 1; b[1] += ok
        if ok and lat is not None:
            b[5] += lat
            b[7] += 1
            if src == "round":
                b[2] += lat
                b[4] += 1
                if tcp is not None:
                    b[3] += tcp
        elif ok and tcp is not None:
            b[6] += tcp
    out = []
    for h in sorted(buckets):
        t, ok, lat_q, tcp_q, n_q, lat_all, tcp_all, n_all = buckets[h]
        use_q = n_q > 0
        ls = lat_q if use_q else lat_all
        ts_sum = tcp_q if use_q else tcp_all
        denom = n_q if use_q else n_all
        out.append({
            "hour": datetime.fromtimestamp(h * 3600, timezone.utc).astimezone().strftime("%m-%d %H:%M"),
            "total": t, "ok": ok,
            "rate": round(ok / t * 100, 1) if t else None,
            "avg_ms": round(ls / denom) if denom else None,
            "avg_tcp": round(ts_sum / denom) if denom else None,
        })
    return out

def last_sync_note():
    return db_meta_get("last_sync")

# ---------------------------------------------------------------------------
# 运行日志(只读尾部 + 脱敏)
# ---------------------------------------------------------------------------

LOG_TAIL_MAX = 2000          # 单次最多返回行数
LOG_READ_BYTES = 512 * 1024  # 只从文件尾部读这么多字节,避免大文件拖慢

def _redact(text):
    """日志脱敏:登录路径与访问密钥绝不出现在页面上。"""
    try:
        if AUTH_PATH and AUTH_PATH != "/":
            text = text.replace(AUTH_PATH, "/<登录路径已隐藏>")
        if AUTH_TOKEN:
            text = text.replace(AUTH_TOKEN, "<密钥已隐藏>")
    except Exception:
        pass
    return text

def read_log_tail(lines=300, query=""):
    """返回 monitor.log 的尾部若干行(可选子串过滤)。"""
    path = _LOG_PATH
    info = {"file": os.path.basename(path), "lines": [], "total_lines": 0,
            "size": 0, "mtime": 0}
    try:
        st = os.stat(path)
        info["size"] = st.st_size
        info["mtime"] = int(st.st_mtime)
    except OSError:
        return info
    try:
        with open(path, "rb") as f:
            if st.st_size > LOG_READ_BYTES:
                f.seek(st.st_size - LOG_READ_BYTES)
                f.readline()  # 丢弃可能被截断的首行
            raw = f.read()
    except OSError:
        return info
    text = raw.decode("utf-8", "replace")
    all_lines = [ln for ln in text.splitlines() if ln.strip()]
    info["total_lines"] = len(all_lines)
    if query:
        q = query.lower()
        sel = [ln for ln in all_lines if q in ln.lower()]
    else:
        sel = all_lines
    n = max(1, min(int(lines or 300), LOG_TAIL_MAX))
    info["lines"] = [_redact(ln) for ln in sel[-n:]]
    return info

def itdog_latest_any(ip):
    """同 itdog_latest, 但**不受 ITDOG_ENABLED 门禁**: 仅供"候选选择"等需要历史分的场景。

    为什么需要: ntprxx 巡检的候选取自"itdog 全国分", 若进程没开 --itdog, itdog_latest()
    会在门口就返回 None → 候选恒为 0 → 巡检静默地永不替换(实测过)。历史分在库里本来就在,
    读它不该被"是否启用本轮评测线程"影响。
    """
    with db() as c:
        row = c.execute(
            "SELECT ts, success_rate, median_rtt, p95, nodes, src FROM itdog_scores "
            "WHERE ip=? ORDER BY ts DESC LIMIT 1", (ip,)).fetchone()
    if not row:
        return None
    ts, sr, med, p95, nodes, src = row
    return {"ts": ts, "success_rate": sr, "median_rtt": med, "p95": p95,
            "nodes": nodes, "src": src or "itdog"}


def itdog_latest(ip):
    """取某 IP 最新的全国评测记录(dict 或 None)。不查库为 None。
    src: 该轮的来源(itdog / tcptest / kkce), 供面板标明"这行是回退源测的"。"""
    if not ITDOG_ENABLED:
        return None
    return itdog_latest_any(ip)


def itdog_freshness(ts):
    """itdog 全国数据的新鲜度 0~1, 按年龄线性衰减:
    0h=1.0, 12h=0.75, 24h=0.5, 36h=0.25, ≥--itdog-max-age(默认48h)=0。
    使 itdog 全国维度随数据变旧平滑回归本地实时数据, 而不是 48h 突然归零。"""
    if not ts:
        return 0.0
    age_h = (time.time() - ts) / 3600.0
    max_age = max(0.1, ARGS.itdog_max_age)
    f = 1.0 - age_h / max_age
    return round(max(0.0, min(1.0, f)), 2)


def itdog_score(ip):
    """把 itdog 全国结果折算成 0~100 分(连通率为主 70,中位延迟 30)。无记录返回 None。
    规模对齐本地 score_ip 的 0~100,便于加权融合。"""
    return itdog_score_of(itdog_latest(ip))


def itdog_score_of(d):
    """同 itdog_score, 但直接吃一条记录(供"不受 ITDOG_ENABLED 门禁"的巡检候选选择复用同一公式)。"""
    if not d or d["success_rate"] is None:
        return None
    sr = d["success_rate"]  # 0~100
    def _speed(ms):
        # itdog 分只在"本轮确实有评测记录"时才计算, 所以 median 为 None 只可能
        # 意味着全节点失败(ok_ms 为空)。此时必须给 0 分: 沿用 base_score 里
        # "无数据=善意满分 30" 会让 0% 连通的 IP 白拿 30 速度分(按 w=0.5 约抬 15 分)。
        return 0.0 if ms is None else max(0.0, 30.0 - max(0, ms - 100) / 100.0 * 6)
    med = d.get("median_rtt")
    score = sr / 100.0 * 70 + _speed(med)
    return round(max(0, min(100, score)), 1)


def base_score(s24, d7, d30):
    """长期质量分 = 稳定性(70) + 延迟(30)。不含短期失败惩罚、不含 itdog。"""
    if not s24["total"] or s24["rate"] is None:
        return None
    rate24 = s24["rate"] or 0
    rate7 = d7["rate"] if d7["rate"] is not None else rate24
    rate30 = d30["rate"] if d30["rate"] is not None else rate7
    # 在线率成分(70 分):24h 占一半,7d/30d 长期表现占其余
    rate_score = (rate24 * 0.5 + rate7 * 0.3 + rate30 * 0.2) / 100 * 70
    # 速度成分(30 分):热延迟为主(客户端长连接体感,70%),冷路径为辅
    def _speed(ms):
        return 30.0 if ms is None else max(0.0, 30.0 - max(0, ms - 100) / 100.0 * 6)
    warm = s24.get("med_warm_ms")
    cold = s24.get("med_ms")
    if cold is None:
        cold = s24["avg_ms"]
    if warm is not None and cold is not None:
        speed_score = _speed(warm) * 0.7 + _speed(cold) * 0.3
    elif warm is not None:
        speed_score = _speed(warm)
    else:
        speed_score = _speed(cold)
    return round(max(0, min(100, rate_score + speed_score)), 1)


def itdog_blend(base, ip):
    """把 itdog 全国分按权重+新鲜度融合进 base:
       w_eff = --itdog-weight × freshness
       无 itdog 记录/freshness=0 时返回 base 不变。"""
    if base is None or ip is None or not ITDOG_ENABLED:
        return base
    idog = itdog_score(ip)
    if idog is None:
        return base
    latest = itdog_latest(ip)
    fr = itdog_freshness(latest["ts"]) if latest else 0.0
    if fr <= 0:
        return base
    w = ARGS.itdog_weight * fr
    return round(base * (1.0 - w) + idog * w, 1)


def score_ip(s24, d7, d30, cfail, ip=None):
    """综合评分 0~100, 分两层:
      base   = 长期质量(稳定性70 + 延迟30), 再按 freshness 融合 itdog 全国分
      final  = base − recent_failure_penalty(短期惩罚, 恢复后归零)
    调用方如只想要"长期质量"(如资格判断)请用 base_score + itdog_blend。"""
    base = base_score(s24, d7, d30)
    if base is None:
        return None
    base = itdog_blend(base, ip)
    # 短期失败惩罚:故意不进入 base, 只影响 final; 成功恢复(连败0)自动归零
    final = base - min(15, cfail * 5)
    return round(max(0, min(100, final)), 1)

def grade_of(score):
    if score is None:
        return None
    if score >= 90: return "A"
    if score >= 75: return "B"
    if score >= 60: return "C"
    return "D"

def _chunks(seq, n):
    for i in range(0, len(seq), n):
        yield seq[i:i + n]


def _median(values):
    """中位数(偶数个取中间两个的均值)。None 值必须由调用方先滤掉。"""
    if not values:
        return None
    srt = sorted(values)
    mid = len(srt) // 2
    return srt[mid] if len(srt) % 2 else round((srt[mid - 1] + srt[mid]) / 2)


def _empty_window():
    """无样本时的 window_stats 形状(字段与 window_stats 返回值一致)。"""
    return {"total": 0, "ok": 0, "rate": None, "avg_ms": None, "med_ms": None,
            "med_warm_ms": None, "avg_tcp": None, "med_tcp": None, "p95_ms": None}


def _rate_only(total, ok):
    """7d/30d 只需要在线率 —— 面板与评分都只读 .rate。

    旧实现为这两档也算中位数,把 30 天的原始延迟行(每 IP 数千行)拉回
    Python 排序,而结果从未被使用。现在改成纯 SQL 聚合。
    """
    total = total or 0
    ok = ok or 0
    return {"total": total, "ok": ok,
            "rate": round(ok / total * 100, 1) if total else None}


def batch_window_stats(ips, now):
    """一次批量算出所有 IP 的 h24 / d7 / d30 / 末次探测 / 连续失败。

    替代原来"每 IP 各调 3 次 window_stats + 1 次末次查询"的 N+1 写法:
    61 个 IP 从 250 次查询降到 5 次,且 30 天的原始行不再进入 Python。

    h24 与 window_stats(ip, now-DAY) 逐字段等价,包括:
      - 延迟只统计常规轮样本(COALESCE(src,'round')='round');
      - 该窗口没有常规轮样本时,延迟回落到全部样本(新入池 IP 不显示空白);
      - 热延迟/TCP 中位数恒用常规轮样本。
    """
    t24, t7, t30 = now - DAY, now - 7 * DAY, now - 30 * DAY
    out = {}
    for ip in ips:
        out[ip] = {"h24": _empty_window(), "d7": _rate_only(0, 0),
                   "d30": _rate_only(0, 0), "last": None, "cfail": 0}
    if not ips:
        return out

    with db() as c:
        for chunk in _chunks(list(ips), 300):
            ph = ",".join("?" for _ in chunk)
            args = list(chunk)

            # --- 1) 三档窗口的样本数 / 成功数 ---
            for ip, n24, o24, n7, o7, n30, o30 in c.execute(
                    "SELECT ip,"
                    " SUM(CASE WHEN ts>=? THEN 1 ELSE 0 END),"
                    " SUM(CASE WHEN ts>=? THEN ok ELSE 0 END),"
                    " SUM(CASE WHEN ts>=? THEN 1 ELSE 0 END),"
                    " SUM(CASE WHEN ts>=? THEN ok ELSE 0 END),"
                    " SUM(CASE WHEN ts>=? THEN 1 ELSE 0 END),"
                    " SUM(CASE WHEN ts>=? THEN ok ELSE 0 END) "
                    f"FROM probes WHERE ip IN ({ph}) AND ts>=? GROUP BY ip",
                    [t24, t24, t7, t7, t30, t30] + args + [t30]):
                e = out[ip]
                e["h24"].update(total=n24 or 0, ok=o24 or 0)
                e["h24"]["rate"] = round((o24 or 0) / n24 * 100, 1) if n24 else None
                e["d7"] = _rate_only(n7, o7)
                e["d30"] = _rate_only(n30, o30)

            # --- 2) 24h 均值:用 SQL 聚合,保证与旧的 AVG() 逐位一致 ---
            for row in c.execute(
                    "SELECT ip,"
                    " COUNT(CASE WHEN " + QUIET_SRC + " THEN 1 END),"
                    " SUM(CASE WHEN " + QUIET_SRC + " THEN latency_ms END),"
                    " COUNT(CASE WHEN " + QUIET_SRC + " THEN latency_ms END),"
                    " SUM(CASE WHEN " + QUIET_SRC + " THEN tcp_ms END),"
                    " COUNT(CASE WHEN " + QUIET_SRC + " THEN tcp_ms END),"
                    " SUM(latency_ms), COUNT(latency_ms),"
                    " SUM(tcp_ms), COUNT(tcp_ms) "
                    f"FROM probes WHERE ip IN ({ph}) AND ts>=? AND ok=1 GROUP BY ip",
                    args + [t24]):
                (ip, n_round, sl_r, cl_r, st_r, ct_r,
                 sl_a, cl_a, st_a, ct_a) = row
                h = out[ip]["h24"]
                if n_round:
                    h["avg_ms"] = round(sl_r / cl_r) if cl_r else None
                    h["avg_tcp"] = round(st_r / ct_r) if ct_r else None
                else:
                    # 该窗口还没有常规轮样本:回落到全部样本
                    h["avg_ms"] = round(sl_a / cl_a) if cl_a else None
                    h["avg_tcp"] = round(st_a / ct_a) if ct_a else None

            # --- 3) 24h 中位数 / p95:只能取原始值在 Python 里做次序统计 ---
            raw = {}
            for ip, lat, warm, tcp, src in c.execute(
                    "SELECT ip, latency_ms, warm_ms, tcp_ms, COALESCE(src,'round') "
                    f"FROM probes WHERE ip IN ({ph}) AND ts>=? AND ok=1",
                    args + [t24]):
                raw.setdefault(ip, []).append((lat, warm, tcp, src))
            for ip, rows in raw.items():
                h = out[ip]["h24"]
                has_round = any(r[3] == "round" for r in rows)
                # 与 window_stats 同规则:有常规轮样本就只用常规轮
                pool_rows = [r for r in rows if r[3] == "round"] if has_round else rows
                lats = [r[0] for r in pool_rows if r[0] is not None]
                warms = [r[1] for r in rows if r[3] == "round" and r[1] is not None]
                tcps = [r[2] for r in rows if r[3] == "round" and r[2] is not None]
                h["med_ms"] = _median(lats)
                h["p95_ms"] = pct95(lats)
                h["med_warm_ms"] = _median(warms)
                h["med_tcp"] = _median(tcps)

            # --- 4) 每个 IP 的末次探测 ---
            for ip, ts, ok, reason in c.execute(
                    "SELECT p.ip, p.ts, p.ok, p.reason FROM probes p "
                    "JOIN (SELECT ip, MAX(ts) AS mts FROM probes "
                    f"WHERE ip IN ({ph}) GROUP BY ip) m "
                    "ON p.ip=m.ip AND p.ts=m.mts GROUP BY p.ip", args):
                out[ip]["last"] = {"ts": ts, "ok": bool(ok), "reason": reason or ""}

    # --- 5) 连续失败:走 (ip,ts) 索引的定长取尾,61 次很便宜;
    #         语义(取尾 50 条数前导失败、上限 50)需要精确保持,故不批量化。---
    for ip in ips:
        out[ip]["cfail"] = consecutive_failures(ip)
    return out


def all_stats(dns_ips=None):
    # 只展示「可用池」内的 IP(外加当前 DNS 记录,防御池文件未跟上时遗漏),
    # 不展示大池里历史探测过的几千个 IP。
    ips = set(load_pool())
    # 必须用带 300 秒缓存的 current_dns_records():旧实现直接调未缓存的
    # get_dns_records(),于是每次刷新面板都要等一次 CF API 往返(实测
    # 1.6~2.6 秒,还可能在直连失败时走 3 次退避重试 + SOCKS5 回落)。
    # 面板每次加载都为此卡住,是"IP 加载慢"的最大单项。
    try:
        if dns_ips is None:
            dns_ips = current_dns_records_cached()
        ips |= set(dns_ips or [])
    except Exception:
        pass
    ips.add(DOMAIN_LABEL)  # 域名整体端到端探针始终保留
    ips = sorted(ips)
    now = int(time.time())
    pre = batch_window_stats(ips, now)
    per_ip = []
    for ip in ips:
        e = pre[ip]
        s24, s7, s30 = e["h24"], e["d7"], e["d30"]
        last = e["last"]
        cf = e["cfail"]
        sc = score_ip(s24, s7, s30, cf, ip)
        idog = itdog_latest(ip) if ITDOG_ENABLED else None
        if idog:
            idog = dict(idog)
            idog["freshness"] = itdog_freshness(idog.get("ts"))
        per_ip.append({
            "ip": ip,
            "info": ipinfo_lookup(ip),
            "itdog": idog,
            "h24": s24, "d7": s7, "d30": s30,
            "cfail": cf,
            "last": last,
            "samples": s30["total"],
            "score": sc,
            "grade": grade_of(sc),
            "status": ("在线" if (last and last["ok"]) else
                       ("离线" if last else "无数据")),
        })
    per_ip.sort(key=lambda x: (x["ip"] != DOMAIN_LABEL,
                               -(x["score"] if x["score"] is not None else -1),
                               x["ip"]))
    total_probes = sum(p["h24"]["total"] for p in per_ip)
    total_ok = sum(p["h24"]["ok"] for p in per_ip)
    return {
        "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "pool_size": len(load_pool()),
        "last_sync": last_sync_note(),
        "fallback": _fallback_active,
        "fallback_target": FALLBACK_CNAME,
        "ips": per_ip,
        "overall_24h": {
            "total": total_probes,
            "ok": total_ok,
            "rate": round(total_ok / total_probes * 100, 1) if total_probes else None,
        },
    }


def best_ips(n=8, include_dns=True):
    """返回当前融合评分最好的 N 个 IP(按最终 score_ip 降序)。
    只取真实 IP(排除"域名整体"标签),附评分/在线率/延迟/DNS状态。
    n: 取前多少个; include_dns: 是否标注当前在 DNS 的 IP(*)。"""
    ips = set(load_pool())
    try:
        dns = current_dns_records_cached()
    except Exception:
        dns = []
    try:
        ips |= set(dns)
    except Exception:
        pass
    ips.discard(DOMAIN_LABEL)
    ips = sorted(ips)
    now = int(time.time())
    pre = batch_window_stats(ips, now)
    rows = []
    for ip in ips:
        e = pre[ip]
        s24, s7, s30 = e["h24"], e["d7"], e["d30"]
        cf = e["cfail"]
        sc = score_ip(s24, s7, s30, cf, ip)
        if sc is None:
            continue
        # itdog 分(融合前)与新鲜度
        idog = itdog_score(ip) if ITDOG_ENABLED else None
        latest = itdog_latest(ip) if ITDOG_ENABLED else None
        fr = itdog_freshness(latest.get("ts")) if latest else None
        rows.append({
            "ip": ip,
            "score": sc,
            "grade": grade_of(sc),
            "in_dns": ip in (dns or []),
            "rate_24h": s24.get("rate"),
            "med_ms": s24.get("med_ms"),
            "med_warm_ms": s24.get("med_warm_ms"),
            "p95_ms": s24.get("p95_ms"),
            "cfail": cf,
            "info": ipinfo_lookup(ip),
            "itdog_score": idog,
            "itdog_freshness": fr,
            # 这一行 itdog 分的来源: itdog / tcptest / kkce(回退源)
            "itdog_src": (latest or {}).get("src") or None,
            "samples_24h": s24.get("total"),
        })
    rows.sort(key=lambda x: -(x["score"] if x["score"] is not None else -1))
    return {
        "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "n": n,
        "pid": os.getpid(),
        "best": rows[:n],
        "dns_count": len(dns or []),
    }

# ---------------------------------------------------------------------------
# 自动换 IP:DNS 中某 IP 连续失败达到阈值 → 测候选池 → CF API 换新
# ---------------------------------------------------------------------------

def recently_failed_ips(minutes=30):
    since = int(time.time()) - minutes * 60
    with db() as c:
        return [r[0] for r in c.execute(
            "SELECT DISTINCT ip FROM probes WHERE ts>=? AND ok=0", (since,))]

def candidate_ips():
    cands, seen = [], set()
    for ip in load_pool():
        if ip not in seen:
            seen.add(ip); cands.append(ip)
    try:
        with open(ARGS.candidates, encoding="utf-8-sig", errors="replace") as f:
            for line in f:
                m = IPV4_RE.search(line)
                if m and m.group(1) not in seen:
                    seen.add(m.group(1)); cands.append(m.group(1))
    except OSError:
        pass
    return cands

# ---------------------------------------------------------------------------
# CNAME 兜底:全部 IP 失效 → 删 A 记录改 CNAME 指向公共优选域名;恢复后切回
# ---------------------------------------------------------------------------

_fallback_active = False   # probe_loop 启动时按 DNS 实际状态初始化

def _fallback_target_ok():
    """预检兜底域名:解析其 IP 后用本 Worker 的 SNI 发真实查询。"""
    try:
        infos = socket.getaddrinfo(FALLBACK_CNAME, 443, type=socket.SOCK_STREAM)
        ip = infos[0][4][0]
    except OSError:
        return False, None
    r = doh_probe(ip)
    return r["ok"], ip

def activate_fallback():
    """删除 DNS_NAME 的 A 记录,改为 CNAME 指向 FALLBACK_CNAME。"""
    global _fallback_active
    if _yield_to_peer():
        return
    ok, ip = _fallback_target_ok()
    if ok:
        log(f"[fallback] 兜底域名预检通过({ip}),切换 CNAME")
    else:
        log(f"[fallback] ⚠️ 兜底域名预检未通过({ip}),仍按计划切换")
    zid = cf_zone_id()
    existing = dns_name_records()
    # CNAME 不能与 A/AAAA 共存:全部删除,但先把 AAAA 暂存,恢复时还原
    aaaa = [r["content"] for r in existing if r["type"] == "AAAA"]
    db_meta_set("fallback_aaaa", json.dumps(aaaa))
    for rec in existing:
        cf_api("DELETE", f"/zones/{zid}/dns_records/{rec['id']}")
    cf_api("POST", f"/zones/{zid}/dns_records",
           {"type": "CNAME", "name": DNS_NAME, "content": FALLBACK_CNAME,
            "proxied": False, "ttl": 60})
    _fallback_active = True
    # 此刻确实没有 A 记录(已被 CNAME 取代):写成"已知为空",面板立刻反映
    _dns_cache.update(at=time.time(), records=[])
    msg = (f"{datetime.now().strftime('%m-%d %H:%M')} 全部 IP 失效, "
           f"已切换 CNAME 兜底 → {FALLBACK_CNAME}(恢复后自动切回)")
    db_meta_set("last_sync", msg)
    log(f"[fallback] ✅ {msg}")

def deactivate_fallback(ips):
    """删除兜底 CNAME,按传入的可用 IP 恢复 A 记录。"""
    global _fallback_active
    if _yield_to_peer():
        return
    zid = cf_zone_id()
    for rec in dns_name_records():
        cf_api("DELETE", f"/zones/{zid}/dns_records/{rec['id']}")
    for ip in ips:
        cf_api("POST", f"/zones/{zid}/dns_records",
               {"type": "A", "name": DNS_NAME, "content": ip,
                "proxied": False, "ttl": 60})
    # 还原兜底期间暂存的 AAAA 记录(IPv6 访问能力),失败不影响 IPv4
    try:
        for addr in json.loads(db_meta_get("fallback_aaaa") or "[]"):
            cf_api("POST", f"/zones/{zid}/dns_records",
                   {"type": "AAAA", "name": DNS_NAME, "content": addr,
                    "proxied": False, "ttl": 60})
    except Exception as e:
        log(f"[fallback] AAAA 恢复失败(不影响 IPv4): {type(e).__name__}: {e}")
    _fallback_active = False
    # 刚写进去的就是这些 A 记录:直接作为已知状态,面板无需等待 CF API 回读
    _dns_cache.update(at=time.time(), records=list(ips))
    msg = (f"{datetime.now().strftime('%m-%d %H:%M')} IP 已恢复, "
           f"解除 CNAME 兜底,A 记录恢复为 {', '.join(ips)}")
    db_meta_set("last_sync", msg)
    log(f"[fallback] ✅ {msg}")
    # A 记录整体换了一批(兜底期间是 CNAME): 择优的历史差距失去可比性, 清掉防抖状态
    reset_upgrade_hysteresis("解除 CNAME 兜底恢复 A 记录")

_SERVED_LOCK = threading.Lock()  # 服役时间记录的线程锁


def _served_get():
    """读 meta: {ip: 首次上 DNS 的 ts}。失败返回 {}。"""
    try:
        raw = db_meta_get("dns_served_at")
        return json.loads(raw) if raw else {}
    except Exception:
        return {}


def _served_set(served):
    try:
        db_meta_set("dns_served_at", json.dumps(served))
    except Exception:
        pass


def _touch_served(ip):
    """标记某 IP 首次上 DNS 的时间(仅当还没有记录时)。"""
    served = _served_get()
    if ip not in served:
        served[ip] = int(time.time())
        _served_set(served)


def _served_age_hours(ip):
    """某 IP 已在 DNS 上服役的小时数;无记录视为 0(刚上)。"""
    served = _served_get()
    ts = served.get(ip)
    if not ts:
        return 0.0
    return max(0.0, (time.time() - ts) / 3600.0)


def eligible_upgrade(ip, s24):
    """主动升级的资格门(只挡主动择优,不挡死亡替换):
       - 24h 样本 ≥ --min-samples
       - 24h 在线率 ≥ --min-availability
       - 当前无连续失败(连败>0 就是刚挂过,无主动升级资格)
    返回 (bool, 原因或 None)。"""
    if s24.get("total", 0) < ARGS.min_samples:
        return False, f"样本{s24.get('total',0)}<{ARGS.min_samples}"
    rate = s24.get("rate")
    if rate is None:
        return False, "无在线率"
    if rate < ARGS.min_availability:
        return False, f"在线率{rate}%<{ARGS.min_availability}%"
    cf = consecutive_failures(ip)
    if cf > 0:
        return False, f"连败{cf}"
    return True, None


def reset_upgrade_hysteresis(why):
    """DNS 被"择优之外"的路径整体改写后, 清掉择优的防抖状态。

    防抖记录(last_upgrade_gap / last_upgrade_removed / last_upgrade_ts)只在
    "同一批 DNS 记录之间互相比较"时才有意义。全量复测把 8 条整体换成"当前最快 8"
    之后, 历史差距与实际可改善空间完全脱节 —— 实测事故: 09-27 13:49 一次真实的大差距
    (某 IP 全国连通率崩到 28.6% → 差 27.4)被当成永久门槛, 而健康池子的真实差距只有
    2~4 分, 结果主动择优自此再也不触发, DNS 只能靠 8 小时复测或死亡替换更新。
    """
    try:
        db_meta_set("last_upgrade_gap", "0")
        db_meta_set("last_upgrade_removed", "")
        db_meta_set("last_upgrade_ts", "0")
        log(f"[择优] 防抖状态已重置({why})")
    except Exception as e:
        log(f"[择优] 防抖状态重置失败: {type(e).__name__}: {e}")


def upgrade_dns_selective(records):
    """每轮择优:把可用池里评分更高且通过资格门的 IP 顶上 DNS,替换最差的一个。

    触发条件(全部满足才换,且 10 分钟内最多换 1 个,避免 DNS 抖动):
      - 候选通过资格门:样本≥--min-samples, 在线率≥--min-availability, 无连败
      - 被替换者已服役 ≥ --min-serve-hours(4h)(防抖;死亡替换不受此限)
      - 评分有实打实改善:候选 base 评分 > 最差者 + --upgrade-score-gain(3)
        且该差值必须比"距上次择优时记录"更有优势(hysteresis, 换回需差 ≥ --hysteresis 5)
    评分用 base(已含 itdog freshness 融合), 不含短期连败惩罚 —— 防止"刚挂过的IP
    因惩罚分低被误换, 而真正因连续短败该被死亡替换的走 auto_sync 那条不设门槛的路径。"""
    if not records:
        return
    now = int(time.time())
    try:
        last = float(db_meta_get("last_upgrade") or 0)
    except (TypeError, ValueError):
        last = 0.0
    if now - last < UPGRADE_COOLDOWN:
        return  # 冷却中:静默(否则每轮刷屏)
    record_ips = [c for c, _ in records]
    pool = [ip for ip in load_pool() if ip not in record_ips]
    if not pool:
        return
    if _yield_to_peer():
        return

    def quality(ip):
        """返回 base 质量分(稳定+延迟,含 itdog freshness 融合), 不扣短期惩罚。"""
        s24 = window_stats(ip, now - DAY)
        base = base_score(s24, s24, s24)
        if base is None:
            return None, s24
        return itdog_blend(base, ip), s24

    # DNS 中每个 IP 的质量与资格(只考虑能评估且通过资格门的被替换候选)
    dns_q = []
    for ip in record_ips:
        q, s24 = quality(ip)
        if q is None:
            continue
        ok, why = eligible_upgrade(ip, s24)
        if not ok:
            continue
        dns_q.append((q, ip, s24))
    if not dns_q:
        return
    worst_q, worst_ip, worst_s24 = min(dns_q, key=lambda x: x[0])

    # 服役期检查:主动择优不替换服役不足的 IP
    if _served_age_hours(worst_ip) < ARGS.min_serve_hours:
        log(f"[择优] 不替换:DNS 最差 {worst_ip} 服役 "
            f"{_served_age_hours(worst_ip):.1f}h < {ARGS.min_serve_hours}h(防抖)")
        return

    # 候选:通过资格门的质量分最高者
    best_q, best_ip, best_s24, best_reason = None, None, None, None
    for ip in pool:
        q, s24 = quality(ip)
        if q is None:
            continue
        ok, why = eligible_upgrade(ip, s24)
        if not ok:
            best_reason = best_reason or ("池内候选均未过资格门: " + str(why))
            continue
        if best_q is None or q > best_q:
            best_q, best_ip, best_s24 = q, ip, s24
            best_reason = None
    if best_ip is None:
        log(f"[择优] 无候选通过资格门({'样本不足/在线率低/有连败'})({best_reason or ''})")
        return

    # 防抖(hysteresis)修正:
    #   旧实现把"上次替换时的评分差"当**全局门槛**(cur_gap ≥ prev_gap − hysteresis)。
    #   这在数学上会单向锁死: 一次真实的大差距(09-27 13:49 某 IP 全国连通率崩到 28.6%,
    #   差 27.4)把门槛永久抬到 22.4, 而健康池子的真实差距只有 2~4 分; 门槛只有在"完成一次
    #   ≥22.4 的替换"之后才会下降 —— 于是主动择优自那次之后一次都没成功过。
    #   正确语义: hysteresis 只用于抑制"刚撤下的 IP 又被换回来"这种来回抖动 —— 仅当候选
    #   恰好是刚撤下那个 IP、且仍在 FLAP_WINDOW 窗口内时才把门槛 +hysteresis; 窗口一过即
    #   恢复常规门槛, 因此任何 IP 都不会被长期锁死。
    try:
        prev_gap = float(db_meta_get("last_upgrade_gap") or 0)
    except (TypeError, ValueError):
        prev_gap = 0.0
    try:
        removed_ip = db_meta_get("last_upgrade_removed") or ""
        removed_ts = float(db_meta_get("last_upgrade_ts") or 0)
    except (TypeError, ValueError):
        removed_ip, removed_ts = "", 0.0
    cur_gap = best_q - worst_q
    flap = bool(removed_ip) and best_ip == removed_ip and (now - removed_ts) < FLAP_WINDOW
    need_gain = ARGS.upgrade_score_gain + (ARGS.hysteresis if flap else 0.0)
    if cur_gap < need_gain:
        log(f"[择优] 不替换:DNS 最差 {worst_ip}({worst_q:.1f}) "
            f"vs 候选最佳 {best_ip}({best_q:.1f}), 当前差 {cur_gap:.1f}<门槛 {need_gain:.1f}"
            + (f"(候选是 {int((now - removed_ts) / 60)} 分钟前刚撤下的 IP, 防抖 +{ARGS.hysteresis:.0f})"
               if flap else f"(上次替换差 {prev_gap:.1f})"))
        return

    zid = cf_zone_id()
    # 先加新记录再删旧记录:避免替换瞬间 DNS 少一条(空窗)
    cf_api("POST", f"/zones/{zid}/dns_records",
           {"type": "A", "name": DNS_NAME, "content": best_ip, "proxied": False, "ttl": 60})
    for content, rid in records:
        if content == worst_ip:
            cf_api("DELETE", f"/zones/{zid}/dns_records/{rid}")
    _dns_cache.update(at=0.0, records=[ip for ip in record_ips if ip != worst_ip] + [best_ip])
    db_meta_set("last_upgrade", str(now))
    db_meta_set("last_upgrade_gap", str(cur_gap))     # 仅作日志/观察, 不再当全局门槛
    db_meta_set("last_upgrade_removed", worst_ip)     # 防抖:这次撤下的 IP(FLAP_WINDOW 内不许换回)
    db_meta_set("last_upgrade_ts", str(now))          # 防抖:撤下时间
    _touch_served(worst_ip)  # 退役 IP 保留旧记录不影响(服役时间按 IP 记)
    _touch_served(best_ip)   # 新 IP 开始计服役
    msg = (f"{datetime.now().strftime('%m-%d %H:%M')} 择优替换(按base评分+hysteresis): "
           f"{worst_ip} → {best_ip}({worst_q:.1f}→{best_q:.1f}, 差 {cur_gap:.1f})")
    db_meta_set("last_sync", msg)
    log(f"[auto-sync] {msg}")

def trim_extra_dns_records(records, keep_n):
    """把多余的 A 记录裁掉,只保留 keep_n 条。

    为什么会有多余的:择优替换是"先加新记录、再删旧记录"(避免替换瞬间出现
    解析空窗)。若删除那步因 CF API 抖动失败,新旧两条就都留下 —— 每失败
    一次多一条。全量复测本来负责收敛,但它同样依赖 CF API,一卡住就只能拖到
    下一次复测(实测就是这么从 8 条漂到 10 条的)。

    裁剪顺序:先丢"样本充足但评分最低"的,再丢"样本不足"的 —— 这样刚被换上
    来、还没有 24h 样本的新记录不会被误删。
    """
    if len(records) <= keep_n:
        return 0
    now = int(time.time())
    scored, unsampled = [], []
    for content, rid in records:
        s24 = window_stats(content, now - DAY)
        if s24["total"] >= ARGS.min_samples:
            v = score_ip(s24, s24, s24, consecutive_failures(content), content)
            scored.append((v if v is not None else -1.0, content, rid))
        else:
            unsampled.append((content, rid))
    scored.sort(key=lambda x: x[0])
    order = [(c, r) for _, c, r in scored] + unsampled
    drop = order[:len(records) - keep_n]
    zid = cf_zone_id()
    for content, rid in drop:
        cf_api("DELETE", f"/zones/{zid}/dns_records/{rid}")
        log(f"[dns] 裁剪多余 A 记录: {content}(期望 {keep_n} 条,实际 {len(records)} 条)")
    dropped = {c for c, _ in drop}
    _dns_cache.update(at=time.time(),
                      records=[c for c, _ in records if c not in dropped])
    return len(drop)


def auto_sync_check():
    global _fallback_active, _last_dns_ips
    if _fallback_active:
        return
    if _yield_to_peer():
        return
    records = get_dns_records()
    record_ips = [c for c, _ in records]
    _last_dns_ips = record_ips   # 供每轮摘要复用,避免重复调用 CF API
    # 自愈:择优是"先加后删",删除失败会多留记录。这里裁回 ARGS.count 条,
    # 不依赖 8 小时一次的全量复测(它自己也会被 CF API 卡住)。
    if len(record_ips) > ARGS.count:
        try:
            trim_extra_dns_records(records, ARGS.count)
        except Exception as e:
            log(f"[auto-sync] 记录裁剪失败: {type(e).__name__}: {e}")
        records = get_dns_records()
        record_ips = [c for c, _ in records]
        _last_dns_ips = record_ips
    dead = [ip for ip in record_ips
            if consecutive_failures(ip) >= ARGS.fail_threshold]
    if not dead:
        # 没有失效 IP:做一次温和择优——可用池里的备用 IP 明显优于 DNS
        # 中最差者(评分高 15% 以上、双方样本充足、最差者近期抖动过)才替换。
        try:
            upgrade_dns_selective(records)
        except Exception as e:
            log(f"[auto-sync] 择优跳过: {type(e).__name__}: {e}")
        return
    keep = [ip for ip in record_ips if ip not in dead]
    log(f"[auto-sync] 检测到失效 IP: {', '.join(dead)}")

    # —— 三阶梯替补:先 60 池 → 再候选文件 → 仍不够才全量 sweep ——
    recent_fail = set(recently_failed_ips(30))
    need = len(dead)

    def probe_tier(ips, tier_name):
        """对一批候选做并发热探测,返回活着且排除近期失败的列表。"""
        live = []
        B = 20
        for i in range(0, len(ips), B):
            if len(live) >= need:
                break
            batch = ips[i:i + B]
            results = {}
            lock = threading.Lock()

            def work(ip):
                r = doh_probe(ip)
                with lock:
                    results[ip] = (r["ok"], r["total_ms"])

            with concurrent.futures.ThreadPoolExecutor(max_workers=10) as ex:
                list(ex.map(work, batch))
            for ip, (ok, lat) in results.items():
                if ok and ip not in recent_fail and ip not in record_ips:
                    live.append((lat, ip))
            live.sort()
            log(f"[auto-sync] {tier_name}批次 {i//B+1}: 累计可用 {len(live)}")
            if len(live) >= need:
                break
        return live

    # 第 1 层:60 可用池里未在 DNS 的(最重要——日常替换主力)
    pool_cands = [ip for ip in load_pool() if ip not in record_ips]
    live = probe_tier(pool_cands, "池内")
    # 第 2 层:60 池不够 → 候选文件补充
    if len(live) < need:
        cand_extra = [ip for ip in candidate_ips()
                      if ip not in record_ips and ip not in pool_cands]
        live2 = probe_tier(cand_extra, "候选文件")
        live.extend(live2)
        live.sort()
    # 第 3 层:还差 → 全量复测(重新发现),而不是直接 CNAME 兜底
    if len(live) < need:
        log(f"[auto-sync] 60池+候选文件仅 {len(live)}/{need} 个可用,触发全量复测重新发现")
        if not _kick_sweep(force=True):
            log("[auto-sync] 复测跑不起来或已在跑,本轮暂不替换(保底留给下轮)")
        return

    # 替换优先级:历史评分高者优先(有 ≥10 样本者),否则按延迟
    now = int(time.time())
    scored = []
    for lat, ip in live:
        s7 = window_stats(ip, now - 7 * DAY)
        if s7["total"] >= 10:
            sc = itdog_blend(base_score(s7, s7, s7), ip)
        else:
            sc = max(0.0, 60.0 - lat / 20.0)  # 无历史:延迟近似
        scored.append((sc, -lat, ip))
    scored.sort(reverse=True)
    replacements = [ip for _, _, ip in scored[:need]]
    if not replacements:
        log("[auto-sync] 候选池中也没有可用 IP,切换 CNAME 兜底")
        try:
            activate_fallback()
        except Exception as e:
            log(f"[fallback] 切换失败: {type(e).__name__}: {e}")
        return

    zid = cf_zone_id()
    # 先加新后删旧:避免替换瞬间出现 DNS 空窗
    for ip in replacements:
        cf_api("POST", f"/zones/{zid}/dns_records",
               {"type": "A", "name": DNS_NAME, "content": ip, "proxied": False, "ttl": 60})
    for content, rid in records:
        if content in dead:
            cf_api("DELETE", f"/zones/{zid}/dns_records/{rid}")
    # 死亡替换不受服役期限制,但替换完成后要开始计服役
    for ip in replacements:
        _touch_served(ip)
    msg = (f"{datetime.now().strftime('%m-%d %H:%M')} 自动换 IP: "
           f"移除 {','.join(dead)};新增 {','.join(replacements)}")
    db_meta_set("last_sync", msg)
    log(f"[auto-sync] {msg}")

# ---------------------------------------------------------------------------
# 全量复测:整个候选文件 → 按延迟取最快的 count 个同步 DNS
# ---------------------------------------------------------------------------

def _kick_sweep(force=False):
    """后台触发一轮全量复测(互斥:同一时间只跑一轮)。返回是否已启动。
    force=False 时受 --sweep-hours 最近一次复测间隔保护(避免手动/自动频繁触发)。"""
    if force:
        pass  # 手动兜底:跳过间隔保护,直接跑(仅用于"60池+候选都不够"的极端场景)
    else:
        try:
            last_sweep = float(db_meta_get("last_sweep") or 0)
        except (TypeError, ValueError):
            last_sweep = 0.0
        if ARGS.sweep_hours > 0 and time.time() - last_sweep < ARGS.sweep_hours * 3600:
            return False
    if _sweep_running.is_set():
        log("[sweep] 上一轮复测仍在进行,跳过本轮触发")
        return False
    db_meta_set("last_sweep", str(time.time()))
    def job():
        _sweep_running.set()
        try:
            sweep_all()
        except Exception as e:
            log(f"[sweep] 异常: {type(e).__name__}: {e}")
        finally:
            _sweep_running.clear()
    threading.Thread(target=job, daemon=True).start()
    log("[sweep] 全量复测已在后台启动")
    return True


def sweep_all():
    import time as _t
    started = _t.time()
    if _yield_to_peer():
        return
    cands = candidate_ips()
    if not cands:
        log("[sweep] 候选为空,跳过")
        return
    log(f"[sweep] 全量复测 {len(cands)} 个候选…")
    live = []
    lock = threading.Lock()
    B = 10

    def work(ip):
        if _stop.is_set():
            return
        r = doh_probe(ip)
        db_insert(ip, r["ok"], r["total_ms"] if r["ok"] else None,
                  r["tcp_ms"], r["reason"], src="sweep")
        with lock:
            if r["ok"]:
                live.append((r["total_ms"], ip))

    i = 0
    while i < len(cands) and not _stop.is_set():
        batch = cands[i:i + B]
        with concurrent.futures.ThreadPoolExecutor(max_workers=B) as ex:
            list(ex.map(work, batch))
        i += B
        log(f"[sweep] {min(i, len(cands))}/{len(cands)} | 可用 {len(live)}")

    now_ts = int(time.time())
    scored = []
    for lat, ip in live:
        s7 = window_stats(ip, now_ts - 7 * DAY)
        sc = itdog_blend(base_score(s7, s7, s7), ip) if s7["total"] >= 10 else max(0.0, 60.0 - lat / 20.0)
        scored.append((sc, -lat, ip))
    scored.sort(reverse=True)
    live = [(-neg_lat, ip) for _, neg_lat, ip in scored]
    now = datetime.now().strftime("%m-%d %H:%M")

    # itdog 全国评测状态
    if ITDOG_ENABLED:
        with_itdog = sum(1 for ip in [x[2] for x in scored[:LIVE_POOL_MAX]] if itdog_latest(ip))
        if with_itdog:
            log(f"[sweep] 可用池前 {LIVE_POOL_MAX} 个中有 {with_itdog} 个已有 itdog 全国分(已融合评分)")
        else:
            log("[sweep] 尚无 itdog 全国分(启用 --itdog 后台线程后会自动补齐)")

    # 中间层「可用池」:全部测活的 IP(按评分排序,上限 LIVE_POOL_MAX)
    # 写入池文件,供每 5 分钟的小池循环探测与自动换 IP 快速取用。
    live_pool = [ip for _, _, ip in scored[:LIVE_POOL_MAX]]
    if live_pool:
        try:
            with open(ARGS.pool, "w", encoding="utf-8") as f:
                f.write(chr(10).join(live_pool) + chr(10))
            log(f"[sweep] 可用池已更新: {len(live_pool)} 个 → {os.path.basename(ARGS.pool)}")
        except OSError as e:
            log(f"[sweep] 可用池写入失败: {e}")
    if _fallback_active:
        # 兜底期间:全量复测就是恢复扫描,找够了就切回 A 记录
        if len(live) >= ARGS.count:
            deactivate_fallback([ip for _, ip in live[:ARGS.count]])
        else:
            log(f"[sweep] 兜底中: 仅 {len(live)} 个可用(<{ARGS.count}),维持 CNAME 兜底")
            db_meta_set("last_sync", f"{now} 兜底复测: 仅 {len(live)} 个可用,维持 CNAME 兜底")
        return
    if len(live) < ARGS.count:
        log(f"[sweep] 可用仅 {len(live)} 个(<{ARGS.count}),DNS 保持不变")
        db_meta_set("last_sync", f"{now} 全量复测: 仅 {len(live)} 个可用,DNS 未改动")
        return

    top = [ip for _, ip in live[:ARGS.count]]
    records = get_dns_records()
    zid = cf_zone_id()
    # 先补齐目标记录,再删除多余的:整个过程 DNS 始终可用
    have = [c for c, _ in records]
    for ip in top:
        if ip not in have:
            cf_api("POST", f"/zones/{zid}/dns_records",
                   {"type": "A", "name": DNS_NAME, "content": ip,
                    "proxied": False, "ttl": 60})
    for content, rid in records:
        if content not in top:
            cf_api("DELETE", f"/zones/{zid}/dns_records/{rid}")
    msg = f"{now} 全量复测: DNS 已更新为最快 {len(top)} 个"
    db_meta_set("last_sync", msg)
    log(f"[sweep] ✅ {msg}: {', '.join(top)}")
    # DNS 已被整体重选为"当前最快 N 个": 择优的历史差距不再具备可比性, 清掉防抖状态
    # (否则一次大差距会变成永久门槛, 把主动择优锁死 —— 见 reset_upgrade_hysteresis)
    reset_upgrade_hysteresis("全量复测重选 DNS")

# ---------------------------------------------------------------------------
# tcptest 全国评测(备用源):当 itdog 被 8h 配额/风控拦截时自动回退使用。
# 标准 REST API,无需登录,无 itdog 那种硬性配额;结果自带 ip_location。
# 依赖 tcptest_api.py(本仓库 tcptest/ 目录)。
# ---------------------------------------------------------------------------

TCPTEST_API_PATH = os.path.join(BASE, "..", "tcptest")
_tcptest_api_mod = None
_tcptest_nodes = []          # 节点 uuid 缓存
_tcptest_nodes_at = 0.0
_tcptest_node_meta = {}      # uuid -> {isp, city}(来自节点元数据 operator/province/city)
TCPTEST_NODES_TTL = 3600     # 节点列表 1h 刷新一次


def _tcptest_api():
    global _tcptest_api_mod
    if _tcptest_api_mod is None:
        if TCPTEST_API_PATH not in sys.path:
            sys.path.insert(0, TCPTEST_API_PATH)
        import tcptest_api as m
        _tcptest_api_mod = m
    return _tcptest_api_mod


def _join_region(province, city):
    """把 省 + 市 合并成 itdog/kkce 惯用的"地区"写法(省+市)。

    三个来源的 itdog_nodes.city 必须粒度一致, 否则面板的"地区"列与筛选会错乱:
      itdog: "广东东莞" / "山东济南2"(省+市, 站点自带序号)  |  kkce: "广东广州"(省+市, node_name)
      tcptest 节点列表则是 province="广东" + city="广州" 两个独立字段 → 这里合并。
    港澳台/直辖市/海外会出现 省==市(如 香港/香港、海外/海外) → 去重, 只留一个。
    """
    p = (province or "").strip()
    c = (city or "").strip()
    if not p:
        return c
    if not c:
        return p
    if p == c:
        return c
    if c.startswith(p) or p.startswith(c):      # 已经是"广东省广州市"或"广州/广州市"
        return c if len(c) >= len(p) else p
    return p + c


def _tcptest_nodes_full():
    """拉取(带缓存)tcptest 节点: 返回 (uuids, {uuid: {isp, city}})。

    地区/运营商**必须**取自节点元数据, 不能用结果里的 ip_location:
      - 节点元数据(/api/v1/nodes): country / province / city / **operator**(运营商) —— 权威
      - 结果里的 ip_location: 形如 "中国/浙江" —— **只有国家/省份, 根本没有运营商**
    旧实现把 ip_location 最后一段当 isp, 于是两段值时 isp==city(实测大量 "香港"/"香港"),
    更短时 isp 与 city 双双为空(实测 473 行), 全国节点的地区/运营商识别因此是错的。
    """
    global _tcptest_nodes, _tcptest_nodes_at, _tcptest_node_meta
    if _tcptest_nodes and time.time() - _tcptest_nodes_at < TCPTEST_NODES_TTL:
        return _tcptest_nodes, _tcptest_node_meta
    try:
        api = _tcptest_api()
        uuids, meta, cursor = [], {}, "0"
        while True:
            st, d = api.request("GET", "/api/v1/nodes?after=%s&limit=500" % cursor)
            if st != 200:
                raise RuntimeError("nodes fetch failed: %s" % str(d)[:120])
            for n in d.get("nodes", []):
                u = n.get("uuid")
                if not u:
                    continue
                uuids.append(u)
                meta[u] = {
                    "isp": (n.get("operator") or "").strip(),
                    # city 存"省+市"(与 itdog/kkce 粒度一致); city 缺失时退回 display_location/name
                    "city": _join_region(
                        n.get("province"),
                        n.get("city") or n.get("display_location") or n.get("name")),
                }
            if not d.get("has_more"):
                break
            cursor = d["next_cursor"]
        if uuids:
            _tcptest_nodes, _tcptest_node_meta = uuids, meta
            _tcptest_nodes_at = time.time()
            log(f"[tcptest] 节点刷新: {len(uuids)} 个(含地区/运营商元数据)")
        return _tcptest_nodes or [], _tcptest_node_meta
    except Exception as e:
        log(f"[tcptest] 节点拉取失败: {type(e).__name__}: {e}")
        return _tcptest_nodes or [], _tcptest_node_meta


def _tcptest_node_uuids():
    """拉取(带缓存)tcptest 全部可用节点 uuid。失败返回 []。"""
    return _tcptest_nodes_full()[0]


def tcptest_single(ip):
    """用 tcptest 对单个 IP 跑一次 tcping:<port>, 返回与 itdog_single 同构:
    {ok_node, fail_node, med_rtt, p95, nodes:[{node_id,isp,city,result,ip}], source:"tcptest"}
    失败返回 None。node_id 用 tcptest 的 uuid;地区/运营商取自节点元数据(见 _tcptest_nodes_full)。"""
    api = _tcptest_api()
    uuids, node_meta = _tcptest_nodes_full()
    if not uuids:
        return None
    target = f"{ip}:{ARGS.itdog_port}"
    try:
        payload, task_id, cancel = api.build_payload(target, uuids)
        st, d = api.request("POST", "/api/v2/tasks", payload,
                            {"Idempotency-Key": task_id, "X-Task-Cancel-Token": cancel})
        if st != 202:
            log(f"[tcptest] {ip} 建任务失败(HTTP {st}): {str(d)[:120]}")
            return None
    except Exception as e:
        log(f"[tcptest] {ip} 建任务异常: {type(e).__name__}: {e}")
        return None
    # 轮询快照到结束
    try:
        for _ in range(60):
            time.sleep(2)
            _st, d = api.request("GET", f"/api/v2/tasks/{task_id}")
            if _st == 200 and d.get("state") in ("succeeded", "partial", "failed", "cancelled"):
                break
    except Exception as e:
        log(f"[tcptest] {ip} 轮询异常: {type(e).__name__}: {e}")
    # 翻页取结果
    results = []
    try:
        cursor = "0"
        while True:
            _st, d = api.request("GET", f"/api/v2/tasks/{task_id}/results?after={cursor}&limit=100")
            if _st != 200:
                break
            results += d.get("results", [])
            if not d.get("has_more"):
                break
            cursor = d["next_cursor"]
    except Exception as e:
        log(f"[tcptest] {ip} 取结果异常: {type(e).__name__}: {e}")
    # 取消任务(收尾;失败不影响)
    try:
        api.request("DELETE", f"/api/v2/tasks/{task_id}", None,
                    {"X-Task-Cancel-Token": cancel})
    except Exception:
        pass
    # 汇总: 成功节点取 data.duration_ms; 失败节点 error 非空
    ok_ms, fail = [], 0
    nodes = []
    for r in results:
        if not r.get("final"):
            continue
        node_uuid = r.get("node_uuid", "")
        data = r.get("data") or {}
        succ = bool(r.get("success"))
        dur = data.get("duration_ms")
        # ⚠️ 地区只能取**节点元数据**(节点列表的 province/city/operator, 与目标无关)。
        #    结果里的 ip_location / resolved_ip / asn 是"**目标域名在该节点解析到的 CDN 边缘**"
        #    的归属地, 形如 "中国/河北省/石家庄市/移动"(国家/省/市/运营商), 会随目标变化 ——
        #    实测同一节点在 baidu.com 与 www.qq.com 下 154/154 条 ip_location 全不相同。
        #    旧代码把它当节点地区, 属于概念错位(不只是解析错): 香港节点会被标成"河北保定联通"。
        #    元数据缺失时宁可留空, 也不拿目标边缘的归属地冒充节点地区。
        nm = node_meta.get(node_uuid) or {}
        nodes.append({
            "node_id": node_uuid,
            "isp": nm.get("isp", ""),
            "city": nm.get("city", ""),
            "result": None if not succ else dur,
            # node_ip: 该节点实际连上的目标 IP(它解析到的 CDN 边缘), 与 itdog 口径一致;
            # 取不到时退回目标字符串。想直接看边缘归属地可查 data.ip_location。
            "ip": (data.get("resolved_ip") or ip),
        })
        if succ and dur is not None:
            try:
                ok_ms.append(float(dur))
            except (TypeError, ValueError):
                fail += 1
        else:
            fail += 1
    if not ok_ms and fail == 0:
        return None
    srt = sorted(ok_ms)
    med = srt[len(srt) // 2] if srt else None
    p95 = srt[min(len(srt) - 1, int(len(srt) * 0.95))] if srt else None
    return {"ok_node": len(ok_ms), "fail_node": fail,
            "med_rtt": round(med, 1) if med is not None else None,
            "p95": round(p95, 1) if p95 is not None else None,
            "nodes": nodes, "source": "tcptest"}


# ---------------------------------------------------------------------------
# kkce 全国评测(第二备用源):itdog、tcptest 均不可用时回退。节点最多(约314),
# 无验证码(仅 CDN cookie),共享 WS 端点。依赖 kkce_api.py(tcptest/ 同级 kkce/)。
# ---------------------------------------------------------------------------

KKCE_API_PATH = os.path.join(BASE, "..", "kkce")
_kkce_api_mod = None


def _kkce_api():
    global _kkce_api_mod
    if _kkce_api_mod is None:
        if KKCE_API_PATH not in sys.path:
            sys.path.insert(0, KKCE_API_PATH)
        import kkce_api as m
        _kkce_api_mod = m
    return _kkce_api_mod


def _kkce_time_ms(txt):
    """把 '10.440ms' / '0.00%' 之类带单位字符串解析成 float;失败返回 None。"""
    if txt is None:
        return None
    try:
        return float(str(txt).replace("ms", "").replace("%", "").strip())
    except (TypeError, ValueError):
        return None


def kkce_single(ip):
    """用 kkce.com 对单个 IP 跑一次 tcping:<port>, 返回与 itdog_single 同构:
    {ok_node, fail_node, med_rtt, p95, nodes:[{node_id,isp,city,result,ip}], source:"kkce"}
    失败返回 None。node_name 作 city,node_isp 作 isp,result 取 s_avg_time。

    ⚠️ 必须用**同一个 Session** 建任务并连 WS: kkce 的 WS 是共享端点
    (wss://www.kkce.com/upgrade), 服务端**按会话 Cookie(s_token) 关联任务**。
    旧实现在这里写了两个 api.Session() —— 连 WS 的那个是空 jar, 于是每次都
    "0 项、0.1 秒"返回, 第三优先回退源长期形同虚设(线上日志表现为
    "kkce 无结果" 且 1 秒内就落到 tcptest)。
    """
    api = _kkce_api()
    session = api.Session()
    try:
        st, html = api.start_task(session, ip, port=str(ARGS.itdog_port))
        if st != 200:
            log(f"[kkce] {ip} 建任务失败(HTTP {st})")
            return None
        results, count, _others = api.collect_results(session, timeout=120)
    except Exception as e:
        log(f"[kkce] {ip} 建任务/收结果异常: {type(e).__name__}: {e}")
        return None
    ok_ms, fail = [], 0
    nodes = []
    for it in results:
        r = it.get("tcp_ping_check_resp") or {}
        node_id = str(r.get("node_id", ""))
        name = r.get("node_name", "") or ""
        isp = r.get("node_isp", "") or ""
        status = r.get("s_status", "")
        avg = _kkce_time_ms(r.get("s_avg_time"))
        nodes.append({
            "node_id": node_id,
            "isp": isp,
            "city": name,
            "result": round(avg, 1) if status == "1" and avg is not None else None,
            "ip": ip,
        })
        if status == "1" and avg is not None:
            ok_ms.append(avg)
        else:
            fail += 1
    if not ok_ms and fail == 0:
        return None
    srt = sorted(ok_ms)
    med = srt[len(srt) // 2] if srt else None
    p95 = srt[min(len(srt) - 1, int(len(srt) * 0.95))] if srt else None
    return {"ok_node": len(ok_ms), "fail_node": fail,
            "med_rtt": round(med, 1) if med is not None else None,
            "p95": round(p95, 1) if p95 is not None else None,
            "nodes": nodes, "source": "kkce"}


# ---------------------------------------------------------------------------
# itdog 全国评测:后台线程,对可用池 top-N 逐个跑 itdog tcping:443,
# 得到全国 305 节点的连通成功率 + RTT,入库后融合进 score_ip。
# 需要 itdog_api.py(本仓库 itdog/ 目录)与 websockets 库。
# 默认关闭(--itdog 开启),不主动连外网,不影响原有监控行为。
# ---------------------------------------------------------------------------

ITDOG_API_PATH = os.path.join(BASE, "..", "itdog")
_itdog_api_mod = None

def _itdog_api():
    """懒加载 itdog/itdog_api.py(避免未启用时引入任何额外依赖/IO)。"""
    global _itdog_api_mod
    if _itdog_api_mod is None:
        if ITDOG_API_PATH not in sys.path:
            sys.path.insert(0, ITDOG_API_PATH)
        import itdog_api as m
        _itdog_api_mod = m
    return _itdog_api_mod

_NODE_TR_RE = re.compile(r'<tr class="node_tr" node="([^"]+)"[^>]*>(.*?)</tr>', re.S)
_NODE_BADGE_RE = re.compile(r'badge badge-(?:success|warning|info|secondary)"[^>]*>\s*([^<]+?)\s*</span>\s*([^<]+)', re.S)


def _parse_itdog_node_map(html):
    """从 itdog 结果页 HTML 解析 node_id -> {isp, city}。
    结果页每行 <tr class="node_tr" node="<id>"> 内含
    <span class="badge badge-success">电信</span> 湖北襄阳, 即运营商+城市。"""
    out = {}
    if not html:
        return out
    for m in _NODE_TR_RE.finditer(html):
        nid, inner = m.group(1), m.group(2)
        bm = _NODE_BADGE_RE.search(inner)
        if bm:
            out[nid] = {"isp": bm.group(1).strip(), "city": bm.group(2).strip()}
    return out


def itdog_single(ip):
    """对单个 IP 跑一次 itdog tcping:<port>。
    返回 {ok_node, fail_node, med_rtt, p95, nodes:[{node_id,isp,city,result,ip}]}
    失败(建任务失败/无结果)返回 None。nodes 为节点级明细(可空)。"""
    try:
        api = _itdog_api()  # 依赖缺失(如 itdog/ 目录未随部署带上)也只让这一个 IP 失败
        info = api.start_task(f"{ip}:{ARGS.itdog_port}", "tcping")
    except Exception as e:
        log(f"[itdog] {ip} 建任务失败: {type(e).__name__}: {e}")
        return None
    node_map = _parse_itdog_node_map(info.get("html") or "")
    # itdog 被风控时会返回"装饰性任务": check_node_num 骤降到几十(实测 39),
    # 结果页也真只有那几十行, 但 WS 一条结果都不推 —— 直接判为被拦, 别白等 WS 超时。
    if 0 < info.get("check_node_num", 0) < ARGS.itdog_min_nodes:
        log(f"[itdog] {ip} 返回可疑任务(check_node_num={info.get('check_node_num')} "
            f"< {ARGS.itdog_min_nodes}), 视为被拦, 跳过 WS")
        return None
    try:
        # 传 expected_nodes 收满即走: itdog 305 节点几秒到齐, 别空等 finished(常缺省)
        results, _ = api.collect_results(
            info["task_id"], info["wss_url"], timeout=120,
            expected_nodes=info.get("check_node_num", 0))
    except Exception as e:
        log(f"[itdog] {ip} 收结果失败: {type(e).__name__}: {e}")
        return None
    ok_ms, fail = [], 0
    nodes = []
    for m in results:
        if m.get("type") == "finished":
            continue  # finished 是结束哨兵, 不是节点; 漏掉会让 fail 多算 1 个
        res = m.get("result")
        node_id = m.get("node_id", "")
        ipv = m.get("ip", "")
        node_meta = node_map.get(node_id) or {}
        nodes.append({
            "node_id": node_id,
            "isp": node_meta.get("isp", ""),
            "city": node_meta.get("city", ""),
            "result": res,
            "ip": ipv,
        })
        if res == "-1" or ipv == "0.0.0.0" or res is None:
            fail += 1
        else:
            try:
                ok_ms.append(float(res))
            except (TypeError, ValueError):
                fail += 1
    if not ok_ms and fail == 0:
        return None
    srt = sorted(ok_ms)
    med = srt[len(srt) // 2] if srt else None
    p95 = srt[min(len(srt) - 1, int(len(srt) * 0.95))] if srt else None
    return {"ok_node": len(ok_ms), "fail_node": fail,
            "med_rtt": round(med, 1) if med is not None else None,
            "p95": round(p95, 1) if p95 is not None else None,
            "nodes": nodes}

def write_itdog_rank():
    """把可用池内所有 IP 的融合评分(本地 + itdog)写到 --itdog-rankfile,供人工查看排序。"""
    try:
        pool = load_pool()
    except Exception:
        return
    now = int(time.time())
    rows = []
    for ip in pool:
        s24 = window_stats(ip, now - DAY)
        local = score_ip(s24, s24, s24, consecutive_failures(ip))  # 面板口径(含短期连败惩罚)
        local_base = base_score(s24, s24, s24)                     # 长期质量(不含惩罚)
        idog = itdog_score(ip)
        latest = itdog_latest(ip)
        fr = itdog_freshness(latest["ts"]) if latest else None
        # merged 改用与 /api/best、择优同一个 itdog_blend(含 w×freshness 衰减),
        # 不再用固定权重 w —— 旧写法不乘 freshness 也不扣惩罚, 数据超过 12h 后
        # 与面板/择优的口径就越差越远, 人工照本文件挑 IP 会挑错。
        # 注: 这里基于 local_base(不含短期连败惩罚), 与"择优"的 quality() 完全一致;
        # /api/best 的 score 会在融合后再扣一次惩罚, 故本文件的 merged_score 可能略高。
        merged = itdog_blend(local_base, ip)
        row = {
            "ip": ip, "local_score": local, "local_base": local_base,
            "itdog_score": idog, "itdog_freshness": fr,
            "w_eff": round(ARGS.itdog_weight * (fr or 0.0), 3),
            "source": (latest or {}).get("src") or None,
            "merged_score": merged,
            "itdog": latest,
        }
        if latest:
            # 附带最新一轮的节点级明细(每个节点 运营商/城市/延迟/目标IP)
            row["nodes"] = itdog_nodes_latest(ip)
        rows.append(row)
    rows.sort(key=lambda r: -(r["merged_score"] if r["merged_score"] is not None else -1))
    try:
        with open(ARGS.itdog_rankfile, "w", encoding="utf-8") as f:
            json.dump({
                "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "weight_itdog": ARGS.itdog_weight,
                "rows": rows,
            }, f, ensure_ascii=False, indent=2)
        log(f"[itdog] 综合排行已写入 {os.path.basename(ARGS.itdog_rankfile)}")
    except OSError as e:
        log(f"[itdog] 排行写入失败: {e}")

def itdog_eval_round():
    """整轮 itdog 评测:按融合前本地评分取池内 top-N → 逐个测 → 入库。
    返回评测成功的 IP 数;整个退出(不中断监控)。

    _itdog_busy 互斥(修复):
      - 已在评测(自动轮或手动轮)时**直接跳过**, 不再"看到已 set 还往下跑";
        旧实现只在 /api/itdog/run 入口查锁, 定时轮完全不查, 于是"手动轮进行中 +
        24h 定时到点"会并发跑两轮 —— 对 itdog 的请求速率翻倍(正是最怕的频率风控),
        而且两个线程同时写 itdog-rank.json。
      - 锁一律由 finally 释放:旧实现在"池为空"早退(pool 空 → return 0)时不会清锁,
        _itdog_busy 永久停在 set 状态, 之后 /api/itdog/run 永远回"上一轮评测仍在进行"
        (提示还误导), 只能重启进程才能恢复。"""
    if _itdog_busy.is_set():
        log("[itdog] 上一轮评测仍在进行,跳过本轮")
        return 0
    _itdog_busy.set()
    try:
        return _itdog_eval_round_locked()
    finally:
        _itdog_busy.clear()


def _itdog_eval_round_locked():
    """评测实体(调用方 itdog_eval_round 已持有 _itdog_busy)。"""
    pool = load_pool()
    if not pool:
        log("[itdog] 池为空,跳过本轮")
        return 0
    now = int(time.time())
    scored = []
    for ip in pool:
        s24 = window_stats(ip, now - DAY)
        if s24["rate"] is None:
            continue
        sc = score_ip(s24, s24, s24, consecutive_failures(ip))  # 纯本地分排序
        scored.append((sc if sc is not None else -1.0, ip))
    scored.sort(reverse=True)
    top = [ip for _, ip in scored[:ARGS.itdog_top]]
    log(f"[itdog] 本轮评测 {len(top)} 个(top-{ARGS.itdog_top} by 本地分): "
        f"{', '.join(top[:6])}{' ...' if len(top) > 6 else ''}")
    ok_n = 0
    fallback_n = 0
    itdog_block = [0]        # itdog 连续被拦计数(见 --itdog-break-after 熔断)
    for i, ip in enumerate(top, 1):
        if _stop.is_set():
            break
        # 熔断: itdog 连续被拦(验证码页 / 39 节点装饰任务)达到阈值后, 本轮剩余 IP 不再试 itdog,
        # 直接走回退源 —— 省掉几十次注定失败的请求, 也避免把风控越撞越死。
        r = None
        if itdog_block[0] < ARGS.itdog_break_after:
            r = itdog_single(ip)
            if r is None:
                itdog_block[0] += 1
                if itdog_block[0] >= ARGS.itdog_break_after and i < len(top):
                    log(f"[itdog] itdog 连续 {itdog_block[0]} 次被拦(验证码/可疑任务) → "
                        f"本轮剩余 {len(top) - i} 个 IP 直接走回退源")
            else:
                itdog_block[0] = 0
        if r is None:
            # itdog 被配额/风控拦:回退到 kkce(第二优先)
            why = "itdog 已熔断" if itdog_block[0] >= ARGS.itdog_break_after else "itdog 无结果"
            log(f"[itdog] ({i}/{len(top)}) {ip} {why},尝试 kkce 回退")
            r = kkce_single(ip)
            if r is None:
                # kkce 也失败:改用 tcptest 兜底(第三)
                log(f"[itdog] ({i}/{len(top)}) {ip} kkce 无结果,尝试 tcptest 回退")
                r = tcptest_single(ip)
                if r is None:
                    log(f"[itdog] ({i}/{len(top)}) {ip} tcptest 也无结果,跳过入库")
                    if i < len(top):
                        _stop.wait(max(5, ARGS.itdog_sleep))
                    continue
            fallback_n += 1
        sr = round(r["ok_node"] / max(1, r["ok_node"] + r["fail_node"]) * 100, 1)
        now_ts = int(time.time())
        src_tag = r.get("source") or "itdog"
        # 来源一并入库: 回退源(tcptest/kkce)的节点数与地区口径和 itdog 不同, 事后必须能区分
        db_itdog_insert(ip, sr, r["med_rtt"], r["p95"],
                        r["ok_node"] + r["fail_node"], src=src_tag)
        try:
            if r.get("nodes"):
                db_itdog_nodes_insert(ip, now_ts, r["nodes"])
        except Exception as e:
            log(f"[itdog] {ip} 节点明细入库失败: {type(e).__name__}: {e}")
        log(f"[itdog] ({i}/{len(top)}) {ip} ({src_tag}): 连通率 {sr}% "
            f"({r['ok_node']}/{r['ok_node']+r['fail_node']}) 中位 {r['med_rtt']}ms p95 {r['p95']}ms")
        ok_n += 1
        if i < len(top):
            _stop.wait(max(5, ARGS.itdog_sleep))
    try:
        db_meta_set("itdog_last", f"{datetime.now().strftime('%m-%d %H:%M')} "
                                   f"评测 {len(top)} 个(成功 {ok_n}, 其中回退源 {fallback_n})")
        # itdog 是否整轮被拦(给面板/日志提示: 需要人工过验证码, 或已被回退源接管)
        if fallback_n and itdog_block[0] >= ARGS.itdog_break_after:
            db_meta_set("itdog_blocked",
                        f"{datetime.now().strftime('%m-%d %H:%M')} itdog 连续被拦(验证码/可疑任务), "
                        f"本轮 {fallback_n}/{len(top)} 个改用回退源(kkce/tcptest)")
        else:
            db_meta_set("itdog_blocked", "")
    except Exception:
        pass
    try:
        write_itdog_rank()
    except Exception as e:
        log(f"[itdog] 排行写入异常: {type(e).__name__}: {e}")
    return ok_n

def _itdog_run_thread():
    """后台线程包装:被 /api/itdog/run 触发时调用;异常兜底并释放 busy 锁。"""
    try:
        itdog_eval_round()
    except Exception as e:
        log(f"[itdog] 手动评测异常: {type(e).__name__}: {e}")
        try:
            _itdog_busy.clear()
        except Exception:
            pass

_itdog_busy = threading.Event()  # itdog 评测互斥:自动轮/手动轮不并发

def itdog_loop():
    """后台调度线程:按 --itdog-hours 周期跑 itdog_eval_round();周期 0 表示只在启动后跑一次。"""
    if not ITDOG_ENABLED:
        return
    if ARGS.itdog_hours <= 0:
        try:
            itdog_eval_round()
        except Exception as e:
            log(f"[itdog] 评测异常: {type(e).__name__}: {e}")
        return
    last = 0.0
    while not _stop.is_set():
        if time.time() - last >= ARGS.itdog_hours * 3600:
            last = time.time()
            try:
                itdog_eval_round()
            except Exception as e:
                log(f"[itdog] 评测异常: {type(e).__name__}: {e}")
                try:
                    _itdog_busy.clear()
                except Exception:
                    pass
        _stop.wait(60)

# ---------------------------------------------------------------------------
# 域名监控:对 --monitor-domains 列表每 --interval 检测一次
#   端到端: 系统 DNS 解析域名 -> 连解析出的 IP(SNI=域名) -> DoH 查询
#   频率 = --interval(10min), 与 monitor 对 DoH 主域的域名整体探针一致。
# 结果存 domain_status(每域名一行), 不参与 IP 评分。新建 /abc 页面展示。
# ---------------------------------------------------------------------------

def doh_probe_named(domain, ip):
    """对指定域名+IP 做一次通用 HTTPS 连通探测(SNI=domain, GET /, 2xx/3xx 视为可达)。
    适用于任何网站(Worker / Pages / 普通站点), 不假定有 DoH 路径。
    返回 {ok, total_ms, tcp_ms, status, reason};解析失败返回 ok=False。"""
    started = time.time()
    CRLF = "\r\n"
    try:
        raw = socket.create_connection((ip, 443), timeout=ARGS.timeout / 1000)
        tcp_ms = int((time.time() - started) * 1000)
        try:
            tls = TLS_CTX.wrap_socket(raw, server_hostname=domain)
        except Exception:
            raw.close()
            raise
        try:
            head = (
                f"GET / HTTP/1.1{CRLF}"
                f"Host: {domain}{CRLF}"
                f"user-agent: {UA}{CRLF}"
                f"accept: */*{CRLF}"
                f"connection: close{CRLF}{CRLF}"
            )
            tls.sendall(head.encode("ascii"))
            buf = b""
            tls.settimeout(ARGS.timeout / 1000)
            while True:
                chunk = tls.recv(4096)
                if not chunk:
                    break
                buf += chunk
                if len(buf) > 65536:
                    break
        finally:
            tls.close()
        sep = buf.find(b"\r\n\r\n")
        if sep < 0:
            return {"ok": False, "total_ms": int((time.time()-started)*1000), "tcp_ms": tcp_ms,
                    "status": 0, "reason": "无HTTP响应"}
        head_s = buf[:sep].decode("utf-8", "replace")
        m = re.search(r"HTTP/[\d.]+ (\d{3})", head_s)
        status = int(m.group(1)) if m else 0
        ok = 200 <= status < 400   # 2xx/3xx 视为可达
        return {"ok": ok, "total_ms": int((time.time()-started)*1000), "tcp_ms": tcp_ms,
                "status": status, "reason": "" if ok else f"HTTP {status}"}
    except socket.timeout:
        return {"ok": False, "total_ms": int((time.time()-started)*1000), "tcp_ms": None,
                "status": 0, "reason": "超时"}
    except ssl.SSLCertVerificationError:
        return {"ok": False, "total_ms": int((time.time()-started)*1000), "tcp_ms": None,
                "status": 0, "reason": "证书不匹配"}
    except Exception as e:
        return {"ok": False, "total_ms": int((time.time()-started)*1000), "tcp_ms": None,
                "status": 0, "reason": f"{type(e).__name__}"}


def probe_domain_national_target(domain):
    """对域名做全国 tcping(各节点自己 DNS 解析域名再连), 三级回退。
    返回 dict {rate, med_rtt, p95, ok_node, fail_node, src, nodes:[...]} 或 None。
    nodes 与 itdog_single/tcptest_single/kkce_single 同构: {node_id,isp,city,result,ip}。"""
    # itdog
    try:
        api = _itdog_api()
        info = api.start_task(f"{domain}:{ARGS.itdog_port}", "tcping")
        node_map = _parse_itdog_node_map(info.get("html") or "")
        # 同 itdog_single: check_node_num 骤降(实测 39) = itdog 被风控给的装饰任务, WS 不会有结果
        if 0 < info.get("check_node_num", 0) < ARGS.itdog_min_nodes:
            raise RuntimeError(f"itdog 返回可疑任务(check_node_num={info.get('check_node_num')}), 视为被拦")
        results, _ = api.collect_results(info["task_id"], info["wss_url"], timeout=90,
                                         expected_nodes=info.get("check_node_num", 0))
        ok_ms, fail = [], 0
        nodes = []
        for m in results:
            if m.get("type") == "finished":
                continue  # 结束哨兵不计入节点统计(node_error 要保留: 它代表节点离线)
            res = m.get("result")
            node_id = m.get("node_id", "")
            ipv = m.get("ip", "")
            meta = node_map.get(node_id) or {}
            nodes.append({"node_id": node_id, "isp": meta.get("isp",""), "city": meta.get("city",""),
                          "result": None if res in ("-1", None) or ipv == "0.0.0.0" else res, "ip": ipv})
            if res in ("-1", None) or ipv == "0.0.0.0":
                fail += 1
            else:
                try:
                    ok_ms.append(float(res))
                except (TypeError, ValueError):
                    fail += 1
        if ok_ms:
            srt = sorted(ok_ms)
            med = srt[len(srt)//2]; p95 = srt[min(len(srt)-1, int(len(srt)*0.95))]
            rate = round(len(ok_ms)/max(1, len(ok_ms)+fail)*100, 1)
            return {"rate": rate, "med_rtt": round(med,1), "p95": round(p95,1),
                    "ok_node": len(ok_ms), "fail_node": fail, "src": "itdog", "nodes": nodes}
    except Exception as e:
        log(f"[abc] {domain} itdog 域名检测失败: {type(e).__name__}: {e}")
    # tcptest
    try:
        rr = tcptest_single(domain)
        if rr:
            return {"rate": round(rr["ok_node"]/max(1, rr["ok_node"]+rr["fail_node"])*100,1),
                    "med_rtt": rr["med_rtt"], "p95": rr["p95"],
                    "ok_node": rr["ok_node"], "fail_node": rr["fail_node"],
                    "src": "tcptest", "nodes": rr.get("nodes") or []}
    except Exception as e:
        log(f"[abc] {domain} tcptest 域名检测失败: {type(e).__name__}: {e}")
    # kkce
    try:
        rk = kkce_single(domain)
        if rk:
            return {"rate": round(rk["ok_node"]/max(1, rk["ok_node"]+rk["fail_node"])*100,1),
                    "med_rtt": rk["med_rtt"], "p95": rk["p95"],
                    "ok_node": rk["ok_node"], "fail_node": rk["fail_node"],
                    "src": "kkce", "nodes": rk.get("nodes") or []}
    except Exception as e:
        log(f"[abc] {domain} kkce 域名检测失败: {type(e).__name__}: {e}")
    return None


def domain_monitor_once():
    """对 --monitor-domains 列表逐个做检测:
       ① 通用连通: 系统 DNS 解析域名 -> 连解析出的 IP(SNI=域名) -> GET / (2xx/3xx)
       ② 全国 itdog: 对域名 tcping(itdog->tcptest->kkce 三级回退)
       频率 = --interval(10min)。结果存 domain_status。"""
    domains = [d.strip() for d in (ARGS.monitor_domains or "").split(",") if d.strip()]
    if not domains:
        return
    now = int(time.time())
    for dom in domains:
        ip = None
        r = {"ok": False, "total_ms": None, "tcp_ms": None, "reason": ""}
        try:
            infos = socket.getaddrinfo(dom, 443, type=socket.SOCK_STREAM)
            ip = next((i[4][0] for i in infos if i[0] == socket.AF_INET), infos[0][4][0])
            r = doh_probe_named(dom, ip)
        except Exception as e:
            r["reason"] = type(e).__name__
            log(f"[abc] {dom} 解析/探测异常: {type(e).__name__}: {e}")
        # ② 全国 itdog(三级回退)
        nat = probe_domain_national_target(dom)
        nodes = []
        if nat:
            rate, med, p95, src = nat["rate"], nat["med_rtt"], nat["p95"], nat["src"]
            nodes = nat.get("nodes") or []
            log(f"[abc] {dom} 全国: {rate}% 中位{med}ms p95{p95} [{src}] ({len(nodes)}节点)")
        else:
            rate = med = p95 = src = None
            log(f"[abc] {dom} 全国: 三源均失败")
        with db() as c:
            c.execute("""INSERT INTO domain_status(domain,resolve_ip,e2e_ok,e2e_total,e2e_latency_ms,
                         itdog_rate,itdog_med_rtt,itdog_nodes,itdog_ts,last_ts,itdog_src)
                         VALUES(?,?,?,?,?,?,?,?,?,?,?)
                         ON CONFLICT(domain) DO UPDATE SET
                           resolve_ip=excluded.resolve_ip, e2e_ok=excluded.e2e_ok, e2e_total=excluded.e2e_total,
                           e2e_latency_ms=excluded.e2e_latency_ms,
                           itdog_rate=excluded.itdog_rate, itdog_med_rtt=excluded.itdog_med_rtt,
                           itdog_nodes=excluded.itdog_nodes, itdog_ts=excluded.itdog_ts,
                           itdog_src=excluded.itdog_src, last_ts=excluded.last_ts""",
                      (dom, ip, 1 if r.get("ok") else 0, 1, r.get("total_ms"),
                       rate, med, len(nodes), now if nat else None, now, src))
        # 存节点明细(只留最新一轮)
        if nodes:
            with db() as c:
                c.execute("DELETE FROM domain_nodes WHERE domain=?", (dom,))
                c.executemany(
                    "INSERT INTO domain_nodes(domain,round_ts,node_id,isp,city,result,node_ip) VALUES(?,?,?,?,?,?,?)",
                    [(dom, now, n.get("node_id",""), n.get("isp",""), n.get("city",""),
                      n.get("result"), n.get("ip","")) for n in nodes])
        log(f"[abc] {dom}: 解析 {ip} 端到端 {'OK' if r.get('ok') else 'FAIL'} ({r.get('total_ms')}ms)")


def domain_monitor_loop():
    """后台线程:每 --interval(10min) 跑一次域名端到端监控(与 monitor 域名探针同频)。"""
    last = 0.0
    while not _stop.is_set():
        if time.time() - last >= max(5, ARGS.interval):
            last = time.time()
            try:
                domain_monitor_once()
            except Exception as e:
                log(f"[abc] 域名监控异常: {type(e).__name__}: {e}")
        _stop.wait(5)


# ---------------------------------------------------------------------------
# 反代域名 IP 巡检(可选, --ntprxx-patrol;域名取自 .monitor.env 的 NTPRXX_DOMAIN)
#   与 DoH 主域(monitor 自己管 --count 条 A)相互独立:
#   本域名固定 --ntprxx-keep 条(默认 3)灰云 A, 规则 =
#     ① 初始/对齐: 按 itdog 全国分取**最优 N 个**(--ntprxx-align 或首次启用时)
#     ② 常态: 逐个 IP 做全国连通率检测, **任一低于 --ntprxx-threshold(默认 95%)** 才替换
#   替换候选同样取"池内 itdog 最优且未在用"的 IP; 先加后删, 删失败重试 + 超量裁剪。
# ---------------------------------------------------------------------------

_NTPRXX_ZONE_CACHE = [None]


def _ntprxx_zone_id():
    """ntprxx 域名的 zone id: 显式参数优先, 否则按域名匹配 token 可见的 zone。"""
    if ARGS.ntprxx_zone:
        return ARGS.ntprxx_zone
    if _NTPRXX_ZONE_CACHE[0]:
        return _NTPRXX_ZONE_CACHE[0]
    zones = cf_api("GET", "/zones?per_page=50")
    dom = ARGS.ntprxx_domain
    z = next((x for x in (zones or [])
              if dom == x.get("name") or dom.endswith("." + (x.get("name") or ""))), None)
    if not z:
        raise RuntimeError(f"token 无法访问包含 {dom} 的 zone")
    _NTPRXX_ZONE_CACHE[0] = z["id"]
    return z["id"]


def ntprxx_records():
    """读该域名当前 A 记录 -> [(content, id)]; 走 monitor 的 cf_api(直连3次退避→代理回落)。"""
    zid = _ntprxx_zone_id()
    recs = cf_api("GET", f"/zones/{zid}/dns_records?name={ARGS.ntprxx_domain}&per_page=100")
    return [(r["content"], r["id"]) for r in (recs or []) if r.get("type") == "A"]


def ntprxx_probe_ip(ip):
    """单个 IP 的全国连通率: itdog → kkce → tcptest(与主域回退顺序一致)。
    返回 (rate%, ok, tot, src) 或 None。"""
    for fn, name in ((itdog_single, "itdog"), (kkce_single, "kkce"), (tcptest_single, "tcptest")):
        try:
            r = fn(ip)
        except Exception as e:
            log(f"[ntprxx] {ip} {name} 异常: {type(e).__name__}: {e}")
            continue
        if not r:
            log(f"[ntprxx] {ip} {name} 无结果, 试下一个源")
            continue
        tot = (r.get("ok_node") or 0) + (r.get("fail_node") or 0)
        if tot <= 0:
            continue
        rate = round((r.get("ok_node") or 0) / tot * 100, 1)
        return (rate, r.get("ok_node") or 0, tot, name)
    return None


def ntprxx_best_by_itdog(n, exclude=()):
    """按 **itdog 全国分**从池内挑最优候选(这就是"取 itdog 最好 N 个"的定义)。

    只考虑有全国评测记录的 IP(无记录的不参与, 否则就成"按本机分挑"了); 排序键优先级:
      ① **来源是 itdog**(而不是 tcptest/kkce 回退源 —— 回退源节点数/口径不同, 分数不可直接比)
      ② itdog 分(连通率70 + 延迟30)  ③ **数据新鲜度**(同为 100 分时, 1 小时前的比 30 小时前的可信)
      ④ itdog 连通率  ⑤ 本机 24h 在线率
    返回 [(ip, itdog分, 来源, 新鲜度)]。
    """
    excl = set(exclude)
    now = int(time.time())
    rows = []
    for ip in load_pool():
        if ip in excl:
            continue
        # 用 itdog_latest_any / itdog_score_of: 候选选择不该被 --itdog 开关挡住
        # (否则没开 --itdog 时巡检永远"候选不足", 静默不替换 —— 实测踩过)
        latest = itdog_latest_any(ip) or {}
        sc = itdog_score_of(latest)
        if sc is None:
            continue
        src = latest.get("src") or "itdog"
        fr = itdog_freshness(latest.get("ts")) or 0.0
        s24 = window_stats(ip, now - DAY)
        rows.append((1 if src == "itdog" else 0, sc, fr,
                     latest.get("success_rate") or 0.0,
                     s24.get("rate") or 0.0, ip, src))
    rows.sort(reverse=True)
    return [(ip, sc, src, fr) for _is_idog, sc, fr, _sr, _r24, ip, src in rows[:n]]


def _ntprxx_apply(add_ips, remove_pairs, why):
    """先加后删; 删除失败重试。返回 (added, removed)。"""
    zid = _ntprxx_zone_id()
    added, removed = [], []
    for ip in add_ips:
        try:
            cf_api("POST", f"/zones/{zid}/dns_records",
                   {"type": "A", "name": ARGS.ntprxx_domain, "content": ip,
                    "proxied": False, "ttl": 60})
            added.append(ip)
            log(f"[ntprxx] + 新增 A {ip}  ({why})")
        except Exception as e:
            log(f"[ntprxx] 新增 {ip} 失败: {type(e).__name__}: {e}")
    for ip, rid in remove_pairs:
        ok = False
        for attempt in range(3):
            try:
                cf_api("DELETE", f"/zones/{zid}/dns_records/{rid}")
                ok = True
                break
            except Exception as e:
                log(f"[ntprxx] 删除 {ip} 第 {attempt + 1} 次失败: {type(e).__name__}: {e}")
                _stop.wait(2 + attempt * 3)
        if ok:
            removed.append(ip)
            log(f"[ntprxx] - 删除 A {ip}  ({why})")
        else:
            log(f"[ntprxx] !! 删除 {ip} 三次均失败, 该记录残留(下次巡检会裁剪)")
    return added, removed


def ntprxx_candidate_ok(ip):
    """安全闸: 候选必须能**按 SNI 直连该 IP** 正常服务本域名(2xx/3xx)。

    池子(tools/ips-latest.csv)是对 DoH 主域验证过的反代 IP; 换到本域名之前必须实测:
    否则会写进一条"解析过去了但 522/1000"的 A 记录。复用 doh_probe_named(SNI=域名)。
    """
    try:
        r = doh_probe_named(ARGS.ntprxx_domain, ip)
    except Exception as e:
        log(f"[ntprxx] 候选 {ip} SNI 探测异常: {type(e).__name__}: {e}")
        return False
    if r.get("ok"):
        return True
    log(f"[ntprxx] 候选 {ip} 未通过 SNI 探测({r.get('status') or 0} {r.get('reason') or ''}), 弃用")
    return False


def ntprxx_pick(n, exclude=()):
    """挑 n 个可用候选: 从 itdog 最优开始往下走, 逐个过 SNI 安全闸。

    排序仍以 itdog 分为准; 只是把"实测能服务本域名"作为**硬前提** —— 失败者跳过、继续往下取。
    """
    need = max(1, n)
    picked, tried = [], set(exclude)
    while len(picked) < need:
        cands = [c for c in ntprxx_best_by_itdog(len(tried) + need, exclude=tried)
                 if c[0] not in tried]
        if not cands:
            break
        best = cands[0]
        tried.add(best[0])
        if ntprxx_candidate_ok(best[0]):
            picked.append(best)
    return picked


def ntprxx_patrol_once(align=False):
    """跑一轮巡检。align=True 时按"itdog 最优 N 个"整体对齐(即使当前都健康)。

    返回 dict 摘要(供 meta/日志), 读不到记录或全源失败时返回 None。
    """
    tag = "对齐" if align else "巡检"
    recs = ntprxx_records()
    if not recs:
        log(f"[ntprxx] {tag}: 读不到 A 记录, 本轮跳过(不写 DNS)")
        return None
    in_use = {ip for ip, _ in recs}
    log(f"[ntprxx] === {tag} {ARGS.ntprxx_domain}: {sorted(in_use)} (阈值 {ARGS.ntprxx_threshold}%) ===")

    # 1) 逐 IP 全国检测(带节流)
    bad, rates = [], {}
    for i, (ip, rid) in enumerate(recs):
        r = ntprxx_probe_ip(ip)
        if r is None:
            log(f"[ntprxx] {ip}: 三源均失败, 跳过判定")
        else:
            rate, ok, tot, src = r
            rates[ip] = rate
            flag = "[OK]" if rate >= ARGS.ntprxx_threshold else "[BAD]"
            log(f"[ntprxx] {ip}: {rate}% ({ok}/{tot}) [{src}] {flag}")
            if rate < ARGS.ntprxx_threshold:
                bad.append((ip, rid, rate))
        if i < len(recs) - 1 and ARGS.ntprxx_sleep > 0:
            _stop.wait(ARGS.ntprxx_sleep)

    # 2) 决定动作
    add_ips, remove_pairs = [], []
    if align:
        keep = max(1, ARGS.ntprxx_keep)
        target_rows = ntprxx_pick(keep)
        target = [t[0] for t in target_rows]
        if len(target) < keep:
            log(f"[ntprxx] 池内过 SNI 安全闸的 itdog 最优候选不足({len(target)}/{keep}), 放弃对齐")
            return {"align": True, "skipped": "候选不足", "rates": rates}
        log(f"[ntprxx] itdog 最优 {keep} 个(已过 SNI 安全闸) = "
            + ", ".join(f"{ip}(分{sc} {src} 新鲜{fr})" for ip, sc, src, fr in target_rows))
        remove_pairs = [(ip, rid) for ip, rid in recs if ip not in target]
        add_ips = [ip for ip in target if ip not in in_use]
        log(f"[ntprxx] 计划: 新增 {add_ips or '无'}; 移除 {[ip for ip, _ in remove_pairs] or '无'}")
    elif bad:
        n_need = min(len(bad), max(1, ARGS.ntprxx_keep))
        cands = ntprxx_pick(n_need, exclude=in_use)
        log(f"[ntprxx] {len(bad)} 个问题 IP(<{ARGS.ntprxx_threshold}%): "
            f"{[(ip, f'{r}%') for ip, _rid, r in bad]}; 候选(itdog 最优+过 SNI 闸, 未在用): "
            + (", ".join(f"{ip}(分{sc} {src} 新鲜{fr})" for ip, sc, src, fr in cands) or "无"))
        for (ip, rid, _rate), (rep, sc, _csrc, _cfr) in zip(bad, cands):
            add_ips.append(rep)
            remove_pairs.append((ip, rid))
            log(f"[ntprxx] 计划替换: {ip} -> {rep} (itdog 分 {sc})")
        if not cands:
            log("[ntprxx] 无可用候选, 本轮不替换")
    else:
        log(f"[ntprxx] 全部 {len(recs)} 个 IP ≥ {ARGS.ntprxx_threshold}%, 无需替换")

    if not add_ips and not remove_pairs:
        if rates:
            db_meta_set("ntprxx_last", f"{datetime.now().strftime('%m-%d %H:%M')} "
                                       f"{tag}: " + ", ".join(f"{ip} {r}%" for ip, r in rates.items()))
        return {"align": align, "rates": rates, "changed": False}

    if ARGS.ntprxx_dry_run:
        log(f"[ntprxx] --dry-run: 不写 DNS(计划 新增 {add_ips}, 移除 {[ip for ip, _ in remove_pairs]})")
        return {"align": align, "rates": rates, "changed": False, "dry_run": True,
                "would_add": add_ips, "would_remove": [ip for ip, _ in remove_pairs]}

    added, removed = _ntprxx_apply(add_ips, remove_pairs, tag)

    # 3) 自愈: 先加后删失败会多留记录, 裁回 keep 条(优先保留 itdog 分高的)
    try:
        cur = ntprxx_records()
        keep = max(1, ARGS.ntprxx_keep)
        if len(cur) > keep:
            rank = {t[0]: t[1] for t in ntprxx_best_by_itdog(len(load_pool()))}
            cur.sort(key=lambda x: -(rank.get(x[0], -1)))
            drop = cur[keep:]
            log(f"[ntprxx] 裁剪多余 A 记录 {[ip for ip, _ in drop]} (现有 {len(cur)} 条 > {keep})")
            _ntprxx_apply([], drop, "裁剪多余")
    except Exception as e:
        log(f"[ntprxx] 裁剪失败: {type(e).__name__}: {e}")

    summary = {"align": align, "rates": rates, "added": added, "removed": removed}
    try:
        db_meta_set("ntprxx_last",
                    f"{datetime.now().strftime('%m-%d %H:%M')} {tag}: "
                    + (f"换 {len(added)} 个({', '.join(added)})" if added else "无需替换")
                    + " | " + ", ".join(f"{ip} {r}%" for ip, r in rates.items()))
    except Exception:
        pass
    return summary


def ntprxx_patrol_loop():
    """后台线程:启用后先(可选)对齐, 再按 --ntprxx-hours 周期巡检。"""
    if not ARGS.ntprxx_patrol:
        return
    if ARGS.ntprxx_align:
        try:
            ntprxx_patrol_once(align=True)
        except Exception as e:
            log(f"[ntprxx] 对齐异常: {type(e).__name__}: {e}")
    if ARGS.ntprxx_hours <= 0:
        try:
            ntprxx_patrol_once()
        except Exception as e:
            log(f"[ntprxx] 巡检异常: {type(e).__name__}: {e}")
        return
    last = time.time()
    while not _stop.is_set():
        if time.time() - last >= ARGS.ntprxx_hours * 3600:
            last = time.time()
            try:
                ntprxx_patrol_once()
            except Exception as e:
                log(f"[ntprxx] 巡检异常: {type(e).__name__}: {e}")
        _stop.wait(60)


def domain_status_payload():
    """/api/abc 与 /abc 页数据(含每域名最新一轮节点明细)。"""
    domains = [d.strip() for d in (ARGS.monitor_domains or "").split(",") if d.strip()]
    out = []
    with db() as c:
        for dom in domains:
            row = c.execute("SELECT * FROM domain_status WHERE domain=?", (dom,)).fetchone()
            if row:
                cols = [x[1] for x in c.execute("PRAGMA table_info(domain_status)")]
                entry = dict(zip(cols, row))
                # 最新一轮节点明细
                nodes = [{"node_id": r[0], "isp": r[1], "city": r[2], "result": r[3], "ip": r[4]}
                         for r in c.execute(
                             "SELECT node_id,isp,city,result,node_ip FROM domain_nodes "
                             "WHERE domain=? ORDER BY city LIMIT 2000", (dom,))]
                entry["nodes"] = nodes
                out.append(entry)
            else:
                out.append({"domain": dom, "resolve_ip": None, "e2e_ok": None, "e2e_total": None,
                            "e2e_latency_ms": None, "last_ts": None, "nodes": []})
    return {"generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "interval": ARGS.interval, "domains": out}

# ---------------------------------------------------------------------------
# DoH 测速(经系统 DNS 解析域名 → 真实轮询路径;WebUI 测速面板用)
# ---------------------------------------------------------------------------

def dohspeed_test(domain, rounds):
    """经系统 DNS 解析域名后,对解析到的 IP 发 N 轮真实 DoH 查询。"""
    results = []
    ip = None
    try:
        infos = socket.getaddrinfo(domain, 443, type=socket.SOCK_STREAM)
        # 优先 IPv4(与端到端探针一致:中继走 v4;v6 首地址在本机可能不可达)
        ip = next((i[4][0] for i in infos if i[0] == socket.AF_INET), infos[0][4][0])
    except OSError:
        return {"error": "域名解析失败", "ip": None, "rounds": rounds, "results": []}
    b64 = base64.urlsafe_b64encode(DOH_QUERY).decode().rstrip("=")
    path = DOH_PATH + "?dns=" + b64
    CRLF = "\r\n"
    for _ in range(rounds):
        t0 = time.time()
        entry = {"ms": None, "status": 0, "cache": "-", "answers_n": 0}
        try:
            raw = socket.create_connection((ip, 443), timeout=8)
            try:
                tls = TLS_CTX.wrap_socket(raw, server_hostname=DOH_HOST)
            except Exception:
                raw.close()   # 握手失败必须显式关闭,否则泄漏 fd(同 doh_probe)
                raise
            try:
                head = ("GET " + path + " HTTP/1.1" + CRLF +
                        "Host: " + DOH_HOST + CRLF +
                        "user-agent: monitor-speedtest" + CRLF +
                        "accept: application/dns-message" + CRLF +
                        "connection: close" + CRLF + CRLF)
                tls.sendall(head.encode("ascii"))
                buf = b""
                tls.settimeout(8)
                while True:
                    chunk = tls.recv(4096)
                    if not chunk:
                        break
                    buf += chunk
                    if len(buf) > 65536:
                        break
            finally:
                tls.close()
            entry["ms"] = int((time.time() - t0) * 1000)
            sep = buf.find(b"\r\n\r\n")
            if sep < 0:
                entry["status"] = 0
            else:
                head_s = buf[:sep].decode("utf-8", "replace")
                body = buf[sep + 4:]
                parts = head_s.split("\r\n")[0].split(" ")
                entry["status"] = int(parts[1]) if len(parts) > 1 else 0
                low = head_s.lower()
                entry["cache"] = ("HIT" if "x-doh-cache: hit" in low else
                                  "MISS" if "x-doh-cache" in low else "-")
                if len(body) >= 12:
                    entry["answers_n"] = int.from_bytes(body[6:8], "big")
        except Exception as e:
            reason = str(e)[:40]
            if "timed out" in reason:
                reason += "(该域名非 CF 托管时,本测试不适用)"
            entry["status"] = 0
            entry["cache"] = "-"
            entry["err"] = reason
        results.append(entry)
    ok_ms = [r["ms"] for r in results if r["status"] == 200]
    stats = None
    if ok_ms:
        srt = sorted(ok_ms)
        stats = {"ok": len(ok_ms), "min": srt[0], "max": srt[-1],
                 "avg": round(sum(ok_ms) / len(ok_ms)), "med": srt[len(srt) // 2]}
    return {"ip": ip, "domain": domain, "rounds": rounds,
            "results": results, "stats": stats}

# ---------------------------------------------------------------------------
# DNS 解析耗时(直测 AGH:从发起查询到得到 IP)
# ---------------------------------------------------------------------------

def build_dns_query(domain, qtype=1):
    tid = int.from_bytes(os.urandom(2), "big")
    q = b"".join(bytes([len(l)]) + l.encode("idna") for l in domain.split(".") if l)
    q += bytes.fromhex("00")
    head = bytes.fromhex("01000001000000000000")
    return (tid.to_bytes(2, "big") + head + q +
            qtype.to_bytes(2, "big") + bytes.fromhex("0001")), tid

def parse_dns_records(buf, tid):
    """极简解析:返回 (rcode, [IP 字符串]),同时识别 A(1) 与 AAAA(28)。"""
    if len(buf) < 12 or buf[:2] != tid.to_bytes(2, "big"):
        raise ValueError("响应不匹配")
    rcode = buf[3] & 0x0F
    qd = int.from_bytes(buf[4:6], "big")
    an = int.from_bytes(buf[6:8], "big")
    i = 12
    for _ in range(qd):
        while buf[i] != 0:
            if buf[i] & 0xC0:
                i += 2
                break
            i += 1 + buf[i]
        else:
            i += 1
        i += 4
    ips = []
    for _ in range(an):
        if buf[i] & 0xC0 == 0xC0:
            i += 2
        else:
            while buf[i] != 0:
                i += 1 + buf[i]
            i += 1
        rtype = int.from_bytes(buf[i:i+2], "big")
        rdlen = int.from_bytes(buf[i+8:i+10], "big")
        if rtype == 1 and rdlen == 4:
            ips.append(".".join(str(b) for b in buf[i+10:i+10+4]))
        elif rtype == 28 and rdlen == 16:
            raw = buf[i+10:i+26]
            groups = [int.from_bytes(raw[k:k+2], "big") for k in range(0, 16, 2)]
            ips.append(_format_ipv6(groups))
        i += 10 + rdlen
    return rcode, ips


def _format_ipv6(groups):
    """按 RFC 5952 压缩 IPv6 地址(零段合并为 ::)。"""
    best_start, best_len, cur_start, cur_len = -1, 0, -1, 0
    for idx, g in enumerate(groups):
        if g == 0:
            if cur_start < 0:
                cur_start = idx
            cur_len += 1
            if cur_len > best_len:
                best_start, best_len = cur_start, cur_len
        else:
            cur_start, cur_len = -1, 0
    hexs = [format(g, "x") for g in groups]
    if best_len < 2:
        return ":".join(hexs)
    left, right = hexs[:best_start], hexs[best_start + best_len:]
    if not left and not right:
        return "::"
    if not left:
        return "::" + ":".join(right)
    if not right:
        return ":".join(left) + "::"
    return ":".join(left) + "::" + ":".join(right)

def resolve_test(domain, rounds, server="192.168.5.202", qtype=1):
    """向 AGH 发真实 DNS 查询,测量「从查询到得到 IP」的完整链路耗时。
    qtype: 1=A(IPv4), 28=AAAA(IPv6)。"""
    results = []
    for _ in range(rounds):
        q, tid = build_dns_query(domain, qtype)
        t0 = time.time()
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(8)
            sock.sendto(q, (server, 53))
            data, _ = sock.recvfrom(4096)
            sock.close()
            ms = int((time.time() - t0) * 1000)
            rcode, ips = parse_dns_records(data, tid)
            results.append({"ms": ms, "rcode": rcode, "ips": ips[:3]})
        except socket.timeout:
            results.append({"ms": int((time.time() - t0) * 1000), "rcode": -1,
                            "ips": [], "err": "超时"})
        except Exception as e:
            results.append({"ms": int((time.time() - t0) * 1000), "rcode": -1,
                            "ips": [], "err": str(e)[:40]})
    ok_ms = [r["ms"] for r in results if r["rcode"] == 0 and r["ips"]]
    stats = None
    if ok_ms:
        srt = sorted(ok_ms)
        stats = {"ok": len(ok_ms), "min": srt[0], "max": srt[-1],
                 "avg": round(sum(ok_ms) / len(ok_ms)), "med": srt[len(srt) // 2]}
    return {"server": server, "rounds": rounds, "qtype": "AAAA" if qtype == 28 else "A",
            "results": results, "stats": stats}

# ---------------------------------------------------------------------------
# 监控循环
# ---------------------------------------------------------------------------

_stop = threading.Event()
_sweep_running = threading.Event()  # 后台复测互斥:同一时间只跑一轮
_last_dns_ips = []  # 最近一次 auto_sync 读到的 DNS 记录(摘要展示用)

def probe_round(ips, max_workers=10):
    """并发探测一批 IP,返回 {ip: result};每轮结果独立,便于统计本轮在线率。
    常规轮额外测量热延迟(复用 TLS 会话),供展示与评分使用。"""
    results = {}
    lock = threading.Lock()

    def work(ip):
        # 复测进行中时降并发为 1 会拖慢整轮;这里保持并发,但把测量结果
        # 标记为 scan 不参与延迟统计——由调用方决定 src。
        r = doh_probe(ip, warm=True)
        db_insert(ip, r["ok"], r["total_ms"] if r["ok"] else None, r["tcp_ms"],
                  r["reason"], src=("scan" if _sweep_running.is_set() else "round"),
                  warm_ms=r.get("warm_ms"))
        with lock:
            results[ip] = r

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as ex:
        list(ex.map(work, ips))
    return results

def probe_loop():
    global _fallback_active
    last_cleanup = 0.0
    rounds = 0
    # 复测时间持久化:重启进程不应触发新一轮 DNS 洗牌
    try:
        last_sweep = float(db_meta_get("last_sweep") or 0)
    except (TypeError, ValueError):
        last_sweep = 0.0
    cand_idx = 0
    # 快/慢两套节奏:高频=域名端到端+DNS IP;低频=池内全部
    last_fast = 0.0
    last_pool = 0.0
    # 启动时按 DNS 实际记录类型恢复兜底状态(进程重启不丢状态)
    try:
        recs = dns_name_records()
        _fallback_active = any(r["type"] == "CNAME" for r in recs)
        if _fallback_active:
            log(f"[fallback] 检测到 DNS 处于 CNAME 兜底状态({FALLBACK_CNAME}),"
                  f"将持续探测直到 IP 恢复")
    except Exception as e:
        log(f"[fallback] 启动状态检测失败: {type(e).__name__}: {e}")
    # 服役期初始化:把当前 DNS 的 IP 记为"已服役很久",避免重启后因
    # 无服役记录(视为刚上)而立即被主动择优换掉。
    try:
        served = _served_get()
        changed = False
        for ip in [c for c, _ in get_dns_records()]:
            if ip not in served:
                served[ip] = int(time.time()) - int(ARGS.min_serve_hours * 3600) - 3600
                changed = True
        if changed:
            _served_set(served)
    except Exception as e:
        log(f"[monitor] 服役期初始化失败: {type(e).__name__}: {e}")
    while not _stop.is_set():
        try:
            now = time.time()
            # 域名端到端 + DNS IP 频率
            do_fast = (now - last_fast >= ARGS.interval)
            # 池内全部频率
            do_pool = (now - last_pool >= ARGS.pool_interval)
            # 域名出问题即时触发池内全测(见下方 dip 失败置位 _domain_fail)
            if _domain_fail.is_set():
                do_pool = True
            if not (do_fast or do_pool):
                _stop.wait(min(max(5, ARGS.interval), max(5, ARGS.pool_interval)))
                continue
            if do_fast:
                last_fast = now
            if do_pool:
                last_pool = now

            round_res = {}
            if do_pool:
                # 低频轮:池内全部 60 个(+ 兜住 DNS 里可能不在池的记录)
                ips = load_pool() or db_pool_ips()
                try:
                    for rec in get_dns_records():
                        if rec[0] not in ips:
                            ips = list(ips) + [rec[0]]
                except Exception:
                    pass
                if _stop.is_set():
                    return
                round_res = probe_round(list(ips))
            else:
                # 高频轮:只测 DNS 在用的 IP(快,小集合)
                dns_ips = []
                try:
                    dns_ips = [c for c, _ in get_dns_records()]
                except Exception:
                    pass
                if dns_ips and not _stop.is_set():
                    round_res = probe_round(list(dns_ips))

            if not _stop.is_set():
                # 🌐 域名整体探针:走系统 DNS 解析 → 轮询到的中转 → Worker,
                # 反映最终用户的真实端到端体验(含解析和轮询运气)
                dip = _resolve_doh_ip()
                if dip is None:
                    db_insert(DOMAIN_LABEL, 0, None, None, "域名解析失败")
                    _domain_fail.set()
                if dip:
                    r = doh_probe(dip)
                    db_insert(DOMAIN_LABEL, 1 if r["ok"] else 0,
                              r["total_ms"] if r["ok"] else None,
                              r["tcp_ms"], "域名探针")
                    if not r["ok"]:
                        _domain_fail.set()   # 域名挂了 → 下一轮立即触发池内全测
                    else:
                        _domain_fail.clear()

            if not _stop.is_set() and _fallback_active:
                # 兜底中:池内 IP + 轮转候选批次,找够可用 IP 立即切回 A 记录
                alive = sorted((r["total_ms"], ip) for ip, r in round_res.items() if r["ok"])
                cands = [ip for ip in candidate_ips() if ip not in round_res]
                if cands:
                    batch = [cands[(cand_idx + k) % len(cands)] for k in range(min(50, len(cands)))]
                    cand_idx = (cand_idx + 50) % max(1, len(cands))
                    log(f"[fallback] 兜底轮转探测候选 {len(batch)} 个(当前可用 {len(alive)})")
                    lock = threading.Lock()

                    def cwork(ip):
                        rr = doh_probe(ip)
                        db_insert(ip, rr["ok"], rr["total_ms"] if rr["ok"] else None,
                                  rr["tcp_ms"], rr["reason"], src="scan")
                        with lock:
                            if rr["ok"]:
                                alive.append((rr["total_ms"], ip))

                    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as ex:
                        list(ex.map(cwork, batch))
                alive.sort()
                if len(alive) >= ARGS.count:
                    deactivate_fallback([ip for _, ip in alive[:ARGS.count]])
            if not _stop.is_set() and not ARGS.no_auto_sync:
                try:
                    auto_sync_check()
                except Exception as e:
                    log(f"[auto-sync] 异常: {type(e).__name__}: {e}")
            rounds += 1
            # 每轮一行摘要
            try:
                alive_n = sum(1 for r in round_res.values() if r["ok"])
                dns = list(_last_dns_ips)
                dns_worst = max((consecutive_failures(ip) for ip in dns), default=0)
                if dns:
                    ws = [window_stats(ip, int(time.time()) - DAY) for ip in dns]
                    warms = sorted(x["med_warm_ms"] for x in ws if x["med_warm_ms"] is not None)
                    colds = sorted(x["med_ms"] for x in ws if x["med_ms"] is not None)
                    w_med = warms[len(warms) // 2] if warms else None
                    c_med = colds[len(colds) // 2] if colds else None
                    dns_state = (f"DNS {len(dns)} 条(连败 {dns_worst}, 热中位 {w_med}ms/冷中位 {c_med}ms)")
                else:
                    dns_state = "DNS 未读到"
                log(f"[轮次] 第 {rounds} 轮 · {'池' if do_pool else 'DNS'} {len(round_res)} 个(可用 {alive_n}) · "
                    f"{dns_state} · 兜底 {'是' if _fallback_active else '否'} · "
                    f"{(last_sync_note() or '无同步记录')[:30]}")
            except Exception as e:
                log(f"[轮次] 第 {rounds} 轮(摘要生成失败: {type(e).__name__})")
            if ARGS.sweep_hours > 0 and not _stop.is_set():
                if time.time() - last_sweep >= ARGS.sweep_hours * 3600:
                    last_sweep = time.time()
                    _kick_sweep()
            now = time.time()
            if now - last_cleanup > DAY:
                db_cleanup()
                last_cleanup = now
        except Exception as e:
            log(f"[probe] 轮次异常: {type(e).__name__}: {e}")
        _stop.wait(max(5, min(ARGS.interval, ARGS.pool_interval)))

_domain_fail = threading.Event()  # 域名端到端失败标志,置位后下一轮立即触发池内全测

# ---------------------------------------------------------------------------
# Web 服务
# ---------------------------------------------------------------------------

PAGE = """<!DOCTYPE html>
<html lang="zh-CN"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>优选 IP 在线率监控</title>
<style>
:root{--bg:#0d1117;--card:#161b22;--bd:#30363d;--tx:#e6edf3;--mu:#8b949e;
--g:#3fb950;--y:#d29922;--r:#f85149;--accent:#4493f8}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--tx);
font-family:"Segoe UI","Microsoft YaHei",sans-serif;font-size:14px}
.wrap{max-width:1100px;margin:0 auto;padding:20px}
h1{font-size:18px;margin:0 0 4px}
.sub{color:var(--mu);font-size:12px;margin-bottom:16px;display:flex;
align-items:center;flex-wrap:wrap;gap:6px}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:12px;margin-bottom:18px}
.card{background:var(--card);border:1px solid var(--bd);border-radius:10px;padding:12px 16px}
.card .l{color:var(--mu);font-size:12px}.card .v{font-size:22px;font-weight:700;margin-top:2px}
table{width:100%;border-collapse:collapse;background:var(--card);
border:1px solid var(--bd);border-radius:10px;overflow:hidden}
th,td{padding:9px 10px;text-align:left;border-bottom:1px solid var(--bd);font-size:13px}
th{color:var(--mu);font-weight:500;background:#11161d}
tr:last-child td{border-bottom:none}
.badge{display:inline-block;padding:2px 8px;border-radius:9px;font-size:11px;font-weight:600}
.b-g{background:rgba(63,185,80,.15);color:var(--g)}
.b-y{background:rgba(210,153,34,.15);color:var(--y)}
.b-r{background:rgba(248,81,73,.15);color:var(--r)}
.b-n{background:rgba(139,148,158,.15);color:var(--mu)}
.rate-g{color:var(--g);font-weight:600}.rate-y{color:var(--y);font-weight:600}
.rate-r{color:var(--r);font-weight:600}.rate-n{color:var(--mu)}
.star{color:var(--y)}
.mono{font-family:Consolas,monospace}
.muted{color:var(--mu)}
svg{display:block}
.note{color:var(--mu);font-size:12px;margin-top:12px;line-height:1.6}
select{background:var(--card);color:var(--tx);border:1px solid var(--bd);
border-radius:8px;padding:7px 10px;font-size:13px;outline:none;cursor:pointer;
appearance:none;-webkit-appearance:none;
background-image:url("data:image/svg+xml;charset=utf-8,%3Csvg xmlns='http://www.w3.org/2000/svg' width='10' height='6'%3E%3Cpath d='M1 1l4 4 4-4' stroke='%238b949e' stroke-width='1.5' fill='none'/%3E%3C/svg%3E");
background-repeat:no-repeat;background-position:right 10px center;padding-right:28px}
select:focus{border-color:var(--accent);box-shadow:0 0 0 2px rgba(68,147,248,.2)}
select option{background:var(--card);color:var(--tx)}
.btn2{background:none;border:1px solid var(--bd);color:var(--tx);border-radius:8px;
padding:4px 12px;font-size:12px;cursor:pointer;margin-left:10px}
.btn2:hover{border-color:var(--accent);color:var(--accent)}
.btn{background:var(--accent);color:#fff;border:none;border-radius:8px;
padding:8px 16px;font-size:13px;cursor:pointer}
.btn:hover{background:#3b87e8}.btn:disabled{opacity:.5;cursor:wait}
input{background:var(--bg);color:var(--tx);border:1px solid var(--bd);
border-radius:8px;padding:7px 10px;font-size:13px;outline:none}
input:focus{border-color:var(--accent);box-shadow:0 0 0 2px rgba(68,147,248,.2)}
.banner{display:none;background:rgba(210,153,34,.12);border:1px solid var(--y);
color:var(--y);border-radius:10px;padding:10px 14px;margin-bottom:14px;font-size:13px}

/* ---------- 窄屏 / 手机适配 ---------- */
/* 让表单控件、滚动条跟随深色主题(手机上尤其明显) */
html{color-scheme:dark}
svg{max-width:100%}
/* 宽表在窄屏改成横向滚动容器,而不是把页面整体撑宽 */
.tablewrap{overflow-x:auto;-webkit-overflow-scrolling:touch}
.tablewrap>table{min-width:1080px}
.tablewrap th{white-space:nowrap}
.wrap{max-width:1240px}
.sparkcell{white-space:nowrap}
.num-sm{width:70px}

@media (max-width:900px){
  .wrap{padding:14px 12px}
  h1{font-size:16px}
  .sub{font-size:12px;gap:8px;margin-bottom:12px}
  .sub .btn2{margin-left:0;padding:7px 12px}
  .cards{grid-template-columns:repeat(2,minmax(0,1fr));gap:10px}
  .card{padding:12px}
  .card .v{font-size:19px}
  /* 触屏上把控件拉满,免去在小格子里点选 */
  select,input,.num-sm{width:100%}
  #c-sel,#sp-rounds{max-width:none}
  .btn{width:100%;padding:10px 16px}
  .note{font-size:11px;line-height:1.5}

  /* 12 列宽表 -> 每行一张卡:隐藏表头,单元格用 data-label 当行内标题 */
  .tablewrap{overflow-x:visible}
  /* 必须写成 .tablewrap>table 才压得住基线的 min-width:1080px
     (同权重、靠后者胜);否则卡片右侧的数值会被推到视口之外 */
  .tablewrap>table{min-width:0}
  /* 关键:table/tbody 也要脱离 table 布局。只把 tr/td 改成 block/flex
     的话,它们会落入匿名 table 盒并按 max-content 撑宽(约 490px),
     width:100% 失效 -> 行内右对齐的数值被推出屏幕。 */
  .rtable{display:block;background:transparent;border:none;border-radius:0}
  .rtable tbody{display:block}
  .rtable thead{display:none}
  .rtable tr{display:block;background:var(--card);border:1px solid var(--bd);
    border-radius:10px;padding:2px 0;margin-bottom:10px}
  .rtable td{display:flex;align-items:baseline;justify-content:space-between;gap:12px;
    padding:6px 12px;border-bottom:1px solid rgba(48,54,61,.55);font-size:13px}
  .rtable tr td:last-child{border-bottom:none}
  .rtable td::before{content:attr(data-label);color:var(--mu);font-size:12px;
    flex:0 0 auto;white-space:nowrap}
  /* 第一列(IP)当卡片标题:占满整行、不加标签 */
  .rtable td.rowhead{display:block;padding:9px 12px 7px;font-size:14px;
    border-bottom:1px solid var(--bd)}
  .rtable td.rowhead::before{content:none}
  .rtable td.sparkcell{display:block}
  .rtable td.sparkcell::before{content:attr(data-label);display:block;margin-bottom:4px}
}

@media (max-width:400px){
  .cards{grid-template-columns:repeat(2,minmax(0,1fr))}
  .card .v{font-size:17px}
}
</style></head><body><div class="wrap">
<h1>优选 IP 在线率监控</h1>
<div class="banner" id="banner"></div>
<div class="sub"><span id="meta">加载中…</span><button class="btn2" onclick="refresh()">🔄 手动刷新</button><a class="btn2" href="/itdog" target="_blank" style="text-decoration:none">🌐 itdog 全国评测</a><a class="btn2" href="/abc" target="_blank" style="text-decoration:none">🌐 域名监控</a><a class="btn2" href="/logs" target="_blank" style="text-decoration:none">📜 运行日志</a></div>
<div class="cards" id="cards"></div>

<div class="card" style="margin-bottom:18px">
<div class="l">📈 曲线 <span class="muted">(在线率 / 延迟 / TCP,可选对象与范围)</span></div>
<div style="display:flex;gap:10px;margin:8px 0;flex-wrap:wrap">
<select id="c-sel" style="max-width:360px"></select>
<select id="c-hours">
<option value="24">24小时</option><option value="48" selected>48小时</option>
<option value="168">7天</option><option value="720">30天</option></select>
<select id="c-metric"><option value="rate" selected>在线率 %</option>
<option value="avg_ms">延迟 ms</option><option value="avg_tcp">TCP 握手 ms</option></select>
</div>
<div id="curve"><span class="muted">加载中…</span></div>
</div>

<div class="card" style="margin-bottom:18px">
<div class="l">🔍 DNS 解析耗时 <span class="muted">(从发起查询到得到 IP · 经 AGH 完整链路)</span></div>
<div style="display:flex;gap:10px;align-items:center;flex-wrap:wrap;margin:8px 0">
<input id="sp-domain" placeholder="要测试的域名,如 chatgpt.com / linux.do" style="flex:1;min-width:200px">
<select id="sp-type"><option value="BOTH" selected>A + AAAA(两者)</option><option value="A">A(IPv4)</option><option value="AAAA">AAAA(IPv6)</option></select>
<input id="sp-rounds" class="num-sm" type="number" value="5" min="1" max="20">
<button class="btn" id="sp-go">测速</button>
</div>
<div id="sp-out"><span class="muted">输入域名,点「测速」</span></div>
</div>

<div class="card" style="margin-bottom:18px">
<div class="l">📌 当前 DNS A 记录(自动维护的最快组合)</div>
<div id="dnstable"><span class="muted">加载中…</span></div>
</div>
<div class="tablewrap">
<table class="rtable"><thead><tr>
<th>IP</th><th>状态</th><th>评分</th><th>itdog 全国</th><th>在线率 24h</th><th>7d</th><th>30d</th>
<th>延迟(热 · 冷)</th><th>p95</th><th>TCP 握手</th><th>连续失败</th><th>48h 趋势</th><th>最后检测</th>
</tr></thead><tbody id="rows"></tbody></table>
</div>
<div class="note">
· 在线率 = 探测成功次数 ÷ 该时段内总探测次数(电脑关机期间无记录,按实际样本计算)<br>
· ★ 表示该 IP 当前在 DNS A 记录中 · 探测后台每 10 分钟一轮,点「🔄 手动刷新」更新视图 ·
数据保留 30 天</div>
</div>

</div>
<script>
function cls(rate){if(rate==null)return"rate-n";
if(rate>=95)return"rate-g";if(rate>=80)return"rate-y";return"rate-r"}
function badge(text,level){return `<span class="badge b-${level}">${text}</span>`}
function spark(hist){if(!hist.length)return '<span class="muted">—</span>';
let w=5,h=26,cells="";
hist.forEach((b,i)=>{const c=b.rate==null?"#30363d":(b.rate>=95?"#3fb950":b.rate>=80?"#d29922":"#f85149");
const hh=Math.max(2,b.rate==null?2:b.rate/100*h);
cells+=`<rect width="4" y="${h-hh}" x="${i*w}" height="${hh}" fill="${c}" rx="1"></rect>`;});
return `<svg width="${hist.length*w}" height="${h}" title="48h 逐小时成功率">${cells}</svg>`}

let CURVE = {ip:"域名整体(端到端)", hours:"48", metric:"rate"};

async function refresh(){
  const d = await fetch("/api/stats").then(r=>r.json());
  window._last = d;
  renderMeta(d);
  renderCards(d);
  renderRows(d);
  renderDnsTable(d);
  if(!document.getElementById("c-sel").options.length) initCurveOptions(d);
  refreshCurve();
}

function renderMeta(d){
  const bn = document.getElementById("banner");
  if(d.fallback){
    bn.style.display = "block";
    bn.innerHTML = `🛡️ <b>CNAME 兜底生效中</b> — 全部 IP 失效,DNS 已指向 ${d.fallback_target||"cf.877774.xyz"}。`+
      `系统每轮探测池内 IP 并轮转候选池,找够可用 IP 后自动切回 A 记录。`;
  }else{
    bn.style.display = "none";
    bn.innerHTML = "";
  }
  document.getElementById("meta").innerHTML =
  `生成于 ${d.generated_at} · 池 ${d.pool_size} IP · 24h 总探测 ${d.overall_24h.total} 次`+
  (d.overall_24h.rate!=null?` · 整体在线率 ${d.overall_24h.rate}%`:"")+
  (d.last_sync?` · ${d.last_sync}`:"");
}

function renderCards(d){
  const dm = d.ips.find(p=>p.ip==="域名整体(端到端)");
  document.getElementById("cards").innerHTML =
  `<div class="card"><div class="l">池内 IP</div><div class="v">${d.pool_size}</div></div>`+
  `<div class="card"><div class="l">24h 总探测</div><div class="v">${d.overall_24h.total}</div></div>`+
  `<div class="card"><div class="l">24h 整体在线率</div><div class="v">${d.overall_24h.rate==null?"—":d.overall_24h.rate+"%"}</div></div>`+
  `<div class="card"><div class="l">当前 DNS 记录</div><div class="v">${d.fallback?"CNAME 兜底":(d.dns?d.dns.length:"?")}</div></div>`+
  (dm?`<div class="card" style="border-color:var(--y)"><div class="l">🌐 DoH 域名端到端(24h)</div><div class="v" style="color:var(--y)">${dm.h24.rate==null?"—":dm.h24.rate+"%"}</div><div class="l">样本 ${dm.h24.total} · 平均 ${dm.h24.avg_ms!=null?dm.h24.avg_ms+" ms":"—"}</div></div>`:"");
}

function renderRows(d){
  document.getElementById("rows").innerHTML = d.ips.map(p=>{
  const isDomain = p.ip==="域名整体(端到端)";
  const indns = d.dns && d.dns.includes(p.ip) ? '<span class="star">★</span>' : "";
  const nameHtml = isDomain
    ? `<span style="color:var(--y)">🌐 域名整体(端到端)</span><div class="muted" style="font-size:11px">系统DNS→轮询中转→Worker</div>`
    : (()=>{const inf=p.info;const sub=inf?[(inf.provider||inf.asn||""),inf.region].filter(Boolean).join(" · "):"";
    return `<span class="mono">${p.ip}</span> ${indns}${sub?`<div class="muted" style="font-size:11px">${sub}</div>`:""}`;})();
  const st = p.status==="在线"?badge("在线","g"):p.status==="离线"?badge("离线","r"):badge("无数据","n");
  const gColor = p.grade==="A"?"var(--g)":p.grade==="B"?"var(--accent)":p.grade==="C"?"var(--y)":"var(--r)";
  const scoreHtml = p.score==null?'<span class="muted">—</span>':`<span style="color:${gColor};font-weight:700">${p.score}</span> <span class="muted">${p.grade}</span>`;
  const itdogHtml = (()=>{const d=p.itdog; if(!d||d.success_rate==null)return '<span class="muted">—</span>';
    const cls=d.success_rate>=90?"var(--g)":d.success_rate>=75?"var(--y)":"var(--r)";
    const fr = d.freshness!=null?(d.freshness>=0.98?"新":Math.round(d.freshness*100)+"%效"):"";
    // 回退源(tcptest/kkce)的分必须标出来: 节点数与地区口径和 itdog 不同
    const sb = (d.src&&d.src!=="itdog")?` <span class="badge b-y" title="该行来自回退源, 节点数与地区口径与 itdog 不同">${d.src}</span>`:"";
    return `<span style="color:${cls};font-weight:600">${d.success_rate}%</span>${sb}<div class="muted" style="font-size:11px">${d.median_rtt!=null?d.median_rtt+"ms":"—"} · ${fr} ${new Date(d.ts*1000).toLocaleDateString("zh-CN")}</div>`;})();
  return `<tr${isDomain?' style="background:rgba(210,153,34,.06)"':""}>
  <td class="rowhead">${nameHtml}</td><td data-label="状态">${st}</td><td data-label="评分">${scoreHtml}</td><td data-label="itdog 全国">${itdogHtml}</td>
  <td data-label="在线率 24h" class="${cls(p.h24.rate)}">${p.h24.rate==null?"—":p.h24.rate+"%"}<div class="muted" style="font-size:11px">${p.h24.ok}/${p.h24.total}</div></td>
  <td data-label="在线率 7d" class="${cls(p.d7.rate)}">${p.d7.rate==null?"—":p.d7.rate+"%"}</td>
  <td data-label="在线率 30d" class="${cls(p.d30.rate)}">${p.d30.rate==null?"—":p.d30.rate+"%"}</td>
  <td data-label="延迟(热·冷)">${p.h24.med_warm_ms!=null?`<b>${p.h24.med_warm_ms} ms</b><div class="muted" style="font-size:11px">热 · 冷 ${p.h24.med_ms!=null?p.h24.med_ms:"—"}</div>`:(p.h24.med_ms!=null?p.h24.med_ms+" ms":"—")}${p.h24.med_warm_ms==null&&p.h24.avg_ms!=null?`<div class="muted" style="font-size:11px">均值 ${p.h24.avg_ms}</div>`:""}</td>
  <td data-label="p95">${p.h24.p95_ms!=null?p.h24.p95_ms+" ms":"—"}</td>
  <td data-label="TCP 握手">${p.h24.med_tcp!=null?p.h24.med_tcp+" ms":(p.h24.avg_tcp!=null?p.h24.avg_tcp+" ms":"—")}</td>
  <td data-label="连续失败">${p.cfail>0?`<span class="rate-r">${p.cfail}</span>`:"0"}</td>
  <td data-label="48h 趋势" class="sparkcell">${spark(p.hist)}</td>
  <td data-label="最后检测" class="muted">${p.last?new Date(p.last.ts*1000).toLocaleString("zh-CN",{hour12:false})+(p.last.reason?" · "+p.last.reason:""):"—"}</td>
  </tr>`;}).join("");
}

function renderDnsTable(d){
  const byIp = {}; d.ips.forEach(p=>byIp[p.ip]=p);
  const rows = (d.dns||[]).map((ip,i)=>{
    const p = byIp[ip];
    const st = p ? p.status : "未知";
    const bd = st==="在线"?badge("在线","g"):st==="离线"?badge("离线","r"):badge("未知","n");
    const r24 = (p && p.h24.rate!=null) ? `<span class="${cls(p.h24.rate)}">${p.h24.rate}%</span>` : '<span class="rate-n">—</span>';
    const lat = (p && p.h24.avg_ms!=null) ? p.h24.avg_ms+" ms" : "—";
    const inf = p && p.info;
    const sub = inf ? [(inf.provider || inf.asn || ""), inf.region].filter(Boolean).join(" · ") : "";
    return `<tr><td class="rowhead mono">${i+1}. ${ip}</td><td data-label="状态">${bd}</td><td data-label="在线率 24h">${r24}</td><td data-label="平均延迟">${lat}</td><td data-label="服务商" class="muted" style="font-size:11px">${sub}</td></tr>`;
  }).join("");
  document.getElementById("dnstable").innerHTML =
    `<div class="tablewrap"><table class="rtable" style="border:none;background:transparent;width:100%"><tbody>${rows}</tbody></table></div>`;
}

// ---------- 解析耗时测速(支持 A / AAAA) ----------
function renderResolveBlock(title, j){
  let html = `<div style="margin-bottom:2px"><b>${title}</b> <span class="muted">(${j.server||"AGH"} · ${j.rounds} 轮)</span></div>`;
  html += j.results.map((r2,i)=>{
    const ips = r2.ips && r2.ips.length ? r2.ips.join(", ") : "—";
    const bad = r2.rcode!==0 ? '<span style="color:var(--r)">失败('+(r2.err||("rcode "+r2.rcode))+')</span>' : "";
    const noAns = (r2.rcode===0 && (!r2.ips || !r2.ips.length)) ? '<span style="color:var(--y)">无记录(NODATA)</span>' : "";
    return `<div>第${i+1}次: <b>${r2.ms} ms</b>  得到IP: ${ips} ${bad}${noAns}</div>`;
  }).join("");
  if(j.stats) html += `<div style="margin:2px 0 10px"><b>统计:成功 ${j.stats.ok}/${j.rounds} | 最快 ${j.stats.min}ms | 平均 ${j.stats.avg}ms | 中位 ${j.stats.med}ms | 最慢 ${j.stats.max}ms</b></div>`;
  else html += `<div style="margin:2px 0 10px" class="muted">无成功样本</div>`;
  return html;
}
document.getElementById("sp-go").addEventListener("click", async () => {
  const d = document.getElementById("sp-domain").value.trim();
  if(!d){ alert("请输入域名"); return; }
  const n = Number(document.getElementById("sp-rounds").value) || 5;
  const t = document.getElementById("sp-type").value;
  const types = t === "BOTH" ? ["A","AAAA"] : [t];
  const btn = document.getElementById("sp-go");
  btn.disabled = true; btn.textContent = "测速中…";
  const out = document.getElementById("sp-out");
  out.innerHTML = '<span class="muted">测速中…(每轮为一次真实 DNS 查询,走 AGH 完整链路)</span>';
  try{
    const resp = await Promise.all(types.map(x =>
      fetch("/api/resolvetest?domain="+encodeURIComponent(d)+"&rounds="+n+"&type="+x).then(r=>r.json())));
    const err = resp.find(j=>j.error);
    if(err){ out.innerHTML = '<span style="color:var(--r)">'+err.error+'</span>'; }
    else{
      out.innerHTML = resp.map((j,i)=>renderResolveBlock(types[i]==="AAAA"?"AAAA(IPv6)":"A(IPv4)", j)).join("");
    }
  }catch(e){ out.innerHTML = '<span style="color:var(--r)">失败:'+e+'</span>'; }
  btn.disabled = false; btn.textContent = "测速";
});

// ---------- 曲线 ----------
function initCurveOptions(d){
  const sel = document.getElementById("c-sel");
  sel.innerHTML = "";
  sel.add(new Option("🌐 域名整体(端到端)","域名整体(端到端)"));
  sel.add(new Option("整池合并(全部 IP)","all"));
  d.ips.filter(p=>p.ip!=="域名整体(端到端)").forEach(p=>sel.add(new Option(p.ip,p.ip)));
}
function refreshCurve(){
  const ip = document.getElementById("c-sel").value;
  const hours = Number(document.getElementById("c-hours").value);
  const metric = document.getElementById("c-metric").value;
  document.getElementById("curve").innerHTML = '<span class="muted">加载中…</span>';
  fetch("/api/series?ip="+encodeURIComponent(ip)+"&hours="+hours)
    .then(r=>r.json()).then(pts=>drawSeries(pts,metric,ip,hours))
    .catch(()=>{document.getElementById("curve").innerHTML='<span class="muted">加载失败</span>';});
}
function drawSeries(pts,metric,label,hours){
  window._pts=pts; window._curveArgs=[metric,label,hours];
  // 窄屏用更小的 viewBox:否则 1000 宽的坐标系被压到 ~350px,
  // 里面的 10px 字号会缩成 3-4px 而完全看不清。
  const narrow = window.innerWidth < 760;
  const W=narrow?380:1000, H=narrow?190:240, L=narrow?30:46, R=narrow?8:12, T=14, B=narrow?24:28;
  const vals = pts.map(p=>metric==="rate"?p.rate:p.avg_ms).map(v=>v==null?null:v);
  const known = vals.filter(v=>v!=null);
  if(!known.length){document.getElementById("curve").innerHTML='<span class="muted">该时段暂无数据</span>';return;}
  let vmin = metric==="rate"?0:Math.min(...known);
  let vmax = metric==="rate"?100:Math.max(...known);
  if(vmax-vmin<10) vmax=vmin+10;
  const X=i=>pts.length<2?(L+W)/2:L+i*(W-L-R)/(pts.length-1);
  const Y=v=>T+(H-T-B)*(1-(v-vmin)/(vmax-vmin));
  let segs=[],cur=[];
  vals.forEach((v,i)=>{if(v==null){if(cur.length)segs.push(cur);cur=[];}else cur.push([X(i),Y(v)]);});
  if(cur.length)segs.push(cur);
  let svg="";
  for(let g=0;g<=4;g++){
    const gy=T+(H-T-B)*g/4, gv=Math.round((vmax-(vmax-vmin)*g/4)*10)/10;
    svg+=`<line x1="${L}" y1="${gy}" x2="${W-R}" y2="${gy}" stroke="var(--bd)" stroke-width="0.5"/>`;
    svg+=`<text x="4" y="${gy+4}" font-size="10" fill="var(--mu)">${gv}</text>`;
  }
  for(const s2 of segs){
    svg+=`<polyline fill="none" stroke="var(--accent,#4493f8)" stroke-width="2" points="${s2.map(p=>p[0]+","+p[1]).join(" ")}"/>`;
    svg+=s2.map(p=>`<circle cx="${p[0]}" cy="${p[1]}" r="2.5" fill="var(--accent,#4493f8)"/>`).join("");
  }
  const ticks=[0,Math.floor((pts.length-1)/2),pts.length-1].filter((v,i,a)=>a.indexOf(v)===i);
  for(const i of ticks){
    if(pts[i]) svg+=`<text x="${X(i)}" y="${H-8}" font-size="10" fill="var(--mu)" text-anchor="middle">${pts[i].hour}</text>`;
  }
  document.getElementById("curve").innerHTML=
    `<svg viewBox="0 0 ${W} ${H}" style="width:100%;background:var(--bg);border:1px solid var(--bd);border-radius:8px">${svg}</svg>`;
}
["c-sel","c-hours","c-metric"].forEach(id=>{
  const el=document.getElementById(id);
  if(el) el.addEventListener("change",()=>refreshCurve());
});
// 横竖屏切换/改窗口宽度后重画曲线(用缓存的数据,不重新请求)
let _rzTimer=null;
window.addEventListener("resize",()=>{
  clearTimeout(_rzTimer);
  _rzTimer=setTimeout(()=>{
    if(window._pts && window._curveArgs) drawSeries(window._pts,...window._curveArgs);
  },200);
});
refresh();
</script></body></html>"""

PAGE_LOGS = """<!DOCTYPE html>
<html lang="zh-CN"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>运行日志 · 优选 IP 监控</title>
<style>
:root{--bg:#0d1117;--card:#161b22;--bd:#30363d;--tx:#e6edf3;--mu:#8b949e;
--g:#3fb950;--y:#d29922;--r:#f85149;--accent:#4493f8}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--tx);
font-family:"Segoe UI","Microsoft YaHei",sans-serif;font-size:14px}
.wrap{max-width:1100px;margin:0 auto;padding:20px}
h1{font-size:18px;margin:0 0 8px}
.sub{color:var(--mu);font-size:12px;margin-bottom:14px;display:flex;align-items:center;
flex-wrap:wrap;gap:8px}
.btn2{background:transparent;color:var(--tx);border:1px solid var(--bd);border-radius:8px;
padding:6px 12px;font-size:13px;cursor:pointer}
.btn2:hover{border-color:var(--accent);color:var(--accent)}
.card{background:var(--card);border:1px solid var(--bd);border-radius:10px;padding:14px 16px}
select,input{background:var(--bg);color:var(--tx);border:1px solid var(--bd);
border-radius:8px;padding:7px 10px;font-size:13px;outline:none}
input:focus,select:focus{border-color:var(--accent)}
pre{max-height:calc(100vh - 220px);overflow:auto;background:#0b0f14;border:1px solid var(--bd);
border-radius:8px;padding:10px;font-size:12px;line-height:1.55;white-space:pre-wrap;
word-break:break-all;margin:10px 0 6px}
@media (max-width:760px){
  .wrap{padding:14px 12px}
  h1{font-size:16px}
  select,input,button{width:100%}
  pre{max-height:58vh;font-size:11px}
}
.muted{color:var(--mu)}
</style></head><body><div class="wrap">
<h1>📜 运行日志</h1>
<div class="sub">
<a class="btn2" href="/" style="text-decoration:none">← 返回监控面板</a>
<span class="muted">只读 · 已脱敏(登录路径与密钥不会显示)</span>
</div>
<div class="card">
<div style="display:flex;gap:10px;align-items:center;flex-wrap:wrap">
<select id="log-lines">
<option value="100">最近 100 行</option>
<option value="300" selected>最近 300 行</option>
<option value="1000">最近 1000 行</option>
</select>
<input id="log-q" placeholder="过滤关键字,如 择优 / auto-sync / sweep / 异常" style="flex:1;min-width:220px">
<button class="btn2" id="log-go">🔄 刷新</button>
</div>
<pre id="log-out">加载中…</pre>
<div class="muted" style="font-size:11px" id="log-meta"></div>
</div>
<script>
function escapeHtml(s){return String(s).replace(/[&<>"']/g,(c)=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]))}
// ------------------------------------------------------------------
// 运行日志
// ------------------------------------------------------------------
function logLineHtml(line){
  const esc = escapeHtml(line);
  let cls = "";
  if(/择优替换|自动换 IP|兜底|已恢复/.test(line)) cls = "color:var(--g)";
  else if(/异常|失败|错误|Exception|Traceback/.test(line)) cls = "color:var(--r)";
  else if(/sweep|复测|轮转/.test(line)) cls = "color:var(--mu)";
  return cls ? `<span style="${cls}">${esc}</span>` : esc;
}
async function renderLogs(){
  const n = document.getElementById("log-lines").value;
  const q = document.getElementById("log-q").value.trim();
  const out = document.getElementById("log-out");
  const meta = document.getElementById("log-meta");
  out.textContent = "加载中…";
  try{
    const j = await fetch(`/api/logs?lines=${encodeURIComponent(n)}&q=${encodeURIComponent(q)}`).then(r=>r.json());
    if(!j.lines || !j.lines.length){
      out.textContent = "（没有匹配的日志行）";
    }else{
      out.innerHTML = j.lines.map(logLineHtml).join(String.fromCharCode(10));
      out.scrollTop = out.scrollHeight;
    }
    const when = j.mtime ? new Date(j.mtime*1000).toLocaleString("zh-CN",{hour12:false}) : "?";
    meta.textContent = `文件 ${j.file} · ${(j.size/1024).toFixed(1)} KB · 最后写入 ${when} · 显示 ${(j.lines||[]).length}/${j.total_lines||0} 行${q?` · 过滤「${q}」`:""}`;
  }catch(e){
    out.textContent = "日志读取失败: " + e.message;
    meta.textContent = "";
  }
}
document.getElementById("log-go").addEventListener("click", renderLogs);
document.getElementById("log-lines").addEventListener("change", renderLogs);
document.getElementById("log-q").addEventListener("keydown", (e)=>{ if(e.key==="Enter") renderLogs(); });
</script></body></html>"""

PAGE_ITDOG = """<!DOCTYPE html>
<html lang="zh-CN"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>itdog 全国评测 · 优选 IP 监控</title>
<style>
:root{--bg:#0d1117;--card:#161b22;--bd:#30363d;--tx:#e6edf3;--mu:#8b949e;
--g:#3fb950;--y:#d29922;--r:#f85149;--accent:#4493f8}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--tx);
font-family:"Segoe UI","Microsoft YaHei",sans-serif;font-size:14px}
.wrap{max-width:1240px;margin:0 auto;padding:20px}
h1{font-size:18px;margin:0 0 4px}
.sub{color:var(--mu);font-size:12px;margin-bottom:14px;display:flex;align-items:center;flex-wrap:wrap;gap:6px}
a{color:var(--accent);text-decoration:none}
.btn2{background:none;border:1px solid var(--bd);color:var(--tx);border-radius:8px;
padding:4px 12px;font-size:12px;cursor:pointer;text-decoration:none;margin-left:8px}
.btn2:hover{border-color:var(--accent);color:var(--accent)}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin-bottom:16px}
.card{background:var(--card);border:1px solid var(--bd);border-radius:10px;padding:12px 16px}
.card .l{color:var(--mu);font-size:12px}.card .v{font-size:20px;font-weight:700;margin-top:2px}
table{width:100%;border-collapse:collapse;background:var(--card);
border:1px solid var(--bd);border-radius:10px;overflow:hidden}
th,td{padding:8px 10px;text-align:left;border-bottom:1px solid var(--bd);font-size:13px}
th{color:var(--mu);font-weight:500;background:#11161d;white-space:nowrap}
tr:last-child td{border-bottom:none}
.mono{font-family:Consolas,monospace}
.muted{color:var(--mu)}
.badge{display:inline-block;padding:2px 8px;border-radius:9px;font-size:11px;font-weight:600}
.b-g{background:rgba(63,185,80,.15);color:var(--g)}
.b-y{background:rgba(210,153,34,.15);color:var(--y)}
.b-r{background:rgba(248,81,73,.15);color:var(--r)}
.b-n{background:rgba(139,148,158,.15);color:var(--mu)}
.tag{display:inline-block;padding:1px 7px;border-radius:6px;font-size:11px;margin-right:4px}
.t-isp{background:rgba(68,147,248,.15);color:var(--accent)}
.t-city{background:rgba(139,148,158,.15);color:var(--mu)}
.chip{display:inline-block;padding:3px 10px;border:1px solid var(--bd);border-radius:14px;
font-size:12px;cursor:pointer;margin:2px 3px;color:var(--mu)}
.chip.on{border-color:var(--accent);color:var(--accent);background:rgba(68,147,248,.1)}
.banner{display:none;background:rgba(210,153,34,.12);border:1px solid var(--y);
color:var(--y);border-radius:10px;padding:10px 14px;margin-bottom:14px;font-size:13px}
svg{display:block;max-width:100%}
.tablewrap{overflow-x:auto;-webkit-overflow-scrolling:touch}
.tablewrap>table{min-width:760px}
select,input{background:var(--bg);color:var(--tx);border:1px solid var(--bd);
border-radius:8px;padding:7px 10px;font-size:13px;outline:none}
select:focus,input:focus{border-color:var(--accent)}
#ip-list{max-height:280px;overflow:auto;border:1px solid var(--bd);border-radius:10px;
background:var(--card);margin-bottom:16px;font-size:13px}
#ip-list .row{display:flex;justify-content:space-between;padding:7px 12px;cursor:pointer;border-bottom:1px solid rgba(48,54,61,.5);gap:10px}
#ip-list .row:hover{background:rgba(68,147,248,.08)}
#ip-list .row.on{background:rgba(68,147,248,.16)}
#ip-list .row:last-child{border-bottom:none}
.hist{display:flex;gap:6px;align-items:flex-end;height:70px}
.hist .bar{width:18px;background:var(--accent);border-radius:3px 3px 0 0;position:relative;min-width:2px}
.hist .bar.fail{background:var(--r)}
.hist .lbl{font-size:10px;color:var(--mu);text-align:center}
@media (max-width:760px){
  .wrap{padding:14px 12px}
  #ip-list{max-height:200px}
  .cards{grid-template-columns:repeat(2,1fr)}
}
</style></head><body><div class="wrap">
<h1>🌐 itdog 全国评测</h1>
<div class="sub">
<span id="meta">加载中…</span>
<button class="btn2" id="run-btn" onclick="triggerRun()" style="margin-left:10px">▶ 手动触发本轮评测</button>
<a class="btn2" href="/" style="text-decoration:none">← 返回监控面板</a>
</div>
<div class="banner" id="banner"></div>

<div class="sub">1. 选择 IP(按融合评分排序,仅显示已有 itdog 评测的):</div>
<div id="ip-list"><span class="muted">加载中…</span></div>

<div id="detail" style="display:none">
<div class="cards" id="cards"></div>
<div class="sub" style="margin-top:6px">2. 历史多轮趋势</div>
<div class="card" style="margin-bottom:16px"><div id="hist"></div></div>
<div class="sub">3. 最新一轮节点明细 <span class="muted" id="node-count"></span>
<select id="f-isp" style="margin-left:10px"><option value="">全部运营商</option></select>
<select id="f-state" style="margin-left:6px">
<option value="">全部状态</option><option value="ok">只有连通</option><option value="fail">只有失败</option></select>
<input id="f-city" placeholder="筛选城市,如 广州" style="margin-left:6px">
</div>
<div class="tablewrap"><table class="rtable"><thead><tr>
<th>#</th><th>运营商</th><th>城市</th><th>节点</th><th>延迟 ms</th><th>目标 IP</th>
</tr></thead><tbody id="nodes"></tbody></table></div>
</div>
</div>
<script>
let DATA = null, CUR = null, f = {isp:"", state:"", city:""};

async function triggerRun(){
  const btn = document.getElementById("run-btn");
  btn.disabled = true; btn.textContent = "启动中…";
  try{
    const j = await fetch("/api/itdog/run").then(r=>r.json());
    alert(j.ok ? ("✅ " + j.msg) : ("⚠️ " + (j.error||"无法启动")));
  }catch(e){ alert("失败: " + e.message); }
  btn.disabled = false; btn.textContent = "▶ 手动触发本轮评测";
}

async function refresh(){
  const d = await fetch("/api/itdog").then(r=>r.json());
  DATA = d;
  const dn = d.ips.filter(x=>x.itdog_score!=null);
  const sc = d.src_count||{};
  const fb = Object.keys(sc).filter(k=>k!=="itdog").map(k=>`${k}×${sc[k]}`).join(", ");
  document.getElementById("meta").innerHTML =
    `生成于 ${d.generated_at} · 池 ${d.ips.length} IP · 已评测 ${dn.length}`+
    (d.itdog_last?` · 最近一轮 ${d.itdog_last}`:"")+(d.itdog_enabled?"":" · ⚠️ itdog 未启用(--itdog)")+
    (fb?` · <span style="color:var(--y)">⚠️ 含回退源: ${fb}(节点数/地区口径与 itdog 不同)</span>`:"")+
    (d.itdog_blocked?`<br><span style="color:var(--y)">⚠️ ${d.itdog_blocked}</span>`:"");
  document.getElementById("banner").style.display = d.itdog_enabled ? "none":"block";
  if(!d.itdog_enabled) document.getElementById("banner").innerHTML =
    `⚠️ 当前进程未启用 itdog 评测(--itdog)。本页只显示历史数据。`+
    (d.itdog_error?`<br>依赖自检失败: ${d.itdog_error}`:"");
  renderList(dn);
}

function renderList(list){
  const el = document.getElementById("ip-list");
  if(!list.length){ el.innerHTML = '<div class="muted" style="padding:10px">暂无 itdog 评测数据</div>'; return; }
  el.innerHTML = list.map((x,i)=>{
    const sc = x.itdog_score;
    const cls = sc>=90?"var(--g)":sc>=75?"var(--y)":"var(--r)";
    return `<div class="row" data-i="${i}" onclick="pick(${i})">
      <span class="mono">${x.ip}</span>
      <span><span style="color:${cls};font-weight:700">${sc}</span>
      <span class="muted">${sc!=null?`${x.latest.median_rtt!=null?x.latest.median_rtt+"ms":"—"} · ${x.latest.success_rate}% · ${x.latest.nodes}节点`:"—"}</span>
      ${x.src&&x.src!=="itdog"?`<span class="badge b-y" title="该行来自回退源, 节点数与地区口径与 itdog 不同">${x.src}</span>`:""}</span>
    </div>`;
  }).join("");
}

function pick(i){
  const ip = DATA.ips.filter(x=>x.itdog_score!=null)[i];
  CUR = ip;
  document.querySelectorAll("#ip-list .row").forEach(r=>r.classList.toggle("on", +r.dataset.i===i));
  renderDetail(ip);
}

function renderDetail(ip){
  document.getElementById("detail").style.display = "block";
  const l = ip.latest||{};
  const merged = ip.merged_score, local = ip.local_score;
  const scCol = (v)=> v==null ? "var(--mu)" : (v>=90?"var(--g)":v>=75?"var(--y)":"var(--r)");
  document.getElementById("cards").innerHTML =
   `<div class="card" style="grid-column:1/-1;border-color:var(--accent)"><div class="l">当前选中</div>
     <div class="v mono">${ip.ip}</div>
     <div class="muted" style="font-size:11px">${(ip.info?[ip.info.provider||ip.info.asn||"",ip.info.region].filter(Boolean).join(" · "):"")}</div></div>
   <div class="card"><div class="l">itdog 全国分</div><div class="v" style="color:${scCol(ip.itdog_score)}">${ip.itdog_score!=null?ip.itdog_score:"—"}</div></div>
   <div class="card"><div class="l">本地分</div><div class="v" style="color:${scCol(local)}">${local!=null?local:"—"}</div></div>
   <div class="card"><div class="l">融合分 <span class="muted" style="font-size:10px">(w=${DATA.weight_itdog}×新${ip.freshness!=null?Math.round(ip.freshness*100):0}%)</span></div><div class="v" style="color:${scCol(merged)}">${merged!=null?merged:"—"}</div></div>
   <div class="card"><div class="l">连通率</div><div class="v">${l.success_rate!=null?l.success_rate+"%":"—"}</div></div>
   <div class="card"><div class="l">评测来源</div><div class="v" style="font-size:14px">${l.src||"—"}${l.src&&l.src!=="itdog"?` <span class="badge b-y">回退源</span>`:""}</div></div>
   <div class="card"><div class="l">中位 / p95</div><div class="v">${l.median_rtt!=null?l.median_rtt+" / "+l.p95+"ms":"—"}</div></div>
   <div class="card"><div class="l">评测时间</div><div class="v" style="font-size:13px">${l.ts?new Date(l.ts*1000).toLocaleString("zh-CN",{hour12:false}):"—"}</div></div>`;
  renderHist(ip.history||[]);
  renderNodes(ip.nodes||[]);
}

function renderHist(hist){
  const el = document.getElementById("hist");
  if(!hist.length){ el.innerHTML = '<span class="muted">暂无历史(只显示最新一轮)</span>'; return; }
  // 按时间正向排列(旧->新)
  const h = hist.slice().reverse();
  const bar = h.map(x=>{
    const pct = x.success_rate!=null?Math.max(3,x.success_rate):0;
    return `<div style="display:flex;flex-direction:column;align-items:center;gap:4px">
      <div style="font-size:11px">${x.median_rtt!=null?x.median_rtt+"ms":""}</div>
      <div class="bar ${x.success_rate!=null&&x.success_rate<90?"fail":""}" style="height:${pct}px;min-height:3px"></div>
      <div class="lbl">${new Date(x.ts*1000).toLocaleDateString("zh-CN",{month:"2-digit",day:"2-digit"})}</div>
    </div>`;
  }).join("");
  el.innerHTML = `<div style="display:flex;gap:14px;align-items:flex-end;flex-wrap:wrap">${bar}</div>
  <div class="muted" style="font-size:11px;margin-top:6px">每根 = 一轮评测;柱高 = 连通率(%)。<span style="color:var(--r)">红色</span> = 该轮连通率 &lt; 90%</div>`;
}

function renderNodes(nodes){
  const el = document.getElementById("nodes");
  const src = (CUR&&CUR.latest&&CUR.latest.src)||"";
  document.getElementById("node-count").textContent =
    `(${nodes.length} 个节点${src?` · 来源 ${src}`:""}${src&&src!=="itdog"?" ⚠️ 回退源, 节点/地区口径与 itdog 不同":""})`;
  // 运营商选项
  const isps = [...new Set(nodes.map(n=>n.isp).filter(Boolean))].sort();
  const sel = document.getElementById("f-isp");
  const curIsp = sel.value;
  sel.innerHTML = '<option value="">全部运营商</option>'+isps.map(s=>`<option ${s===curIsp?"selected":""}>${s}</option>`).join("");
  const rows = nodes
    .filter(n=>!f.isp || n.isp===f.isp)
    .filter(n=>!f.city || (n.city||"").includes(f.city))
    .filter(n=> f.state==="" || (f.state==="ok" ? n.result!=='-1' : n.result==='-1'))
    .map((n,i)=>{
      const ok = n.result !== '-1';
      const lat = ok ? n.result : "—";
      const st = ok ? `<span class="badge b-g">通</span>` : `<span class="badge b-r">败</span>`;
      return `<tr><td>${i+1}</td>
        <td>${n.isp?`<span class="tag t-isp">${n.isp}</span>`:"—"}</td>
        <td>${n.city||"—"}</td>
        <td class="mono muted" style="font-size:11px">${n.node_id||"—"}</td>
        <td>${lat}${ok&&Number(lat)>150?` <span class="badge b-y">慢</span>`:""}</td>
        <td class="mono muted" style="font-size:11px">${n.ip||"—"}</td></tr>`;
    }).join("");
  el.innerHTML = rows || '<tr><td colspan="6" class="muted">无匹配节点</td></tr>';
}

document.getElementById("f-isp").addEventListener("change", e=>{ f.isp=e.target.value; if(CUR) renderNodes(CUR.nodes||[]);});
document.getElementById("f-state").addEventListener("change", e=>{ f.state=e.target.value; if(CUR) renderNodes(CUR.nodes||[]);});
document.getElementById("f-city").addEventListener("input", e=>{ f.city=e.target.value.trim(); if(CUR) renderNodes(CUR.nodes||[]);});
refresh();
</script></body></html>"""

PAGE_DOMAIN = """<!DOCTYPE html>
<html lang="zh-CN"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>域名监控 · 优选 IP 监控</title>
<style>
:root{--bg:#0d1117;--card:#161b22;--bd:#30363d;--tx:#e6edf3;--mu:#8b949e;
--g:#3fb950;--y:#d29922;--r:#f85149;--accent:#4493f8}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--tx);
font-family:"Segoe UI","Microsoft YaHei",sans-serif;font-size:14px}
.wrap{max-width:1100px;margin:0 auto;padding:20px}
h1{font-size:18px;margin:0 0 4px}
.sub{color:var(--mu);font-size:12px;margin-bottom:14px;display:flex;align-items:center;flex-wrap:wrap;gap:6px}
a{color:var(--accent);text-decoration:none}
.btn2{background:none;border:1px solid var(--bd);color:var(--tx);border-radius:8px;
padding:4px 12px;font-size:12px;cursor:pointer;text-decoration:none;margin-left:8px}
.btn2:hover{border-color:var(--accent);color:var(--accent)}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin-bottom:16px}
.card{background:var(--card);border:1px solid var(--bd);border-radius:10px;padding:12px 16px}
.card .l{color:var(--mu);font-size:12px}.card .v{font-size:20px;font-weight:700;margin-top:2px}
table{width:100%;border-collapse:collapse;background:var(--card);
border:1px solid var(--bd);border-radius:10px;overflow:hidden}
th,td{padding:9px 10px;text-align:left;border-bottom:1px solid var(--bd);font-size:13px}
th{color:var(--mu);font-weight:500;background:#11161d;white-space:nowrap}
tr:last-child td{border-bottom:none}
.mono{font-family:Consolas,monospace}
.muted{color:var(--mu)}
.badge{display:inline-block;padding:2px 8px;border-radius:9px;font-size:11px;font-weight:600}
.b-g{background:rgba(63,185,80,.15);color:var(--g)}
.b-y{background:rgba(210,153,34,.15);color:var(--y)}
.b-r{background:rgba(248,81,73,.15);color:var(--r)}
.rate-g{color:var(--g);font-weight:600}.rate-r{color:var(--r);font-weight:600}.rate-n{color:var(--mu)}
@media (max-width:760px){.wrap{padding:14px 12px}}
</style></head><body><div class="wrap">
<h1>🌐 域名监控</h1>
<div class="sub">
<span id="meta">加载中…</span>
<a class="btn2" href="/" style="text-decoration:none">← 返回监控面板</a>
</div>
<div class="cards" id="cards"></div>
<div class="tablewrap">
<table><thead><tr>
<th>域名</th><th>解析 IP</th><th>端到端状态</th><th>端到端延迟</th><th>全国连通率</th><th>全国中位</th><th>数据源</th><th>最后检测</th>
</tr></thead><tbody id="rows"></tbody></table>
</div>
<div class="note muted" style="font-size:12px;margin-top:12px">
· 端到端 = 系统 DNS 解析域名 → 连解析出的 IP(SNI=域名) → GET /(2xx/3xx 视为可达),每 <span id="iv"></span> 一次<br>
· 全国 = 对域名做 tcping(itdog → tcptest → kkce 三级回退),各节点用自己的 DNS 解析域名再连,反映全国各运营商连通性
</div>
</div>
<script>
function esc(s){return String(s);}
function renderCards(d){
  const n = d.domains.length;
  const ok = d.domains.filter(x=>x.e2e_ok===1).length;
  document.getElementById("cards").innerHTML =
   `<div class="card"><div class="l">监控域名</div><div class="v">${n}</div></div>`+
   `<div class="card"><div class="l">当前端到端正常</div><div class="v">${ok}/${n}</div></div>`;
}
function rateCls(v){ return v==null?"rate-n":(v>=95?"rate-g":"rate-r"); }
let DATA = null;
function renderRows(d){
  const el = document.getElementById("rows");
  DATA = d;
  el.innerHTML = d.domains.map((x,i)=>{
    const ok = x.e2e_ok===1;
    const bd = ok?`<span class="badge b-g">在线</span>`:`<span class="badge b-r">离线</span>`;
    const lat = x.e2e_latency_ms!=null ? x.e2e_latency_ms+" ms" : "—";
    const r24 = x.itdog_rate!=null ? x.itdog_rate+"%" : "—";
    const med = x.itdog_med_rtt!=null ? x.itdog_med_rtt+" ms" : "—";
    const src = x.itdog_src ? `<span class="badge b-y">${esc(x.itdog_src)}</span>` : "—";
    const when = x.last_ts ? new Date(x.last_ts*1000).toLocaleString("zh-CN",{hour12:false}) : "—";
    const ncnt = (x.nodes||[]).length;
    return `<tr class="drow" data-i="${i}" onclick="toggle(${i})" style="cursor:pointer">
      <td class="mono">${esc(x.domain)} <span class="muted" style="font-size:11px">▸ ${ncnt?ncnt+"节点":"无明细"}</span></td>
      <td class="mono muted">${x.resolve_ip||"—"}</td>
      <td>${bd}</td>
      <td>${lat}</td>
      <td class="${rateCls(x.itdog_rate)}">${r24}</td>
      <td>${med}</td>
      <td>${src}</td>
      <td class="muted">${when}</td></tr>
      <tr class="dnodes" id="dn-${i}" style="display:none"><td colspan="8" style="padding:6px">明细加载中…</td></tr>`;
  }).join("");
}
function toggle(i){
  const tr = document.getElementById("dn-"+i);
  if(!tr) return;
  if(tr.style.display !== "none"){ tr.style.display="none"; return; }
  tr.style.display = "table-row";
  const dom = DATA.domains[i];
  const nodes = dom.nodes || [];
  if(!nodes.length){ tr.innerHTML = `<td colspan="8" class="muted" style="padding:10px">暂无节点明细</td>`; return; }
  const okN = nodes.filter(n=>n.result!==null && n.result!=='-1' && n.result!=='').length;
  const rows = nodes.map((n,j)=>{
    const isOk = n.result!==null && n.result!=='-1' && n.result!=='';
    const lat = isOk ? n.result+" ms" : "—";
    const st = isOk ? `<span class="badge b-g">通</span>` : `<span class="badge b-r">败</span>`;
    return `<tr><td>${j+1}</td><td>${n.isp?`<span class="badge b-y">${esc(n.isp)}</span>`:"—"}</td><td>${esc(n.city||"—")}</td><td class="mono muted" style="font-size:11px">${esc(n.node_id||"—")}</td><td>${st}</td><td>${lat}</td></tr>`;
  }).join("");
  tr.innerHTML = `<td colspan="8" style="padding:8px">
    <div class="muted" style="margin-bottom:6px">${esc(dom.domain)} · 全国 tcping 节点明细 · 成功 ${okN}/${nodes.length} 个</div>
    <div style="overflow-x:auto;max-height:420px;overflow-y:auto">
    <table style="background:#0b0f14"><thead><tr><th>#</th><th>运营商</th><th>城市</th><th>节点</th><th>状态</th><th>延迟</th></tr></thead>
    <tbody>${rows}</tbody></table></div>
  </td>`;
}
async function refresh(){
  const d = await fetch("/api/abc").then(r=>r.json());
  document.getElementById("meta").innerHTML =
    `生成于 ${d.generated_at} · 每 ${d.interval}s 一次`;
  document.getElementById("iv").textContent = d.interval+"s";
  renderCards(d);
  renderRows(d);
}
refresh();
setInterval(refresh, 30000);
</script></body></html>"""

PAGE_LOGIN = """<!DOCTYPE html>
<html lang="zh-CN"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>需要访问路径</title>
<style>
:root{--bg:#0d1117;--card:#161b22;--bd:#30363d;--tx:#e6edf3;--mu:#8b949e;--accent:#4493f8}
*{box-sizing:border-box}
body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;
background:var(--bg);color:var(--tx);font-family:"Segoe UI","Microsoft YaHei",sans-serif}
.box{width:min(420px,92vw);background:var(--card);border:1px solid var(--bd);
border-radius:12px;padding:24px}
h1{font-size:16px;margin:0 0 6px}
p{color:var(--mu);font-size:12px;line-height:1.6;margin:0 0 16px}
input{width:100%;background:var(--bg);color:var(--tx);border:1px solid var(--bd);
border-radius:8px;padding:10px 12px;font-size:14px;outline:none}
input:focus{border-color:var(--accent);box-shadow:0 0 0 2px rgba(68,147,248,.2)}
button{width:100%;margin-top:10px;background:var(--accent);color:#fff;border:none;
border-radius:8px;padding:10px;font-size:14px;cursor:pointer}
button:hover{background:#3b87e8}
.err{color:#f85149;font-size:12px;margin-top:8px;min-height:16px}
</style></head><body>
<div class="box">
<h1>🔒 需要访问路径</h1>
<p>请输入你的访问路径(即你自己设置的那段串),将跳转到
<code id="host"></code>/&lt;路径&gt; 完成登录。</p>
<form id="f">
<input id="p" placeholder="访问路径" autocomplete="off" autofocus>
<button type="submit">进入</button>
<div class="err" id="e"></div>
</form>
</div>
<script>
document.getElementById("host").textContent = location.origin;
document.getElementById("f").addEventListener("submit", function(ev){
  ev.preventDefault();
  var v = document.getElementById("p").value.trim().replace(/^[/]+|[/]+$/g, "");
  if(!v){ document.getElementById("e").textContent = "请输入路径"; return; }
  if(/[^A-Za-z0-9._~-]/.test(v)){ document.getElementById("e").textContent = "路径只含字母、数字、-、_、.、~"; return; }
  location.href = "/" + v;
});
</script></body></html>"""

class Handler(BaseHTTPRequestHandler):
    def _authed(self):
        if not AUTH_TOKEN:
            return True
        q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query).get("key", [None])[0]
        if q and hmac.compare_digest(q, AUTH_TOKEN):
            return "set-cookie"
        m = re.search(r"auth=([0-9a-f]{8,64})", self.headers.get("cookie", ""))
        if m and hmac.compare_digest(m.group(1), AUTH_TOKEN):
            return True
        return False

    def _send(self, code, ctype, body, cookie=None):
        self.send_response(code)
        self.send_header("content-type", ctype)
        self.send_header("content-length", str(len(body)))
        self.send_header("cache-control", "no-store")
        if cookie:
            self.send_header("set-cookie",
                             f"auth={cookie}; Path=/; Max-Age=2592000; HttpOnly")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path0 = self.path.split("?")[0]
        if path0 == AUTH_PATH:
            self.send_response(302)
            self.send_header("location", "/")
            self.send_header("set-cookie",
                             f"auth={AUTH_TOKEN}; Path=/; Max-Age=2592000; HttpOnly")
            self.send_header("content-length", "0")
            self.end_headers()
            return
        authed = self._authed()
        if authed == "set-cookie":
            if path0.startswith("/api/"):
                # API 调用直接放行, 不做 302。
                # 原因: "带 ?key= → 302 跳转到去掉 query 的地址 + 种 Cookie" 的设计会把
                # **除 key 以外的所有 query 参数一起丢掉** —— 实测 /api/best?n=60&key=… 只
                # 返回默认 8 条、/api/logs?lines=5&key=… 直接空响应。跟随跳转的脚本客户端
                # (urllib/Invoke-RestMethod) 全部中招; daily_test_dns.py --n-best 30 实际只拿到 8 个候选。
                # 脚本每次都自带 ?key=, 不需要 Cookie, 所以 API 路径直接按已认证处理。
                authed = True
            else:
                clean = urllib.parse.urlparse(self.path)._replace(query="").geturl()
                self.send_response(302)
                self.send_header("location", clean)
                self.send_header("set-cookie",
                                 f"auth={AUTH_TOKEN}; Path=/; Max-Age=2592000; HttpOnly")
                self.send_header("content-length", "0")
                self.end_headers()
                return
        if not authed:
            # 绝不回显真实登录路径(那等于把门禁口令写在门上)。
            # 浏览器请求返回一个输入框:输入后跳到 当前域名/<输入内容>,
            # 命中登录路径即种 Cookie 并跳回面板。
            if "text/html" in (self.headers.get("accept") or ""):
                self._send(401, "text/html; charset=utf-8", PAGE_LOGIN.encode("utf-8"))
            else:
                self._send(401, "text/plain; charset=utf-8",
                           "unauthorized".encode("utf-8"))
            return
        path = self.path.split("?")[0]
        if path == "/" or path == "/index.html":
            self._send(200, "text/html; charset=utf-8", PAGE.encode("utf-8"))
        elif path == "/logs" or path == "/logs/":
            self._send(200, "text/html; charset=utf-8", PAGE_LOGS.encode("utf-8"))
        elif path == "/api/stats":
            # 用不阻塞的版本:CF API 慢起来要几分钟,面板不能等它。
            dns = current_dns_records_cached()
            stats = all_stats(dns)
            # 曲线仍逐 IP 查询:48 小时窗口下每次都能直接走 (ip,ts) 索引且无需
            # 分组,实测(119ms)比"一条 GROUP BY ip,h 批量聚合"(143ms)更快,
            # 所以这里不做批量化。
            for p in stats["ips"]:
                p["hist"] = hourly_series(p["ip"], 48)
            stats["dns"] = dns
            self._send(200, "application/json; charset=utf-8",
                       json.dumps(stats, ensure_ascii=False).encode("utf-8"))
        elif path == "/api/series":
            q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            sip = (q.get("ip") or [""])[0]
            hours = int((q.get("hours") or ["48"])[0])
            if sip == "all":
                data = merged_series(hours)
            else:
                data = hourly_series(sip, hours)
            self._send(200, "application/json; charset=utf-8",
                       json.dumps(data, ensure_ascii=False).encode("utf-8"))
        elif path == "/api/resolvetest":
            q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            dm = (q.get("domain") or [""])[0].strip()
            rounds = min(20, max(1, int((q.get("rounds") or ["5"])[0])))
            qtype = 28 if (q.get("type") or ["A"])[0].upper() == "AAAA" else 1
            if not re.match(r"^[A-Za-z0-9.-]+$", dm):
                self._send(400, "application/json; charset=utf-8",
                           json.dumps({"error": "域名格式不合法"}).encode("utf-8"))
                return
            data = resolve_test(dm, rounds, qtype=qtype)
            self._send(200, "application/json; charset=utf-8",
                       json.dumps(data, ensure_ascii=False).encode("utf-8"))
        elif path == "/api/dohspeed":
            q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            dm = (q.get("domain") or [""])[0].strip()
            rounds = min(20, max(1, int((q.get("rounds") or ["5"])[0])))
            if not re.match(r"^[A-Za-z0-9.-]+$", dm):
                self._send(400, "application/json; charset=utf-8",
                           json.dumps({"error": "域名格式不合法"}).encode("utf-8"))
                return
            data = dohspeed_test(dm, rounds)
            self._send(200, "application/json; charset=utf-8",
                       json.dumps(data, ensure_ascii=False).encode("utf-8"))
        elif path == "/api/logs":
            q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            lines = int((q.get("lines") or ["300"])[0])
            query = (q.get("q") or [""])[0].strip()[:80]
            data = read_log_tail(lines, query)
            self._send(200, "application/json; charset=utf-8",
                       json.dumps(data, ensure_ascii=False).encode("utf-8"))
        elif path == "/api/itdog":
            self._send(200, "application/json; charset=utf-8",
                       json.dumps(itdog_api_payload(), ensure_ascii=False).encode("utf-8"))
        elif path == "/api/best":
            # 当前融合评分最好的 N 个 IP(默认 8,可用 ?n= 调整)
            q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
            try:
                n = max(1, min(60, int((q.get("n") or ["8"])[0])))
            except (TypeError, ValueError):
                n = 8
            self._send(200, "application/json; charset=utf-8",
                       json.dumps(best_ips(n=n), ensure_ascii=False).encode("utf-8"))
        elif path == "/api/abc":
            self._send(200, "application/json; charset=utf-8",
                       json.dumps(domain_status_payload(), ensure_ascii=False).encode("utf-8"))
        elif path == "/abc" or path == "/abc/":
            self._send(200, "text/html; charset=utf-8", PAGE_DOMAIN.encode("utf-8"))
        elif path == "/api/itdog/run":
            # 手动触发一轮 itdog 评测(后台线程,立即返回;已在跑则拒绝)
            if not ITDOG_ENABLED:
                self._send(400, "application/json; charset=utf-8",
                           json.dumps({"ok": False, "error": "itdog 未启用(--itdog)"}).encode("utf-8"))
                return
            if _itdog_busy.is_set():
                self._send(200, "application/json; charset=utf-8",
                           json.dumps({"ok": False, "error": "上一轮评测仍在进行"}).encode("utf-8"))
                return
            # 不在这里 set 锁: itdog_eval_round 自己"查锁→set→finally 清",
            # 线程启动后若发现已有一轮在跑会自己跳过。此处再 set 会让新一轮
            # 误判"已在评测"而空转(并因无处 clear 而把锁留给下一轮)。
            threading.Thread(target=_itdog_run_thread, daemon=True).start()
            self._send(200, "application/json; charset=utf-8",
                       json.dumps({"ok": True, "msg": "评测已在后台启动"}).encode("utf-8"))
        elif path == "/itdog" or path == "/itdog/":
            self._send(200, "text/html; charset=utf-8", PAGE_ITDOG.encode("utf-8"))
        else:
            self._send(404, "text/plain; charset=utf-8", b"not found")

    def log_message(self, fmt, *args_):
        pass  # 静默访问日志

def main():
    global ITDOG_ENABLED, _ITDOG_LOAD_ERROR
    db_init()
    # 先把上次已知的 A 记录装回缓存(面板一开就有数据,不用空等 CF API),
    # 再在后台主动刷新一次校正。
    _load_dns_cache_from_meta()
    _kick_dns_refresh()
    if ITDOG_ENABLED:
        # 启动自检: itdog/ 目录缺失或 itdog_api.py 不可导入时, 明确告警并关闭功能,
        # 不启动评测线程 —— 否则每 24h 只留一行异常日志, 而 /api/itdog 仍显示历史数据。
        # itdog/ 是 tools/monitor.py 的相对路径硬依赖(已入库, 但部署机/拷贝可能漏掉)。
        try:
            _itdog_api()
        except Exception as e:
            _ITDOG_LOAD_ERROR = "%s: %s (期望 %s)" % (
                type(e).__name__, e, os.path.join(ITDOG_API_PATH, "itdog_api.py"))
            ITDOG_ENABLED = False
            log(f"[itdog] 依赖自检失败, 已关闭 itdog 评测: {_ITDOG_LOAD_ERROR}")
    if ITDOG_ENABLED:
        threading.Thread(target=itdog_loop, daemon=True).start()
        log(f"[itdog] 全国评测线程已启动(周期 {ARGS.itdog_hours}h, top-{ARGS.itdog_top}, "
            f"权重 {ARGS.itdog_weight}, 节流 {ARGS.itdog_sleep}s)")
    threads = 0
    if ARGS.monitor_domains and ARGS.monitor_domains.strip():
        threading.Thread(target=domain_monitor_loop, daemon=True).start()
        log(f"[abc] 域名监控线程已启动({ARGS.monitor_domains}, 每 {ARGS.interval}s)")
        threads += 1
    if ARGS.ntprxx_patrol:
        if not ITDOG_ENABLED:
            log("[ntprxx] ⚠️ 未启用 --itdog: 候选排序只能用库里已有的历史全国分(可能过期), "
                "建议同时开 --itdog")
        threading.Thread(target=ntprxx_patrol_loop, daemon=True).start()
        log(f"[ntprxx] 反代 IP 巡检线程已启动(域名 {ARGS.ntprxx_domain}, "
            f"阈值 {ARGS.ntprxx_threshold}%, keep {ARGS.ntprxx_keep}, 周期 {ARGS.ntprxx_hours}h, "
            f"节流 {ARGS.ntprxx_sleep}s"
            + (", 启动即按 itdog 最优对齐" if ARGS.ntprxx_align else "")
            + (", DRY-RUN(不写 DNS)" if ARGS.ntprxx_dry_run else "") + ")")
        threads += 1
    else:
        log("[ntprxx] 反代 IP 巡检未启用(--ntprxx-patrol); 该域名的 A 记录不会被本进程改动")
    threading.Thread(target=probe_loop, daemon=True).start()
    server = ThreadingHTTPServer((ARGS.host, ARGS.port), Handler)
    log(f"[monitor] 池文件: {ARGS.pool} | 高频探测: {ARGS.interval}s(域名+DNS IP) | 池内全测: {ARGS.pool_interval}s")
    log(f"[monitor] WebUI: http://localhost:{ARGS.port}/")
    log("[monitor] Ctrl+C 退出")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        _stop.set()

if __name__ == "__main__":
    main()
