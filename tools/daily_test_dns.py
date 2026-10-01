#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
daily_test_dns.py - 每日巡检反代域名 IP 全国在线率, 问题 IP 自动替换。

流程:
  1. 读巡检域名当前 A 记录(CF API, 灰云)
  2. 对每个 IP 做全国 TCP 检测: itdog -> tcptest -> kkce 三级回退(缺配额自动换源)
  3. 连通率 < --threshold(默认90%) 判为问题 IP
  4. 有问题则从 monitor /api/best 拉候选, 挑 不在用 + 24h在线率>=99% + itdog分高 的替补
  5. 先新增替补 A 记录, 再删除问题 IP 记录(防空窗)

用法:
  python daily_test_dns.py                       # 用默认参数跑一次
  python daily_test_dns.py --threshold 95        # 阈值
  python daily_test_dns.py --dry-run             # 只检测不替换
  # 定时(每天): 用任务计划或 cron 调本脚本

域名 / zone id 来自 tools/.monitor.env(NTPRXX_DOMAIN / CF_ZONE_ID),真实值不入库;
本脚本会写 DNS, 因此启动时硬校验: 占位符一律拒绝运行。

依赖: itdog_api.py / tcptest_api.py / kkce_api.py; 需联网能访问这三站。
"""
import io, json, os, sys, socket, ssl, time, argparse, http.client, urllib.request, http.cookiejar

TOOLS_DIR = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(TOOLS_DIR)
sys.path.insert(0, os.path.join(REPO, "itdog"))
sys.path.insert(0, os.path.join(REPO, "tcptest"))
sys.path.insert(0, os.path.join(REPO, "kkce"))

# ---- 本地私有配置(tools/.monitor.env):真实域名/zone id 不写进源码 ----
_ENV_PATH = os.path.join(TOOLS_DIR, ".monitor.env")


def _load_env(path):
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


def env(key, fallback=""):
    return os.environ.get(key) or ENV.get(key) or fallback


def _is_placeholder(val):
    """空值, 或以 your- 开头的占位符(路径类占位符前面带 /, 故先剥掉 /)。"""
    s = str(val or "").strip()
    if not s:
        return True
    return s.lstrip("/").startswith("your-")


AP = argparse.ArgumentParser()
AP.add_argument("--threshold", type=float, default=95.0, help="连通率低于此值判问题IP(百分比,默认95)")
AP.add_argument("--domain", default=env("NTPRXX_DOMAIN", "your-domain.example"),
                help="巡检域名(默认取 tools/.monitor.env 的 NTPRXX_DOMAIN)")
AP.add_argument("--zone-id", default=env("CF_ZONE_ID", ""),
                help="zone id(默认取 tools/.monitor.env 的 CF_ZONE_ID;留空=按域名自动匹配)")
AP.add_argument("--dry-run", action="store_true", help="只检测不写DNS")
AP.add_argument("--target-port", type=int, default=443, help="tcping 端口")
AP.add_argument("--monitor", default="http://127.0.0.1:8080", help="monitor 面板地址")
AP.add_argument("--min-rate", type=float, default=99.0, help="候选要求 24h 在线率下限(百分比,默认99)")
AP.add_argument("--n-best", type=int, default=30, help="从 /api/best 取多少候选")
AP.add_argument("--max-replace", type=int, default=3, help="每轮最多替换几个问题IP")
AP.add_argument("--throttle", type=float, default=28.0,
                help="逐个 IP 之间的节流秒(默认28, 防 itdog 频率风控)")
AP.add_argument("--keep", type=int, default=3, help="保持的 A 记录条数(默认3, 用于裁剪多余记录)")
AP.add_argument("--blacklist", default="",
                help="额外排除的 IP(逗号分隔)。默认空 —— 原先硬编码在用的 3 个 IP, 会随 DNS 变化而过期")
ARGS = AP.parse_args()

# 额外黑名单(可选)。注意: 早先这里硬编码了"当前在用的 3 个 IP", 一旦 DNS 变化就过期,
# 而"在用"本来就由 existing 过滤, 属于冗余+隐患 → 改为参数, 默认空。
BLACKLIST = {s.strip() for s in (ARGS.blacklist or "").split(",") if s.strip()}

_LOG_PATH = os.path.join(TOOLS_DIR, "daily_test_dns.log")
log_fh = open(_LOG_PATH, "a", buffering=1, encoding="utf-8")

def log(*a):
    msg = " ".join(str(x) for x in a)
    ts = time.strftime("%m-%d %H:%M:%S")
    line = (ts + " " + msg + "\n")
    try:
        sys.stdout.write(line)
        sys.stdout.flush()
    except Exception:
        try:
            sys.stdout.buffer.write(line.encode("utf-8", "replace"))
            sys.stdout.buffer.flush()
        except Exception:
            pass
    log_fh.write(line)

# ---------- 启动硬校验:本脚本会写 DNS,占位符一律拒绝运行 ----------
if _is_placeholder(ARGS.domain):
    log("!! 启动中止: --domain 仍是占位符或为空, 拒绝运行(本脚本会写 DNS)")
    log("   请在 tools/.monitor.env 里设置 NTPRXX_DOMAIN=<真实域名>")
    if not os.path.exists(_ENV_PATH):
        log(f"!! 配置文件不存在: {_ENV_PATH}")
        log("   模板见 tools/.monitor.env.example")
    sys.exit(1)

# ---------- CF token + 代理回落(复用 monitor 方案) ----------
def _read_tok():
    for f in (os.path.join(TOOLS_DIR, ".cf-token"), os.path.join(REPO, ".dev.vars")):
        if os.path.exists(f):
            c = open(f, encoding="utf-8").read()
            if f.endswith(".cf-token"):
                return c.strip()
            for line in c.splitlines():
                if line.startswith("CLOUDFLARE_API_TOKEN="):
                    return line.split("=", 1)[1].strip()
    raise RuntimeError("no token")

PROXY = ("127.0.0.1", 10808)
class S5C(http.client.HTTPSConnection):
    def __init__(self, *a, **k): self.proxy = PROXY; super().__init__(*a, **k)
    def connect(self):
        s = socket.create_connection(self.proxy, timeout=12)
        try:
            s.sendall(bytes([5, 1, 0])); s.recv(2)
            h = self.host
            try: addr = bytes([1]) + socket.inet_aton(h)
            except OSError: he = h.encode("idna"); addr = bytes([3, len(he)]) + he
            s.sendall(bytes([5, 1, 0]) + addr + self.port.to_bytes(2, "big")); s.recv(10)
        except Exception: s.close(); raise
        try: self.sock = self._context.wrap_socket(s, server_hostname=self.host)
        except Exception: s.close(); raise
class S5H(urllib.request.HTTPSHandler):
    def https_open(self, req): return self.do_open(lambda *a, **k: S5C(*a, **k), req)

TOK = _read_tok()
TLS_CTX = ssl.create_default_context()
TLS_CTX.check_hostname = False; TLS_CTX.verify_mode = ssl.CERT_NONE

def cf_api(method, path, body=None):
    data = json.dumps(body).encode() if body is not None else None
    op = urllib.request.build_opener(urllib.request.ProxyHandler({}), S5H())
    req = urllib.request.Request("https://api.cloudflare.com/client/v4"+path, data=data,
        headers={"Authorization": "Bearer "+TOK, "Content-Type": "application/json"}, method=method)
    try:
        with op.open(req, timeout=30) as r: return r.status, json.load(r)
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode("utf-8", "replace") or "{}")
    except Exception as e:
        return None, {"error": repr(e)}

# ---------- monitor /api/best ----------
def best_candidates(n):
    try:
        mto = open(os.path.join(TOOLS_DIR, "monitor-token.txt"), encoding="utf-8").read().strip()
    except Exception:
        mto = None
    url = f"{ARGS.monitor}/api/best?n={n}" + (f"&key={mto}" if mto else "")
    try:
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req, timeout=30) as r:
            d = json.load(r)
        return d.get("best", [])
    except Exception as e:
        log("[monitor] /api/best 失败:", repr(e))
        return []

# ---------- 全国检测: itdog -> tcptest -> kkce ----------
def itdog_probe(ip):
    import itdog_api as ia
    info = ia.start_task(f"{ip}:{ARGS.target_port}", "tcping")
    results, _ = ia.collect_results(info["task_id"], info["wss_url"], timeout=90,
                                    expected_nodes=info.get("check_node_num", 0))
    ok = sum(1 for m in results if m.get("result") not in (None, "-1") and m.get("ip") != "0.0.0.0")
    tot = len(results)
    return None if tot == 0 else (ok / tot * 100, ok, tot)

def tcptest_probe(ip):
    import tcptest_api as ta
    uuids = ta.list_nodes()
    payload, tid, cancel = ta.build_payload(f"{ip}:{ARGS.target_port}", uuids)
    st, d = ta.request("POST", "/api/v2/tasks", payload,
                       {"Idempotency-Key": tid, "X-Task-Cancel-Token": cancel})
    if st != 202: return None
    for _ in range(60):
        time.sleep(2)
        st, d = ta.request("GET", f"/api/v2/tasks/{tid}")
        if st == 200 and d.get("state") in ("succeeded", "partial", "failed", "cancelled"):
            break
    results = []; cursor = "0"
    while True:
        st, d = ta.request("GET", f"/api/v2/tasks/{tid}/results?after={cursor}&limit=100")
        if st != 200: break
        results += d.get("results", [])
        if not d.get("has_more"): break
        cursor = d["next_cursor"]
    try: ta.request("DELETE", f"/api/v2/tasks/{tid}", None, {"X-Task-Cancel-Token": cancel})
    except Exception: pass
    ok = sum(1 for r in results if r.get("success"))
    tot = len(results)
    return None if tot == 0 else (ok / tot * 100, ok, tot)

def kkce_probe(ip):
    import kkce_api as kk
    st, _html, results, count, _o = kk.run_probe(ip, port=str(ARGS.target_port), verbose=False)
    ok = 0; tot = 0
    for it in results:
        r = it.get("tcp_ping_check_resp") or {}
        if str(r.get("s_status")) == "1" and r.get("s_avg_time"):
            ok += 1
        tot += 1
    return None if tot == 0 else (ok / tot * 100, ok, tot)

def probe_ip(ip):
    """三级回退: itdog -> kkce -> tcptest(与 monitor 的回退顺序保持一致)。
    注: kkce 节点数(314~325)远多于 tcptest(151~158), 所以放在第二优先。
    返回 (rate%, ok, tot, src) 或 None。"""
    for fn, name in ((itdog_probe, "itdog"), (kkce_probe, "kkce"), (tcptest_probe, "tcptest")):
        try:
            r = fn(ip)
            if r:
                return (r[0], r[1], r[2], name)
        except Exception as e:
            log(f"  {name} 失败: {type(e).__name__}: {e}")
    return None

def get_test_records(retries=3):
    """读 A 记录。失败重试(等差数列退避), 最终失败**抛异常** —— 由 main() 转成非零退出码。

    旧实现在这里失败后返回 [] , main() 打印"无 A 记录"就以 **退出码 0** 结束,
    于是计划任务显示"成功"、整轮静默空转(2026-09-27 09:00 就是这样: SOCKS5 到
    api.cloudflare.com 的 TLS 握手超时 → 那天等于没巡检)。
    """
    last = None
    for i in range(retries):
        st, d = cf_api("GET", f"/zones/{ARGS.zone_id}/dns_records?name={ARGS.domain}&per_page=100")
        if st == 200:
            return [(r["content"], r["id"]) for r in (d.get("result") or []) if r["type"] == "A"]
        last = d.get("errors") or d.get("error")
        log(f"[cf] 读记录失败({i + 1}/{retries}): {last}")
        if i < retries - 1:
            time.sleep(2 + i * 3)
    raise RuntimeError(f"CF 读记录失败(已重试 {retries} 次): {last}")

def trim_records(keep, recs=None):
    """把 A 记录裁回 keep 条(先加后删失败会残留记录)。

    优先保留 monitor 评分高的; 拿不到评分时按本轮实测连通率; 都没有则保留前 keep 条。
    """
    cur = recs if recs is not None else get_test_records()
    if len(cur) <= keep:
        return 0
    rank = {}
    for c in best_candidates(60):
        ip = c.get("ip")
        if ip:
            rank[ip] = c.get("itdog_score") if c.get("itdog_score") is not None else c.get("score") or 0
    cur_sorted = sorted(cur, key=lambda x: -(rank.get(x[0], -1)))
    drop = cur_sorted[keep:]
    for ip, rid in drop:
        st, d = cf_api("DELETE", f"/zones/{ARGS.zone_id}/dns_records/{rid}")
        log(f"[cf] 裁剪多余 A 记录: {ip} ({'OK' if st == 200 else 'FAIL'})")
    return len(drop)

def replace_ip(bad_ip, bad_id, replacement):
    # 先加后删
    st, d = cf_api("POST", f"/zones/{ARGS.zone_id}/dns_records",
                   {"type": "A", "name": ARGS.domain, "content": replacement,
                    "proxied": False, "ttl": 60})
    if st != 200:
        log(f"[cf] 新增 {replacement} 失败:", d.get("errors") or d.get("error"))
        return False
    st, d = cf_api("DELETE", f"/zones/{ARGS.zone_id}/dns_records/{bad_id}")
    log(f"[cf] 替换: {bad_ip} -> {replacement}  删除 {'OK' if st==200 else 'FAIL'}")
    return True

def resolve_zone():
    """zone id:优先 --zone-id / CF_ZONE_ID;留空则按域名后缀匹配 token 可见的 zone。"""
    if ARGS.zone_id:
        return ARGS.zone_id
    st, d = cf_api("GET", "/zones?per_page=50")
    if st != 200 or not (d or {}).get("success"):
        log(f"!! 读 zone 列表失败(HTTP {st}): {str(d)[:200]} → 退出码 1")
        sys.exit(1)
    parts = ARGS.domain.split(".")
    for i in range(1, len(parts) - 1):
        cand = ".".join(parts[i:])
        for z in d.get("result") or []:
            if z.get("name") == cand:
                log(f"[zone] {ARGS.domain} -> {cand} (zone {z.get('id')})")
                return z["id"]
    log(f"!! 找不到 {ARGS.domain} 对应的 zone(token 权限或域名写错) → 退出码 1")
    sys.exit(1)


def main():
    ARGS.zone_id = resolve_zone()
    try:
        recs = get_test_records()
    except Exception as e:
        # 不再静默: 读不到记录 = 无法巡检, 必须让计划任务看到失败
        log(f"[cf] 读记录最终失败: {type(e).__name__}: {e}  → 退出码 1")
        sys.exit(1)
    if not recs:
        log(f"无 A 记录: {ARGS.domain} → 退出码 1(记录缺失本身就是故障)")
        sys.exit(1)
    log(f"=== 巡检 {ARGS.domain}: {[ip for ip,_ in recs]} ===")
    bad = []
    n_fail_all = 0
    for i, (ip, rid) in enumerate(recs):
        r = probe_ip(ip)
        if r is None:
            log(f"  {ip}: 三源均失败(跳过)")
            n_fail_all += 1
        else:
            rate, ok, tot, src = r
            flag = "[OK]" if rate >= ARGS.threshold else "[BAD]"
            log(f"  {ip}: {rate:.1f}% ({ok}/{tot}) [{src}] {flag}")
            if rate < ARGS.threshold:
                bad.append((ip, rid, rate))
        if i < len(recs) - 1 and ARGS.throttle > 0:
            time.sleep(ARGS.throttle)      # 逐个 IP 之间的节流: 防 itdog 频率风控
    if n_fail_all == len(recs):
        log("三源对全部 IP 都失败, 无法判定 → 退出码 1")
        sys.exit(1)
    if len(recs) > ARGS.keep:
        log(f"[cf] 现有 {len(recs)} 条 A 记录 > keep={ARGS.keep}, 先裁剪")
        trim_records(ARGS.keep, recs)
        recs = get_test_records()
    if not bad:
        log(f"=== 全部 {len(recs)} 个 IP 正常(阈值 {ARGS.threshold}%), 无需替换 ===")
        return
    if ARGS.dry_run:
        log(f"[dry-run] 检测到 {len(bad)} 个问题IP, 不执行替换")
        for ip, _, rate in bad: log(f"    问题: {ip} ({rate:.1f}%)")
        return
    # 从 monitor 拉候选
    cands = best_candidates(ARGS.n_best)
    if not cands:
        log("[monitor] 无候选, 跳过替换")
        return
    log(f"[monitor] 候选 {len(cands)} 个(取 itdog 分最高的)")
    existing = {ip for ip, _ in recs}
    # 过滤: 不在 test 里 + 不在黑名单 + 24h>=min-rate
    pool = []
    for c in cands:
        ip = c.get("ip")
        if not ip or ip in existing or ip in BLACKLIST:
            continue
        if (c.get("rate_24h") or 0) < ARGS.min_rate:
            continue
        pool.append(c)
    if not pool:
        log("[monitor] 候选不足(未过 24h>=%.0f%% 或都在用)" % ARGS.min_rate)
        return
    pool.sort(key=lambda c: -(c.get("itdog_score") if c.get("itdog_score") is not None else c.get("score") or 0))
    log(f"候选池 {len(pool)} 个, 前几: {[c['ip'] for c in pool[:5]]}")
    # 逐个替换问题 IP(最多 max-replace)
    for ip, rid, rate in bad[:ARGS.max_replace]:
        if not pool:
            break
        rep = pool.pop(0)
        log(f"  替 {ip}({rate:.1f}%) -> 候选 {rep.get('ip')} (score={rep.get('score')}, 24h={rep.get('rate_24h')}%, itdog={rep.get('itdog_score')})")
        replace_ip(ip, rid, rep.get("ip"))
    # 替换后自愈: 删除失败会多留记录 → 裁回 keep 条
    try:
        trim_records(ARGS.keep)
    except Exception as e:
        log(f"[cf] 裁剪失败: {type(e).__name__}: {e}")
    log("=== 巡检完成 ===")

if __name__ == "__main__":
    main()