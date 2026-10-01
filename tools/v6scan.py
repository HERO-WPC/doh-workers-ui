#!/usr/bin/env python3
# IPv6 优选探测:在 Cloudflare 的 IPv6 anycast 段内采样,用真实 DoH 请求测速排序。
#
# 背景:CF 对整个 2606:4700::/32 做 anycast 广播,段内地址都会路由到最近边缘,
# 因此可以在段内采样找"本机 IPv6 出口最快"的边缘地址,用作 AAAA 优选。
# 同时把 CF 官方 IPv4 段(104.16/12、172.64/13)映射为 IPv6 末 32 位一起测。
import concurrent.futures
import ipaddress
import os
import random
import socket
import ssl
import sys
import time

# 真实 DoH 域名/路径不写进源码(公开仓库里等同凭据),从 tools/.monitor.env 读。
# 见同目录 envcfg.mjs 的说明;这里保持单文件、不依赖其它模块,便于独立运行。
_ENV_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".monitor.env")


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


_ENV = _load_env(_ENV_PATH)
HOST = os.environ.get("DOH_HOST") or _ENV.get("DOH_HOST") or "your-doh-domain.example"
PATH = os.environ.get("DOH_PATH") or _ENV.get("DOH_PATH") or "/your-doh-path/dns-query"
if HOST.lstrip("/").startswith("your-") or PATH.lstrip("/").startswith("your-"):
    print(f"[v6scan] 缺少私有配置 DOH_HOST/DOH_PATH: 请在 {_ENV_PATH} 里设置"
          f"(模板 tools/.monitor.env.example)", file=sys.stderr)
    sys.exit(1)

QUERY_B64 = "AAABAAABAAAAAAAAB2V4YW1wbGUDY29tAAABAAE"
TIMEOUT = 6

CTX = ssl.create_default_context()


def probe(addr):
    """返回 (耗时ms, addr) ;失败为 (None, addr)"""
    try:
        t0 = time.time()
        raw = socket.create_connection((addr, 443), timeout=TIMEOUT)
        try:
            tls = CTX.wrap_socket(raw, server_hostname=HOST)
        except Exception:
            raw.close()
            return None, addr
        try:
            req = (
                f"GET {PATH}?dns={QUERY_B64} HTTP/1.1\r\n"
                f"Host: {HOST}\r\n"
                "accept: application/dns-message\r\n"
                "user-agent: v6-scan/1.0\r\n"
                "connection: close\r\n\r\n"
            ).encode()
            tls.sendall(req)
            buf = b""
            tls.settimeout(TIMEOUT)
            while True:
                chunk = tls.recv(4096)
                if not chunk:
                    break
                buf += chunk
                if len(buf) > 65536:
                    break
        finally:
            tls.close()
        ms = int((time.time() - t0) * 1000)
        head = buf.split(b"\r\n\r\n")[0].decode("utf-8", "replace")
        ok = head.startswith("HTTP/1.1 200") and "x-doh-cache" in head.lower()
        return (ms if ok else None), addr
    except Exception:
        return None, addr


def candidates(count=80):
    out = []
    seen = set()
    rnd = random.Random(20260913)
    # ① 直接在 2606:4700::/32 内采样(anycast 段内任意地址)
    while len(out) < count // 2:
        a = f"2606:4700:{rnd.randrange(1, 0xffff):x}::{rnd.randrange(1, 0xffffffff):x}"
        if a not in seen:
            seen.add(a)
            out.append(a)
    # ② CF 官方 IPv4 段映射:末 32 位 = IPv4,前缀取 3030~3037
    for _ in range(count // 2):
        v4 = rnd.choice([104, 172])
        if v4 == 104:
            ip = f"104.{rnd.randrange(16, 32)}.{rnd.randrange(0, 256)}.{rnd.randrange(1, 255)}"
        else:
            ip = f"172.{rnd.randrange(64, 72)}.{rnd.randrange(0, 256)}.{rnd.randrange(1, 255)}"
        hex32 = f"{int(ipaddress.IPv4Address(ip)):08x}"
        a = f"2606:4700:{rnd.choice(range(0x3030, 0x3038)):x}::{hex32[:4]}:{hex32[4:]}"
        if a not in seen:
            seen.add(a)
            out.append(a)
    return out


def main():
    cands = candidates(80)
    print(f"候选 {len(cands)} 个,并发 12 探测…", flush=True)
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=12) as ex:
        for ms, addr in ex.map(probe, cands):
            if ms is not None:
                results.append((ms, addr))
    results.sort()
    ok = len(results)
    print(f"可用 {ok}/{len(cands)}")
    for ms, addr in results[:12]:
        print(f"  {ms:5}ms  {addr}")


if __name__ == "__main__":
    main()
