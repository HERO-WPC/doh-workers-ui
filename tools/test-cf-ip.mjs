#!/usr/bin/env node
// 优选 IP 反代测试工具:测试一个 IP(:port)能否作为 Cloudflare 边缘反代,
// 服务指定域名的 DoH Worker。
//
// 原理:向 IP:port 发起 TLS,SNI/Host 填目标域名:
//   1. TCP + TLS 握手成功(证书必须是目标域名的,拒绝自签/错误证书)
//   2. GET /health 返回本 Worker 的 {"status":"ok",...}
//   3. POST 一个真实 DoH 查询,必须 200 且带 x-doh-cache 头
// 三关全过才算"可用反代"。
//
// 用法:
//   node tools/test-cf-ip.mjs 104.16.0.1 172.64.0.1:8443
//   node tools/test-cf-ip.mjs --in 服务数据.csv
//   node tools/test-cf-ip.mjs --in ips.json --domain example.com --rounds 3
//
// 输入文件支持:CSV(host,ip,port,... 表头)、JSON 数组(字符串或对象)、纯文本行。

import fs from "node:fs";
import tls from "node:tls";
import { dohHost, dohPath, PLACEHOLDER_HOST } from "./envcfg.mjs";

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

// 目标域名默认取 tools/.monitor.env 的 DOH_HOST(真实值不入库);也可 --domain 指定。
const DEFAULT_DOMAIN = dohHost();

function usage() {
  console.log(`用法: node tools/test-cf-ip.mjs [IP...] --in <文件> [选项]
  IP...               直接指定,如 104.16.0.1 或 47.83.1.19:8443
  --in <文件>         从文件读取(CSV / JSON 数组 / 纯文本行,自动识别)
  --domain <域名>     目标域名(默认 ${DEFAULT_DOMAIN}${DEFAULT_DOMAIN === PLACEHOLDER_HOST ? ";未配置 .monitor.env 时请用本参数指定" : ""})
  --path <路径>       DoH 路径(默认取 .monitor.env 的 DOH_PATH;自定义路径的 Worker 需传入,如 your-doh-path/dns-query)
                      注意: Git Bash 下以 / 开头的参数会被 MSYS 转成本地路径,请省略前导 /
  --rounds <N>        每个可用 IP 的 DoH 测速轮数(默认 2)
  --concurrency <N>   并发数(默认 8)
  --timeout <ms>      单次连接/响应超时(默认 5000)
  --top <N>           结果表只显示前 N 个(默认 15)
  --out <文件>        把全部可用 IP(ip:port)写入该文件`);
  process.exit(1);
}

const args = process.argv.slice(2);
const opts = { domain: DEFAULT_DOMAIN, path: dohPath(), rounds: 2, concurrency: 8, timeout: 5000, top: 15, out: null, in: null, ips: [] };
for (let i = 0; i < args.length; i++) {
  const a = args[i];
  if (a === "--in") opts.in = args[++i];
  else if (a === "--domain") opts.domain = args[++i];
  else if (a === "--path") {
    const v = args[++i] ?? "";
    opts.path = v.startsWith("/") ? v : "/" + v;
  }
  else if (a === "--rounds") opts.rounds = Math.max(1, Number(args[++i]) || 2);
  else if (a === "--concurrency") opts.concurrency = Math.max(1, Number(args[++i]) || 8);
  else if (a === "--timeout") opts.timeout = Math.max(500, Number(args[++i]) || 5000);
  else if (a === "--top") opts.top = Math.max(1, Number(args[++i]) || 15);
  else if (a === "--out") opts.out = args[++i];
  else if (a === "-h" || a === "--help") usage();
  else opts.ips.push(a);
}

// ---------------------------------------------------------------------------
// 输入解析(CSV / JSON / 文本)→ [{ip, port, extra}]
// ---------------------------------------------------------------------------

const IP_RE = /^(\d{1,3}(?:\.\d{1,3}){3}|\[[0-9a-fA-F:]+\]|(?:[a-f0-9]{0,4}:){2,7}[a-f0-9]{0,4})(?::(\d{1,5}))?$/;

function parseHostEntry(raw) {
  const s = String(raw).trim();
  if (!s) return null;
  const bare = s.replace(/^https?:\/\//i, "").split(/[/?#]/)[0];
  const m = IP_RE.exec(bare);
  if (!m) return null;
  return { ip: m[1].replace(/^\[|\]$/g, ""), port: m[2] ? Number(m[2]) : 443, extra: "" };
}

function parseCsv(text) {
  const lines = text.replace(/^\uFEFF/, "").split(/\r?\n/).filter((l) => l.trim());
  if (lines.length === 0) return [];
  const first = lines[0].split(",").map((h) => h.trim().toLowerCase());
  const ipIdx = first.indexOf("ip");
  const portIdx = first.indexOf("port");
  const hostIdx = first.indexOf("host");
  const out = [];
  const rows = ipIdx >= 0 ? lines.slice(1) : lines;
  for (const line of rows) {
    const cols = line.split(",");
    let entry = null;
    if (ipIdx >= 0 && cols[ipIdx]) {
      entry = parseHostEntry(cols[ipIdx].trim() + (portIdx >= 0 && cols[portIdx] ? ":" + cols[portIdx].trim() : ""));
    } else if (hostIdx >= 0 && cols[hostIdx]) {
      entry = parseHostEntry(cols[hostIdx]);
    } else if (cols.length >= 3) {
      entry = parseHostEntry(cols[1].trim() + (cols[2] ? ":" + cols[2].trim() : "")) ?? parseHostEntry(cols[0]);
    }
    if (entry) {
      entry.extra = ipIdx >= 0 ? `${cols[4] ?? ""} ${cols[5] ?? ""}`.trim() : "";
      out.push(entry);
    }
  }
  return out;
}

function parseJson(text) {
  const data = JSON.parse(text);
  const arr = Array.isArray(data) ? data : Array.isArray(data?.list) ? data.list : Array.isArray(data?.proxies) ? data.proxies : null;
  if (!arr) throw new Error("JSON 顶层必须是数组(或含 list/proxies 数组的对象)");
  const out = [];
  for (const item of arr) {
    if (typeof item === "string") {
      const e = parseHostEntry(item);
      if (e) out.push(e);
    } else if (item && typeof item === "object") {
      const ip = item.ip ?? item.address ?? item.addr ?? item.host ?? item.IP;
      const port = Number(item.port) || 443;
      const e = ip ? parseHostEntry(String(ip) + ":" + port) : null;
      if (e) {
        e.extra = [item.country, item.city, item.org].filter(Boolean).join(" ");
        out.push(e);
      }
    }
  }
  return out;
}

function parseText(text) {
  return text
    .split(/\r?\n/)
    .map((l) => parseHostEntry(l))
    .filter(Boolean);
}

function loadTargets() {
  let rawList = [];
  if (opts.in) {
    const text = fs.readFileSync(opts.in, "utf8");
    const firstLine = text.split(/\r?\n/)[0];
    if (text.trim().startsWith("[") || text.trim().startsWith("{")) {
      rawList = parseJson(text);
    } else if (/,,?/.test(firstLine) && /ip/i.test(firstLine)) {
      rawList = parseCsv(text);
    } else {
      rawList = parseText(text);
    }
  }
  for (const s of opts.ips) {
    const e = parseHostEntry(s);
    if (e) rawList.push(e);
  }
  if (rawList.length === 0) {
    console.error("没有解析到任何有效 IP。检查输入文件内容(CSV 需含 ip/port 列,JSON 需为数组)。");
    process.exit(1);
  }
  const seen = new Map();
  for (const e of rawList) {
    const key = `${e.ip}:${e.port}`;
    if (!seen.has(key)) seen.set(key, e);
  }
  return [...seen.values()];
}

// ---------------------------------------------------------------------------
// TLS + HTTP/1.1 连接(SNI = 目标域名,keep-alive,按 Content-Length 读响应)
// ---------------------------------------------------------------------------

// 预编码的 DoH 查询:example.com A(TXID 0x1a2b, RD=1)
// 1a2b 0100 0001 0000 0000 0000 | 07 example 03 com 00 | 0001 0001
const DOH_QUERY = Buffer.from("1a2b01000001000000000000" + "076578616d706c6503636f6d00" + "00010001", "hex");

function friendlyError(err) {
  const code = String(err?.code ?? err?.message ?? err ?? "");
  if (/certificate|CERT|self-signed|hostname/i.test(code)) return "证书不匹配(非本域名的边缘)";
  if (/ECONNREFUSED/.test(code)) return "连接被拒";
  if (/ECONNRESET|EPIPE/.test(code)) return "连接被重置";
  if (/ETIMEDOUT|timeout|TIMEOUT/i.test(code)) return "超时";
  if (/ENOTFOUND|EAI_AGAIN/.test(code)) return "域名解析失败";
  if (/EHOSTUNREACH|ENETUNREACH/.test(code)) return "网络不可达";
  return `连接失败(${code})`;
}

/** 建立 TLS 连接;rejectUnauthorized 保证证书确实属于目标域名。 */
function tlsConnect(ip, port, timeoutMs) {
  return new Promise((resolve) => {
    const started = Date.now();
    const socket = tls.connect({ host: ip, port, servername: opts.domain, rejectUnauthorized: true });
    let settled = false;
    const done = (r) => {
      if (settled) return;
      settled = true;
      resolve(r);
    };
    const timer = setTimeout(() => {
      socket.destroy();
      done({ ok: false, error: new Error("ETIMEDOUT") });
    }, timeoutMs);
    socket.once("secureConnect", () => {
      clearTimeout(timer);
      done({ ok: true, socket, handshakeMs: Date.now() - started });
    });
    socket.once("error", (e) => {
      clearTimeout(timer);
      done({ ok: false, error: e });
    });
  });
}

/**
 * 一个 TLS 连接上的 HTTP/1.1 keep-alive 客户端。
 * 每个响应按头部 + Content-Length(或 chunked 结束标记)精确读取,
 * 因此同一个连接可以连续发多个请求。服务器提前断开时 send() 会抛
 * { reconnect: true },由调用方重建连接重试。
 */
function makeConn(ip, port, timeoutMs) {
  let socket = null;
  let handshakeMs = 0;

  async function connect() {
    const r = await tlsConnect(ip, port, timeoutMs);
    if (!r.ok) throw { fatal: friendlyError(r.error) };
    socket = r.socket;
    handshakeMs = r.handshakeMs;
    socket.on("error", () => {}); // 错误通过 close/read 路径暴露
  }

  function send(method, path, headers, body = null) {
    return new Promise((resolve, reject) => {
      if (!socket || socket.destroyed) {
        return reject({ reconnect: true });
      }
      let req = `${method} ${path} HTTP/1.1\r\nHost: ${opts.domain}\r\nuser-agent: doh-ip-test/1.0\r\nconnection: keep-alive\r\n`;
      for (const [k, v] of Object.entries(headers)) req += `${k}: ${v}\r\n`;
      req += "\r\n";

      const chunks = [];
      let headEnd = -1;
      let need = -1; // 需要 reads 的 body 字节数(content-length)
      let settled = false;
      const finish = (fn, arg) => {
        if (settled) return;
        settled = true;
        cleanup();
        fn(arg);
      };
      const timer = setTimeout(() => finish(reject, { fatal: "响应超时" }), timeoutMs);
      const cleanup = () => {
        clearTimeout(timer);
        socket.off("data", onData);
        socket.off("close", onClose);
        socket.off("error", onError);
      };
      const onData = (c) => {
        chunks.push(c);
        const buf = Buffer.concat(chunks);
        if (headEnd < 0) headEnd = buf.indexOf("\r\n\r\n");
        if (headEnd < 0) return;
        const head = buf.subarray(0, headEnd).toString("utf8");
        const status = Number((head.split("\r\n")[0].match(/HTTP\/[\d.]+ (\d{3})/) ?? [])[1] ?? 0);
        const headerMap = {};
        for (const line of head.split("\r\n").slice(1)) {
          const i = line.indexOf(":");
          if (i > 0) headerMap[line.slice(0, i).trim().toLowerCase()] = line.slice(i + 1).trim();
        }
        let body = buf.subarray(headEnd + 4);
        if ((headerMap["transfer-encoding"] ?? "").includes("chunked")) {
          body = dechunk(body);
          if (body === null) return; // chunk 未收完
        } else if (need < 0) {
          need = headerMap["content-length"] !== undefined ? Number(headerMap["content-length"]) : body.length;
        }
        if (body.length >= need) {
          finish(resolve, { status, headers: headerMap, body: body.subarray(0, need) });
        }
      };
      const onClose = () => finish(reject, { reconnect: true });
      const onError = (e) => finish(reject, { fatal: friendlyError(e) });

      socket.on("data", onData);
      socket.once("close", onClose);
      socket.once("error", onError);
      socket.write(req, () => {
        if (body) socket.write(body);
      });
    });
  }

  function destroy() {
    socket?.destroy();
  }

  return {
    get handshakeMs() {
      return handshakeMs;
    },
    async sendWithRetry(method, path, headers, body) {
      for (let attempt = 0; attempt < 2; attempt++) {
        if (!socket || socket.destroyed) await connect();
        try {
          return await send(method, path, headers, body);
        } catch (e) {
          if (e?.reconnect && attempt === 0) {
            socket?.destroy();
            continue; // 服务器提前断开:重建连接再试一次
          }
          throw e;
        }
      }
    },
    destroy,
  };
}

function dechunk(buf) {
  const out = [];
  let off = 0;
  while (off < buf.length) {
    const nl = buf.indexOf("\r\n", off);
    if (nl < 0) return null;
    const size = parseInt(buf.subarray(off, nl).toString("ascii").split(";")[0], 16);
    if (!Number.isFinite(size)) return null;
    if (size === 0) break;
    if (buf.length < nl + 2 + size + 2) return null; // 未收完
    out.push(buf.subarray(nl + 2, nl + 2 + size));
    off = nl + 2 + size + 2;
  }
  return Buffer.concat(out);
}

// ---------------------------------------------------------------------------
// 测试逻辑
// ---------------------------------------------------------------------------

/** 完整测试一个目标:TLS → /health → DoH(rounds 轮测速)。 */
async function testTarget(target) {
  const { ip, port, extra } = target;
  const conn = makeConn(ip, port, opts.timeout);
  try {
    // 1. /health 必须是本 Worker(同时完成 TLS 握手)
    const health = await conn.sendWithRetry("GET", "/health", { accept: "application/json" });
    let healthOk = false;
    try {
      const j = JSON.parse(health.body.toString("utf8"));
      healthOk = j.status === "ok" && typeof j.version === "string";
    } catch {
      healthOk = false;
    }
    if (health.status !== 200 || !healthOk) {
      return { ip, port, extra, ok: false, reason: `响应不是本 Worker(HTTP ${health.status})`, handshakeMs: conn.handshakeMs };
    }

    // 2. DoH 查询,rounds 轮
    const dohMs = [];
    let lastReason = "";
    let successes = 0;
    for (let r = 0; r < opts.rounds; r++) {
      const started = Date.now();
      try {
        const res = await conn.sendWithRetry("POST", opts.path, {
          "content-type": "application/dns-message",
          "content-length": String(DOH_QUERY.length),
        }, DOH_QUERY);
        const elapsed = Date.now() - started;
        const bodyOk = res.body.length >= 12 && (res.body[2] & 0x80) !== 0; // QR 位
        if (res.status === 200 && res.headers["x-doh-cache"] && bodyOk) {
          successes += 1;
          dohMs.push(elapsed);
        } else if (res.status === 404) {
          lastReason = `DoH 路径 404(本 Worker 但路径不对,请传 --path <你的DoH路径>)`;
        } else {
          lastReason = `DoH 异常(HTTP ${res.status}${res.headers["x-doh-cache"] ? "" : ",无 x-doh-cache 头"})`;
        }
      } catch (e) {
        lastReason = e?.fatal ?? "DoH 请求失败";
        break;
      }
    }
    if (successes === 0) return { ip, port, extra, ok: false, reason: lastReason, handshakeMs: conn.handshakeMs };
    return { ip, port, extra, ok: true, handshakeMs: conn.handshakeMs, dohMs, successes, rounds: opts.rounds };
  } catch (e) {
    return { ip, port, extra, ok: false, reason: e?.fatal ?? friendlyError(e), handshakeMs: conn.handshakeMs };
  } finally {
    conn.destroy();
  }
}

// ---------------------------------------------------------------------------
// 并发调度 + 输出
// ---------------------------------------------------------------------------

async function runPool(targets, worker) {
  const results = [];
  let idx = 0;
  let done = 0;
  async function runner() {
    while (idx < targets.length) {
      const i = idx++;
      results[i] = await worker(targets[i]);
      done += 1;
      const r = results[i];
      process.stdout.write(
        `\r进度 ${done}/${targets.length}  最近: ${r.ok ? "✓" : "✗"} ${r.ip}:${r.port}${r.ok ? "" : " " + r.reason}          `,
      );
    }
  }
  await Promise.all(Array.from({ length: Math.min(opts.concurrency, targets.length) }, runner));
  process.stdout.write("\n");
  return results;
}

const targets = loadTargets();
console.log(`目标域名: ${opts.domain}`);
console.log(`待测目标: ${targets.length} 个(去重后),并发 ${opts.concurrency},每目标 ${opts.rounds} 轮 DoH\n`);

const results = await runPool(targets, testTarget);
const okList = results.filter((r) => r.ok);
const failList = results.filter((r) => !r.ok);

const reasonCount = new Map();
for (const f of failList) reasonCount.set(f.reason, (reasonCount.get(f.reason) ?? 0) + 1);

okList.sort((a, b) => {
  const avg = (x) => x.dohMs.reduce((s, v) => s + v, 0) / x.dohMs.length;
  return avg(a) - avg(b);
});

console.log(`\n========== 结果: ${okList.length} 可用 / ${failList.length} 不可用 ==========\n`);

if (okList.length > 0) {
  console.log("可用反代 IP(按 DoH 平均延迟排序):\n");
  console.log("  #  IP:端口                握手    DoH(avg/min)    轮次  备注");
  console.log("  --  --------------------  ------  ---------------  ----  ----");
  for (const [i, r] of okList.slice(0, opts.top).entries()) {
    const avg = Math.round(r.dohMs.reduce((s, v) => s + v, 0) / r.dohMs.length);
    const min = Math.min(...r.dohMs);
    console.log(
      `  ${String(i + 1).padStart(2)}  ${(r.ip + ":" + r.port).padEnd(20)}  ${String(r.handshakeMs).padStart(4)}ms  ${String(avg).padStart(5)}ms/${String(min).padStart(4)}ms   ${r.successes}/${r.rounds}    ${r.extra}`.trimEnd(),
    );
  }
  console.log(`\n使用方法(把域名指向优选 IP):`);
  console.log(`  Windows: 管理员编辑 C:\\Windows\\System32\\drivers\\etc\\hosts 加一行`);
  console.log(`      <选出的IP>  ${opts.domain}`);
  console.log(`  路由器/AdGuard Home: 为 ${opts.domain} 指定该 IP 的自定义解析`);
  console.log(`  注意: hosts 只影响该域名,不影响其他网站;优选 IP 可能失效,建议定期重测。\n`);
}

if (opts.out) {
  if (okList.length > 0) {
    fs.writeFileSync(opts.out, okList.map((r) => `${r.ip}:${r.port}`).join("\n") + "\n");
    console.log(`已把 ${okList.length} 个可用 IP 写入 ${opts.out}`);
  } else {
    fs.writeFileSync(opts.out, "");
  }
}

if (failList.length > 0) {
  console.log("失败原因统计:");
  for (const [reason, count] of [...reasonCount.entries()].sort((a, b) => b[1] - a[1])) {
    console.log(`  ${String(count).padStart(4)}  ${reason}`);
  }
}

if (okList.length === 0) {
  console.log("\n没有可用反代 IP。若输入的是非 Cloudflare 网段(如阿里云/腾讯云),这是预期结果——");
  console.log("建议改用 Cloudflare 官方网段测速(如 104.16.0.0/13、172.64.0.0/13),再用本工具验证 DoH 可用性。");
}
