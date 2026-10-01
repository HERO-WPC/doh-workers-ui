#!/usr/bin/env node
// 优选 IP 定时测活 + 同步 Cloudflare DNS。
//
// 流程:读取 IP 列表(CSV/JSON/文本)→ 并发测活(TLS 证书 + DoH 200 + x-doh-cache 头)
// → 按延迟取前 N 个 → 通过 Cloudflare API 把域名 A 记录同步成存活集合
// (删死 IP 记录、补新 IP 记录)。
//
// 用法:
//   node tools/sync-ips.mjs --in tools/ips-latest.csv
//   node tools/sync-ips.mjs --in 优选IP.csv --domain your-doh-domain.example --count 5
//
// 域名与 DoH 路径默认取 tools/.monitor.env 的 DOH_HOST / DOH_PATH(真实值不入库)。
//
// Cloudflare API Token:从 --token-file(默认 tools/.cf-token,勿提交 Git)或环境变量
// CF_API_TOKEN 读取。需要权限:Zone → DNS → Edit(限你的域名所在 zone)。

import fs from "node:fs";
import tls from "node:tls";
import { cfg, dohPath, PLACEHOLDER_HOST, requireReal } from "./envcfg.mjs";

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

const DEFAULT_DOMAIN = cfg("DOH_HOST", PLACEHOLDER_HOST);
const DEFAULT_TOKEN_FILE = "tools/.cf-token";

const args = process.argv.slice(2);
const opts = {
  domain: DEFAULT_DOMAIN,
  path: dohPath(), // 本 Worker 的 DoH 路径(来自 .monitor.env)
  in: null,
  count: 5,
  concurrency: 10,
  timeout: 4000,
  rounds: 2,
  tokenFile: DEFAULT_TOKEN_FILE,
  dryRun: false,
  out: null,
};
for (let i = 0; i < args.length; i++) {
  const a = args[i];
  if (a === "--in") opts.in = args[++i];
  else if (a === "--domain") opts.domain = args[++i];
  else if (a === "--path") opts.path = dohPath(args[++i]);   // 顺带修掉原来的 args[++i] 双自增
  else if (a === "--count") opts.count = Math.max(1, Number(args[++i]) || 5);
  else if (a === "--concurrency") opts.concurrency = Math.max(1, Number(args[++i]) || 10);
  else if (a === "--timeout") opts.timeout = Math.max(500, Number(args[++i]) || 4000);
  else if (a === "--rounds") opts.rounds = Math.max(1, Number(args[++i]) || 2);
  else if (a === "--token-file") opts.tokenFile = args[++i];
  else if (a === "--dry-run") opts.dryRun = true;
  else if (a === "--out") opts.out = args[++i];
}

// 本脚本会写真实 DNS 记录:域名/路径还是占位符就直接退出,别动错域名。
requireReal([["--domain (DOH_HOST)", opts.domain], ["--path (DOH_PATH)", opts.path]]);

// 预编码 DoH 查询:example.com A(TXID 0x1a2b, RD=1)
const DOH_QUERY = Buffer.from("1a2b01000001000000000000" + "076578616d706c6503636f6d00" + "00010001", "hex");

// ---------------------------------------------------------------------------
// 输入解析(CSV / JSON / 文本,与 test-cf-ip.mjs 同规则)
// ---------------------------------------------------------------------------

const IP_RE = /^(\d{1,3}(?:\.\d{1,3}){3}|\[[0-9a-fA-F:]+\]|(?:[a-f0-9]{0,4}:){2,7}[a-f0-9]{0,4})(?::(\d{1,5}))?$/;

function parseHostEntry(raw) {
  const s = String(raw).trim();
  if (!s) return null;
  const bare = s.replace(/^https?:\/\//i, "").split(/[/?#]/)[0];
  const m = IP_RE.exec(bare);
  if (!m) return null;
  return { ip: m[1].replace(/^\[|\]$/g, ""), port: m[2] ? Number(m[2]) : 443 };
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
      entry = parseHostEntry(cols[1].trim() + ":" + cols[2].trim()) ?? parseHostEntry(cols[0]);
    }
    if (entry) out.push(entry);
  }
  return out;
}

function parseJson(text) {
  const data = JSON.parse(text);
  const arr = Array.isArray(data) ? data : Array.isArray(data?.list) ? data.list : Array.isArray(data?.proxies) ? data.proxies : null;
  if (!arr) throw new Error("JSON 顶层必须是数组");
  const out = [];
  for (const item of arr) {
    if (typeof item === "string") {
      const e = parseHostEntry(item);
      if (e) out.push(e);
    } else if (item && typeof item === "object") {
      const ip = item.ip ?? item.address ?? item.addr ?? item.host ?? item.IP;
      const port = Number(item.port) || 443;
      const e = ip ? parseHostEntry(String(ip) + ":" + port) : null;
      if (e) out.push(e);
    }
  }
  return out;
}

function loadTargets() {
  if (!opts.in || !fs.existsSync(opts.in)) {
    console.error(`[错误] 找不到 IP 列表文件: ${opts.in}`);
    console.error(`把你下载的优选 IP 列表保存为该文件(CSV/JSON/文本均可),或用 --in 指定路径。`);
    process.exit(2);
  }
  const text = fs.readFileSync(opts.in, "utf8");
  const firstLine = text.split(/\r?\n/)[0];
  let list;
  if (text.trim().startsWith("[") || text.trim().startsWith("{")) list = parseJson(text);
  else if (/,/.test(firstLine) && /ip/i.test(firstLine)) list = parseCsv(text);
  else list = parseText(text);
  const seen = new Map();
  for (const e of list) {
    const key = `${e.ip}:${e.port}`;
    if (!seen.has(key)) seen.set(key, e);
  }
  return [...seen.values()].filter((e) => e.port === 443); // A 记录不带端口,客户端只连 443
}

function parseText(text) {
  return text.split(/\r?\n/).map((l) => parseHostEntry(l)).filter(Boolean);
}

// ---------------------------------------------------------------------------
// 测活:TLS(SNI=域名)→ POST DoH → 200 + x-doh-cache 头
// ---------------------------------------------------------------------------

function friendlyError(err) {
  const code = String(err?.code ?? err?.message ?? err ?? "");
  if (/certificate|CERT|hostname/i.test(code)) return "证书不匹配";
  if (/ECONNREFUSED/.test(code)) return "连接被拒";
  if (/ECONNRESET|EPIPE|10054/.test(code)) return "连接被重置";
  if (/ETIMEDOUT|timeout|TIMEOUT|aggregated/i.test(code)) return "超时";
  return `连接失败(${code})`;
}

function tlsConnect(ip, port, timeoutMs) {
  return new Promise((resolve) => {
    const started = Date.now();
    const socket = tls.connect({ host: ip, port, servername: opts.domain, rejectUnauthorized: true });
    let settled = false;
    const done = (r) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
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

function sendDoH(socket, authority) {
  return new Promise((resolve, reject) => {
    let head = `POST ${opts.path} HTTP/1.1\r\nHost: ${authority}\r\nuser-agent: sync-ips/1.0\r\nconnection: close\r\ncontent-type: application/dns-message\r\naccept: application/dns-message\r\ncontent-length: ${DOH_QUERY.length}\r\n\r\n`;
    const chunks = [];
    let settled = false;
    const finish = (fn, arg) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      socket.off("data", onData);
      socket.off("close", onClose);
      socket.off("error", onError);
      fn(arg);
    };
    const timer = setTimeout(() => finish(reject, new Error("响应超时")), opts.timeout);
    const onData = (c) => chunks.push(c);
    const onClose = () => {
      const buf = Buffer.concat(chunks);
      const sep = buf.indexOf("\r\n\r\n");
      if (sep < 0) return finish(reject, new Error("无 HTTP 响应"));
      const headStr = buf.subarray(0, sep).toString("utf8");
      const status = Number((headStr.split("\r\n")[0].match(/HTTP\/[\d.]+ (\d{3})/) ?? [])[1] ?? 0);
      const headerMap = {};
      for (const line of headStr.split("\r\n").slice(1)) {
        const i = line.indexOf(":");
        if (i > 0) headerMap[line.slice(0, i).trim().toLowerCase()] = line.slice(i + 1).trim();
      }
      finish(resolve, { status, headers: headerMap, body: buf.subarray(sep + 4) });
    };
    const onError = (e) => finish(reject, e);
    socket.on("data", onData);
    socket.once("close", onClose);
    socket.once("error", onError);
    socket.write(head, () => socket.write(DOH_QUERY));
  });
}

async function testTarget(t) {
  const started = Date.now();
  const r = await tlsConnect(t.ip, t.port, opts.timeout);
  if (!r.ok) return { ...t, ok: false, reason: friendlyError(r.error) };
  const socket = r.socket;
  try {
    const res = await sendDoH(socket, opts.domain);
    const bodyOk = res.body?.length >= 12 && (res.body[2] & 0x80) !== 0;
    if (res.status !== 200 || !res.headers["x-doh-cache"] || !bodyOk) {
      return { ...t, ok: false, reason: `DoH 异常(HTTP ${res.status})`, handshakeMs: r.handshakeMs };
    }
    const firstMs = Date.now() - started;
    const dohMs = [firstMs];
    for (let i = 1; i < opts.rounds; i++) {
      const s2 = Date.now();
      const res2 = await sendDoH(socket, opts.domain).catch(() => null);
      if (res2 && res2.status === 200) dohMs.push(Date.now() - s2);
    }
    return { ...t, ok: true, handshakeMs: r.handshakeMs, dohMs, avg: Math.round(dohMs.reduce((s, v) => s + v, 0) / dohMs.length) };
  } catch (e) {
    return { ...t, ok: false, reason: friendlyError(e), handshakeMs: r.handshakeMs };
  } finally {
    socket.destroy();
  }
}

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
      process.stdout.write(`\r进度 ${done}/${targets.length}  最近: ${r.ok ? "✓" : "✗"} ${r.ip}${r.ok ? " " + r.avg + "ms" : " " + r.reason}          `);
    }
  }
  await Promise.all(Array.from({ length: Math.min(opts.concurrency, targets.length) }, runner));
  process.stdout.write("\n");
  return results;
}

// ---------------------------------------------------------------------------
// Cloudflare DNS API
// ---------------------------------------------------------------------------

function readToken() {
  if (process.env.CF_API_TOKEN) return process.env.CF_API_TOKEN.trim();
  if (fs.existsSync(opts.tokenFile)) return fs.readFileSync(opts.tokenFile, "utf8").trim();
  return null;
}

async function cfApi(token, method, path, body) {
  const res = await fetch(`https://api.cloudflare.com/client/v4${path}`, {
    method,
    headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
    body: body ? JSON.stringify(body) : undefined,
  });
  const json = await res.json().catch(() => ({}));
  if (!json.success) {
    const msg = json.errors?.map((e) => `${e.code}: ${e.message}`).join("; ") || `HTTP ${res.status}`;
    throw new Error(`CF API ${method} ${path} 失败: ${msg}`);
  }
  return json.result;
}

async function syncDns(token, working) {
  const zoneName = opts.domain.split(".").slice(-2).join(".");
  // 二级托管域(如 xxx.dpdns.org 这类免费域名):zone 名取前两段可能不对,直接按域名后缀模糊查。
  const zones = await cfApi(token, "GET", `/zones?per_page=50`);
  const zone = zones.find((z) => opts.domain.endsWith(`.${z.name}`) || z.name === opts.domain);
  if (!zone) throw new Error(`找不到包含 ${opts.domain} 的 zone(检查 token 权限/zone 列表)`);
  process.stdout.write(`zone: ${zone.name} (${zone.id.slice(0, 8)}…)\n`);

  const records = await cfApi(token, "GET", `/zones/${zone.id}/dns_records?type=A&name=${encodeURIComponent(opts.domain)}&per_page=100`);
  const existing = new Map(records.map((r) => [r.content, r.id]));
  const desired = working.slice(0, opts.count).map((w) => w.ip);

  const toDelete = [...existing.entries()].filter(([content]) => !desired.includes(content));
  const toCreate = desired.filter((ip) => !existing.has(ip));

  for (const [content, id] of toDelete) {
    await cfApi(token, "DELETE", `/zones/${zone.id}/dns_records/${id}`);
    console.log(`  已删除死记录: ${content}`);
  }
  for (const ip of toCreate) {
    await cfApi(token, "POST", `/zones/${zone.id}/dns_records`, { type: "A", name: opts.domain, content: ip, proxied: false, ttl: 60 });
    console.log(`  已新增记录: ${ip}`);
  }
  return { deleted: toDelete.map((d) => d[0]), created: toCreate, final: desired };
}

// ---------------------------------------------------------------------------
// 主流程
// ---------------------------------------------------------------------------

const targets = loadTargets();
if (targets.length === 0) {
  console.error("[错误] 列表为空或没有有效 IP。");
  process.exit(2);
}
console.log(`目标: ${opts.domain}${opts.path}`);
console.log(`待测: ${targets.length} 个 IP(去重后),并发 ${opts.concurrency},每目标 ${opts.rounds} 轮\n`);

const results = await runPool(targets, testTarget);
const okList = results.filter((r) => r.ok).sort((a, b) => a.avg - b.avg);
const failCount = results.length - okList.length;

console.log(`\n===== 测活完成: ${okList.length} 可用 / ${failCount} 失败 =====\n`);
for (const [i, r] of okList.slice(0, 10).entries()) {
  console.log(`  ${String(i + 1).padStart(2)}  ${r.ip.padEnd(16)}  平均 ${String(r.avg).padStart(5)}ms  (${r.dohMs.join("/")})`);
}

if (okList.length === 0) {
  console.error("\n[严重] 没有任何可用 IP!域名 DNS 保持不变,请尽快手动更换优选 IP 来源。");
  process.exit(3);
}

const chosen = okList.slice(0, opts.count);
if (opts.out) {
  const fs = await import("node:fs");
  fs.writeFileSync(opts.out, okList.map((c) => c.ip).join("\n") + "\n");
  console.log(`全部可用 IP(${okList.length} 个)已写入: ${opts.out}`);
}
console.log(`\n将同步的 ${chosen.length} 个 IP: ${chosen.map((c) => c.ip).join(", ")}\n`);

if (opts.dryRun) {
  console.log("(dry-run 模式,不改动 DNS)");
  process.exit(0);
}

const token = readToken();
if (!token) {
  console.error(`\n[错误] 没有找到 Cloudflare API Token。`);
  console.error(`获取方式: dash.cloudflare.com → 右上角头像 → My Profile → API Tokens → Create Token`);
  console.error(`→ 模板 "Edit zone DNS" → Zone 选 ${opts.domain.split(".").slice(-2).join(".")} → 创建后把 token 保存到 ${opts.tokenFile}(不要提交 Git)。`);
  process.exit(4);
}

try {
  const { deleted, created, final } = await syncDns(token, chosen);
  console.log(`\n✅ DNS 已同步: 当前 ${opts.domain} A 记录 = ${final.join(", ")}`);
  if (deleted.length) console.log(`   删除: ${deleted.join(", ")}`);
  if (created.length) console.log(`   新增: ${created.join(", ")}`);
  console.log(`   (TTL 300s,生效需几分钟;AGH 缓存自然过期)`);
} catch (e) {
  console.error(`\n[错误] DNS 同步失败: ${e.message}`);
  console.error(`存活 IP 列表(请手动更新 DNS): ${chosen.map((c) => c.ip).join(", ")}`);
  process.exit(5);
}
