#!/usr/bin/env node
// DoH 查询测速:测量通过你的 DoH 服务解析一个域名的端到端耗时。
//
// 用法:
//   node tools/dohspeed.mjs 域名 [次数] [DoH地址] [强制IP]
// 例:
//   node tools/dohspeed.mjs chatgpt.com 10
//   node tools/dohspeed.mjs chatgpt.com 10 "https://your-doh-domain.example/your-doh-path/dns-query"
//   node tools/dohspeed.mjs example.com 5 "" 8.210.250.14   // 强制走指定 IP
//
// 不传 DoH 地址时,自动用 tools/.monitor.env 的 DOH_HOST + DOH_PATH 拼出。
//
// 直连测量,不受系统代理影响。输出每次耗时 + 缓存状态 + 解析结果 + 统计。

import dnsPacket from "dns-packet";
import https from "node:https";
import { dohUrl } from "./envcfg.mjs";

const domain = process.argv[2] || "example.com";
const rounds = Math.max(1, Number(process.argv[3]) || 5);
const urlArg = dohUrl(process.argv[4]);
const forceIp = process.argv[5] || null;

const u = new URL(urlArg);
const b64 = dnsPacket.encode({
  id: 0, type: "query", flags: 256,
  questions: [{ name: domain, type: "A" }],
}).toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

function queryOnce() {
  return new Promise((resolve, reject) => {
    const t0 = process.hrtime.bigint();
    const req = https.request({
      host: forceIp || u.hostname,
      port: u.port || 443,
      servername: u.hostname,                 // TLS SNI 仍是域名
      path: u.pathname + "?dns=" + b64,
      method: "GET",
      headers: { accept: "application/dns-message", "user-agent": "dohspeed/1.0",
                 host: u.hostname },  // 强制 IP 时 Host 头仍必须是域名,否则 CF 回 403
      timeout: 8000,
      ...(forceIp ? { lookup: (h, o, cb) => cb(null, forceIp, 4) } : {}),
    }, (res) => {
      const chunks = [];
      res.on("data", (c) => chunks.push(c));
      res.on("end", () => {
        const ms = Number(process.hrtime.bigint() - t0) / 1e6;
        let answers = "?";
        try {
          const d = dnsPacket.decode(Buffer.concat(chunks));
          answers = (d.answers || []).map((a) => `${String(a.type)} ${a.data}`).join(", ") || "(无答案)";
        } catch {}
        resolve({ status: res.statusCode, ms,
                  cache: res.headers["x-doh-cache"] || "-", answers });
      });
    });
    req.on("timeout", () => req.destroy(new Error("超时")));
    req.on("error", reject);
    req.end();
  });
}

console.log(`== ${domain} → ${u.hostname}${u.pathname} × ${rounds} 次${forceIp ? `(强制IP ${forceIp})` : ""} ==`);
const times = [];
let okCount = 0;
for (let i = 1; i <= rounds; i++) {
  try {
    const r = await queryOnce();
    if (r.status === 200) { times.push(r.ms); okCount++; }
    console.log(`  第${i}次: HTTP ${r.status}  ${r.ms.toFixed(0)} ms  缓存:${r.cache}  → ${r.answers}`);
  } catch (e) {
    console.log(`  第${i}次: 失败(${e.message})`);
  }
}
if (times.length) {
  const sorted = [...times].sort((a, b) => a - b);
  const avg = times.reduce((s, v) => s + v, 0) / times.length;
  console.log(`  统计: 成功 ${times.length}/${rounds} | 最快 ${sorted[0].toFixed(0)}ms | 平均 ${avg.toFixed(0)}ms | 最慢 ${sorted[sorted.length - 1].toFixed(0)}ms | 中位 ${sorted[Math.floor(sorted.length / 2)].toFixed(0)}ms`);
} else {
  console.log("  全部失败");
}
