// 审计修复的回归测试。
//
// 覆盖四处「静默出错」的缺陷:指标被整块覆盖抹掉、竞速败者重复计成功、
// EDNS 扩展 rcode 被当 NOERROR 缓存、L1 单条超限永不驱逐。
import { describe, expect, it, vi } from "vitest";
import * as packet from "dns-packet";
import { loadModules } from "./helpers";
import type { Config } from "../src/types";

const m = await loadModules();
const { MetricsStore, FLUSH_INTERVAL_MS } = m.metrics;

// ---------------------------------------------------------------------------
// 1) 指标 flush 必须与 KV 现有 blob 合并,不能整块覆盖
// ---------------------------------------------------------------------------
describe("MetricsStore flush 合并", () => {
  class FakeKV {
    store = new Map<string, string>();
    async get(key: string) { return this.store.get(key) ?? null; }
    async put(key: string, value: string) { this.store.set(key, value); }
  }
  const metric = (ok: number) => ({ ok, fail: 0, timeout: 0, rttEmaMs: 10, lastSuccess: null, lastFailure: null, updatedAt: null });

  it("本 isolate 只 record 过一个上游时,不会抹掉 KV 里其它上游的历史", async () => {
    const kv = new FakeKV();
    kv.store.set("metrics", JSON.stringify({ google: metric(500), quad9: metric(400) }));

    vi.useFakeTimers();
    try {
      const s = new MetricsStore(kv);
      s.record("cloudflare", { success: true, rttMs: 12 }); // 未 get → 本地只有 cloudflare
      vi.advanceTimersByTime(FLUSH_INTERVAL_MS + 1000);      // 越过节流窗口
      const waits: Promise<unknown>[] = [];
      s.flush((p) => waits.push(p));
      await Promise.allSettled(waits);

      const blob = JSON.parse(kv.store.get("metrics")!) as Record<string, { ok: number }>;
      expect(Object.keys(blob).sort()).toEqual(["cloudflare", "google", "quad9"]);
      expect(blob.google.ok).toBe(500);   // 历史保留
      expect(blob.quad9.ok).toBe(400);
      expect(blob.cloudflare.ok).toBe(1); // 本地增量写入
    } finally {
      vi.useRealTimers();
    }
  });
});

// ---------------------------------------------------------------------------
// 2) 竞速:两个上游几乎同时成功时,败者不得被记为成功
// ---------------------------------------------------------------------------
describe("race 记账", () => {
  const Q = { qname: "example.com", qtype: "A", qclass: "IN", opcode: 0 };
  const wire = (): Buffer =>
    packet.encode({
      id: 0x0abc, type: "query", flags: 0x0100,
      questions: [{ name: "example.com", type: "A" }],
    } as unknown as packet.Packet);

  function cfg(): Config {
    return {
      version: 1, updatedAt: "",
      doh: { path: "/aaaaaaaaaaaaaaaa/dns-query" },
      cache: { minTTL: 10, maxTTL: 600, staleTTL: 86400, jitterPercent: 10, maxBody: 65535 },
      routing: { mode: "race", raceCount: 2 },
      ecs: { mode: "off", ipv4Prefix: 24, ipv6Prefix: 56, fixedSubnet: "" },
      upstreams: [
        { id: "a", name: "a", url: "https://a.test/dns-query", enabled: true, priority: 1, timeout: 2500 },
        { id: "b", name: "b", url: "https://b.test/dns-query", enabled: true, priority: 2, timeout: 2500 },
      ],
    };
  }

  it("同时返回时只有胜者被计成功", async () => {
    const answerBody = packet.encode({
      id: 0x0abc, type: "response", flags: 0x8180,
      questions: [{ name: "example.com", type: "A" }],
      answers: [{ name: "example.com", type: "A", ttl: 300, data: "1.2.3.4" }],
    } as unknown as packet.Packet);
    // 两个上游都在同一微任务批次里返回成功
    const fetchImpl = (async () =>
      new Response(answerBody, { status: 200, headers: { "content-type": "application/dns-message" } })) as unknown as typeof fetch;

    const metrics = new MetricsStore(null);
    const rec = vi.spyOn(metrics, "record");
    await m.routing.resolveQuery(wire(), Q, { cfg: cfg(), metrics, fetchImpl });

    const successes = rec.mock.calls.filter(([, o]) => (o as { success?: boolean }).success);
    expect(successes.length).toBe(1); // 不是 2
  });
});

// ---------------------------------------------------------------------------
// 3) EDNS 扩展 rcode(BADVERS)不得被当作 NOERROR 缓存
// ---------------------------------------------------------------------------
describe("EDNS 扩展 rcode", () => {
  it("extendedRcode=1 时有效 rcode 为 16 且不可缓存", () => {
    const wire = packet.encode({
      id: 0x1234, type: "response", flags: 0x8180, // 低 4 位 = NOERROR
      questions: [{ name: "example.com", type: "A" }],
      additionals: [
        { name: ".", type: "OPT", udpPayloadSize: 4096, extendedRcode: 1, ednsVersion: 0, flags: 0, options: [] },
      ],
    } as unknown as packet.Packet);
    const ans = m.dnsmsg.validateUpstreamResponse(
      0x1234,
      { qname: "example.com", qtype: "A", qclass: "IN", opcode: 0 },
      wire,
    );
    expect(ans).not.toBeNull();
    expect(ans!.rcode).toBe(16);        // BADVERS,而不是 0
    expect(ans!.cacheable).toBe(false); // 不会被缓存
    expect(m.doh.computeStoreTtl(ans!.rcode, ans!.ttlSeconds, { minTTL: 10, maxTTL: 600, staleTTL: 86400, jitterPercent: 0, maxBody: 65535 }, "deadbeef")).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// 4) L1:单个超过 maxBytes 的条目也要能被驱逐
// ---------------------------------------------------------------------------
describe("L1 驱逐", () => {
  it("单条超限条目会被驱逐,内存统计不超上限", async () => {
    const cache = m.cache.createDnsCache(10, 16); // maxBytes = 16
    const url = new URL("https://doh-cache.internal/v1/oversize");
    await cache.put(url, Buffer.alloc(100, 1), 60, 0);
    const stats = cache.stats();
    expect(stats.bytes).toBeLessThanOrEqual(16);
    expect(stats.entries).toBe(0);
  });
});
