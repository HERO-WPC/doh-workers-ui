// Metrics tests, including the lazy isolate-clock regression:
// Date.now() at Workers global scope returns epoch 0, so the stats clock
// must only start on the first request (uptimeSeconds() guards for that).

import { describe, expect, it, vi } from "vitest";

async function freshMetrics() {
  vi.resetModules();
  return import("../src/metrics");
}

describe("isolate stats clock", () => {
  it("reports 0 uptime before the clock starts and never a negative uptime", async () => {
    const { isolateStats, uptimeSeconds, ensureStatsClock } = await freshMetrics();
    // Fresh module registry: clock not started.
    expect(isolateStats.startedAt).toBeNull();
    expect(uptimeSeconds()).toBe(0);

    ensureStatsClock();
    expect(isolateStats.startedAt).not.toBeNull();
    expect(uptimeSeconds()).toBeGreaterThanOrEqual(0);
  });

  it("statsSnapshot tolerates a not-yet-started clock", async () => {
    const { statsSnapshot } = await freshMetrics();
    const snap = statsSnapshot();
    expect(snap.startedAt).toBeNull();
    expect(snap.uptimeSeconds).toBe(0);
  });
});

describe("MetricsStore legacy fallback", () => {
  class FakeKV {
    store = new Map<string, string>();
    async get(key: string) { return this.store.get(key) ?? null; }
    async put(key: string, value: string) { this.store.set(key, value); }
  }
  it("回读旧版 metrics:<id> key 找回历史(blob 缺失时)", async () => {
    const { MetricsStore } = await import("../src/metrics");
    const kv = new FakeKV();
    kv.store.set("metrics:cloudflare", JSON.stringify({ ok: 120, fail: 3, timeout: 1, rttEmaMs: 88, lastSuccess: "x", lastFailure: null, updatedAt: "y" }));
    const s = new MetricsStore(kv);
    const m = await s.get("cloudflare");
    expect(m.ok).toBe(120);
    expect(m.rttEmaMs).toBe(88);
    // 二次读取不重复回读
    const m2 = await s.get("cloudflare");
    expect(m2.ok).toBe(120);
    // blob 缺失时其它 id 正常返回空指标
    const g = await s.get("google");
    expect(g.ok).toBe(0);
  });

  it("blob 存在时优先用 blob,不回读旧 key", async () => {
    const { MetricsStore } = await import("../src/metrics");
    const kv = new FakeKV();
    kv.store.set("metrics", JSON.stringify({ google: { ok: 5, fail: 0, timeout: 0, rttEmaMs: 40, lastSuccess: null, lastFailure: null, updatedAt: null } }));
    kv.store.set("metrics:google", JSON.stringify({ ok: 999, fail: 0, timeout: 0, rttEmaMs: 999, lastSuccess: null, lastFailure: null, updatedAt: null }));
    const s = new MetricsStore(kv);
    const m = await s.get("google");
    expect(m.ok).toBe(5);   // 来自 blob,而不是旧 key 的 999
  });
});
