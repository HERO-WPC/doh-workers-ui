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

describe("global stats persistence", () => {
  class FakeKV {
    store = new Map<string, string>();
    async get(key: string) {
      return this.store.get(key) ?? null;
    }
    async put(key: string, value: string) {
      this.store.set(key, value);
    }
  }

  function makeCtx() {
    const promises: Promise<unknown>[] = [];
    return { promises, waitUntil: (p: Promise<unknown>) => promises.push(p) };
  }

  it("aggregates counters into KV and reads them back across isolates", async () => {
    // Isolate A: serves 5 requests (3 hits, 2 misses), 2 upstream OKs.
    const kv = new FakeKV();
    let m = await freshMetrics();
    m.isolateStats.requests = 5;
    m.isolateStats.cacheHits = 3;
    m.isolateStats.cacheMisses = 2;
    m.isolateStats.upstreamOk = 2;
    m.isolateStats.rttSumMs = 200;
    const ctxA = makeCtx();
    m.flushStats(kv, ctxA.waitUntil);
    await Promise.allSettled(ctxA.promises);

    const globalA = await m.getGlobalStats(kv);
    expect(globalA.requests).toBe(5);
    expect(globalA.cacheHits).toBe(3);
    expect(globalA.upstreamAvgRttMs).toBe(100);

    // Isolate B (fresh module, same KV): serves 2 more requests, both misses.
    vi.resetModules();
    m = await import("../src/metrics");
    m.isolateStats.requests = 2;
    m.isolateStats.cacheMisses = 2;
    m.isolateStats.upstreamFail = 1;
    const globalB = await m.getGlobalStats(kv);
    expect(globalB.requests).toBe(7); // 5 stored + 2 local unflushed
    expect(globalB.cacheHits).toBe(3);
    expect(globalB.cacheMisses).toBe(4); // 2 stored + 2 local

    // Isolate B flushes; totals now fully accumulated.
    const ctxB = makeCtx();
    m.flushStats(kv, ctxB.waitUntil);
    await Promise.allSettled(ctxB.promises);
    const globalAfter = await m.getGlobalStats(kv);
    expect(globalAfter.requests).toBe(7);
    expect(globalAfter.upstreamFail).toBe(1);
    expect(globalAfter.upstreamAvgRttMs).toBe(100); // only isolate A contributed RTT
  });
});

describe("usage day-bucket", () => {
  class FakeKV {
    store = new Map<string, string>();
    async get(key: string) {
      return this.store.get(key) ?? null;
    }
    async put(key: string, value: string) {
      this.store.set(key, value);
    }
  }

  function makeCtx() {
    const promises: Promise<unknown>[] = [];
    return { promises, waitUntil: (p: Promise<unknown>) => promises.push(p) };
  }

  it("keeps totals across a stale-day seed but starts today fresh", async () => {
    const kv = new FakeKV();
    const today = new Date().toISOString().slice(0, 10);
    // Pre-seed: yesterday's totals and a stale today-bucket.
    kv.store.set("stats", JSON.stringify({
      requests: 100,
      kvWrites: 50,
      day: "2000-01-01",
      today: { requests: 7, kvWrites: 3 },
    }));

    const m = await freshMetrics();
    m.isolateStats.requests = 5;
    m.isolateStats.kvWrites = 2;
    const ctx = makeCtx();
    m.flushStats(kv, ctx.waitUntil);
    await Promise.allSettled(ctx.promises);

    const usage = await m.getUsageSnapshot(kv);
    expect(usage.totals.requests).toBe(105); // 100 stored + 5 delta
    expect(usage.totals.kvWrites).toBe(52);
    expect(usage.day).toBe(today);
    expect(usage.today.requests).toBe(5); // stale 7 discarded, fresh delta only
    expect(usage.today.kvWrites).toBe(2);
  });

  it("counts KV operations through the countKv wrapper", async () => {
    const m = await freshMetrics();
    class RichKV {
      store = new Map<string, string>();
      reads = 0;
      async get(key: string) {
        this.reads += 1;
        return this.store.get(key) ?? null;
      }
      async put(key: string, value: string) {
        this.store.set(key, value);
      }
      async list() {
        return { keys: [], list_complete: true };
      }
    }
    const raw = new RichKV();
    const wrapped = m.countKv(raw as unknown as import("../src/types").Env["CONFIG_KV"]);
    await wrapped.put("config", "{\"v\":1}");
    await wrapped.get("config");
    await wrapped.get("stats");
    await wrapped.list();
    expect(m.isolateStats.kvReads).toBe(2);
    expect(m.isolateStats.kvWrites).toBe(1);
    expect(m.isolateStats.kvLists).toBe(1);
    expect(m.isolateStats.kvReadBytes).toBeGreaterThan(0);
    expect(m.isolateStats.kvWriteBytes).toBeGreaterThan(0);
    // The underlying store still worked through the wrapper.
    expect(raw.store.get("config")).toBe('{"v":1}');
  });
});
