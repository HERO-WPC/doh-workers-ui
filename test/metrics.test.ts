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
