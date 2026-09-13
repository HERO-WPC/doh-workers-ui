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
