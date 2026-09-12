// Routing tests: sequential failover, racing with abort, adaptive scoring,
// and metrics recording.

import { describe, expect, it } from "vitest";
import * as packet from "dns-packet";
import { loadModules, makeFakeUpstream } from "./helpers";
import type { Config } from "../src/types";

const m = await loadModules();
const { MetricsStore } = m.metrics;
const { resolveQuery, AllUpstreamsFailedError } = m.routing;

const Q = { qname: "example.com", qtype: "A", qclass: "IN", opcode: 0 };

function makeWire(): Buffer {
  return packet.encode({
    id: 0x0abc,
    type: "query",
    flags: 0x0100,
    questions: [{ name: "example.com", type: "A" }],
  } as unknown as packet.Packet);
}

function upstream(id: string, priority: number, url = `https://${id}.test/dns-query`) {
  return { id, name: id, url, enabled: true, priority, timeout: 2500 };
}

function makeConfig(overrides: Partial<Config["routing"]> = {}, upstreams = [upstream("a", 1), upstream("b", 2)]): Config {
  return {
    version: 1,
    updatedAt: "",
    doh: { path: "/aaaaaaaaaaaaaaaa/dns-query" },
    cache: { minTTL: 10, maxTTL: 600, staleTTL: 86400, jitterPercent: 10, maxBody: 65535 },
    routing: { mode: "sequential", raceCount: 2, ...overrides },
    ecs: { mode: "off", ipv4Prefix: 24, ipv6Prefix: 56, fixedSubnet: "" },
    upstreams,
  };
}

function store(): InstanceType<typeof MetricsStore> {
  return new MetricsStore(null);
}

describe("sequential failover", () => {
  it("falls through a failing upstream to the next by priority", async () => {
    const fake = makeFakeUpstream();
    fake.behaviors.set("a.test", { kind: "httpStatus", status: 500 });
    const cfg = makeConfig({ mode: "sequential" });
    const r = await resolveQuery(makeWire(), Q, { cfg, metrics: store(), fetchImpl: fake.fetch });
    expect(r.upstreamId).toBe("b");
    expect(r.attempts.map((a) => a.id)).toEqual(["a", "b"]);
  });

  it("falls through timeouts and malformed responses", async () => {
    const fake = makeFakeUpstream();
    fake.behaviors.set("a.test", { kind: "hang" });
    fake.behaviors.set("b.test", { kind: "garbage" });
    const cfg = makeConfig({ mode: "sequential" }, [upstream("a", 1), upstream("b", 2), upstream("c", 3)]);
    const r = await resolveQuery(makeWire(), Q, { cfg, metrics: store(), fetchImpl: fake.fetch });
    expect(r.upstreamId).toBe("c");
  });

  it("throws AllUpstreamsFailedError when everything fails", async () => {
    const fake = makeFakeUpstream();
    fake.behaviors.set("a.test", { kind: "httpStatus", status: 503 });
    fake.behaviors.set("b.test", { kind: "httpStatus", status: 503 });
    const cfg = makeConfig({ mode: "sequential" });
    await expect(resolveQuery(makeWire(), Q, { cfg, metrics: store(), fetchImpl: fake.fetch })).rejects.toThrow(AllUpstreamsFailedError);
  });

  it("throws when no upstreams are enabled", async () => {
    const cfg = makeConfig({ mode: "sequential" }, [{ ...upstream("a", 1), enabled: false }]);
    await expect(resolveQuery(makeWire(), Q, { cfg, metrics: store() })).rejects.toThrow(AllUpstreamsFailedError);
  });
});

describe("racing", () => {
  it("returns the fastest valid answer and aborts the losers", async () => {
    const fake = makeFakeUpstream();
    fake.behaviors.set("a.test", { kind: "answer", delayMs: 400 });
    // b answers immediately.
    const cfg = makeConfig({ mode: "race", raceCount: 2 });
    const r = await resolveQuery(makeWire(), Q, { cfg, metrics: store(), fetchImpl: fake.fetch });
    expect(r.upstreamId).toBe("b");
    // Let abort callbacks propagate, then check the loser was aborted.
    await new Promise((res) => setTimeout(res, 30));
    const loser = fake.calls.find((c) => c.url.includes("a.test"))!;
    expect(loser.aborted).toBe(true);
  }, 10000);

  it("skips invalid racers and falls back to the rest", async () => {
    const fake = makeFakeUpstream();
    fake.behaviors.set("a.test", { kind: "garbage" });
    fake.behaviors.set("b.test", { kind: "garbage" });
    const cfg = makeConfig({ mode: "race", raceCount: 2 }, [upstream("a", 1), upstream("b", 2), upstream("c", 3)]);
    const r = await resolveQuery(makeWire(), Q, { cfg, metrics: store(), fetchImpl: fake.fetch });
    expect(r.upstreamId).toBe("c");
  });

  it("respects raceCount: only N racers fire first", async () => {
    const fake = makeFakeUpstream();
    fake.behaviors.set("a.test", { kind: "answer", delayMs: 50 });
    const cfg = makeConfig({ mode: "race", raceCount: 1 }, [upstream("a", 1), upstream("b", 2)]);
    const r = await resolveQuery(makeWire(), Q, { cfg, metrics: store(), fetchImpl: fake.fetch });
    expect(r.upstreamId).toBe("a");
    expect(fake.calls.filter((c) => c.url.includes("b.test")).length).toBe(0);
  }, 10000);
});

describe("adaptive ordering", () => {
  it("prefers the upstream with the better score", async () => {
    const fake = makeFakeUpstream();
    fake.behaviors.set("unhealthy.test", { kind: "answer", delayMs: 5 });
    const metrics = store();
    // Poison "unhealthy" with failures so its score tanks.
    for (let i = 0; i < 10; i++) metrics.record("unhealthy", { timeout: true });
    metrics.record("healthy", { success: true, rttMs: 10 });

    const cfg = makeConfig({ mode: "adaptive" }, [upstream("unhealthy", 1), upstream("healthy", 2)]);
    const r = await resolveQuery(makeWire(), Q, { cfg, metrics, fetchImpl: fake.fetch });
    expect(r.upstreamId).toBe("healthy");
  });

  it("records successes and failures for both winners and losers", async () => {
    const fake = makeFakeUpstream();
    fake.behaviors.set("a.test", { kind: "httpStatus", status: 500 });
    const cfg = makeConfig({ mode: "sequential" });
    const metrics = store();
    await resolveQuery(makeWire(), Q, { cfg, metrics, fetchImpl: fake.fetch });
    const a = await metrics.get("a");
    const b = await metrics.get("b");
    expect(a.fail).toBe(1);
    expect(b.ok).toBe(1);
  });

  it("races do not record superseded losers as failures", async () => {
    const fake = makeFakeUpstream();
    fake.behaviors.set("slow.test", { kind: "answer", delayMs: 300 });
    const cfg = makeConfig({ mode: "race", raceCount: 2 }, [upstream("slow", 1), upstream("fast", 2)]);
    const metrics = store();
    await resolveQuery(makeWire(), Q, { cfg, metrics, fetchImpl: fake.fetch });
    await new Promise((res) => setTimeout(res, 50));
    const slow = await metrics.get("slow");
    // The slow loser was aborted because fast won; it must not be counted.
    expect(slow.fail).toBe(0);
    expect(slow.timeout).toBe(0);
  }, 10000);
});
