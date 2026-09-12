// Upstream fetch tests: HTTP errors, content-type, timeout, malformed and
// mismatched responses.

import { describe, expect, it } from "vitest";
import * as packet from "dns-packet";
import { loadModules, makeFakeUpstream } from "./helpers";

const m = await loadModules();
const { queryUpstream } = m.upstream;

const Q = { qname: "example.com", qtype: "A", qclass: "IN", opcode: 0 };

function makeWire(): Buffer {
  return packet.encode({
    id: 0x0abc,
    type: "query",
    flags: 0x0100,
    questions: [{ name: "example.com", type: "A" }],
  } as unknown as packet.Packet);
}

const UPSTREAM = { id: "test", name: "Test", url: "https://upstream.test/dns-query", enabled: true, priority: 1, timeout: 2500 };

describe("queryUpstream", () => {
  it("returns a validated answer on success", async () => {
    const wire = makeWire();
    const okFake = makeFakeUpstream();
    const r = await queryUpstream(UPSTREAM, wire, Q, { timeoutMs: 1000, fetchImpl: okFake.fetch });
    expect(r.ok).toBe(true);
    expect(r.rttMs).toBeGreaterThanOrEqual(0);
    expect(r.answer!.rcode).toBe(0);
    expect(m.dnsmsg.readU16(r.buf!, 0)).toBe(0x0abc);
  });

  it("rejects non-2xx", async () => {
    const fake = makeFakeUpstream();
    fake.behaviors.set("upstream.test", { kind: "httpStatus", status: 500 });
    const r = await queryUpstream(UPSTREAM, makeWire(), Q, { timeoutMs: 1000, fetchImpl: fake.fetch });
    expect(r.ok).toBe(false);
    expect(r.error).toContain("500");
  });

  it("rejects wrong content-type", async () => {
    const wire = makeWire();
    const fetchImpl = (async () => new Response(Buffer.from([1, 2, 3]), { status: 200, headers: { "content-type": "text/html" } })) as unknown as typeof fetch;
    const r = await queryUpstream(UPSTREAM, wire, Q, { timeoutMs: 1000, fetchImpl });
    expect(r.ok).toBe(false);
    expect(r.error).toContain("content-type");
  });

  it("rejects malformed response body", async () => {
    const fake = makeFakeUpstream();
    fake.behaviors.set("upstream.test", { kind: "garbage" });
    const r = await queryUpstream(UPSTREAM, makeWire(), Q, { timeoutMs: 1000, fetchImpl: fake.fetch });
    expect(r.ok).toBe(false);
  });

  it("rejects response whose question does not match the query", async () => {
    const fake = makeFakeUpstream();
    fake.behaviors.set("upstream.test", { kind: "wrongQuestion" });
    const r = await queryUpstream(UPSTREAM, makeWire(), Q, { timeoutMs: 1000, fetchImpl: fake.fetch });
    expect(r.ok).toBe(false);
  });

  it("times out a hanging upstream", async () => {
    const fake = makeFakeUpstream();
    fake.behaviors.set("upstream.test", { kind: "hang" });
    const r = await queryUpstream(UPSTREAM, makeWire(), Q, { timeoutMs: 60, fetchImpl: fake.fetch });
    expect(r.ok).toBe(false);
    expect(r.timedOut).toBe(true);
  });

  it("aborts when the external signal fires", async () => {
    const fake = makeFakeUpstream();
    fake.behaviors.set("upstream.test", { kind: "hang" });
    const controller = new AbortController();
    setTimeout(() => controller.abort(), 30);
    const r = await queryUpstream(UPSTREAM, makeWire(), Q, { timeoutMs: 30_000, signal: controller.signal, fetchImpl: fake.fetch });
    expect(r.ok).toBe(false);
    expect(r.timedOut).toBe(true);
  });
});

describe("probeUpstream", () => {
  it("reports rtt for a healthy upstream", async () => {
    const { probeUpstream } = m.upstream;
    const okFake = makeFakeUpstream();
    const r = await probeUpstream(UPSTREAM, { timeoutMs: 1000, fetchImpl: okFake.fetch });
    expect(r.ok).toBe(true);
    expect(r.rttMs).toBeGreaterThanOrEqual(0);
  });
});
