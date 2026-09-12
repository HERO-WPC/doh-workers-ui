// DNS wire-format unit tests: parsing, validation, TXID/TTL rewriting,
// record-type round trips (incl. opaque HTTPS/SVCB), and malformed input.

import { describe, expect, it } from "vitest";
import * as packet from "dns-packet";
import { loadModules, buildClientQuery } from "./helpers";
import type { DnsPacket } from "../src/dnsmsg";

const m = await loadModules();
const { DnsMessageError, parseClientQuery, validateUpstreamResponse, answerTtlSeconds, withTxid, materializeForClient, buildReply, buildUpstreamQuery, forCache, FLAG_QR, readU16 } = m.dnsmsg;

function makeQuery(opts = {}) {
  return buildClientQuery(opts);
}

describe("parseClientQuery", () => {
  it("parses a valid A query", () => {
    const q = parseClientQuery(makeQuery({ name: "Example.COM", txid: 0x4242 }));
    expect(q.txid).toBe(0x4242);
    expect(q.qname).toBe("Example.COM");
    expect(q.qnameLower).toBe("example.com");
    expect(q.qtype).toBe("A");
    expect(q.qclass).toBe("IN");
    expect(q.opcode).toBe(0);
    expect(q.do).toBe(false);
    expect(q.cd).toBe(false);
  });

  it("parses DO bit from EDNS", () => {
    const q = parseClientQuery(makeQuery({ do: true }));
    expect(q.do).toBe(true);
  });

  it("parses CD flag", () => {
    const q = parseClientQuery(makeQuery({ cd: true }));
    expect(q.cd).toBe(true);
  });

  it("rejects empty and short messages", () => {
    expect(() => parseClientQuery(new ArrayBuffer(0))).toThrow(DnsMessageError);
    expect(() => parseClientQuery(new Uint8Array(11))).toThrow(DnsMessageError);
  });

  it("rejects QR bit set", () => {
    const resp = packet.encode({ id: 1, type: "response", flags: 0x8000, questions: [{ name: "a.com", type: "A" }] } as unknown as packet.Packet);
    expect(() => parseClientQuery(resp)).toThrow(DnsMessageError);
  });

  it("rejects truncated question section", () => {
    const full = makeQuery({ name: "a.b.c.example.com" });
    expect(() => parseClientQuery(full.subarray(0, full.length - 3))).toThrow(DnsMessageError);
  });

  it("rejects multiple questions", () => {
    const buf = packet.encode({
      id: 1,
      type: "query",
      flags: 0,
      questions: [
        { name: "a.com", type: "A" },
        { name: "b.com", type: "A" },
      ],
    } as unknown as packet.Packet);
    expect(() => parseClientQuery(buf)).toThrow(DnsMessageError);
  });

  it("rejects zero questions", () => {
    const buf = Buffer.alloc(12);
    buf.writeUInt16BE(0, 0); // id
    buf.writeUInt16BE(0x0100, 2); // RD
    expect(() => parseClientQuery(buf)).toThrow(DnsMessageError);
  });
});

describe("validateUpstreamResponse", () => {
  const q = { qname: "example.com", qtype: "A", qclass: "IN", opcode: 0 };

  function makeResponse(overrides: Record<string, unknown> = {}) {
    return packet.encode({
      id: 0x1234,
      type: "response",
      flags: 0x8000 | 0x0100,
      questions: [{ name: "example.com", type: "A" }],
      answers: [{ name: "example.com", type: "A", ttl: 300, data: "93.184.216.34" }],
      ...overrides,
    } as unknown as packet.Packet);
  }

  it("accepts a matching response and extracts TTL", () => {
    const a = validateUpstreamResponse(0x1234, q, makeResponse())!;
    expect(a).not.toBeNull();
    expect(a.rcode).toBe(0);
    expect(a.cacheable).toBe(true);
    expect(a.ttlSeconds).toBe(300);
  });

  it("rejects TXID mismatch", () => {
    expect(validateUpstreamResponse(0x9999, q, makeResponse())).toBeNull();
  });

  it("rejects non-response (QR missing)", () => {
    const bad = packet.encode({
      id: 0x1234,
      type: "query",
      flags: 0x0100,
      questions: [{ name: "example.com", type: "A" }],
    } as unknown as packet.Packet);
    expect(validateUpstreamResponse(0x1234, q, bad)).toBeNull();
  });

  it("rejects opcode mismatch", () => {
    const bad = makeResponse({ flags: 0x8000 | (2 << 11) });
    expect(validateUpstreamResponse(0x1234, q, bad)).toBeNull();
  });

  it("rejects wrong question name (cache poisoning defense)", () => {
    const bad = packet.encode({
      id: 0x1234,
      type: "response",
      flags: 0x8000,
      questions: [{ name: "evil.com", type: "A" }],
      answers: [{ name: "evil.com", type: "A", ttl: 300, data: "6.6.6.6" }],
    } as unknown as packet.Packet);
    expect(validateUpstreamResponse(0x1234, q, bad)).toBeNull();
  });

  it("rejects wrong question type", () => {
    const bad = packet.encode({
      id: 0x1234,
      type: "response",
      flags: 0x8000,
      questions: [{ name: "example.com", type: "AAAA" }],
    } as unknown as packet.Packet);
    expect(validateUpstreamResponse(0x1234, q, bad)).toBeNull();
  });

  it("rejects garbage", () => {
    expect(validateUpstreamResponse(0x1234, q, Buffer.from([1, 2, 3]))).toBeNull();
  });
});

describe("answerTtlSeconds", () => {
  it("returns min answer TTL", () => {
    const p = packet.decode(packet.encode({
      id: 1,
      type: "response",
      flags: 0x8000,
      questions: [{ name: "a.com", type: "A" }],
      answers: [
        { name: "a.com", type: "A", ttl: 500, data: "1.1.1.1" },
        { name: "a.com", type: "A", ttl: 30, data: "2.2.2.2" },
      ],
    } as unknown as packet.Packet)) as unknown as DnsPacket;
    expect(answerTtlSeconds(p)).toBe(30);
  });

  it("uses SOA min(ttl, MINIMUM) for negative answers", () => {
    const p = packet.decode(packet.encode({
      id: 1,
      type: "response",
      flags: 0x8000 | 3,
      questions: [{ name: "missing.com", type: "A" }],
      authorities: [{ name: "com", type: "SOA", ttl: 1800, data: { mname: "ns.com", rname: "a.com", serial: 1, refresh: 2, retry: 3, expire: 4, minimum: 60 } }],
    } as unknown as packet.Packet)) as unknown as DnsPacket;
    expect(answerTtlSeconds(p)).toBe(60);
  });

  it("returns null when no answers and no SOA", () => {
    const p = packet.decode(packet.encode({ id: 1, type: "response", flags: 0x8000, questions: [{ name: "a.com", type: "A" }] } as unknown as packet.Packet)) as unknown as DnsPacket;
    expect(answerTtlSeconds(p)).toBeNull();
  });
});

describe("TXID / TTL rewriting", () => {
  it("withTxid overwrites the first two bytes", () => {
    const wire = makeQuery({ txid: 0x1111 });
    const out = withTxid(wire, 0x2222);
    expect(readU16(out, 0)).toBe(0x2222);
    expect(readU16(wire, 0)).toBe(0x1111); // original untouched
  });

  it("materializeForClient sets TXID and ages TTLs", () => {
    const cached = packet.encode({
      id: 0,
      type: "response",
      flags: 0x8000,
      questions: [{ name: "a.com", type: "A" }],
      answers: [{ name: "a.com", type: "A", ttl: 300, data: "1.1.1.1" }],
      additionals: [{ name: ".", type: "OPT", udpPayloadSize: 1232, ednsVersion: 0, flags: 0 }],
    } as unknown as packet.Packet);
    const out = materializeForClient(cached, 0x7777, 100);
    expect(readU16(out, 0)).toBe(0x7777);
    const dec = packet.decode(out) as unknown as { answers: { ttl: number }[]; additionals: { type: string; udpPayloadSize: number }[] };
    expect(dec.answers[0].ttl).toBe(200);
    expect(dec.additionals[0].udpPayloadSize).toBe(1232); // OPT untouched
  });

  it("materializeForClient never returns negative TTL", () => {
    const cached = packet.encode({
      id: 0,
      type: "response",
      flags: 0x8000,
      questions: [{ name: "a.com", type: "A" }],
      answers: [{ name: "a.com", type: "A", ttl: 50, data: "1.1.1.1" }],
    } as unknown as packet.Packet);
    const dec = packet.decode(materializeForClient(cached, 1, 1000)) as unknown as { answers: { ttl: number }[] };
    expect(dec.answers[0].ttl).toBe(0);
  });
});

describe("record type round trips", () => {
  const types: Array<[string, unknown]> = [
    ["A", "1.2.3.4"],
    ["AAAA", "2606:2800:220:1:248:1893:25c8:1946"],
    ["CNAME", "target.example.com"],
    ["TXT", ["some text"]],
    ["MX", { preference: 10, exchange: "mail.example.com" }],
    ["NS", "ns1.example.com"],
    ["SOA", { mname: "ns1.example.com", rname: "admin.example.com", serial: 2026091101, refresh: 7200, retry: 900, expire: 1209600, minimum: 300 }],
  ];

  for (const [type, data] of types) {
    it(`round-trips ${type} through cache encode/decode`, () => {
      const resp = packet.encode({
        id: 9,
        type: "response",
        flags: 0x8000,
        questions: [{ name: "example.com", type }],
        answers: [{ name: "example.com", type, ttl: 120, data }],
      } as unknown as packet.Packet);
      const q = { qname: "example.com", qtype: type, qclass: "IN", opcode: 0 };
      const answer = validateUpstreamResponse(9, q, resp)!;
      expect(answer).not.toBeNull();
      const cached = forCache(answer.packet);
      expect(readU16(cached, 0)).toBe(0);
      const served = materializeForClient(cached, 7, 0);
      const dec = packet.decode(served) as unknown as { answers: { type: string; data: unknown }[] };
      expect(dec.answers.length).toBe(1);
      expect(dec.answers[0].type).toBe(type);
      if (type === "TXT") {
        const d = dec.answers[0].data as unknown;
        const txt = Array.isArray(d) ? d.map((x) => String(x)).join("") : String(d);
        expect(txt).toBe("some text");
      } else if (typeof data === "object" && data !== null) {
        expect(dec.answers[0].data).toMatchObject(data);
      } else {
        expect(dec.answers[0].data).toBe(data);
      }
    });
  }

  it("round-trips opaque HTTPS (type 65) rdata untouched", () => {
    // Hand-built HTTPS SVCB rdata: priority=1, target=., alpn=h2
    const rdata = Buffer.from([0, 1, 0, 0, 0, 2, 0, 2, 0x68, 0x32]);
    const resp = packet.encode({
      id: 5,
      type: "response",
      flags: 0x8000,
      questions: [{ name: "example.com", type: "UNKNOWN_65" }],
      answers: [{ name: "example.com", type: "UNKNOWN_65", ttl: 120, data: rdata }],
    } as unknown as packet.Packet);
    const answer = validateUpstreamResponse(5, { qname: "example.com", qtype: "UNKNOWN_65", qclass: "IN", opcode: 0 }, resp)!;
    expect(answer).not.toBeNull();
    const served = materializeForClient(forCache(answer.packet), 8, 0);
    const dec = packet.decode(served) as unknown as { answers: { type: string; data: Buffer }[] };
    expect(dec.answers[0].type).toBe("UNKNOWN_65");
    expect(Buffer.compare(Buffer.from(dec.answers[0].data), rdata)).toBe(0);
  });
});

describe("buildUpstreamQuery / buildReply", () => {
  it("sets RD, random TXID, and passes CD through", () => {
    const w1 = buildUpstreamQuery({ qname: "a.com", qtype: "A", qclass: "IN", cd: false, do: false }, null);
    const w2 = buildUpstreamQuery({ qname: "a.com", qtype: "A", qclass: "IN", cd: true, do: false }, null);
    const d1 = packet.decode(w1) as unknown as { flags: number; id: number };
    const d2 = packet.decode(w2) as unknown as { flags: number };
    expect(d1.flags & 0x0100).toBe(0x0100);
    expect(d2.flags & 0x0010).toBe(0x0010);
    expect(d1.id).not.toBe(0);
  });

  it("includes ECS option when provided", () => {
    const w = buildUpstreamQuery({ qname: "a.com", qtype: "A", qclass: "IN", cd: false, do: false }, { family: 1, sourcePrefix: 24, address: "198.51.100.0" });
    const dec = packet.decode(w) as unknown as { additionals: { type: string; options: { code: number; family: number; sourcePrefixLength: number; ip: string }[] }[] };
    const opt = dec.additionals.find((r) => r.type === "OPT");
    expect(opt).toBeTruthy();
    expect(opt!.options[0]).toMatchObject({ code: 8, family: 1, sourcePrefixLength: 24, ip: "198.51.100.0" });
  });

  it("buildReply produces QR|opcode|rcode header with question echo", () => {
    const buf = buildReply(0xabcd, 2, 4, "a.com", "A", "IN");
    expect(readU16(buf, 0)).toBe(0xabcd);
    expect(readU16(buf, 2)).toBe(FLAG_QR | (2 << 11) | 4);
    const dec = packet.decode(buf) as unknown as { questions: { name: string }[] };
    expect(dec.questions[0].name).toBe("a.com");
  });
});
