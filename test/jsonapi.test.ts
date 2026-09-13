// Human-friendly DoH surface: ?name=&type= query building and JSON output.

import { describe, expect, it } from "vitest";
import * as packet from "dns-packet";
import {
  buildQueryFromName,
  normalizeQType,
  validateQueryName,
  wantsJson,
  wireToJson,
} from "../src/jsonapi";

describe("name query validation", () => {
  it("accepts normal names and strips a trailing dot", () => {
    expect(validateQueryName("chatgpt.com")).toBeNull();
    expect(validateQueryName("www.example.com.")).toBeNull();
    expect(validateQueryName("_dmarc.example.com")).toBeNull();
  });

  it("rejects malformed names", () => {
    expect(validateQueryName("")).not.toBeNull();
    expect(validateQueryName("a..b")).not.toBeNull();
    expect(validateQueryName("bad name.com")).not.toBeNull();
    expect(validateQueryName(`${"a".repeat(64)}.com`)).not.toBeNull();
  });

  it("normalizes types", () => {
    expect(normalizeQType(null)).toBe("A");
    expect(normalizeQType("aaaa")).toBe("AAAA");
    expect(normalizeQType("28")).toBe("AAAA");
    expect(normalizeQType("cname")).toBe("CNAME");
    expect(normalizeQType("bogus")).toBeNull();
  });

  it("only treats dns-json accept/ct as JSON", () => {
    expect(wantsJson("application/dns-json", null)).toBe(true);
    expect(wantsJson(null, "application/dns-json")).toBe(true);
    expect(wantsJson("application/dns-message", null)).toBe(false);
    expect(wantsJson(null, null)).toBe(false);
  });
});

describe("buildQueryFromName", () => {
  it("produces a decodable RD query for the requested name/type", () => {
    const wire = buildQueryFromName({ name: "chatgpt.com", type: "AAAA" });
    const dec = packet.decode(Buffer.from(wire)) as {
      flags?: number;
      questions?: { name?: string; type?: string }[];
    };
    expect(dec.questions?.[0]?.name).toBe("chatgpt.com");
    expect(dec.questions?.[0]?.type).toBe("AAAA");
    expect((dec.flags ?? 0) & 0x0100).toBe(0x0100); // RD
  });

  it("sets the CD bit when requested", () => {
    const wire = buildQueryFromName({ name: "example.com", type: "A", cd: true });
    const dec = packet.decode(Buffer.from(wire)) as { flags?: number };
    expect((dec.flags ?? 0) & 0x0010).toBe(0x0010);
  });
});

describe("wireToJson", () => {
  it("renders A / MX / TXT / SOA answers in the JSON API shape", () => {
    const wire = new Uint8Array(
      packet.encode({
        id: 0,
        type: "response",
        flags: 0x8180,
        questions: [{ name: "example.com", type: "A", class: "IN" }],
        answers: [
          { name: "example.com", type: "A", class: "IN", ttl: 300, data: "93.184.216.34" },
          { name: "example.com", type: "MX", class: "IN", ttl: 600, data: { preference: 10, exchange: "mail.example.com" } },
          { name: "example.com", type: "TXT", class: "IN", ttl: 60, data: [Buffer.from("v=spf1 -all")] },
          {
            name: "example.com", type: "SOA", class: "IN", ttl: 900,
            data: { mname: "ns1.example.com", rname: "hostmaster.example.com", serial: 1, refresh: 2, retry: 3, expire: 4, minimum: 5 },
          },
        ],
      }),
    );
    const json = wireToJson(wire, "HIT");
    expect(json.Status).toBe(0);
    expect(json.Question).toEqual([{ name: "example.com", type: 1 }]);
    expect(json.Answer?.[0]).toEqual({ name: "example.com", type: 1, TTL: 300, data: "93.184.216.34" });
    expect(json.Answer?.[1].data).toBe("10 mail.example.com");
    expect(json.Answer?.[2].data).toBe("v=spf1 -all");
    expect(json.Answer?.[3].data).toBe("ns1.example.com hostmaster.example.com 1 2 3 4 5");
    expect(json.Comment).toBe("HIT");
    expect(json.RA).toBe(true);
  });

  it("reports NXDOMAIN status and no answers", () => {
    const wire = new Uint8Array(
      packet.encode({
        id: 0, type: "response", flags: 0x8183,
        questions: [{ name: "nope.example.com", type: "A", class: "IN" }],
        answers: [],
      }),
    );
    const json = wireToJson(wire);
    expect(json.Status).toBe(3);
    expect(json.Answer).toBeUndefined();
  });
});
