// Human-friendly DoH surface: `?name=example.com&type=A`.
//
// RFC 8484's GET form requires base64url wireformat (`?dns=...`), which is
// unreadable in a browser. Cloudflare's resolver also accepts `?name=`/`?type=`
// with a JSON response; we mirror that on the secret DoH path so the same URL
// can be pasted, curl'd, or opened in a browser.
//
// Wireformat clients are unaffected: `?dns=` still takes priority, and a
// `?name=` request without a JSON Accept header still returns dns-message.

import * as packet from "dns-packet";

/** Common RR type names -> numeric codes (as used by the JSON API spec). */
export const QTYPE_CODE: Record<string, number> = {
  A: 1,
  NS: 2,
  CNAME: 5,
  SOA: 6,
  PTR: 12,
  HINFO: 13,
  MX: 15,
  TXT: 16,
  AAAA: 28,
  SRV: 33,
  NAPTR: 35,
  DS: 43,
  SSHFP: 44,
  RRSIG: 46,
  DNSKEY: 48,
  TLSA: 52,
  SVCB: 64,
  HTTPS: 65,
  CAA: 257,
  ANY: 255,
};

const QTYPE_NAME = new Map<number, string>(Object.entries(QTYPE_CODE).map(([n, c]) => [c, n]));

export interface NameQueryInput {
  name: string;
  type: string;
  cd?: boolean;
}

/** Validate a query name: RFC 1035 limits, no empty labels, ASCII only. */
export function validateQueryName(name: string): string | null {
  const n = name.trim().replace(/\.$/, "");
  if (!n) return "name is empty";
  if (n.length > 253) return "name is longer than 253 characters";
  if (!/^[A-Za-z0-9._-]+$/.test(n)) return "name contains invalid characters";
  for (const label of n.split(".")) {
    if (!label) return "name contains an empty label";
    if (label.length > 63) return "a label is longer than 63 characters";
  }
  return null;
}

export function normalizeQType(type: string | null): string | null {
  const t = (type ?? "A").trim().toUpperCase();
  if (!t) return "A";
  if (/^\d+$/.test(t)) {
    const num = Number(t);
    return QTYPE_NAME.get(num) ?? `UNKNOWN_${num}`;
  }
  return t in QTYPE_CODE ? t : null;
}

/** Build a wireformat DNS query for the JSON-style GET surface. */
export function buildQueryFromName(input: NameQueryInput): Uint8Array {
  const flags = 0x0100 | (input.cd ? 0x0010 : 0); // RD=1, optional CD
  return new Uint8Array(
    packet.encode({
      id: 0,
      type: "query",
      flags,
      questions: [{ name: input.name, type: input.type as never, class: "IN" }],
    }),
  );
}

function typeCode(t: unknown): number | undefined {
  if (typeof t === "number") return t;
  if (typeof t === "string") return QTYPE_CODE[t] ?? undefined;
  return undefined;
}

/** Render RDATA the way the JSON DNS API does (dns.google / 1.1.1.1). */
function renderRdata(type: string | number | undefined, data: unknown): string {
  const t = String(type);
  const d = data as Record<string, unknown> | unknown[] | string;
  switch (t) {
    case "A":
    case "AAAA":
    case "CNAME":
    case "NS":
    case "PTR":
    case "DNAME":
      return String(d);
    case "MX":
      return `${(d as { preference: number }).preference} ${(d as { exchange: string }).exchange}`;
    case "TXT":
      return (Array.isArray(d) ? d : [d])
        .map((chunk) => Buffer.from(chunk as ArrayBuffer).toString("utf8"))
        .join("");
    case "SOA": {
      const s = d as Record<string, unknown>;
      return [s.mname, s.rname, s.serial, s.refresh, s.retry, s.expire, s.minimum].join(" ");
    }
    case "SRV": {
      const s = d as Record<string, unknown>;
      return `${s.priority} ${s.weight} ${s.port} ${s.target}`;
    }
    case "CAA": {
      const s = d as Record<string, unknown>;
      return `${s.flags} ${s.tag} "${s.value}"`;
    }
    default:
      return typeof d === "string" ? d : JSON.stringify(d);
  }
}

interface JsonAnswer {
  name: string;
  type: number;
  TTL?: number;
  data: string;
}

function rrToJson(rr: { name?: string; type?: string | number; ttl?: number; data?: unknown }): JsonAnswer {
  const out: JsonAnswer = {
    name: rr.name ?? ".",
    type: typeCode(rr.type) ?? 0,
    data: renderRdata(rr.type, rr.data),
  };
  if (typeof rr.ttl === "number") out.TTL = rr.ttl;
  return out;
}

export interface JsonDnsResponse {
  Status: number;
  TC: boolean;
  RD: boolean;
  RA: boolean;
  AD: boolean;
  CD: boolean;
  Question?: { name: string; type: number }[];
  Answer?: JsonAnswer[];
  Authority?: JsonAnswer[];
  Comment?: string;
}

/** Convert a wireformat DNS response into the JSON DNS API shape. */
export function wireToJson(wire: Uint8Array, comment?: string | null): JsonDnsResponse {
  const dec = packet.decode(Buffer.from(wire)) as {
    flags?: number;
    questions?: { name?: string; type?: string | number }[];
    answers?: { name?: string; type?: string | number; ttl?: number; data?: unknown }[];
    authorities?: { name?: string; type?: string | number; ttl?: number; data?: unknown }[];
  };
  const flags = dec.flags ?? 0;
  const q = dec.questions?.[0];
  const json: JsonDnsResponse = {
    Status: flags & 0x000f,
    TC: Boolean(flags & 0x0200),
    RD: Boolean(flags & 0x0100),
    RA: Boolean(flags & 0x0080),
    AD: Boolean(flags & 0x0020),
    CD: Boolean(flags & 0x0010),
  };
  if (q) json.Question = [{ name: q.name ?? ".", type: typeCode(q.type) ?? 1 }];
  if (dec.answers?.length) json.Answer = dec.answers.map(rrToJson);
  if (dec.authorities?.length) json.Authority = dec.authorities.map(rrToJson);
  if (comment) json.Comment = comment;
  return json;
}

/** Should this request get the JSON representation? */
export function wantsJson(accept: string | null, ctParam: string | null): boolean {
  if (ctParam && ctParam.includes("dns-json")) return true;
  return Boolean(accept && accept.includes("dns-json"));
}
