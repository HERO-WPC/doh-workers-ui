// DNS wire-format handling built on top of dns-packet (MIT).
//
// dns-packet does the risky work (RFC 1035 name compression, EDNS0, all
// standard RR types); unknown RR types (SVCB/HTTPS/anything newer) round-trip
// opaquely as "UNKNOWN_<n>" strings carrying a Buffer, which is exactly the
// correct proxy behavior: we never need to interpret rdata we don't know.
//
// Everything here is strict: any structural problem throws DnsMessageError,
// which callers map to HTTP 400 / a FORMERR reply. Malformed input can never
// reach the cache or an upstream.
//
// We intentionally use small local helpers (readU16) and structural record
// types instead of Buffer methods / dns-packet's nominal types, so this file
// compiles identically under Workers types and Node types.

import * as packet from "dns-packet";
import type { EcsOptionLike, EcsSpec } from "./ecs";
import { findClientEcs } from "./ecs";

export const DNS_HEADER_SIZE = 12;
export const MAX_DNS_MESSAGE_SIZE = 65535;

// Header flag bits (RFC 1035 §4.1.1).
export const FLAG_QR = 0x8000;
export const FLAG_RD = 0x0100;
export const FLAG_CD = 0x0010;
export const DO_FLAG = 0x8000; // EDNS DO bit

export const RCODE_NOERROR = 0;
export const RCODE_FORMERR = 1;
export const RCODE_SERVFAIL = 2;
export const RCODE_NXDOMAIN = 3;
export const RCODE_NOTIMP = 4;
export const RCODE_REFUSED = 5;

export class DnsMessageError extends Error {}

/** Structural view of any RR (known or opaque). */
export interface DnsRecord {
  name?: string;
  type?: string | number;
  ttl?: number;
  class?: string | number;
  data?: unknown;
  // EDNS/OPT-specific fields (dns-packet shape):
  udpPayloadSize?: number;
  extendedRcode?: number;
  ednsVersion?: number;
  flags?: number;
  flag_do?: boolean;
  options?: EcsOptionLike[];
}

export interface DnsPacket {
  id?: number;
  type?: string;
  flags?: number;
  questions?: DnsRecord[];
  answers?: DnsRecord[];
  authorities?: DnsRecord[];
  additionals?: DnsRecord[];
}

export interface ParsedClientQuery {
  /** Original Transaction ID from the client, echoed back on every response. */
  txid: number;
  /** 16-bit header flags word of the client query. */
  flags: number;
  opcode: number;
  /** Question owner name with original case (forwarded upstream). */
  qname: string;
  /** Lowercased qname (cache keys). */
  qnameLower: string;
  /** dns-packet type string, e.g. "A" or "UNKNOWN_65" for opaque types. */
  qtype: string;
  /** dns-packet class string, e.g. "IN". */
  qclass: string;
  do: boolean;
  cd: boolean;
  /** EDNS UDP payload size advertised by the client (0 = no EDNS). */
  udpPayloadSize: number;
  /** ECS option the client itself sent, if any. */
  clientEcs: EcsSpec | null;
}

export function readU16(buf: Uint8Array, offset: number): number {
  return (buf[offset] << 8) | buf[offset + 1];
}

function writeU16(buf: Uint8Array, offset: number, value: number): void {
  buf[offset] = (value >>> 8) & 0xff;
  buf[offset + 1] = value & 0xff;
}

function toBuffer(body: ArrayBuffer | ArrayBufferView): Buffer {
  if (body instanceof ArrayBuffer) return Buffer.from(new Uint8Array(body));
  return Buffer.from(body as Uint8Array);
}

function asPacket(p: packet.Packet): DnsPacket {
  return p as unknown as DnsPacket;
}

export function randomTxid(): number {
  const b = new Uint8Array(2);
  crypto.getRandomValues(b);
  return (b[0] << 8) | b[1];
}

export function rcodeOf(flags: number): number {
  return flags & 0xf;
}

export function opcodeOf(flags: number): number {
  return (flags >> 11) & 0xf;
}

/**
 * Parse and strictly validate a client DNS query (GET or POST pipeline).
 * Throws DnsMessageError for anything malformed or unsupported-structure.
 */
export function parseClientQuery(body: ArrayBuffer | ArrayBufferView): ParsedClientQuery {
  const buf = toBuffer(body);
  if (buf.length < DNS_HEADER_SIZE) {
    throw new DnsMessageError(`DNS message too short (${buf.length} bytes)`);
  }
  if (buf.length > MAX_DNS_MESSAGE_SIZE) {
    throw new DnsMessageError(`DNS message too large (${buf.length} bytes)`);
  }

  const headerFlags = readU16(buf, 2);
  if (headerFlags & FLAG_QR) {
    throw new DnsMessageError("QR bit set on a query");
  }

  let dec: DnsPacket;
  try {
    dec = asPacket(packet.decode(buf));
  } catch (e) {
    throw new DnsMessageError(`malformed DNS message: ${(e as Error).message}`);
  }

  if (!dec.questions || dec.questions.length !== 1) {
    throw new DnsMessageError(`expected exactly 1 question, got ${dec.questions?.length ?? 0}`);
  }
  const q = dec.questions[0];
  const qname = q.name;
  if (typeof qname !== "string" || qname.length === 0) {
    throw new DnsMessageError("missing question name");
  }

  const opt = findOpt(dec);
  return {
    txid: readU16(buf, 0),
    flags: headerFlags,
    opcode: opcodeOf(headerFlags),
    qname,
    qnameLower: qname.toLowerCase(),
    qtype: String(q.type),
    qclass: String(q.class ?? "IN"),
    do: opt ? Boolean(opt.flag_do) : false,
    cd: (headerFlags & FLAG_CD) !== 0,
    udpPayloadSize: opt ? opt.udpPayloadSize || 0 : 0,
    clientEcs: opt ? findClientEcs(opt) : null,
  };
}

export function findOpt(p: DnsPacket): DnsRecord | null {
  for (const rr of p.additionals ?? []) {
    if (String(rr.type) === "OPT") return rr;
  }
  return null;
}

/**
 * Build the wire query we send upstream: random TXID, RD=1, CD passthrough,
 * EDNS with DO passthrough and (optionally) one ECS option. Other client
 * EDNS options are intentionally dropped.
 */
export function buildUpstreamQuery(
  q: { qname: string; qtype: string; qclass: string; cd: boolean; do: boolean },
  ecs: EcsSpec | null,
): Buffer {
  const additionals: unknown[] = [];
  if (q.do || ecs) {
    const options: unknown[] = [];
    if (ecs) {
      options.push({ code: 8, family: ecs.family, sourcePrefixLength: ecs.sourcePrefix, ip: ecs.address });
    }
    additionals.push({
      name: ".",
      type: "OPT",
      udpPayloadSize: 1232,
      extendedRcode: 0,
      ednsVersion: 0,
      flags: q.do ? DO_FLAG : 0,
      options,
    });
  }
  return packet.encode({
    id: randomTxid(),
    type: "query",
    flags: FLAG_RD | (q.cd ? FLAG_CD : 0),
    questions: [{ name: q.qname, type: q.qtype, class: q.qclass }],
    additionals,
  } as unknown as packet.Packet);
}

/** Minimal DNS reply used for protocol-level rejections (NOTIMP / FORMERR). */
export function buildReply(txid: number, opcode: number, rcode: number, qname: string, qtype: string, qclass: string): Buffer {
  return packet.encode({
    id: txid,
    type: "response",
    flags: FLAG_QR | (opcode << 11) | rcode,
    questions: [{ name: qname, type: qtype, class: qclass }],
  } as unknown as packet.Packet);
}

export interface UpstreamAnswer {
  packet: DnsPacket;
  rcode: number;
  /** Lowest TTL across answers/authority, honoring SOA negative TTL. */
  ttlSeconds: number | null;
  /** True when the response is safe to cache (NOERROR / NXDOMAIN only). */
  cacheable: boolean;
}

/**
 * Validate an upstream response against the query we sent. Anything that
 * does not match — TXID, QR, opcode, question echo — is rejected so a
 * poisoned or mismatched answer can never enter the cache.
 * Returns null when the response must be discarded.
 */
export function validateUpstreamResponse(
  sentTxid: number,
  q: { qname: string; qtype: string; qclass: string; opcode: number },
  body: ArrayBuffer | ArrayBufferView,
): UpstreamAnswer | null {
  const buf = toBuffer(body);
  if (buf.length < DNS_HEADER_SIZE || buf.length > MAX_DNS_MESSAGE_SIZE) return null;
  if (readU16(buf, 0) !== sentTxid) return null;

  let dec: DnsPacket;
  try {
    dec = asPacket(packet.decode(buf));
  } catch {
    return null;
  }

  const flags = readU16(buf, 2);
  if (!(flags & FLAG_QR)) return null;
  if (opcodeOf(flags) !== q.opcode) return null;
  if (!dec.questions || dec.questions.length !== 1) return null;
  const rq = dec.questions[0];
  if (!rq.name || rq.name.toLowerCase() !== q.qname.toLowerCase()) return null;
  if (String(rq.type) !== q.qtype) return null;
  if (String(rq.class ?? "IN") !== q.qclass) return null;

  // 有效 rcode = EDNS 扩展高 8 位 + 头部低 4 位。只看低 4 位会把
  // BADVERS(16) 之类的扩展错误当成 NOERROR(0) 而错误地缓存。
  const opt = findOpt(dec);
  const extended = opt && typeof opt.extendedRcode === "number" ? opt.extendedRcode : 0;
  const rcode = ((extended & 0xff) << 4) | rcodeOf(flags);
  return {
    packet: dec,
    rcode,
    ttlSeconds: answerTtlSeconds(dec),
    cacheable: rcode === RCODE_NOERROR || rcode === RCODE_NXDOMAIN,
  };
}

/** Minimum TTL across answer records (OPT excluded). */
function minRecordTtl(records: DnsRecord[] | undefined): number | null {
  if (!records || records.length === 0) return null;
  let min: number | null = null;
  for (const rr of records) {
    if (String(rr.type) === "OPT") continue;
    const ttl = rr.ttl;
    if (typeof ttl !== "number" || !Number.isFinite(ttl) || ttl < 0) continue;
    if (min === null || ttl < min) min = ttl;
  }
  return min;
}

/**
 * Effective TTL: min answer TTL, or for empty answers the SOA-based
 * negative TTL (min(SOA.ttl, SOA.MINIMUM)), or null when nothing usable.
 */
export function answerTtlSeconds(p: DnsPacket): number | null {
  const answerTtl = minRecordTtl(p.answers);
  if (answerTtl !== null) return answerTtl;

  for (const rr of p.authorities ?? []) {
    if (String(rr.type) === "SOA") {
      const data = (rr.data ?? {}) as { minimum?: number };
      const ttl = rr.ttl ?? 0;
      const minimum = typeof data.minimum === "number" ? data.minimum : ttl;
      return Math.min(ttl, minimum);
    }
  }
  return null;
}

/** Overwrite the 2-byte TXID of a wire message (returns a copy). */
export function withTxid(buf: Uint8Array, txid: number): Buffer {
  const out = Buffer.from(buf);
  writeU16(out, 0, txid & 0xffff);
  return out;
}

/**
 * Rewrite a cached (TXID=0) message for a specific client: set the client's
 * TXID and age every record's TTL by the seconds the entry spent in cache.
 * OPT records are never touched.
 */
export function materializeForClient(cached: Uint8Array, txid: number, ageSeconds: number): Buffer {
  const dec = asPacket(packet.decode(Buffer.from(cached)));
  dec.id = txid & 0xffff;
  const age = Math.max(0, Math.floor(ageSeconds));
  if (age > 0) {
    for (const section of [dec.answers, dec.authorities, dec.additionals]) {
      for (const rr of section ?? []) {
        if (String(rr.type) === "OPT") continue;
        if (typeof rr.ttl === "number") rr.ttl = Math.max(0, rr.ttl - age);
      }
    }
  }
  return packet.encode(dec as unknown as packet.Packet);
}

/** Re-encode a validated packet with TXID=0 for cache storage. */
export function forCache(p: DnsPacket): Buffer {
  p.id = 0;
  return packet.encode(p as unknown as packet.Packet);
}
