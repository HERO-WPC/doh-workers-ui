// EDNS Client Subnet (RFC 7871) support.
//
// ECS is disabled by default: injecting it fragments the cache key by subnet
// and leaks coarse client location upstream. When enabled we never forward a
// full address — IPv4 is truncated (default /24) and IPv6 (default /56).
// dns-packet encodes the named option form {code:8, family, sourcePrefixLength, ip}
// and truncates the address bytes for us; we do our own parsing/truncation so
// behavior is testable and independent of upstream versions.

import type { EcsConfig } from "./types";

export interface EcsSpec {
  family: 1 | 2;
  sourcePrefix: number;
  /** Already-truncated address as a string. */
  address: string;
}

export interface EcsOptionLike {
  code?: number;
  type?: string;
  family?: number;
  sourcePrefixLength?: number;
  scopePrefixLength?: number;
  ip?: string;
  data?: Uint8Array;
}

/** Extract the client's own ECS option from a decoded OPT record, if any. */
export function findClientEcs(opt: { options?: EcsOptionLike[] }): EcsSpec | null {
  for (const o of opt.options ?? []) {
    const isEcs = o.code === 8 || o.type === "CLIENT_SUBNET";
    if (!isEcs) continue;
    let family = o.family;
    let sourcePrefix = o.sourcePrefixLength;
    let ip = o.ip;
    if (family === undefined || ip === undefined) {
      // Fall back to raw option data: family(2) src(1) scope(1) addr...
      const d = o.data;
      if (!d || d.length < 4) return null;
      family = (d[0] << 8) | d[1];
      sourcePrefix = d[2];
      const addrBytes = d.slice(4);
      ip = bytesToIp(family, addrBytes);
    }
    if ((family === 1 || family === 2) && typeof sourcePrefix === "number" && ip) {
      return { family, sourcePrefix, address: ip };
    }
    return null;
  }
  return null;
}

function bytesToIp(family: number, bytes: Uint8Array): string {
  if (family === 1) return Array.from(bytes.slice(0, 4)).join(".");
  // IPv6: best-effort hex groups (only used for cache-key canonicalization)
  const groups: string[] = [];
  for (let i = 0; i < 16; i += 2) {
    groups.push(((bytes[i] ?? 0) << 8 | (bytes[i + 1] ?? 0)).toString(16));
  }
  return groups.join(":");
}

function ipv4ToBytes(ip: string): Uint8Array | null {
  const parts = ip.split(".");
  if (parts.length !== 4) return null;
  const out = new Uint8Array(4);
  for (let i = 0; i < 4; i++) {
    const n = Number(parts[i]);
    if (!Number.isInteger(n) || n < 0 || n > 255 || !/^\d+$/.test(parts[i])) return null;
    out[i] = n;
  }
  return out;
}

function ipv6ToBytes(ip: string): Uint8Array | null {
  // Handle optional zone id.
  const bare = ip.split("%")[0];
  const dbl = bare.split("::");
  if (dbl.length > 2) return null;
  const parseGroups = (s: string): number[] | null => {
    if (s === "") return [];
    const groups = s.split(":");
    const out: number[] = [];
    for (const g of groups) {
      if (!/^[0-9a-fA-F]{1,4}$/.test(g)) return null;
      out.push(parseInt(g, 16));
    }
    return out;
  };
  const head = parseGroups(dbl[0]);
  const tail = dbl.length === 2 ? parseGroups(dbl[1]) : [];
  if (head === null || tail === null) return null;
  const missing = 8 - head.length - tail.length;
  if (missing < 0 || (dbl.length === 2 && missing === 0)) return null;
  const groups = [...head, ...new Array(dbl.length === 2 ? missing : 0).fill(0), ...tail];
  if (groups.length !== 8) return null;
  const out = new Uint8Array(16);
  for (let i = 0; i < 8; i++) {
    out[i * 2] = groups[i] >> 8;
    out[i * 2 + 1] = groups[i] & 0xff;
  }
  return out;
}

function truncateBytes(bytes: Uint8Array, prefixBits: number): Uint8Array {
  const keep = Math.floor(prefixBits / 8);
  const out = new Uint8Array(bytes.length);
  for (let i = 0; i < bytes.length; i++) {
    out[i] = i < keep ? bytes[i] : 0;
  }
  const remBits = prefixBits % 8;
  if (remBits > 0 && keep < bytes.length) {
    const mask = (0xff << (8 - remBits)) & 0xff;
    out[keep] = bytes[keep] & mask;
  }
  return out;
}

function ipv4FromBytes(b: Uint8Array): string {
  return Array.from(b).join(".");
}

function ipv6FromBytes(b: Uint8Array): string {
  const groups: string[] = [];
  for (let i = 0; i < 16; i += 2) groups.push(((b[i] << 8) | b[i + 1]).toString(16));
  // RFC 5952-ish compression of the longest zero run.
  let bestStart = -1;
  let bestLen = 0;
  let curStart = -1;
  let curLen = 0;
  for (let i = 0; i < 8; i++) {
    if (groups[i] === "0") {
      if (curStart < 0) curStart = i;
      curLen++;
      if (curLen > bestLen) {
        bestLen = curLen;
        bestStart = curStart;
      }
    } else {
      curStart = -1;
      curLen = 0;
    }
  }
  if (bestLen < 2) return groups.join(":");
  // RFC 5952:零段压缩时必须保留 "::"。原实现用空串 join 出 ":",
  // 在零段位于开头或结尾时会产出 "2001:db8:"、":1"、"" 这类非法字面量
  // (下游编码器宽容才没崩,但缓存键/日志里是非规范表示)。
  const left = groups.slice(0, bestStart);
  const right = groups.slice(bestStart + bestLen);
  if (left.length === 0 && right.length === 0) return "::";
  if (left.length === 0) return "::" + right.join(":");
  if (right.length === 0) return left.join(":") + "::";
  return left.join(":") + "::" + right.join(":");
}

function makeSpec(family: 1 | 2, address: string, prefix: number): EcsSpec | null {
  const bytes = family === 1 ? ipv4ToBytes(address) : ipv6ToBytes(address);
  if (!bytes) return null;
  const maxBits = family === 1 ? 32 : 128;
  if (!Number.isInteger(prefix) || prefix < 0 || prefix > maxBits) return null;
  return { family, sourcePrefix: prefix, address: family === 1 ? ipv4FromBytes(truncateBytes(bytes, prefix)) : ipv6FromBytes(truncateBytes(bytes, prefix)) };
}

/** Re-truncate an existing spec to a (possibly coarser) prefix. */
export function withPrefix(spec: EcsSpec, prefix: number): EcsSpec | null {
  const maxBits = spec.family === 1 ? 32 : 128;
  if (!Number.isInteger(prefix) || prefix < 0 || prefix > maxBits) return null;
  return makeSpec(spec.family, spec.address, Math.min(prefix, spec.sourcePrefix));
}

/** Derive a privacy-truncated ECS spec from the client IP (mode "auto"). */
export function deriveEcsFromIp(ip: string, cfg: EcsConfig): EcsSpec | null {
  if (!ip) return null;
  const bare = ip.split("%")[0];
  const family: 1 | 2 = bare.includes(":") ? 2 : 1;
  const prefix = family === 1 ? cfg.ipv4Prefix : cfg.ipv6Prefix;
  return makeSpec(family, bare, prefix);
}

/** Parse an admin-provided fixed subnet like "203.0.113.0/24". */
export function parseFixedSubnet(subnet: string): EcsSpec | null {
  if (!subnet) return null;
  const slash = subnet.indexOf("/");
  if (slash < 0) return null;
  const addr = subnet.slice(0, slash).trim();
  const prefix = Number(subnet.slice(slash + 1).trim());
  const family: 1 | 2 = addr.includes(":") ? 2 : 1;
  return makeSpec(family, addr, prefix);
}

/** Canonical string used inside the cache key; ECS always participates. */
export function ecsKeyString(spec: EcsSpec | null): string {
  return spec ? `ecs=${spec.family}/${spec.sourcePrefix}:${spec.address}` : "ecs=-";
}

/** Option object in the named form dns-packet encodes. */
export function ecsToOption(spec: EcsSpec): Record<string, unknown> {
  return { code: 8, family: spec.family, sourcePrefixLength: spec.sourcePrefix, ip: spec.address };
}
