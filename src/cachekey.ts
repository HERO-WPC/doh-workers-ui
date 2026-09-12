// Cache key construction.
//
// The key must capture everything that can change the answer:
// QNAME (case-normalized), QTYPE, QCLASS, DO bit, CD bit and ECS. The
// Transaction ID is deliberately excluded — cached entries are stored with
// TXID=0 and rewritten per client on the way out.
//
// A SHA-256 digest of the canonical string becomes the synthetic URL used
// with the Cache API. Unlike a short hash (e.g. 32-bit FNV), collisions are
// not a practical concern.

import { ecsKeyString, type EcsSpec } from "./ecs";

export interface CacheKeyParts {
  qnameLower: string;
  qtype: string;
  qclass: string;
  do: boolean;
  cd: boolean;
  ecs: EcsSpec | null;
}

/** The effective ECS spec forwarded upstream (drives the key). */
export type EcsForwarder = (q: { clientEcs: unknown }) => EcsSpec | null;

export function canonicalString(parts: CacheKeyParts): string {
  return [
    parts.qnameLower.toLowerCase(),
    parts.qtype,
    parts.qclass,
    `do=${parts.do ? 1 : 0}`,
    `cd=${parts.cd ? 1 : 0}`,
    ecsKeyString(parts.ecs),
  ].join("|");
}

export async function sha256Hex(input: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(input));
  return Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

const CACHE_ORIGIN = "https://doh-cache.internal";

export async function cacheKeyUrl(parts: CacheKeyParts): Promise<URL> {
  const hex = await sha256Hex(canonicalString(parts));
  return new URL(`${CACHE_ORIGIN}/v1/${hex}`);
}

/**
 * Deterministic TTL jitter factor in [1 - j, 1 + j] derived from the cache
 * key itself, so every isolate computes the same factor for the same key.
 * This de-synchronizes expiry across the fleet without random drift per
 * request, and cannot stampede a key the way per-request jitter can.
 */
export function jitterFactor(keyHex: string, jitterPercent: number): number {
  if (!Number.isFinite(jitterPercent) || jitterPercent <= 0) return 1;
  const pct = Math.min(jitterPercent, 50);
  const h = parseInt(keyHex.slice(-4), 16) / 0xffff; // [0, 1]
  const factor = 1 + (h * 2 - 1) * (pct / 100);
  // Keep the factor sane even for extreme configurations.
  return Math.min(1.5, Math.max(0.5, factor));
}
