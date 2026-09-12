// Two-tier DNS response cache.
//
// L1: per-isolate LRU (Map). Opportunistic only — isolates come and go, and
//     different colos never share this tier.
// L2: Cloudflare Cache API (caches.default) keyed by the synthetic cache-key
//     URL. Per-colo storage: a put is visible to subsequent requests in the
//     same data center; this is a performance optimization, never a source
//     of truth.
//
// Entries are stored with TXID=0 and carry absolute metadata in a response
// header (storedAt epoch ms + fresh/stale windows in seconds), so freshness
// never "restarts" when an entry is served again: age is always measured
// from the original store time. fresh ≤ age < fresh+stale serves stale and
// triggers a background revalidation; beyond that the entry is dead.

import { DNS_CONTENT_TYPE } from "./httputil";

export interface CacheMeta {
  storedAt: number; // epoch ms
  freshFor: number; // seconds
  staleFor: number; // seconds (on top of freshFor)
}

export interface CacheLookup {
  status: "fresh" | "stale";
  body: Buffer; // TXID=0 wire message
  meta: CacheMeta;
  ageSeconds: number;
}

export interface DnsCache {
  get(url: URL): Promise<CacheLookup | null>;
  put(url: URL, body: Buffer, freshFor: number, staleFor: number): Promise<void>;
  stats(): { entries: number; bytes: number };
}

const META_HEADER = "x-doh-cache-meta";

class LruTier {
  private map = new Map<string, { body: Buffer; meta: CacheMeta; bytes: number }>();
  private totalBytes = 0;

  constructor(private maxEntries: number, private maxBytes: number) {}

  get(key: string): { body: Buffer; meta: CacheMeta } | undefined {
    const entry = this.map.get(key);
    if (!entry) return undefined;
    // Move to most-recently-used position.
    this.map.delete(key);
    this.map.set(key, entry);
    return { body: entry.body, meta: entry.meta };
  }

  set(key: string, body: Buffer, meta: CacheMeta): void {
    const existing = this.map.get(key);
    if (existing) {
      this.totalBytes -= existing.bytes;
      this.map.delete(key);
    }
    const bytes = body.length;
    this.map.set(key, { body, meta, bytes });
    this.totalBytes += bytes;
    while (this.map.size > this.maxEntries || (this.totalBytes > this.maxBytes && this.map.size > 1)) {
      const oldest = this.map.keys().next();
      if (oldest.done) break;
      const evicted = this.map.get(oldest.value);
      this.totalBytes -= evicted?.bytes ?? 0;
      this.map.delete(oldest.value);
    }
  }

  delete(key: string): void {
    const entry = this.map.get(key);
    if (entry) {
      this.totalBytes -= entry.bytes;
      this.map.delete(key);
    }
  }

  stats(): { entries: number; bytes: number } {
    return { entries: this.map.size, bytes: this.totalBytes };
  }
}

function ageOf(meta: CacheMeta): number {
  return Math.max(0, (Date.now() - meta.storedAt) / 1000);
}

function classify(body: Buffer, meta: CacheMeta): CacheLookup | "expired" | null {
  const age = ageOf(meta);
  if (age >= meta.freshFor + meta.staleFor) return "expired";
  return {
    status: age < meta.freshFor ? "fresh" : "stale",
    body,
    meta,
    ageSeconds: Math.floor(age),
  };
}

function hasCacheApi(): boolean {
  return typeof caches !== "undefined" && typeof caches.default?.match === "function";
}

export function createDnsCache(maxEntries = 1000, maxBytes = 4 * 1024 * 1024): DnsCache {
  const l1 = new LruTier(maxEntries, maxBytes);

  return {
    async get(url: URL): Promise<CacheLookup | null> {
      const key = url.toString();

      const local = l1.get(key);
      if (local) {
        const result = classify(local.body, local.meta);
        if (result === "expired") {
          l1.delete(key);
        } else if (result) {
          return result;
        }
      }

      if (!hasCacheApi()) return null;
      try {
        const res = await caches.default.match(url);
        if (!res) return null;
        const rawMeta = res.headers.get(META_HEADER);
        if (!rawMeta) return null;
        const meta = JSON.parse(rawMeta) as CacheMeta;
        if (typeof meta.storedAt !== "number" || typeof meta.freshFor !== "number" || typeof meta.staleFor !== "number") {
          return null;
        }
        const body = Buffer.from(await res.arrayBuffer());
        const result = classify(body, meta);
        if (!result || result === "expired") return null;
        // Write-through: backfill L1 from L2.
        l1.set(key, body, meta);
        return result;
      } catch {
        // Cache API failure must never break DNS resolution.
        return null;
      }
    },

    async put(url: URL, body: Buffer, freshFor: number, staleFor: number): Promise<void> {
      const key = url.toString();
      const meta: CacheMeta = { storedAt: Date.now(), freshFor, staleFor };
      l1.set(key, body, meta);
      if (!hasCacheApi()) return;
      try {
        const res = new Response(body, {
          headers: {
            "content-type": DNS_CONTENT_TYPE,
            // The shared cache must retain the entry through the stale window;
            // actual freshness is decided from our metadata, not max-age.
            "cache-control": `public, max-age=${Math.ceil(freshFor + staleFor)}`,
            [META_HEADER]: JSON.stringify(meta),
          },
        });
        await caches.default.put(url, res);
      } catch {
        // Best-effort: L1 still holds the entry.
      }
    },

    stats() {
      return l1.stats();
    },
  };
}

/** Isolate-scoped singleton; opportunistic by design. */
export const dnsCache = createDnsCache();
