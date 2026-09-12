// Cache layer tests: L1/L2 tiers, fresh/stale/expired classification, LRU
// eviction, cache-key separation (QTYPE/DO/CD/ECS), and deterministic jitter.

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { FakeCacheStorage, installCacheApi, loadModules } from "./helpers";

const m = await loadModules();
const { createDnsCache, dnsCache } = m.cache;
const { cacheKeyUrl, canonicalString, jitterFactor } = m.cachekey;

beforeEach(() => {
  installCacheApi(new FakeCacheStorage());
});
afterEach(() => {
  vi.useRealTimers();
});

const body = Buffer.alloc(12, 7);

describe("two-tier get/put", () => {
  it("stores and returns fresh entries", async () => {
    const cache = createDnsCache();
    const url = await cacheKeyUrl({ qnameLower: "a.com", qtype: "A", qclass: "IN", do: false, cd: false, ecs: null });
    await cache.put(url, body, 60, 120);
    const hit = await cache.get(url);
    expect(hit).not.toBeNull();
    expect(hit!.status).toBe("fresh");
    expect(Buffer.from(hit!.body).equals(body)).toBe(true);
  });

  it("serves stale within staleTTL and expires beyond it", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-01-01T00:00:00Z"));
    const cache = createDnsCache();
    const url = await cacheKeyUrl({ qnameLower: "stale.com", qtype: "A", qclass: "IN", do: false, cd: false, ecs: null });
    await cache.put(url, body, 60, 120);

    vi.setSystemTime(new Date("2026-01-01T00:00:30Z"));
    expect((await cache.get(url))!.status).toBe("fresh");

    vi.setSystemTime(new Date("2026-01-01T00:01:30Z"));
    expect((await cache.get(url))!.status).toBe("stale");

    // beyond fresh(60) + stale(120) = 180s -> expired
    vi.setSystemTime(new Date("2026-01-01T00:03:10Z"));
    expect(await cache.get(url)).toBeNull();
  });

  it("backfills L1 from L2", async () => {
    const storage = installCacheApi(new FakeCacheStorage());
    const cache = createDnsCache();
    const url = await cacheKeyUrl({ qnameLower: "backfill.com", qtype: "A", qclass: "IN", do: false, cd: false, ecs: null });
    await cache.put(url, body, 60, 120);

    // New cache instance (fresh L1), same storage (shared L2).
    const cache2 = createDnsCache();
    const hit = await cache2.get(url);
    expect(hit).not.toBeNull();
    expect(storage.default.store.size).toBe(1);
    // And now L1 holds it: stats reflect a backfilled entry.
    expect(cache2.stats().entries).toBe(1);
  });

  it("keeps working when the Cache API throws", async () => {
    installCacheApi({
      default: {
        async match() {
          throw new Error("cache down");
        },
        async put() {
          throw new Error("cache down");
        },
      },
    } as never);
    const cache = createDnsCache();
    const url = await cacheKeyUrl({ qnameLower: "degraded.com", qtype: "A", qclass: "IN", do: false, cd: false, ecs: null });
    await cache.put(url, body, 60, 120); // must not throw
    const hit = await cache.get(url);
    expect(hit).not.toBeNull(); // L1 still serves
  });
});

describe("LRU eviction", () => {
  it("evicts oldest L1 entries beyond maxEntries but L2 still serves them", async () => {
    const cache = createDnsCache(2, 1024 * 1024);
    const urls = await Promise.all(
      ["one.com", "two.com", "three.com"].map((n) => cacheKeyUrl({ qnameLower: n, qtype: "A", qclass: "IN", do: false, cd: false, ecs: null })),
    );
    for (const url of urls) await cache.put(url, body, 60, 60);
    // L1 evicted the oldest down to 2 entries.
    expect(cache.stats().entries).toBe(2);
    // L2 (shared storage) still holds all three, so reads still succeed.
    expect(await cache.get(urls[0])).not.toBeNull();
    expect(await cache.get(urls[2])).not.toBeNull();
  });
});

describe("cache key separation", () => {
  const base = { qnameLower: "example.com", qtype: "A", qclass: "IN", do: false, cd: false, ecs: null };

  it("different QTYPE -> different key", async () => {
    const a = await cacheKeyUrl(base);
    const b = await cacheKeyUrl({ ...base, qtype: "AAAA" });
    expect(a.toString()).not.toBe(b.toString());
  });

  it("QNAME is case-insensitive", async () => {
    const a = await cacheKeyUrl(base);
    const b = await cacheKeyUrl({ ...base, qnameLower: "EXAMPLE.COM" });
    expect(a.toString()).toBe(b.toString());
  });

  it("DO=0 and DO=1 never share", async () => {
    const a = await cacheKeyUrl(base);
    const b = await cacheKeyUrl({ ...base, do: true });
    expect(a.toString()).not.toBe(b.toString());
  });

  it("CD=0 and CD=1 never share", async () => {
    const a = await cacheKeyUrl(base);
    const b = await cacheKeyUrl({ ...base, cd: true });
    expect(a.toString()).not.toBe(b.toString());
  });

  it("ECS participates in the key", async () => {
    const a = await cacheKeyUrl(base);
    const b = await cacheKeyUrl({ ...base, ecs: { family: 1, sourcePrefix: 24, address: "203.0.113.0" } });
    const c = await cacheKeyUrl({ ...base, ecs: { family: 1, sourcePrefix: 24, address: "198.51.100.0" } });
    expect(a.toString()).not.toBe(b.toString());
    expect(b.toString()).not.toBe(c.toString());
  });

  it("canonical string captures all fields", () => {
    const s = canonicalString({ ...base, do: true });
    expect(s).toBe("example.com|A|IN|do=1|cd=0|ecs=-");
  });
});

describe("deterministic jitter", () => {
  it("same key always yields the same factor", () => {
    expect(jitterFactor("abcdef01", 10)).toBe(jitterFactor("abcdef01", 10));
    expect(jitterFactor("abcdef01", 10)).not.toBe(jitterFactor("0000abcd", 10));
  });

  it("zero jitter returns 1", () => {
    expect(jitterFactor("abcdef01", 0)).toBe(1);
  });

  it("stays within ±jitterPercent", () => {
    for (let i = 0; i < 200; i++) {
      const f = jitterFactor(i.toString(16).padStart(8, "0") + "deadbeef", 10);
      expect(f).toBeGreaterThanOrEqual(0.9 - 1e-9);
      expect(f).toBeLessThanOrEqual(1.1 + 1e-9);
    }
  });
});

describe("isolate-scoped singleton", () => {
  it("exposes stats", () => {
    expect(dnsCache.stats()).toMatchObject({ entries: 0, bytes: 0 });
  });
});
