// Provider metrics + isolate-local stats.
//
// Rules (deliberate):
//  - KV is NEVER touched on the DNS hot path. Metrics accumulate in isolate
//    memory and are flushed to KV through ctx.waitUntil at most once every
//    FLUSH_INTERVAL_MS. A lost flush costs a little accuracy, nothing else.
//  - One KV key per provider ("metrics:<id>") so concurrent isolates don't
//    fight over a single blob.
//  - Scoring is explainable: Laplace-smoothed reliability × 1000 / RTT EMA.

import type { ProviderMetrics } from "./types";

// 10 分钟:KV 免费版限 1000 写/天(账号级),全屋 DNS 24h 流经 Worker,
// 节流太短会把当日写入额度打满。统计精度 10 分钟对监控足够。
export const FLUSH_INTERVAL_MS = 600_000;

export function emptyMetrics(): ProviderMetrics {
  return {
    ok: 0,
    fail: 0,
    timeout: 0,
    rttEmaMs: null,
    lastSuccess: null,
    lastFailure: null,
    updatedAt: null,
  };
}

export function reliabilityOf(m: ProviderMetrics): number {
  return (m.ok + 1) / (m.ok + m.fail + m.timeout + 2);
}

export function scoreOf(m: ProviderMetrics): number {
  const rtt = m.rttEmaMs && m.rttEmaMs > 0 ? m.rttEmaMs : 150;
  return (reliabilityOf(m) * 1000) / rtt;
}

export class MetricsStore {
  private mem = new Map<string, ProviderMetrics>();
  private dirty = new Set<string>();
  private lastFlush = 0;

  constructor(private kv: { get(key: string): Promise<string | null>; put(key: string, value: string): Promise<void> } | null) {}

  private key(id: string): string {
    return `metrics:${id}`;
  }

  async get(id: string): Promise<ProviderMetrics> {
    const cached = this.mem.get(id);
    if (cached) return cached;
    let m = emptyMetrics();
    if (this.kv) {
      try {
        const raw = await this.kv.get(this.key(id));
        if (raw) {
          const parsed = JSON.parse(raw) as ProviderMetrics;
          if (parsed && typeof parsed === "object" && typeof parsed.ok === "number") {
            m = { ...emptyMetrics(), ...parsed };
          }
        }
      } catch {
        // Treat KV errors as "no history".
      }
    }
    this.mem.set(id, m);
    return m;
  }

  record(
    id: string,
    outcome: { success?: boolean; timeout?: boolean; rttMs?: number },
  ): void {
    const m = this.mem.get(id) ?? emptyMetrics();
    if (outcome.success) {
      m.ok += 1;
      m.lastSuccess = new Date().toISOString();
      if (typeof outcome.rttMs === "number" && outcome.rttMs >= 0) {
        m.rttEmaMs = m.rttEmaMs === null ? Math.round(outcome.rttMs) : Math.round(m.rttEmaMs * 0.7 + outcome.rttMs * 0.3);
      }
    } else if (outcome.timeout) {
      m.timeout += 1;
      m.lastFailure = new Date().toISOString();
    } else {
      m.fail += 1;
      m.lastFailure = new Date().toISOString();
    }
    m.updatedAt = new Date().toISOString();
    this.mem.set(id, m);
    this.dirty.add(id);
  }

  /** Fire-and-forget persistence; call with ctx.waitUntil on each request. */
  flush(waitUntil: (p: Promise<unknown>) => void): void {
    if (!this.kv || this.dirty.size === 0) return;
    const now = Date.now();
    if (now - this.lastFlush < FLUSH_INTERVAL_MS) return;
    this.lastFlush = now;
    const ids = [...this.dirty];
    this.dirty.clear();
    for (const id of ids) {
      const m = this.mem.get(id);
      if (!m) continue;
      waitUntil(
        this.kv
          .put(this.key(id), JSON.stringify(m))
          .catch(() => {
            // Re-mark so a later flush can retry.
            this.dirty.add(id);
          }),
      );
    }
  }

  snapshot(id: string): ProviderMetrics | undefined {
    return this.mem.get(id);
  }
}

// One store per isolate; the KV binding is stable per deployment.
let sharedStore: MetricsStore | null = null;

export function getMetricsStore(kv: MetricsStore["kv"]): MetricsStore {
  if (!sharedStore) sharedStore = new MetricsStore(kv);
  return sharedStore;
}

// ---------------------------------------------------------------------------
// Isolate-local aggregate stats. These are per-isolate by nature; the admin
// UI labels them as approximate rather than pretending they are global.
// ---------------------------------------------------------------------------

export const isolateStats = {
  // Lazy: Date.now() at Workers global scope returns epoch 0 (no request
  // I/O has happened yet), so the clock must start on the first request.
  startedAt: null as number | null,
  requests: 0,
  cacheHits: 0,
  cacheStale: 0,
  cacheMisses: 0,
  upstreamOk: 0,
  upstreamFail: 0,
  upstreamTimeouts: 0,
  rttSumMs: 0,
  servedFromUpstream: 0,
  // KV 操作用量:由 countKv() 包装器累加,随 stats 一起批量落 KV。
  kvReads: 0,
  kvWrites: 0,
  kvLists: 0,
  kvReadBytes: 0,
  kvWriteBytes: 0,
};

/** Start the isolate clock on first use (call from request handlers). */
export function ensureStatsClock(): void {
  if (isolateStats.startedAt === null) {
    isolateStats.startedAt = Date.now();
  }
}

export function uptimeSeconds(): number {
  if (isolateStats.startedAt === null) return 0;
  return Math.max(0, Math.round((Date.now() - isolateStats.startedAt) / 1000));
}

export function statsSnapshot(): Record<string, number | string | null> {
  const avgRtt = isolateStats.upstreamOk > 0 ? Math.round(isolateStats.rttSumMs / isolateStats.upstreamOk) : null;
  return {
    startedAt: isolateStats.startedAt === null ? null : new Date(isolateStats.startedAt).toISOString(),
    uptimeSeconds: uptimeSeconds(),
    requests: isolateStats.requests,
    cacheHits: isolateStats.cacheHits,
    cacheStale: isolateStats.cacheStale,
    cacheMisses: isolateStats.cacheMisses,
    upstreamOk: isolateStats.upstreamOk,
    upstreamFail: isolateStats.upstreamFail,
    upstreamTimeouts: isolateStats.upstreamTimeouts,
    upstreamAvgRttMs: avgRtt,
    kvReads: isolateStats.kvReads,
    kvWrites: isolateStats.kvWrites,
    kvLists: isolateStats.kvLists,
  };
}

// ---------------------------------------------------------------------------
// Global stats: aggregate isolate counters into KV so the dashboard shows
// meaningful totals across isolates. Same discipline as provider metrics:
// accumulate in memory, flush via waitUntil at most once per interval.
// KV is eventually consistent, so these totals are approximate by nature.
// ---------------------------------------------------------------------------

const STATS_KV_KEY = "stats";

const STATS_COUNTER_KEYS = [
  "requests",
  "cacheHits",
  "cacheStale",
  "cacheMisses",
  "upstreamOk",
  "upstreamFail",
  "upstreamTimeouts",
  "servedFromUpstream",
  "rttSumMs",
  "kvReads",
  "kvWrites",
  "kvLists",
  "kvReadBytes",
  "kvWriteBytes",
] as const;

type CounterKey = (typeof STATS_COUNTER_KEYS)[number];
type CounterMap = Record<CounterKey, number>;

/** Counters already reflected in KV by THIS isolate (null = flushed nothing yet). */
let persistedCounters: CounterMap | null = null;
let lastStatsFlush = 0;

function countersSnapshot(): CounterMap {
  const out = {} as CounterMap;
  for (const k of STATS_COUNTER_KEYS) {
    out[k] = (isolateStats as unknown as Record<string, number>)[k] ?? 0;
  }
  return out;
}

function readCounters(obj: unknown): Partial<CounterMap> {
  const out: Partial<CounterMap> = {};
  if (obj && typeof obj === "object") {
    for (const k of STATS_COUNTER_KEYS) {
      const v = (obj as Record<string, unknown>)[k];
      if (typeof v === "number" && Number.isFinite(v)) out[k] = v;
    }
  }
  return out;
}

function utcDay(): string {
  return new Date().toISOString().slice(0, 10);
}

/** Throttled KV flush of counter deltas. Call from request handlers. */
export function flushStats(
  kv: { get(key: string): Promise<string | null>; put(key: string, value: string): Promise<void> },
  waitUntil: (p: Promise<unknown>) => void,
): void {
  const now = Date.now();
  if (now - lastStatsFlush < FLUSH_INTERVAL_MS) return;
  lastStatsFlush = now;
  waitUntil(
    (async () => {
      const storedRaw = safeParse(await kv.get(STATS_KV_KEY));
      const stored = readCounters(storedRaw);
      const storedDay = typeof storedRaw?.day === "string" ? storedRaw.day : null;
      const storedToday = readCounters(storedRaw?.today);
      const current = countersSnapshot();
      const base = persistedCounters ?? ({} as Partial<CounterMap>);
      const merged: CounterMap = { ...current };
      const todayStr = utcDay();
      const todayBase = storedDay === todayStr ? storedToday : ({} as Partial<CounterMap>);
      const today: CounterMap = { ...current };
      for (const k of STATS_COUNTER_KEYS) {
        const delta = Math.max(0, (current[k] ?? 0) - (base[k] ?? 0));
        merged[k] = (stored[k] ?? 0) + delta;
        today[k] = (todayBase[k] ?? 0) + delta;
      }
      await kv.put(STATS_KV_KEY, JSON.stringify({ ...merged, day: todayStr, today }));
      persistedCounters = current;
    })().catch(() => {
      // Re-arm soon: clear the throttle so the next request retries.
      lastStatsFlush = 0;
    }),
  );
}

function safeParse(raw: string | null): Record<string, unknown> {
  try {
    const v = raw ? JSON.parse(raw) : null;
    return v && typeof v === "object" ? (v as Record<string, unknown>) : {};
  } catch {
    return {};
  }
}

export interface UsageSnapshot {
  totals: CounterMap & { upstreamAvgRttMs: number | null };
  today: Partial<CounterMap>;
  day: string;
}

/**
 * Global totals for display: KV aggregates + this isolate's unflushed deltas.
 * Reads KV every call — this endpoint is admin-only, never on the DNS path.
 * `today` is a UTC-day bucket, reset when a flush happens on a new UTC day.
 */
export async function getUsageSnapshot(
  kv: { get(key: string): Promise<string | null> },
): Promise<UsageSnapshot> {
  const storedRaw = safeParse(await kv.get(STATS_KV_KEY));
  const stored = readCounters(storedRaw);
  const storedDay = typeof storedRaw?.day === "string" ? storedRaw.day : null;
  const storedToday = readCounters(storedRaw?.today);
  const current = countersSnapshot();
  const base = persistedCounters ?? ({} as Partial<CounterMap>);
  const todayStr = utcDay();
  const todayBase = storedDay === todayStr ? storedToday : ({} as Partial<CounterMap>);
  const totals = {} as CounterMap & { upstreamAvgRttMs: number | null };
  const today = {} as CounterMap;
  for (const k of STATS_COUNTER_KEYS) {
    const delta = Math.max(0, (current[k] ?? 0) - (base[k] ?? 0));
    totals[k] = (stored[k] ?? 0) + delta;
    today[k] = (todayBase[k] ?? 0) + delta;
  }
  totals.upstreamAvgRttMs = totals.upstreamOk > 0 ? Math.round(totals.rttSumMs / totals.upstreamOk) : null;
  return { totals, today, day: todayStr };
}

/** Backward-compatible alias used by /admin/api/stats. */
export async function getGlobalStats(
  kv: { get(key: string): Promise<string | null> },
): Promise<CounterMap & { upstreamAvgRttMs: number | null }> {
  return (await getUsageSnapshot(kv)).totals;
}

/**
 * Wrap a KV namespace so every get/put/list/delete is counted into
 * isolateStats. Values sized by (key + value) UTF-16 length — an estimate,
 * good enough for quota dashboards. Install once per isolate (index.ts).
 * Defensive: missing methods (test fakes) pass through uncounted.
 */
export function countKv(kv: KVNamespace): KVNamespace {
  const s = isolateStats;
  const wrapped: Record<string, unknown> = {
    get: async (key: string, opts?: KVNamespaceGetOptions<string>) => {
      s.kvReads += 1;
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const v = await (kv.get as (k: string, o?: unknown) => Promise<unknown>)(key, opts);
      if (typeof v === "string") s.kvReadBytes += key.length + v.length;
      return v;
    },
    put: async (key: string, value: string, opts?: KVNamespacePutOptions) => {
      s.kvWrites += 1;
      s.kvWriteBytes += key.length + value.length;
      return kv.put(key, value, opts);
    },
  };
  if (typeof (kv as { list?: unknown }).list === "function") {
    wrapped.list = async (opts?: KVNamespaceListOptions) => {
      s.kvLists += 1;
      return kv.list(opts);
    };
  }
  if (typeof (kv as { delete?: unknown }).delete === "function") {
    wrapped.delete = async (key: string) => {
      s.kvWrites += 1;
      return kv.delete(key);
    };
  }
  if (typeof (kv as { getWithMetadata?: unknown }).getWithMetadata === "function") {
    wrapped.getWithMetadata = kv.getWithMetadata.bind(kv);
  }
  return wrapped as unknown as KVNamespace;
}
