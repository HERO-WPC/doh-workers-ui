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

// 30 分钟:KV 免费版限 1000 写/天(账号级)。写入量与流量无关,而与
// "活过 flush 周期的 isolate 个数"成正比;10 分钟时每个 isolate 每天都会写,
// 加上部署/多 colo,实测日均 ~500 写,一度打满额度导致写入全部被拒。
// 放宽到 30 分钟后,短命 isolate 不再产生写入,写量降到 ~1/3。
export const FLUSH_INTERVAL_MS = 1_800_000;

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
  private dirty = false;
  private lastFlush = 0;
  private loaded = false;
  private blobMissing = false;
  private legacyTried = new Set<string>();

  constructor(private kv: { get(key: string): Promise<string | null>; put(key: string, value: string): Promise<void> } | null) {}

  /** 所有上游指标存在同一个 KV key 里(见 flush):一次 flush 只花 1 次写额度。
   *  之前每个上游一个 key,一次 flush 写 4 个,把免费额度(1000 写/天)打到 90%。 */
  private static readonly BLOB_KEY = "metrics";

  private async loadAll(): Promise<void> {
    if (this.loaded || !this.kv) return;
    this.loaded = true;
    try {
      const raw = await this.kv.get(MetricsStore.BLOB_KEY);
      if (raw) {
        const obj = JSON.parse(raw) as Record<string, ProviderMetrics>;
        for (const [id, v] of Object.entries(obj)) {
          if (v && typeof v === "object" && typeof (v as ProviderMetrics).ok === "number") {
            this.mem.set(id, { ...emptyMetrics(), ...v });
          }
        }
        this.blobMissing = false;
      } else {
        // blob 尚不存在(旧版是每个上游一个 key,且可能因写额度打满从未写过
        // 新 blob):标记为缺失,get() 时回读旧 key 找回历史——纯读取零写入。
        this.blobMissing = true;
      }
    } catch {
      this.blobMissing = true;
    }
  }

  /** 旧版单 key 格式(metrics:<id>)的历史回读;成功即并入内存,首次 flush 时
   *  会把合并结果写进新 blob,此后不再回读。 */
  private async loadLegacy(id: string): Promise<void> {
    if (!this.kv || this.legacyTried.has(id)) return;
    this.legacyTried.add(id);
    try {
      const raw = await this.kv.get(`metrics:${id}`);
      if (!raw) return;
      const parsed = JSON.parse(raw) as ProviderMetrics;
      if (parsed && typeof parsed === "object" && typeof parsed.ok === "number") {
        const merged = this.mem.get(id) ?? emptyMetrics();
        this.mem.set(id, { ...merged, ...parsed });
      }
    } catch {
      // 旧 key 不存在或损坏:保持现状
    }
  }

  async get(id: string): Promise<ProviderMetrics> {
    const cached = this.mem.get(id);
    if (cached) return cached;
    await this.loadAll();
    if (this.blobMissing && !this.mem.has(id)) {
      await this.loadLegacy(id);
    }
    const m = this.mem.get(id) ?? emptyMetrics();
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
    this.dirty = true;
  }

  /** Fire-and-forget persistence; call with ctx.waitUntil on each request.
   *  整块写入:一次 flush 只产生 1 次 KV 写。 */
  flush(waitUntil: (p: Promise<unknown>) => void): void {
    if (!this.kv || !this.dirty) return;
    const now = Date.now();
    if (now - this.lastFlush < FLUSH_INTERVAL_MS) return;
    this.lastFlush = now;
    this.dirty = false;
    const blob = JSON.stringify(Object.fromEntries(this.mem));
    waitUntil(
      this.kv.put(MetricsStore.BLOB_KEY, blob).catch(() => {
        this.dirty = true; // 下次请求重试
      }),
    );
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
  };
}
