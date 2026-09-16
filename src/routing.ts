// Upstream candidate selection + failover + racing.
//
// Modes:
//   sequential — try upstreams in priority order.
//   race       — fire the first `raceCount` upstreams (priority order) in
//                parallel; first valid answer wins, losers are aborted.
//   adaptive   — like race, but candidates are ordered by live score
//                (reliability & RTT from metrics) instead of static priority.
//
// Every attempt (winner or loser, success or failure) is recorded so the
// adaptive scores stay honest. raceCount is clamped to 1..4 because each
// racer costs a subrequest and Workers cap those per invocation.

import { MetricsStore, scoreOf } from "./metrics";
import { queryUpstream } from "./upstream";
import type { Config, Upstream } from "./types";

export class AllUpstreamsFailedError extends Error {
  constructor(
    message: string,
    public readonly lastTimedOut: boolean,
    public readonly attempts: UpstreamAttemptRecord[],
  ) {
    super(message);
    this.name = "AllUpstreamsFailedError";
  }
}

export interface UpstreamAttemptRecord {
  id: string;
  ok: boolean;
  rttMs?: number;
  error?: string;
  timedOut?: boolean;
}

export interface RoutingDeps {
  cfg: Config;
  metrics: MetricsStore;
  fetchImpl?: typeof globalThis.fetch;
}

export interface ResolvedAnswer {
  buf: Buffer;
  upstreamId: string;
  rttMs: number;
  answer: import("./dnsmsg").UpstreamAnswer;
  attempts: UpstreamAttemptRecord[];
}

function enabledUpstreams(cfg: Config): Upstream[] {
  return cfg.upstreams.filter((u) => u.enabled);
}

async function orderSequential(cfg: Config): Promise<Upstream[]> {
  return [...enabledUpstreams(cfg)].sort((a, b) => a.priority - b.priority);
}

async function orderAdaptive(cfg: Config, deps: RoutingDeps): Promise<Upstream[]> {
  const list = enabledUpstreams(cfg);
  const scores = await Promise.all(
    list.map(async (u) => ({ u, score: scoreOf(await deps.metrics.get(u.id)) })),
  );
  scores.sort((a, b) => b.score - a.score || a.u.priority - b.u.priority);
  return scores.map((s) => s.u);
}

/**
 * Race the given candidates; first *valid* answer wins and the remaining
 * fetches are aborted so losers don't burn egress until their timeout.
 * Attempts that lose only because a sibling won are NOT recorded as
 * failures — that would poison the adaptive scores.
 */
async function runRace(
  candidates: Upstream[],
  wire: Buffer,
  q: { qname: string; qtype: string; qclass: string; opcode: number },
  deps: RoutingDeps,
  records: UpstreamAttemptRecord[],
): Promise<UpstreamAttemptRecord & { result?: Awaited<ReturnType<typeof queryUpstream>> }> {
  const state = { winner: false };
  const controllers = candidates.map(() => new AbortController());

  // Failed attempts REJECT so Promise.any keeps waiting for the first
  // genuine success instead of resolving with the fastest failure.
  const attempts = candidates.map((upstream, i) => {
    const promise = (async () => {
      const r = await queryUpstream(upstream, wire, q, {
        timeoutMs: upstream.timeout || 2500,
        signal: controllers[i].signal,
        fetchImpl: deps.fetchImpl,
      });
      if (r.ok) {
        if (state.winner) {
          // 竞速败者:两个响应几乎同时到达时,abort() 拦不住已进入微任务
          // 队列的兄弟请求。此处不记账,否则失败者也被算成功,污染评分。
          throw new Error(`upstream ${upstream.id} superseded`);
        }
        state.winner = true;
        for (let j = 0; j < controllers.length; j++) {
          if (j !== i) controllers[j].abort();
        }
        deps.metrics.record(upstream.id, { success: true, rttMs: r.rttMs });
        records.push({ id: upstream.id, ok: true, rttMs: r.rttMs });
        return { id: upstream.id, ok: true as const, rttMs: r.rttMs, result: r };
      }
      if (!state.winner) {
        // Genuine failure, not a lost race.
        deps.metrics.record(upstream.id, { timeout: r.timedOut });
        records.push({ id: upstream.id, ok: false, error: r.error, timedOut: r.timedOut });
      }
      // Superseded or failed: reject so Promise.any keeps waiting.
      throw new Error(`upstream ${upstream.id} failed: ${r.error ?? "superseded"}`);
    })();
    return promise;
  });

  try {
    return await Promise.any(attempts);
  } catch {
    return { id: candidates[0]?.id ?? "?", ok: false, error: "all racers failed" };
  }
}

/** CNAME 链存在但没有查询类型的终结记录 → 上游没答全(如只回 CNAME 不回 AAAA)。
 *  仅对 A/AAAA 生效:其它类型的 NODATA/纯 CNAME 语义各异,不做回退。 */
function isIncompleteAnswer(
  answer: import("./dnsmsg").UpstreamAnswer | undefined,
  qtype: string,
): boolean {
  if (!answer) return false;
  if (qtype !== "A" && qtype !== "AAAA") return false;
  const rs = answer.packet.answers ?? [];
  const hasCname = rs.some((a) => String(a.type) === "CNAME");
  const hasType = rs.some((a) => String(a.type) === qtype);
  return hasCname && !hasType;
}

async function trySequentially(
  candidates: Upstream[],
  wire: Buffer,
  q: { qname: string; qtype: string; qclass: string; opcode: number },
  deps: RoutingDeps,
  records: UpstreamAttemptRecord[],
): Promise<UpstreamAttemptRecord & { result: Awaited<ReturnType<typeof queryUpstream>> }> {
  let last: UpstreamAttemptRecord & { result: Awaited<ReturnType<typeof queryUpstream>> } | null = null;
  for (const upstream of candidates) {
    const r = await queryUpstream(upstream, wire, q, {
      timeoutMs: upstream.timeout || 2500,
      fetchImpl: deps.fetchImpl,
    });
    if (r.ok) {
      deps.metrics.record(upstream.id, { success: true, rttMs: r.rttMs });
      const rec = { id: upstream.id, ok: true, rttMs: r.rttMs, result: r };
      records.push(rec);
      // 应答不完整(CNAME 链无终结记录)且还有候选 → 记账成功但继续找
      // 更完整的应答(如某上游只回 CNAME 不回 AAAA,而其它上游会回)。
      const moreLeft = candidates.indexOf(upstream) < candidates.length - 1;
      if (moreLeft && isIncompleteAnswer(r.answer, q.qtype)) continue;
      return rec;
    }
    deps.metrics.record(upstream.id, { timeout: r.timedOut });
    const rec = { id: upstream.id, ok: false, error: r.error, timedOut: r.timedOut, result: r };
    records.push(rec);
    last = rec;
  }
  return last ?? { id: "?", ok: false, error: "no upstreams", result: { upstreamId: "?", ok: false, error: "no upstreams" } };
}

export async function resolveQuery(
  wire: Buffer,
  q: { qname: string; qtype: string; qclass: string; opcode: number },
  deps: RoutingDeps,
): Promise<ResolvedAnswer> {
  const { cfg } = deps;
  const records: UpstreamAttemptRecord[] = [];
  const mode = cfg.routing.mode;
  const raceCount = Math.min(4, Math.max(1, cfg.routing.raceCount));

  if (enabledUpstreams(cfg).length === 0) {
    throw new AllUpstreamsFailedError("no enabled upstreams", false, records);
  }

  if (mode === "sequential") {
    const ordered = await orderSequential(cfg);
    const win = await trySequentially(ordered, wire, q, deps, records);
    if (win.ok && win.result.answer) {
      return { buf: win.result.buf!, upstreamId: win.id, rttMs: win.rttMs!, answer: win.result.answer, attempts: records };
    }
    throw new AllUpstreamsFailedError("all upstreams failed", Boolean(win.timedOut), records);
  }

  const ordered = mode === "adaptive" ? await orderAdaptive(cfg, deps) : await orderSequential(cfg);
  const racers = ordered.slice(0, raceCount);
  const rest = ordered.slice(raceCount);

  const raceWinner = await runRace(racers, wire, q, deps, records);
  // 竞速胜者应答完整 → 直接返回
  if (raceWinner.ok && raceWinner.result?.answer && !isIncompleteAnswer(raceWinner.result.answer, q.qtype)) {
    return {
      buf: raceWinner.result.buf!,
      upstreamId: raceWinner.id,
      rttMs: raceWinner.rttMs!,
      answer: raceWinner.result.answer,
      attempts: records,
    };
  }

  // Failover over the remaining candidates, in order.
  // 也会兜住"竞速胜者应答不完整(CNAME 链无终结记录)"的情形:此时按顺序
  // 尝试剩余上游,寻找更完整的应答(如 AliDNS 会补出 CF/Google 缺失的 AAAA)。
  if (rest.length > 0) {
    const win = await trySequentially(rest, wire, q, deps, records);
    if (win.ok && win.result.answer && !isIncompleteAnswer(win.result.answer, q.qtype)) {
      return { buf: win.result.buf!, upstreamId: win.id, rttMs: win.rttMs!, answer: win.result.answer, attempts: records };
    }
    // 超时归类统一看全部尝试记录,而不是只看最后一次串行尝试:
    // 否则"竞速超时 + 剩余上游返回错误"会被报成 502(应为 504)。
    throw new AllUpstreamsFailedError("all upstreams failed", records.some((r) => r.timedOut), records);
  }

  // 没有 rest:race 胜者即使不完整也只能用它(总比报错好)
  if (raceWinner.ok && raceWinner.result?.answer) {
    return {
      buf: raceWinner.result.buf!,
      upstreamId: raceWinner.id,
      rttMs: raceWinner.rttMs!,
      answer: raceWinner.result.answer,
      attempts: records,
    };
  }

  const lastTimedOut = records.some((r) => r.timedOut);
  throw new AllUpstreamsFailedError("all upstreams failed", lastTimedOut, records);
}
