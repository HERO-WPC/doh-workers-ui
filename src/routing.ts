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
  if (raceWinner.ok && raceWinner.result?.answer) {
    return {
      buf: raceWinner.result.buf!,
      upstreamId: raceWinner.id,
      rttMs: raceWinner.rttMs!,
      answer: raceWinner.result.answer,
      attempts: records,
    };
  }

  // Failover over the remaining candidates, in order.
  if (rest.length > 0) {
    const win = await trySequentially(rest, wire, q, deps, records);
    if (win.ok && win.result.answer) {
      return { buf: win.result.buf!, upstreamId: win.id, rttMs: win.rttMs!, answer: win.result.answer, attempts: records };
    }
    throw new AllUpstreamsFailedError("all upstreams failed", Boolean(win.timedOut), records);
  }

  const lastTimedOut = records.some((r) => r.timedOut);
  throw new AllUpstreamsFailedError("all upstreams failed", lastTimedOut, records);
}
