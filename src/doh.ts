// The DoH request pipeline (RFC 8484).
//
// GET /<custom-path>/dns-query?dns=<base64url>  and
// POST /<custom-path>/dns-query (application/dns-message)
// both land here and share one normalized pipeline:
//
//   parse -> normalize -> ECS policy -> cache key (SHA-256)
//     -> L1/L2 lookup -> (stale? serve + background refresh)
//     -> single-flight -> upstream routing -> validate
//     -> TTL clamp+jitter -> cache write (waitUntil) -> response
//
// Cached entries are stored with TXID=0; every response is rewritten with
// the requesting client's TXID and aged TTLs before it leaves the Worker.

import { dnsCache } from "./cache";
import { cacheKeyUrl, jitterFactor } from "./cachekey";
import {
  buildReply,
  buildUpstreamQuery,
  DnsMessageError,
  forCache,
  materializeForClient,
  parseClientQuery,
  RCODE_NOTIMP,
  withTxid,
  type ParsedClientQuery,
} from "./dnsmsg";
import { deriveEcsFromIp, parseFixedSubnet, withPrefix, type EcsSpec } from "./ecs";
import { DNS_CONTENT_TYPE, DOH_CORS_HEADERS, bareContentType, jsonResponse, textResponse } from "./httputil";
import { buildQueryFromName, normalizeQType, validateQueryName, wantsJson, wireToJson } from "./jsonapi";
import { ensureStatsClock, flushStats, getMetricsStore, isolateStats } from "./metrics";
import { AllUpstreamsFailedError, resolveQuery } from "./routing";
import { probeUpstream } from "./upstream";
import type { Config, Env, WorkerCtx } from "./types";

// ---------------------------------------------------------------------------
// Module-scoped, isolate-local state (all opportunistic by design).
// ---------------------------------------------------------------------------

/** In-flight upstream resolutions keyed by cache-key URL (single-flight). */
const inflight = new Map<string, Promise<InflightOutcome>>();

function getMetrics(env: Env) {
  return getMetricsStore(env.CONFIG_KV);
}

/** Provider metrics + 全局统计一次性节流刷写(均走 waitUntil,不阻塞响应)。 */
function flushTelemetry(env: Env, ctx: WorkerCtx): void {
  const waitUntil = (p: Promise<unknown>) => ctx.waitUntil(p);
  getMetrics(env).flush(waitUntil);
  flushStats(env.CONFIG_KV, waitUntil);
}

interface InflightOutcome {
  /** Response wire message with TXID=0 (cacheable entries only). */
  buf: Buffer;
  /** Raw upstream wire buffer (any rcode) with our random TXID. */
  upstreamBuf: Buffer;
  rcode: number;
  cacheable: boolean;
  upstreamId: string | null;
}

// ---------------------------------------------------------------------------
// Input decoding
// ---------------------------------------------------------------------------

const BASE64_RE = /^[A-Za-z0-9+/\-_]*={0,2}$/;

function decodeBase64UrlParam(value: string): Uint8Array | null {
  if (!value || !BASE64_RE.test(value) || value.length % 4 === 1) return null;
  const std = value.replace(/-/g, "+").replace(/_/g, "/");
  const padded = std + "=".repeat((4 - (std.length % 4)) % 4);
  return new Uint8Array(Buffer.from(padded, "base64"));
}

/** Extract the raw DNS message from a GET (dns=/name= param) or POST (body). */
async function extractDohInput(request: Request, cfg: Config): Promise<{ ok: true; wire: Uint8Array; json: boolean } | { ok: false; response: Response }> {
  const maxBody = cfg.cache.maxBody;

  if (request.method === "GET") {
    const url = new URL(request.url);
    const dnsParam = url.searchParams.get("dns");
    if (!dnsParam) {
      // Human-friendly surface: ?name=example.com&type=A (Cloudflare-style).
      // The base64url ?dns= form stays the primary, RFC 8484-compliant path.
      const name = url.searchParams.get("name");
      if (name) {
        const nameError = validateQueryName(name);
        if (nameError) {
          return { ok: false, response: textResponse(400, `invalid name parameter: ${nameError}`) };
        }
        const qtype = normalizeQType(url.searchParams.get("type"));
        if (!qtype) {
          return { ok: false, response: textResponse(400, "unsupported type parameter") };
        }
        const cdRaw = url.searchParams.get("cd");
        const cd = cdRaw === "1" || cdRaw === "true";
        return {
          ok: true,
          wire: buildQueryFromName({ name, type: qtype, cd }),
          json: wantsJson(request.headers.get("accept"), url.searchParams.get("ct")),
        };
      }
      return { ok: false, response: textResponse(400, "missing dns query parameter (or use ?name=&type=)") };
    }
    // base64url of maxBody bytes is ~maxBody*4/3 chars.
    if (dnsParam.length > Math.ceil((maxBody / 3) * 4) + 4) {
      return { ok: false, response: textResponse(413, "DNS message too large") };
    }
    const wire = decodeBase64UrlParam(dnsParam);
    if (!wire) {
      return { ok: false, response: textResponse(400, "invalid base64url encoding in dns parameter") };
    }
    if (wire.length > maxBody) {
      return { ok: false, response: textResponse(413, "DNS message too large") };
    }
    return { ok: true, wire, json: false };
  }

  // POST
  if (bareContentType(request.headers.get("content-type")) !== DNS_CONTENT_TYPE) {
    return { ok: false, response: textResponse(415, "content-type must be application/dns-message") };
  }
  const body = await request.arrayBuffer();
  if (body.byteLength === 0) {
    return { ok: false, response: textResponse(400, "empty request body") };
  }
  if (body.byteLength > maxBody) {
    return { ok: false, response: textResponse(413, "DNS message too large") };
  }
  return { ok: true, wire: new Uint8Array(body), json: false };
}

// ---------------------------------------------------------------------------
// ECS policy
// ---------------------------------------------------------------------------

export function decideEcs(cfg: Config, q: ParsedClientQuery, clientIp: string | null): EcsSpec | null {
  switch (cfg.ecs.mode) {
    case "off":
      return null;
    case "fixed":
      return parseFixedSubnet(cfg.ecs.fixedSubnet);
    case "auto": {
      if (q.clientEcs) {
        // Clamp a client-provided prefix to at most our configured
        // granularity so cache keys stay coarse.
        const max = q.clientEcs.family === 1 ? cfg.ecs.ipv4Prefix : cfg.ecs.ipv6Prefix;
        return withPrefix(q.clientEcs, max) ?? q.clientEcs;
      }
      return clientIp ? deriveEcsFromIp(clientIp, cfg.ecs) : null;
    }
  }
}

// ---------------------------------------------------------------------------
// TTL & storage policy
// ---------------------------------------------------------------------------

/** Effective storage TTL: clamp to [minTTL, maxTTL], then deterministic jitter. */
export function computeStoreTtl(
  rcode: number,
  ttlSeconds: number | null,
  cacheCfg: Config["cache"],
  keyHex: string,
): number | null {
  // SERVFAIL/REFUSED/FORMERR/NOTIMP are never cached.
  if (rcode !== 0 && rcode !== 3) return null;
  let ttl = ttlSeconds ?? 0;
  ttl = Math.min(cacheCfg.maxTTL, Math.max(cacheCfg.minTTL, ttl));
  ttl = Math.round(ttl * jitterFactor(keyHex, cacheCfg.jitterPercent));
  // Never store something that expires instantly; re-clamp after jitter.
  return Math.min(cacheCfg.maxTTL, Math.max(1, cacheCfg.minTTL, ttl));
}

// ---------------------------------------------------------------------------
// Resolution (single-flight + upstream + cache write)
// ---------------------------------------------------------------------------

function resolveAndStore(
  env: Env,
  cfg: Config,
  ctx: WorkerCtx,
  keyUrl: URL,
  keyHex: string,
  q: ParsedClientQuery,
  ecs: EcsSpec | null,
): Promise<InflightOutcome> {
  const metrics = getMetrics(env);
  const wire = buildUpstreamQuery(q, ecs);

  return resolveQuery(wire, { qname: q.qname, qtype: q.qtype, qclass: q.qclass, opcode: q.opcode }, { cfg, metrics }).then(
    (resolved) => {
      isolateStats.upstreamOk += 1;
      isolateStats.rttSumMs += resolved.rttMs;
      const answer = resolved.answer;
      const storeTtl = computeStoreTtl(answer.rcode, answer.ttlSeconds, cfg.cache, keyHex);
      const cacheable = storeTtl !== null;
      if (cacheable) {
        const body0 = forCache(answer.packet);
        ctx.waitUntil(dnsCache.put(keyUrl, body0, storeTtl!, storeTtl! + cfg.cache.staleTTL));
      }
      return {
        buf: forCache({ ...answer.packet, id: 0 }),
        upstreamBuf: resolved.buf,
        rcode: answer.rcode,
        cacheable,
        upstreamId: resolved.upstreamId,
      };
    },
    (e: unknown) => {
      if (e instanceof AllUpstreamsFailedError) {
        if (e.attempts.length === 0) isolateStats.upstreamFail += 1;
        for (const attempt of e.attempts) {
          if (!attempt.ok) {
            isolateStats.upstreamFail += 1;
            if (attempt.timedOut) isolateStats.upstreamTimeouts += 1;
          }
        }
      } else {
        isolateStats.upstreamFail += 1;
      }
      throw e;
    },
  );
}

function getOrCreateInflight(key: string, factory: () => Promise<InflightOutcome>): Promise<InflightOutcome> {
  const existing = inflight.get(key);
  if (existing) return existing;
  const p = factory().finally(() => {
    inflight.delete(key);
  });
  inflight.set(key, p);
  return p;
}

// ---------------------------------------------------------------------------
// Response building
// ---------------------------------------------------------------------------

function dnsOkResponse(body: Uint8Array, cacheStatus: string, upstreamId: string | null): Response {
  return new Response(body, {
    status: 200,
    headers: {
      "content-type": DNS_CONTENT_TYPE,
      // We manage caching ourselves (L1/L2); intermediaries must not.
      "cache-control": "no-store",
      "x-doh-cache": cacheStatus,
      ...(upstreamId ? { "x-doh-upstream": upstreamId } : {}),
      ...DOH_CORS_HEADERS,
    },
  });
}

/** Serve a cached TXID=0 message to a specific client (TXID + TTL aging). */
function serveCached(cached: Buffer, q: ParsedClientQuery, ageSeconds: number, status: string, upstreamId: string | null): Response {
  const body = ageSeconds > 0 ? materializeForClient(cached, q.txid, ageSeconds) : withTxid(cached, q.txid);
  return dnsOkResponse(body, status, upstreamId);
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

/**
 * DoH entry point. Wireformat requests (`?dns=` / POST) go straight through;
 * human-friendly GETs (`?name=&type=`) get a JSON body when the client asks
 * for it via Accept or `ct=application/dns-json`, wireformat otherwise.
 */
export async function handleDohRequest(request: Request, env: Env, cfg: Config, ctx: WorkerCtx): Promise<Response> {
  const response = await handleDohWireRequest(request, env, cfg, ctx);
  if (
    request.method === "GET" &&
    response.headers.get("content-type") === DNS_CONTENT_TYPE &&
    (response.status === 200 || response.status === 203)
  ) {
    const url = new URL(request.url);
    if (!url.searchParams.get("dns") && url.searchParams.get("name") &&
        wantsJson(request.headers.get("accept"), url.searchParams.get("ct"))) {
      const wire = new Uint8Array(await response.arrayBuffer());
      const json = wireToJson(wire, response.headers.get("x-doh-cache"));
      return jsonResponse(json, 200, DOH_CORS_HEADERS);
    }
  }
  return response;
}

async function handleDohWireRequest(request: Request, env: Env, cfg: Config, ctx: WorkerCtx): Promise<Response> {
  if (request.method === "OPTIONS") {
    return new Response(null, { status: 204, headers: DOH_CORS_HEADERS });
  }
  if (request.method !== "GET" && request.method !== "POST") {
    return textResponse(405, "Method Not Allowed", { allow: "GET, POST, OPTIONS" });
  }

  isolateStats.requests += 1;
  ensureStatsClock();

  const extracted = await extractDohInput(request, cfg);
  if (!extracted.ok) return extracted.response;

  let q: ParsedClientQuery;
  try {
    q = parseClientQuery(extracted.wire);
  } catch (e) {
    if (e instanceof DnsMessageError) {
      return textResponse(400, `malformed DNS query: ${e.message}`, DOH_CORS_HEADERS);
    }
    throw e;
  }

  // Only standard queries are supported; answer NOTIMP at the DNS level.
  if (q.opcode !== 0) {
    return dnsOkResponse(buildReply(q.txid, q.opcode, RCODE_NOTIMP, q.qname, q.qtype, q.qclass), "NOTIMP", null);
  }

  const clientIp = request.headers.get("cf-connecting-ip");
  const ecs = decideEcs(cfg, q, clientIp);

  const keyUrl = await cacheKeyUrl({
    qnameLower: q.qnameLower,
    qtype: q.qtype,
    qclass: q.qclass,
    do: q.do,
    cd: q.cd,
    ecs,
  });
  const keyHex = keyUrl.pathname.split("/").pop() ?? "";

  const lookup = await dnsCache.get(keyUrl);
  if (lookup && lookup.status === "fresh") {
    isolateStats.cacheHits += 1;
    flushTelemetry(env, ctx);
    return serveCached(lookup.body, q, lookup.ageSeconds, "HIT", null);
  }

  const refreshPromise = getOrCreateInflight(keyUrl.toString(), () => resolveAndStore(env, cfg, ctx, keyUrl, keyHex, q, ecs));

  if (lookup && lookup.status === "stale") {
    // Serve stale immediately; the shared refresh runs in the background.
    isolateStats.cacheStale += 1;
    ctx.waitUntil(refreshPromise.catch(() => {}));
    flushTelemetry(env, ctx);
    return serveCached(lookup.body, q, lookup.ageSeconds, "STALE", null);
  }

  isolateStats.cacheMisses += 1;
  flushTelemetry(env, ctx);

  try {
    const outcome = await refreshPromise;
    if (outcome.cacheable) {
      return serveCached(outcome.buf, q, 0, "MISS", outcome.upstreamId);
    }
    // Non-cacheable rcodes (SERVFAIL etc.): pass the validated upstream
    // answer through with the client's TXID; nothing enters the cache.
    return dnsOkResponse(withTxid(outcome.upstreamBuf, q.txid), "UPSTREAM", outcome.upstreamId);
  } catch (e) {
    if (e instanceof AllUpstreamsFailedError) {
      return textResponse(e.lastTimedOut ? 504 : 502, "all upstreams failed", DOH_CORS_HEADERS);
    }
    return textResponse(500, "internal error", DOH_CORS_HEADERS);
  }
}

/** Probe an arbitrary upstream URL (admin "test upstream" endpoint). */
export function testUpstreamUrl(cfg: Config, url: string): Promise<{ ok: boolean; rttMs?: number; error?: string; timedOut?: boolean }> {
  return probeUpstream({ id: "probe", name: "probe", url, enabled: true, priority: 1, timeout: 2500 }, { timeoutMs: 3000 });
}
