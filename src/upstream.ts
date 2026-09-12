// Upstream DoH fetch + response validation plumbing.

import * as packet from "dns-packet";
import { DNS_CONTENT_TYPE } from "./httputil";
import {
  DNS_HEADER_SIZE,
  MAX_DNS_MESSAGE_SIZE,
  readU16,
  validateUpstreamResponse,
  type UpstreamAnswer,
} from "./dnsmsg";
import type { Upstream } from "./types";

export type FetchLike = typeof globalThis.fetch;

export interface UpstreamAttemptResult {
  upstreamId: string;
  ok: boolean;
  /** Validated decoded answer (only when ok). */
  answer?: UpstreamAnswer;
  /** Raw wire bytes with our TXID (only when ok). */
  buf?: Buffer;
  rttMs?: number;
  error?: string;
  timedOut?: boolean;
  /** Set when this attempt was aborted because a racing sibling already won. */
  superseded?: boolean;
}

interface QueryContext {
  qname: string;
  qtype: string;
  qclass: string;
  opcode: number;
}

export function makeTimeoutSignal(timeoutMs: number): { signal: AbortSignal; cancel: () => void } {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), Math.max(1, timeoutMs));
  // Don't hold the Workers event loop open past the response.
  if (typeof timer === "object" && timer && "unref" in timer) (timer as unknown as { unref(): void }).unref();
  return { signal: controller.signal, cancel: () => clearTimeout(timer) };
}

/**
 * Send one DNS query to one upstream and validate the response.
 * Transport errors, non-2xx, wrong content-type, oversize bodies and
 * question-mismatched answers all surface as ok=false (never thrown),
 * so the routing layer can treat them uniformly.
 */
export async function queryUpstream(
  upstream: Upstream,
  wire: Buffer,
  q: QueryContext,
  opts: { timeoutMs: number; signal?: AbortSignal; fetchImpl?: FetchLike },
): Promise<UpstreamAttemptResult> {
  const { signal, cancel } = makeTimeoutSignal(opts.timeoutMs);
  const started = Date.now();
  try {
    const external = opts.signal;
    const combined = external
      ? AbortSignal.any([signal, external])
      : signal;
    const doFetch = opts.fetchImpl ?? globalThis.fetch;
    const res = await doFetch(upstream.url, {
      method: "POST",
      headers: {
        "content-type": DNS_CONTENT_TYPE,
        accept: DNS_CONTENT_TYPE,
      },
      body: new Uint8Array(wire),
      signal: combined,
    });

    if (!res.ok) {
      return { upstreamId: upstream.id, ok: false, error: `HTTP ${res.status}` };
    }
    const contentType = (res.headers.get("content-type") ?? "").split(";")[0].trim().toLowerCase();
    if (contentType !== DNS_CONTENT_TYPE) {
      return { upstreamId: upstream.id, ok: false, error: `unexpected content-type: ${contentType || "none"}` };
    }
    const body = await res.arrayBuffer();
    if (body.byteLength < DNS_HEADER_SIZE || body.byteLength > Math.max(MAX_DNS_MESSAGE_SIZE, wire.length)) {
      return { upstreamId: upstream.id, ok: false, error: `invalid response size ${body.byteLength}` };
    }
    const answer = validateUpstreamResponse(readU16(wire, 0), q, body);
    if (!answer) {
      return { upstreamId: upstream.id, ok: false, error: "response failed validation" };
    }
    return {
      upstreamId: upstream.id,
      ok: true,
      answer,
      buf: Buffer.from(new Uint8Array(body)),
      rttMs: Date.now() - started,
    };
  } catch (e) {
    const err = e as Error;
    if (err?.name === "AbortError" || err?.name === "TimeoutError") {
      return { upstreamId: upstream.id, ok: false, timedOut: true, error: "timeout" };
    }
    return { upstreamId: upstream.id, ok: false, error: err?.message || "network error" };
  } finally {
    cancel();
  }
}

export interface ProbeResult {
  ok: boolean;
  rttMs?: number;
  error?: string;
  timedOut?: boolean;
}

/** Probe a single upstream with a real query ("example.com A"). */
export async function probeUpstream(
  upstream: Upstream,
  opts: { timeoutMs: number; fetchImpl?: FetchLike },
): Promise<ProbeResult> {
  const wire = packet.encode({
    id: 0,
    type: "query",
    flags: 0x0100,
    questions: [{ name: "example.com", type: "A", class: "IN" }],
  } as packet.Packet);
  const r = await queryUpstream(upstream, wire, { qname: "example.com", qtype: "A", qclass: "IN", opcode: 0 }, opts);
  if (r.ok) return { ok: true, rttMs: r.rttMs };
  return { ok: false, error: r.error, timedOut: r.timedOut };
}
