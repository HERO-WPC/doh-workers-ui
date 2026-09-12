// Shared test helpers: fake KV, fake Cache API, fake upstream fetch, and
// DNS message builders. Each test file calls loadModules() (fresh module
// registry) so module-level singletons don't leak between suites.

import * as packet from "dns-packet";
import { vi } from "vitest";

export const DOH_CONTENT_TYPE = "application/dns-message";

// ---------------------------------------------------------------------------
// Fresh module registry per test file
// ---------------------------------------------------------------------------

export async function loadModules() {
  vi.resetModules();
  return {
    dnsmsg: await import("../src/dnsmsg"),
    cache: await import("../src/cache"),
    cachekey: await import("../src/cachekey"),
    config: await import("../src/config"),
    metrics: await import("../src/metrics"),
    routing: await import("../src/routing"),
    upstream: await import("../src/upstream"),
    doh: await import("../src/doh"),
    admin: await import("../src/admin"),
    index: await import("../src/index"),
    pathgen: await import("../src/pathgen"),
    auth: await import("../src/auth"),
  };
}

// ---------------------------------------------------------------------------
// Fake KV
// ---------------------------------------------------------------------------

export class FakeKV {
  store = new Map<string, string>();
  failNext = false;

  async get(key: string): Promise<string | null> {
    if (this.failNext) throw new Error("kv down");
    return this.store.get(key) ?? null;
  }
  async put(key: string, value: string): Promise<void> {
    if (this.failNext) throw new Error("kv down");
    this.store.set(key, value);
  }
}

// ---------------------------------------------------------------------------
// Fake Cache API (caches.default)
// ---------------------------------------------------------------------------

export class FakeCacheStorage {
  default = {
    store: new Map<string, { body: ArrayBuffer; headers: Record<string, string> }>(),
    async match(url: URL | string) {
      const hit = this.store.get(String(url));
      if (!hit) return undefined;
      return new Response(hit.body, { headers: hit.headers });
    },
    async put(url: URL | string, res: Response) {
      const body = await res.arrayBuffer();
      const headers: Record<string, string> = {};
      res.headers.forEach((v, k) => (headers[k] = v));
      this.store.set(String(url), { body, headers });
    },
  };
}

export function installCacheApi(fake?: FakeCacheStorage) {
  (globalThis as Record<string, unknown>).caches = fake ?? new FakeCacheStorage();
  return (globalThis as Record<string, unknown>).caches as FakeCacheStorage;
}

// ---------------------------------------------------------------------------
// Fake ctx
// ---------------------------------------------------------------------------

export class FakeCtx {
  promises: Promise<unknown>[] = [];
  waitUntil(p: Promise<unknown>): void {
    this.promises.push(p);
  }
  async settle(): Promise<void> {
    await Promise.allSettled(this.promises.splice(0));
  }
}

// ---------------------------------------------------------------------------
// Fake upstream fetch
// ---------------------------------------------------------------------------

export interface UpstreamCall {
  url: string;
  body: Buffer;
  aborted: boolean;
}

export type UpstreamBehavior =
  | { kind: "answer"; rcode?: number; ttl?: number; ip?: string; delayMs?: number; extraAuthority?: boolean; noRecords?: boolean }
  | { kind: "httpStatus"; status: number }
  | { kind: "garbage" }
  | { kind: "wrongQuestion" }
  | { kind: "hang" };

/** Builds correct DNS responses (echoing question + TXID) for any query. */
export function buildUpstreamResponseBody(queryWire: Buffer, behavior: UpstreamBehavior): Buffer {
  const q = packet.decode(queryWire) as packet.Packet & { questions: { name: string; type: string | number; class: string }[] };
  const question = q.questions[0];
  const rcode = behavior.kind === "answer" ? behavior.rcode ?? 0 : 0;
  const answers: unknown[] = [];
  const authorities: unknown[] = [];
  if (behavior.kind === "answer" && rcode === 0 && !behavior.noRecords) {
    answers.push({
      name: question.name,
      type: question.type,
      ttl: behavior.ttl ?? 300,
      data: addressForType(question.type, behavior.ip ?? "93.184.216.34"),
    });
  }
  if (behavior.kind === "answer" && behavior.extraAuthority) {
    authorities.push({
      name: question.name,
      type: "SOA",
      ttl: 3600,
      data: { mname: "ns1." + question.name, rname: "admin." + question.name, serial: 1, refresh: 2, retry: 3, expire: 4, minimum: 60 },
    });
  }
  if (behavior.kind === "answer" && rcode === 3) {
    authorities.push({
      name: question.name,
      type: "SOA",
      ttl: 1800,
      data: { mname: "ns1." + question.name, rname: "admin." + question.name, serial: 1, refresh: 2, retry: 3, expire: 4, minimum: 60 },
    });
  }
  return packet.encode({
    id: (queryWire[0] << 8) | queryWire[1],
    type: "response",
    flags: 0x8000 | 0x0100 | rcode,
    questions: [{ name: question.name, type: question.type, class: question.class ?? "IN" }],
    answers,
    authorities,
  } as unknown as packet.Packet);
}

function addressForType(type: string | number, ip: string): unknown {
  const t = String(type);
  if (t === "AAAA") return ip === "93.184.216.34" ? "2606:2800:220:1:248:1893:25c8:1946" : ip;
  if (t === "CNAME") return "target.example.com";
  if (t === "TXT") return ["hello world"];
  if (t === "MX") return { preference: 10, exchange: "mail." + "example.com" };
  if (t === "NS") return "ns1.example.com";
  if (t === "SOA") return { mname: "ns1.example.com", rname: "admin.example.com", serial: 1, refresh: 2, retry: 3, expire: 4, minimum: 60 };
  // Opaque RR types (SVCB/HTTPS/unknown) need Buffer rdata.
  if (t.startsWith("UNKNOWN_") || /^\d+$/.test(t)) return Buffer.from([0, 1, 0, 0, 0, 2, 0, 2, 0x68, 0x32]);
  return ip; // A
}

export interface FakeUpstream {
  calls: UpstreamCall[];
  /** Map of URL substring -> behavior. Unmatched URLs answer normally. */
  behaviors: Map<string, UpstreamBehavior>;
  /** URLs to completely ignore (simulate routing black hole -> timeout). */
  hangingUrls: Set<string>;
  fetch: typeof globalThis.fetch;
  abortSignals: Set<AbortSignal>;
}

export function makeFakeUpstream(): FakeUpstream {
  const fake: FakeUpstream = {
    calls: [],
    behaviors: new Map(),
    hangingUrls: new Set(),
    abortSignals: new Set(),
    async fetch(input, init) {
      const url = String(input instanceof Request ? input.url : input);
      const signal = init?.signal;
      if (signal) fake.abortSignals.add(signal);

      const body = Buffer.from((init?.body as Uint8Array) ?? new Uint8Array(0));
      const call: UpstreamCall = { url, body, aborted: false };
      fake.calls.push(call);
      if (signal) {
        signal.addEventListener("abort", () => {
          call.aborted = true;
        });
      }

      const behavior = [...fake.behaviors.entries()].find(([substr]) => url.includes(substr))?.[1] ?? { kind: "answer" } as UpstreamBehavior;
      if (behavior.kind === "hang" || fake.hangingUrls.has(url)) {
        return new Promise((_resolve, reject) => {
          const t = setTimeout(() => reject(new Error("hung too long in fake")), 30_000);
          if (signal) signal.addEventListener("abort", () => { clearTimeout(t); reject(new DOMException("aborted", "AbortError")); });
        });
      }
      const delayMs = behavior.kind === "answer" ? behavior.delayMs ?? 0 : 0;
      if (delayMs > 0) await new Promise((r) => setTimeout(r, delayMs));
      if (signal?.aborted) throw new DOMException("aborted", "AbortError");

      if (behavior.kind === "httpStatus") {
        return new Response("nope", { status: behavior.status });
      }
      if (behavior.kind === "garbage") {
        return new Response(Buffer.from([1, 2, 3]), { status: 200, headers: { "content-type": DOH_CONTENT_TYPE } });
      }
      if (behavior.kind === "wrongQuestion") {
        const wrong = packet.encode({
          id: (body[0] << 8) | body[1],
          type: "response",
          flags: 0x8000,
          questions: [{ name: "totally-different.example", type: "A" }],
          answers: [{ name: "totally-different.example", type: "A", ttl: 60, data: "6.6.6.6" }],
        } as unknown as packet.Packet);
        return new Response(wrong, { status: 200, headers: { "content-type": DOH_CONTENT_TYPE } });
      }
      const respBody = buildUpstreamResponseBody(body, behavior);
      return new Response(respBody, { status: 200, headers: { "content-type": DOH_CONTENT_TYPE } });
    },
  };
  return fake;
}

// ---------------------------------------------------------------------------
// DNS query builders (client side)
// ---------------------------------------------------------------------------

export interface ClientQueryOptions {
  name?: string;
  type?: string;
  txid?: number;
  do?: boolean;
  cd?: boolean;
  ecs?: { family: 1 | 2; sourcePrefixLength: number; ip: string };
}

export function buildClientQuery(opts: ClientQueryOptions = {}): Buffer {
  const additionals: unknown[] = [];
  if (opts.do || opts.ecs) {
    additionals.push({
      name: ".",
      type: "OPT",
      udpPayloadSize: 1232,
      ednsVersion: 0,
      flags: opts.do ? 0x8000 : 0,
      options: opts.ecs ? [{ code: 8, family: opts.ecs.family, sourcePrefixLength: opts.ecs.sourcePrefixLength, ip: opts.ecs.ip }] : [],
    });
  }
  return packet.encode({
    id: opts.txid ?? 0x1234,
    type: "query",
    flags: 0x0100 | (opts.cd ? 0x0010 : 0),
    questions: [{ name: opts.name ?? "example.com", type: opts.type ?? "A" }],
    additionals,
  } as unknown as packet.Packet);
}

export function toBase64Url(buf: Uint8Array): string {
  let binary = "";
  for (let i = 0; i < buf.length; i += 0x8000) {
    binary += String.fromCharCode(...buf.subarray(i, i + 0x8000));
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** Decode a DoH wire response and assert basics. */
export function decodeResponse(buf: ArrayBuffer) {
  return packet.decode(Buffer.from(new Uint8Array(buf))) as packet.Packet & {
    id: number;
    answers: { name: string; type: string | number; ttl: number; data: unknown }[];
    authorities: { name: string; type: string; data: { minimum?: number } }[];
  };
}

// ---------------------------------------------------------------------------
// Test env
// ---------------------------------------------------------------------------

export interface TestEnv {
  CONFIG_KV: KVNamespace;
  ASSETS: { fetch(req: Request): Promise<Response> };
  ADMIN_SECRET: string;
  CONFIG_CACHE_TTL?: string;
}

export function makeEnv(opts: Partial<TestEnv> = {}): TestEnv {
  return {
    CONFIG_KV: new FakeKV() as unknown as KVNamespace,
    ASSETS: {
      async fetch(req: Request) {
        const path = new URL(req.url).pathname;
        if (path === "/" || path === "/index.html") {
          return new Response("<html>webui</html>", { status: 200, headers: { "content-type": "text/html" } });
        }
        return new Response("not found", { status: 404 });
      },
    },
    ADMIN_SECRET: "test-admin-secret",
    ...opts,
  };
}

export function adminHeaders(secret = "test-admin-secret"): Record<string, string> {
  return { authorization: `Bearer ${secret}` };
}
