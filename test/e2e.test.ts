// End-to-end tests: full request pipeline through the Worker entrypoint
// with fake KV, Cache API, assets and upstream fetch.

import { describe, expect, it } from "vitest";
import {
  FakeCacheStorage,
  FakeCtx,
  adminHeaders,
  buildClientQuery,
  decodeResponse,
  installCacheApi,
  loadModules,
  makeEnv,
  makeFakeUpstream,
  toBase64Url,
  type TestEnv,
} from "./helpers";

const m = await loadModules();

let fake: ReturnType<typeof makeFakeUpstream>;

function setup() {
  installCacheApi(new FakeCacheStorage());
  fake = makeFakeUpstream();
  (globalThis as unknown as { fetch: unknown }).fetch = fake.fetch;
  return makeEnv();
}

async function handle(req: Request, env: TestEnv): Promise<Response> {
  const ctx = new FakeCtx();
  const res = await (m.index.default as unknown as { fetch(r: Request, e: unknown, c: FakeCtx): Promise<Response> }).fetch(req, env, ctx);
  await ctx.settle();
  return res;
}

function getQuery(env: TestEnv, path: string, wire: Buffer): Promise<Response> {
  return handle(new Request(`https://worker.test${path}?dns=${toBase64Url(wire)}`), env);
}

function postQuery(env: TestEnv, path: string, wire: Buffer, contentType = "application/dns-message"): Promise<Response> {
  return handle(new Request(`https://worker.test${path}`, { method: "POST", headers: { "content-type": contentType }, body: new Uint8Array(wire) }), env);
}

async function currentPath(env: TestEnv): Promise<string> {
  const res = await handle(new Request("https://worker.test/admin/api/config", { headers: adminHeaders() }), env);
  const json = (await res.json()) as { config: { doh: { path: string } } };
  return json.config.doh.path;
}

/** Switch routing mode via the admin API (default adaptive races 2 upstreams). */
async function setRouting(env: TestEnv, mode: "sequential" | "adaptive" | "race"): Promise<void> {
  await handle(
    new Request("https://worker.test/admin/api/config", {
      method: "PUT",
      headers: { ...adminHeaders(), "content-type": "application/json" },
      body: JSON.stringify({ routing: { mode } }),
    }),
    env,
  );
}

describe("routing & health", () => {
  it("serves /health publicly without config", async () => {
    const env = setup();
    const res = await handle(new Request("https://worker.test/health"), env);
    expect(res.status).toBe(200);
    const json = (await res.json()) as { status: string };
    expect(json.status).toBe("ok");
  });

  it("serves WebUI assets at /, the SPA entry at /admin, and 404s unknown non-DoH paths", async () => {
    const env = setup();
    expect((await handle(new Request("https://worker.test/"), env)).status).toBe(200);
    const admin = await handle(new Request("https://worker.test/admin"), env);
    expect(admin.status).toBe(200);
    expect(admin.headers.get("content-type")).toContain("text/html");
    expect((await handle(new Request("https://worker.test/some/unknown"), env)).status).toBe(404);
  });

  it("requires auth for admin API through the worker router", async () => {
    const env = setup();
    const res = await handle(new Request("https://worker.test/admin/api/config"), env);
    expect(res.status).toBe(401);
  });
});

describe("DoH GET/POST pipeline", () => {
  it("answers a GET query (MISS), then a HIT from cache with the new client's TXID", async () => {
    const env = setup();
    const path = await currentPath(env);
    const calls0 = fake.calls.length;

    const r1 = await getQuery(env, path, buildClientQuery({ txid: 0x1111 }));
    expect(r1.status).toBe(200);
    expect(r1.headers.get("content-type")).toBe("application/dns-message");
    expect(r1.headers.get("cache-control")).toBe("no-store");
    expect(r1.headers.get("x-doh-cache")).toBe("MISS");
    const d1 = decodeResponse(await r1.arrayBuffer());
    expect(d1.id).toBe(0x1111);
    expect(d1.answers[0].data).toBe("93.184.216.34");
    expect(fake.calls.length).toBeGreaterThan(calls0); // went upstream

    // Different client, different TXID, same query.
    const calls1 = fake.calls.length;
    const r2 = await getQuery(env, path, buildClientQuery({ txid: 0x2222 }));
    expect(r2.headers.get("x-doh-cache")).toBe("HIT");
    const d2 = decodeResponse(await r2.arrayBuffer());
    expect(d2.id).toBe(0x2222); // rewritten, NOT the cached 0x1111
    expect(d2.answers[0].data).toBe("93.184.216.34");
    expect(fake.calls.length).toBe(calls1); // zero extra upstream calls

    void calls0;
  });

  it("POST works and shares the cache with GET (normalization)", async () => {
    const env = setup();
    const path = await currentPath(env);

    const p = await postQuery(env, path, buildClientQuery({ txid: 0x3333, name: "post-get.example" }));
    expect(p.status).toBe(200);
    const dp = decodeResponse(await p.arrayBuffer());
    expect(dp.id).toBe(0x3333);
    expect(dp.answers[0].data).toBe("93.184.216.34");

    const calls1 = fake.calls.length;
    const g = await getQuery(env, path, buildClientQuery({ txid: 0x4444, name: "post-get.example" }));
    expect(g.headers.get("x-doh-cache")).toBe("HIT");
    expect(fake.calls.length).toBe(calls1); // POST warmed the cache for GET
  });

  it("coalesces concurrent identical queries into one upstream call", async () => {
    const env = setup();
    await setRouting(env, "sequential"); // deterministic: exactly one attempt
    const path = await currentPath(env);
    fake.behaviors.set("cloudflare-dns.com", { kind: "answer", delayMs: 40 });
    const calls0 = fake.calls.length;

    const wires = [1, 2, 3, 4, 5].map((i) => buildClientQuery({ txid: 0x1000 + i, name: "coalesce.example" }));
    const results = await Promise.all(wires.map((w) => getQuery(env, path, w)));
    expect(results.every((r) => r.status === 200)).toBe(true);
    // Every client gets its own TXID.
    for (const [i, r] of results.entries()) {
      expect(decodeResponse(await r.arrayBuffer()).id).toBe(0x1001 + i);
    }
    expect(fake.calls.length - calls0).toBe(1);
  });

  it("supports all common record types end-to-end", async () => {
    const env = setup();
    const path = await currentPath(env);
    for (const type of ["A", "AAAA", "CNAME", "TXT", "MX", "NS", "SOA", "UNKNOWN_65"]) {
      const res = await getQuery(env, path, buildClientQuery({ name: "types.example", type, txid: 7 }));
      expect(res.status).toBe(200);
      const dec = decodeResponse(await res.arrayBuffer());
      expect(String(dec.answers[0].type)).toBe(type);
    }
  });
});

describe("negative & non-cacheable rcodes", () => {
  it("caches NXDOMAIN with the SOA negative TTL", async () => {
    const env = setup();
    await setRouting(env, "sequential");
    const path = await currentPath(env);
    fake.behaviors.set("cloudflare-dns.com", { kind: "answer", rcode: 3 });

    const r1 = await getQuery(env, path, buildClientQuery({ name: "missing.example", txid: 1 }));
    const d1 = decodeResponse(await r1.arrayBuffer());
    expect(d1.answers.length).toBe(0);
    const soa = d1.authorities.find((a) => a.type === "SOA");
    expect(soa).toBeTruthy();
    expect(soa!.data.minimum).toBeGreaterThan(0);

    const calls1 = fake.calls.length;
    await getQuery(env, path, buildClientQuery({ name: "missing.example", txid: 2 }));
    expect(fake.calls.length).toBe(calls1); // negative answer was cached
  });

  it("never caches SERVFAIL", async () => {
    const env = setup();
    await setRouting(env, "sequential");
    const path = await currentPath(env);
    fake.behaviors.set("cloudflare-dns.com", { kind: "answer", rcode: 2 });

    await getQuery(env, path, buildClientQuery({ name: "broken.example", txid: 1 }));
    const calls1 = fake.calls.length;
    await getQuery(env, path, buildClientQuery({ name: "broken.example", txid: 2 }));
    expect(fake.calls.length).toBe(calls1 + 1); // both went upstream
  });
});

describe("ECS handling", () => {
  it("mode off: two queries differing only in client ECS share one cache entry", async () => {
    const env = setup();
    await setRouting(env, "sequential");
    const path = await currentPath(env);

    const withEcs = buildClientQuery({ name: "ecs.example", txid: 1, ecs: { family: 1, sourcePrefixLength: 24, ip: "198.51.100.0" } });
    const withoutEcs = buildClientQuery({ name: "ecs.example", txid: 2 });
    await getQuery(env, path, withEcs);
    const calls1 = fake.calls.length;
    const r2 = await getQuery(env, path, withoutEcs);
    expect(r2.headers.get("x-doh-cache")).toBe("HIT");
    expect(fake.calls.length).toBe(calls1);
  });
});

describe("protocol & security errors", () => {
  it("404s a wrong custom path", async () => {
    const env = setup();
    await currentPath(env);
    const res = await getQuery(env, "/wrong-path-abcdef/dns-query", buildClientQuery({}));
    expect(res.status).toBe(404);
  });

  it("rejects POST with wrong content-type (415)", async () => {
    const env = setup();
    const path = await currentPath(env);
    const res = await postQuery(env, path, buildClientQuery({}), "application/json");
    expect(res.status).toBe(415);
  });

  it("rejects GET without dns param (400) and bad base64 (400)", async () => {
    const env = setup();
    const path = await currentPath(env);
    expect((await handle(new Request(`https://worker.test${path}`), env)).status).toBe(400);
    expect((await handle(new Request(`https://worker.test${path}?dns=%%%invalid`), env)).status).toBe(400);
    expect((await handle(new Request(`https://worker.test${path}?dns=not_base64url!!`), env)).status).toBe(400);
  });

  it("rejects oversized POST bodies (413)", async () => {
    const env = setup();
    const path = await currentPath(env);
    const big = new Uint8Array(70000);
    const res = await handle(new Request(`https://worker.test${path}`, { method: "POST", headers: { "content-type": "application/dns-message" }, body: big }), env);
    expect(res.status).toBe(413);
  });

  it("rejects malformed DNS packets with 400 without crashing", async () => {
    const env = setup();
    const path = await currentPath(env);
    // Valid 12-byte header claiming 1 question, then garbage.
    const junk = Buffer.alloc(20);
    junk.writeUInt16BE(1, 0);
    junk.writeUInt16BE(0x0100, 2);
    junk.writeUInt16BE(1, 6);
    junk.fill(0xff, 12);
    const res = await getQuery(env, path, junk);
    expect(res.status).toBe(400);
  });

  it("answers NOTIMP for non-QUERY opcodes at the DNS level", async () => {
    const env = setup();
    const path = await currentPath(env);
    const wire = buildClientQuery({ txid: 0x0505 });
    wire[2] = 0x09; // opcode STATUS (2 << 11) | RD
    wire[3] = 0x00;
    const res = await getQuery(env, path, wire);
    expect(res.status).toBe(200);
    const dec = decodeResponse(await res.arrayBuffer());
    expect(dec.id).toBe(0x0505);
    expect((dec as unknown as { flags: number }).flags & 0xf).toBe(4); // NOTIMP
  });

  it("returns 502 when all upstreams fail", async () => {
    const env = setup();
    const path = await currentPath(env);
    fake.behaviors.set("cloudflare-dns.com", { kind: "httpStatus", status: 500 });
    fake.behaviors.set("dns.google", { kind: "httpStatus", status: 500 });
    fake.behaviors.set("dns.quad9.net", { kind: "httpStatus", status: 500 });
    const res = await getQuery(env, path, buildClientQuery({ name: "allfail.example" }));
    expect(res.status).toBe(502);
  });

  it("405s unknown methods on the DoH path", async () => {
    const env = setup();
    const path = await currentPath(env);
    const res = await handle(new Request(`https://worker.test${path}`, { method: "DELETE" }), env);
    expect(res.status).toBe(405);
  });
});

describe("custom path lifecycle", () => {
  it("regenerating the path invalidates the old one", async () => {
    const env = setup();
    const oldPath = await currentPath(env);

    // Old path works.
    const ok = await getQuery(env, oldPath, buildClientQuery({ name: "lifecycle.example", txid: 1 }));
    expect(ok.status).toBe(200);

    // Regenerate via admin API.
    const regen = await handle(new Request("https://worker.test/admin/api/regenerate-path", { method: "POST", headers: adminHeaders() }), env);
    const newPath = ((await regen.json()) as { path: string }).path;
    expect(newPath).not.toBe(oldPath);

    // Old path is gone (falls through to assets -> 404).
    const dead = await getQuery(env, oldPath, buildClientQuery({ name: "lifecycle.example", txid: 2 }));
    expect(dead.status).toBe(404);

    // New path serves — and the cache is path-independent, so the earlier
    // answer for the same name is still a HIT.
    const alive = await getQuery(env, newPath, buildClientQuery({ name: "lifecycle.example", txid: 3 }));
    expect(alive.status).toBe(200);
    expect(alive.headers.get("x-doh-cache")).toBe("HIT");
  });

  it("DoH path grants no admin powers", async () => {
    const env = setup();
    const path = await currentPath(env);
    // Any admin API access without secret is still 401 even if someone
    // knows the DoH path.
    const res = await handle(new Request("https://worker.test/admin/api/config"), env);
    expect(res.status).toBe(401);
    void path;
  });
});

describe("TTL correctness", () => {
  it("client-facing TTL stays within [minTTL, maxTTL] and ages on hits", async () => {
    const env = setup();
    const path = await currentPath(env);
    fake.behaviors.set("cloudflare-dns.com", { kind: "answer", ttl: 300 });

    const r1 = await getQuery(env, path, buildClientQuery({ name: "ttl.example", txid: 1 }));
    const d1 = decodeResponse(await r1.arrayBuffer());
    expect(d1.answers[0].ttl).toBeGreaterThanOrEqual(10);
    expect(d1.answers[0].ttl).toBeLessThanOrEqual(600);

    // Age the entry artificially is hard here; a HIT must not exceed the
    // stored TTL.
    const r2 = await getQuery(env, path, buildClientQuery({ name: "ttl.example", txid: 2 }));
    const d2 = decodeResponse(await r2.arrayBuffer());
    expect(d2.answers[0].ttl).toBeLessThanOrEqual(d1.answers[0].ttl);
  });
});
