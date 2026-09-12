// Admin API tests: auth enforcement, config/upstream CRUD, path
// regeneration, stats/health, and method/content-type strictness.

import { describe, expect, it } from "vitest";
import { FakeCacheStorage, FakeCtx, installCacheApi, loadModules, makeEnv, makeFakeUpstream, adminHeaders } from "./helpers";
import type { Env } from "../src/types";
import type { TestEnv } from "./helpers";

const m = await loadModules();

async function call(path: string, method = "GET", body?: unknown, opts: { headers?: Record<string, string>; env?: Env | TestEnv } = {}) {
  const e = (opts.env ?? makeEnv()) as unknown as Env;
  // opts.headers fully replaces the default auth header set.
  const headers = { ...(opts.headers ?? adminHeaders()) };
  if (body !== undefined) headers["content-type"] = "application/json";
  const req = new Request(`https://worker.test/admin/api${path}`, {
    method,
    headers,
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });
  const res = await m.admin.handleAdminApi(req, e, new FakeCtx());
  await new Promise((r) => setTimeout(r, 0));
  const json: any = await res.clone().json().catch(() => null);
  return { res, json, env: e };
}

describe("authentication", () => {
  it("rejects missing, wrong, and malformed credentials with 401", async () => {
    const badHeaders: Record<string, string>[] = [{}, { authorization: "Bearer wrong" }, { authorization: "Basic dXNlcjpwYXNz" }, { "x-admin-token": "nope" }];
    for (const headers of badHeaders) {
      const { res } = await call("/config", "GET", undefined, { headers });
      expect(res.status).toBe(401);
    }
  });

  it("accepts the correct bearer token", async () => {
    const { res } = await call("/config");
    expect(res.status).toBe(200);
  });

  it("accepts the correct x-admin-token header", async () => {
    const { res } = await call("/config", "GET", undefined, { headers: { "x-admin-token": "test-admin-secret" } });
    expect(res.status).toBe(200);
  });

  it("never authorizes when the secret is unset", async () => {
    const e = makeEnv();
    e.ADMIN_SECRET = "";
    const { res } = await call("/config", "GET", undefined, { env: e, headers: adminHeaders("") });
    expect(res.status).toBe(401);
  });
});

describe("config endpoints", () => {
  it("GET /config returns config + dohUrl", async () => {
    const { json } = await call("/config");
    expect(json.config.doh.path).toMatch(/\/dns-query$/);
    expect(json.dohUrl).toContain(json.config.doh.path);
  });

  it("PUT /config validates and persists to KV", async () => {
    const { json, env } = await call("/config", "PUT", { cache: { maxTTL: 777 } });
    expect(json.config.cache.maxTTL).toBe(777);
    const stored = JSON.parse((env.CONFIG_KV as unknown as { store: Map<string, string> }).store.get("config")!);
    expect(stored.cache.maxTTL).toBe(777);
  });

  it("PUT /config rejects invalid sections", async () => {
    const { res } = await call("/config", "PUT", { doh: { path: "bad" } });
    expect(res.status).toBe(400);
  });

  it("rejects non-JSON content-type with 415 and bad JSON with 400", async () => {
    const { res: r415 } = await call("/config", "PUT", undefined, { headers: { ...adminHeaders(), "content-type": "text/plain" } });
    expect(r415.status).toBe(415);
    const e = makeEnv() as unknown as Env;
    const req = new Request("https://worker.test/admin/api/config", {
      method: "PUT",
      headers: { ...adminHeaders(), "content-type": "application/json" },
      body: "{not json",
    });
    const res = await m.admin.handleAdminApi(req, e, new FakeCtx());
    expect(res.status).toBe(400);
  });

  it("returns 405 for wrong methods and 404 for unknown routes", async () => {
    const { res: r405 } = await call("/config", "DELETE");
    expect(r405.status).toBe(405);
    const { res: r404 } = await call("/nope");
    expect(r404.status).toBe(404);
  });
});

describe("upstream CRUD", () => {
  it("adds, lists, updates and deletes an upstream", async () => {
    const added = await call("/upstreams", "POST", { name: "AdGuard", url: "https://dns.adguard-dns.com/dns-query", priority: 4 });
    expect(added.res.status).toBe(201);
    const id = added.json.upstream.id;

    const listed = await call("/upstreams");
    expect(listed.json.upstreams.some((u: { id: string }) => u.id === id)).toBe(true);

    const updated = await call(`/upstreams/${id}`, "PUT", { enabled: false });
    expect(updated.json.upstreams.find((u: { id: string }) => u.id === id).enabled).toBe(false);

    const removed = await call(`/upstreams/${id}`, "DELETE");
    expect(removed.res.status).toBe(200);
    expect(removed.json.upstreams.some((u: { id: string }) => u.id === id)).toBe(false);
  });

  it("rejects invalid upstream URLs with 400", async () => {
    const { res } = await call("/upstreams", "POST", { name: "X", url: "http://insecure.example.com/dns-query" });
    expect(res.status).toBe(400);
  });

  it("rejects duplicate ids with 409", async () => {
    const url = "https://dns.example.test/dns-query";
    const first = await call("/upstreams", "POST", { name: "Cloudflare Two", id: "dup", url });
    expect(first.res.status).toBe(201);
    const { res } = await call("/upstreams", "POST", { name: "Cloudflare Three", id: "dup", url });
    expect(res.status).toBe(409);
  });

  it("404s on unknown upstream id", async () => {
    const { res } = await call("/upstreams/nope", "PUT", { enabled: false });
    expect(res.status).toBe(404);
  });

  it("refuses to delete the last upstream", async () => {
    const e = makeEnv() as unknown as Env;
    const cfg = await m.config.getConfig(e);
    const saved = await m.config.saveConfig(e, { ...cfg, upstreams: [cfg.upstreams[0]] });
    expect(saved.upstreams.length).toBe(1);
    const { res } = await call(`/upstreams/${saved.upstreams[0].id}`, "DELETE", undefined, { env: e });
    expect(res.status).toBe(400);
  });
});

describe("test-upstream", () => {
  it("probes by url and reports rtt", async () => {
    installCacheApi(new FakeCacheStorage());
    const fake = makeFakeUpstream();
    const prevFetch = globalThis.fetch;
    (globalThis as unknown as { fetch: unknown }).fetch = fake.fetch;
    try {
      const { json } = await call("/test-upstream", "POST", { url: "https://upstream-test.example/dns-query" });
      expect(json.ok).toBe(true);
      expect(json.rttMs).toBeGreaterThanOrEqual(0);
    } finally {
      (globalThis as unknown as { fetch: unknown }).fetch = prevFetch;
    }
  });

  it("requires id or url", async () => {
    const { res } = await call("/test-upstream", "POST", {});
    expect(res.status).toBe(400);
  });
});

describe("regenerate-path", () => {
  it("generates a new random path and invalidates the old one", async () => {
    const before = await call("/config");
    const oldPath = before.json.config.doh.path;
    const regen = await call("/regenerate-path", "POST", {});
    expect(regen.res.status).toBe(200);
    expect(regen.json.path).toMatch(/^\/[0-9a-f]{32}\/dns-query$/);
    expect(regen.json.path).not.toBe(oldPath);
    expect(regen.json.dohUrl).toContain(regen.json.path);
    const after = await call("/config");
    expect(after.json.config.doh.path).toBe(regen.json.path);
    expect(after.json.config.doh.path).not.toBe(oldPath);
  });
});

describe("stats & health", () => {
  it("GET /stats includes isolate counters and provider metrics", async () => {
    const { json } = await call("/stats");
    expect(json.note).toContain("aggregated");
    expect(json.global.requests).toBeGreaterThanOrEqual(0);
    expect(json.isolate.requests).toBeGreaterThanOrEqual(0);
    expect(json.upstreams.length).toBeGreaterThan(0);
    expect(json.upstreams[0]).toHaveProperty("score");
  });

  it("GET /health reports KV reachability and config version", async () => {
    installCacheApi(new FakeCacheStorage());
    const { json } = await call("/health");
    expect(json.status).toBe("ok");
    expect(json.kvReachable).toBe(true);
    expect(json.configVersion).toBe(1);
  });
});
