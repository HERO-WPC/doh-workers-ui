// Config validation, KV persistence, isolate cache, and path handling.

import { describe, expect, it } from "vitest";
import { loadModules, FakeKV } from "./helpers";
import type { Config, Env } from "../src/types";

const m = await loadModules();
const { parseConfig, mergeConfigUpdate, generateDefaultConfig, getConfig, saveConfig, validateUpstreamUrl } = m.config;
const { generatePathToken, buildPath, normalizeDohPath, isValidDohPath } = m.pathgen;

function env(kv = new FakeKV()): Env {
  return { CONFIG_KV: kv as unknown as Env["CONFIG_KV"], ASSETS: {} as Env["ASSETS"], ADMIN_SECRET: "s" };
}

describe("pathgen", () => {
  it("generates valid high-entropy paths", () => {
    const p1 = buildPath(generatePathToken());
    const p2 = buildPath(generatePathToken());
    expect(isValidDohPath(p1)).toBe(true);
    expect(p1).not.toBe(p2);
    expect(p1).toMatch(/^\/[0-9a-f]{32}\/dns-query$/);
  });

  it("normalizes tokens and full paths", () => {
    expect(normalizeDohPath("abcdef12")).toEqual({ ok: true, path: "/abcdef12/dns-query" });
    expect(normalizeDohPath("/abcdef12/dns-query")).toEqual({ ok: true, path: "/abcdef12/dns-query" });
    expect(normalizeDohPath("bad").ok).toBe(false);
    expect(normalizeDohPath("/dns-query").ok).toBe(false);
  });
});

describe("config validation", () => {
  it("accepts a full valid config", () => {
    const cfg = generateDefaultConfig();
    const r = parseConfig(cfg);
    expect(r.ok).toBe(true);
  });

  it("rejects invalid doh.path", () => {
    const cfg = generateDefaultConfig();
    const r = parseConfig({ ...cfg, doh: { path: "/dns-query" } });
    expect(r.ok).toBe(false);
  });

  it("rejects http:// upstream (SSRF guard)", () => {
    const cfg = generateDefaultConfig();
    cfg.upstreams[0].url = "http://cloudflare-dns.com/dns-query";
    expect(parseConfig(cfg).ok).toBe(false);
  });

  it("rejects non-https schemes and credentials", () => {
    expect(validateUpstreamUrl("ftp://x.com/dns-query")).not.toBeNull();
    expect(validateUpstreamUrl("file:///etc/passwd")).not.toBeNull();
    expect(validateUpstreamUrl("data:text/plain,hi")).not.toBeNull();
    expect(validateUpstreamUrl("https://user:pass@dns.example.com/dns-query")).not.toBeNull();
    expect(validateUpstreamUrl("not a url")).not.toBeNull();
    expect(validateUpstreamUrl("https://dns.example.com/dns-query")).toBeNull();
  });

  it("rejects empty upstream list", () => {
    const cfg = generateDefaultConfig();
    const r = parseConfig({ ...cfg, upstreams: [] });
    expect(r.ok).toBe(false);
  });

  it("clamps TTL bounds sensibly", () => {
    const cfg = generateDefaultConfig();
    const r = parseConfig({ ...cfg, cache: { ...cfg.cache, minTTL: 99999, maxTTL: 2 } }) as { ok: true; config: Config };
    expect(r.ok).toBe(true);
    expect(r.config.cache.minTTL).toBeLessThanOrEqual(86400);
    expect(r.config.cache.maxTTL).toBeGreaterThanOrEqual(r.config.cache.minTTL);
  });

  it("requires a valid CIDR when ecs.mode is fixed", () => {
    const cfg = generateDefaultConfig();
    const bad = parseConfig({ ...cfg, ecs: { ...cfg.ecs, mode: "fixed", fixedSubnet: "not-a-cidr" } });
    expect(bad.ok).toBe(false);
    const good = parseConfig({ ...cfg, ecs: { ...cfg.ecs, mode: "fixed", fixedSubnet: "203.0.113.0/24" } });
    expect(good.ok).toBe(true);
  });
});

describe("mergeConfigUpdate", () => {
  it("merges partial sections", () => {
    const cfg = generateDefaultConfig();
    const r = mergeConfigUpdate(cfg, { cache: { maxTTL: 300 }, routing: { mode: "race" } }) as { ok: true; config: Config };
    expect(r.ok).toBe(true);
    expect(r.config.cache.maxTTL).toBe(300);
    expect(r.config.cache.minTTL).toBe(cfg.cache.minTTL); // untouched
    expect(r.config.routing.mode).toBe("race");
    expect(r.config.routing.raceCount).toBe(cfg.routing.raceCount); // untouched
  });

  it("accepts a bare token as doh.path", () => {
    const cfg = generateDefaultConfig();
    const r = mergeConfigUpdate(cfg, { doh: { path: "my-secret-path-1" } }) as { ok: true; config: Config };
    expect(r.config.doh.path).toBe("/my-secret-path-1/dns-query");
  });

  it("rejects garbage", () => {
    expect(mergeConfigUpdate(generateDefaultConfig(), { cache: { minTTL: "abc" } }).ok).toBe(true); // clamped, not rejected
    expect(mergeConfigUpdate(generateDefaultConfig(), { doh: { path: "short" } }).ok).toBe(false);
  });
});

describe("KV persistence", () => {
  it("initializes KV with defaults + random path on first load", async () => {
    const kv = new FakeKV();
    const cfg = await getConfig(env(kv));
    expect(isValidDohPath(cfg.doh.path)).toBe(true);
    expect(kv.store.has("config")).toBe(true);
  });

  it("round-trips a saved config", async () => {
    const kv = new FakeKV();
    const e = env(kv);
    const initial = await getConfig(e);
    await saveConfig(e, { ...initial, cache: { ...initial.cache, maxTTL: 123 } });
    const reloaded = await getConfig(e, true);
    expect(reloaded.cache.maxTTL).toBe(123);
  });

  it("falls back to defaults on corrupt KV data without crashing", async () => {
    const kv = new FakeKV();
    kv.store.set("config", "{not json");
    const cfg = await getConfig(env(kv));
    expect(isValidDohPath(cfg.doh.path)).toBe(true);
  });

  it("survives a KV outage", async () => {
    const kv = new FakeKV();
    kv.failNext = true;
    const cfg = await getConfig(env(kv));
    expect(isValidDohPath(cfg.doh.path)).toBe(true);
  });
});
