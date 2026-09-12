// Configuration: defaults, schema validation, KV persistence and a short
// isolate-memory cache so DNS requests NEVER read KV on the hot path.
//
// Consistency note: KV is eventually consistent. After an admin save, other
// isolates pick up the new config within CONFIG_CACHE_TTL (default 30s) plus
// KV propagation (up to ~60s). This is honest and documented; making it
// "instant" would require KV reads per request, which is exactly the
// anti-pattern this project forbids.

import { generatePathToken, buildPath, isValidDohPath } from "./pathgen";
import { parseFixedSubnet } from "./ecs";
import type { Config, Env, Upstream } from "./types";

export const CONFIG_KV_KEY = "config";
export const CONFIG_VERSION = 1;

export const DEFAULTS: Omit<Config, "doh"> & { doh: { path: string } } = {
  version: CONFIG_VERSION,
  updatedAt: "",
  doh: { path: "" },
  cache: {
    minTTL: 10,
    maxTTL: 600,
    staleTTL: 86400,
    jitterPercent: 10,
    maxBody: 65535,
  },
  routing: { mode: "adaptive", raceCount: 2 },
  ecs: {
    mode: "off",
    ipv4Prefix: 24,
    ipv6Prefix: 56,
    fixedSubnet: "",
  },
  upstreams: [
    { id: "cloudflare", name: "Cloudflare", url: "https://cloudflare-dns.com/dns-query", enabled: true, priority: 1, timeout: 2500 },
    { id: "google", name: "Google", url: "https://dns.google/dns-query", enabled: true, priority: 2, timeout: 2500 },
    { id: "quad9", name: "Quad9", url: "https://dns.quad9.net/dns-query", enabled: true, priority: 3, timeout: 2500 },
  ],
};

export function generateDefaultConfig(): Config {
  return { ...structuredClone(DEFAULTS), doh: { path: buildPath(generatePathToken()) } };
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

export function validateUpstreamUrl(url: string): string | null {
  if (typeof url !== "string" || url.length === 0 || url.length > 2048) return "URL is empty or too long";
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    return "URL is not parseable";
  }
  // SSRF hardening: HTTPS only, no credentials, no exotic schemes.
  if (parsed.protocol !== "https:") return "upstream URL must use https:";
  if (parsed.username || parsed.password) return "upstream URL must not contain credentials";
  if (!parsed.hostname) return "upstream URL has no host";
  return null;
}

function clampInt(v: unknown, min: number, max: number, fallback: number): number {
  const n = typeof v === "number" ? v : typeof v === "string" && v.trim() !== "" ? Number(v) : NaN;
  if (!Number.isFinite(n)) return fallback;
  return Math.min(max, Math.max(min, Math.round(n)));
}

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

export interface ValidatedUpstream {
  ok: true;
  upstream: Upstream;
}
export interface UpstreamError {
  ok: false;
  error: string;
}

export function validateUpstreamInput(input: unknown): ValidatedUpstream | UpstreamError {
  if (!isPlainObject(input)) return { ok: false, error: "upstream must be an object" };
  const name = typeof input.name === "string" ? input.name.trim().slice(0, 64) : "";
  if (!name) return { ok: false, error: "upstream name is required" };
  const url = typeof input.url === "string" ? input.url.trim() : "";
  const urlError = validateUpstreamUrl(url);
  if (urlError) return { ok: false, error: urlError };
  return {
    ok: true,
    upstream: {
      id: typeof input.id === "string" && /^[a-zA-Z0-9_-]{1,64}$/.test(input.id) ? input.id : slugify(name),
      name,
      url,
      enabled: input.enabled === undefined ? true : Boolean(input.enabled),
      priority: clampInt(input.priority, 1, 1000, 100),
      timeout: clampInt(input.timeout, 100, 10000, 2500),
    },
  };
}

function slugify(name: string): string {
  const base = name.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 40);
  const suffix = Math.floor(Math.random() * 0xffff).toString(16).padStart(4, "0");
  return `${base || "upstream"}-${suffix}`;
}

/**
 * Parse & validate a full config object. Invalid sections fall back to
 * defaults field-by-field, so a partially bad config degrades gracefully
 * instead of crashing the Worker.
 */
export function parseConfig(raw: unknown): { ok: true; config: Config } | { ok: false; error: string } {
  if (!isPlainObject(raw)) return { ok: false, error: "config must be an object" };

  const dohIn = isPlainObject(raw.doh) ? raw.doh : {};
  const path = typeof dohIn.path === "string" ? dohIn.path : "";
  if (!isValidDohPath(path)) {
    return { ok: false, error: `invalid doh.path: ${JSON.stringify(path)}` };
  }

  const cacheIn = isPlainObject(raw.cache) ? raw.cache : {};
  const routingIn = isPlainObject(raw.routing) ? raw.routing : {};
  const ecsIn = isPlainObject(raw.ecs) ? raw.ecs : {};

  const mode = routingIn.mode;
  const ecsMode = ecsIn.mode;
  const fixedSubnet = typeof ecsIn.fixedSubnet === "string" ? ecsIn.fixedSubnet.trim() : "";
  if (ecsMode === "fixed" && !parseFixedSubnet(fixedSubnet)) {
    return { ok: false, error: "ecs.fixedSubnet must be a valid CIDR like 203.0.113.0/24 when ecs.mode is fixed" };
  }

  const upstreamsRaw = Array.isArray(raw.upstreams) ? raw.upstreams : null;
  if (!upstreamsRaw || upstreamsRaw.length === 0) {
    return { ok: false, error: "config.upstreams must be a non-empty array" };
  }
  const upstreams: Upstream[] = [];
  const seenIds = new Set<string>();
  for (const item of upstreamsRaw) {
    const v = validateUpstreamInput(item);
    if (!v.ok) return { ok: false, error: `invalid upstream: ${v.error}` };
    if (seenIds.has(v.upstream.id)) return { ok: false, error: `duplicate upstream id: ${v.upstream.id}` };
    seenIds.add(v.upstream.id);
    upstreams.push(v.upstream);
  }

  const config: Config = {
    version: CONFIG_VERSION,
    updatedAt: typeof raw.updatedAt === "string" ? raw.updatedAt : "",
    doh: { path },
    cache: {
      minTTL: clampInt(cacheIn.minTTL, 0, 86400, DEFAULTS.cache.minTTL),
      maxTTL: clampInt(cacheIn.maxTTL, 1, 604800, DEFAULTS.cache.maxTTL),
      staleTTL: clampInt(cacheIn.staleTTL, 0, 604800, DEFAULTS.cache.staleTTL),
      jitterPercent: clampInt(cacheIn.jitterPercent, 0, 50, DEFAULTS.cache.jitterPercent),
      maxBody: clampInt(cacheIn.maxBody, 512, 65535, DEFAULTS.cache.maxBody),
    },
    routing: {
      mode: mode === "sequential" || mode === "race" ? mode : "adaptive",
      raceCount: clampInt(routingIn.raceCount, 1, 4, DEFAULTS.routing.raceCount),
    },
    ecs: {
      mode: ecsMode === "auto" || ecsMode === "fixed" ? ecsMode : "off",
      ipv4Prefix: clampInt(ecsIn.ipv4Prefix, 0, 32, DEFAULTS.ecs.ipv4Prefix),
      ipv6Prefix: clampInt(ecsIn.ipv6Prefix, 0, 128, DEFAULTS.ecs.ipv6Prefix),
      fixedSubnet,
    },
    upstreams,
  };

  // maxTTL must stay >= minTTL.
  if (config.cache.maxTTL < config.cache.minTTL) {
    config.cache.maxTTL = Math.max(config.cache.minTTL, 1);
  }
  return { ok: true, config };
}

/**
 * Merge an admin PATCH/PUT (partial sections) into the current config and
 * revalidate the whole thing.
 */
export function mergeConfigUpdate(current: Config, patch: unknown): { ok: true; config: Config } | { ok: false; error: string } {
  if (!isPlainObject(patch)) return { ok: false, error: "request body must be a JSON object" };
  const merged = structuredClone(current) as unknown as Record<string, unknown>;
  for (const section of ["doh", "cache", "routing", "ecs"] as const) {
    if (patch[section] !== undefined) {
      if (!isPlainObject(patch[section])) return { ok: false, error: `section "${section}" must be an object` };
      merged[section] = { ...(current[section] as unknown as Record<string, unknown>), ...(patch[section] as Record<string, unknown>) };
    }
  }
  // Path may also be provided as a bare token for convenience.
  const dohSection = merged.doh as { path?: unknown };
  if (typeof dohSection.path === "string") {
    const trimmed = dohSection.path.trim();
    dohSection.path = trimmed.startsWith("/") ? trimmed : buildPath(trimmed);
  }
  const parsed = parseConfig(merged);
  if (!parsed.ok) return parsed;
  return { ok: true, config: { ...parsed.config, updatedAt: new Date().toISOString() } };
}

// ---------------------------------------------------------------------------
// Loading & saving (with isolate cache)
// ---------------------------------------------------------------------------

let cachedConfig: { value: Config; at: number } | null = null;

function cacheTtlMs(env: Env): number {
  const sec = Number(env.CONFIG_CACHE_TTL ?? "30");
  return (Number.isFinite(sec) && sec >= 0 ? sec : 30) * 1000;
}

export function peekCachedConfig(): Config | null {
  return cachedConfig?.value ?? null;
}

/** Force the in-isolate cache to a known value (used right after saves). */
export function setCachedConfig(config: Config): void {
  cachedConfig = { value: config, at: Date.now() };
}

export async function getConfig(env: Env, forceReload = false): Promise<Config> {
  if (!forceReload && cachedConfig && Date.now() - cachedConfig.at < cacheTtlMs(env)) {
    return cachedConfig.value;
  }
  try {
    const raw = await env.CONFIG_KV.get(CONFIG_KV_KEY);
    if (raw === null) {
      // First run: initialize with defaults + a fresh random path.
      const config = generateDefaultConfig();
      config.updatedAt = new Date().toISOString();
      await env.CONFIG_KV.put(CONFIG_KV_KEY, JSON.stringify(config));
      setCachedConfig(config);
      return config;
    }
    const parsed = parseConfig(JSON.parse(raw));
    if (!parsed.ok) {
      // Corrupt config: keep serving with defaults rather than crashing.
      const fallback = peekCachedConfig() ?? generateDefaultConfig();
      setCachedConfig(fallback);
      return fallback;
    }
    setCachedConfig(parsed.config);
    return parsed.config;
  } catch {
    // KV outage: prefer the last known config; otherwise defaults.
    const fallback = peekCachedConfig() ?? generateDefaultConfig();
    setCachedConfig(fallback);
    return fallback;
  }
}

export async function saveConfig(env: Env, config: Config): Promise<Config> {
  const toSave: Config = { ...config, version: CONFIG_VERSION, updatedAt: new Date().toISOString() };
  await env.CONFIG_KV.put(CONFIG_KV_KEY, JSON.stringify(toSave));
  setCachedConfig(toSave);
  return toSave;
}
