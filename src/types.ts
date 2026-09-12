// Shared types for the DoH proxy Worker.

export type RoutingMode = "sequential" | "race" | "adaptive";
export type EcsMode = "off" | "auto" | "fixed";

export interface Upstream {
  id: string;
  name: string;
  url: string;
  enabled: boolean;
  /** Lower = tried first. */
  priority: number;
  /** Per-upstream fetch timeout in ms. */
  timeout: number;
}

export interface CacheConfig {
  minTTL: number;
  maxTTL: number;
  staleTTL: number;
  jitterPercent: number;
  /** Max DoH message bytes accepted from clients (GET decoded / POST body). */
  maxBody: number;
}

export interface RoutingConfig {
  mode: RoutingMode;
  raceCount: number;
}

export interface EcsConfig {
  mode: EcsMode;
  ipv4Prefix: number;
  ipv6Prefix: number;
  /** CIDR used when mode === "fixed", e.g. "203.0.113.0/24". */
  fixedSubnet: string;
}

export interface DohConfig {
  /** Full DoH endpoint path, e.g. "/8f7c2d91e43ab67f/dns-query". */
  path: string;
}

export interface Config {
  version: number;
  updatedAt: string;
  doh: DohConfig;
  cache: CacheConfig;
  routing: RoutingConfig;
  ecs: EcsConfig;
  upstreams: Upstream[];
}

export interface ProviderMetrics {
  ok: number;
  fail: number;
  timeout: number;
  /** Exponential moving average of successful round-trip times in ms. */
  rttEmaMs: number | null;
  lastSuccess: string | null;
  lastFailure: string | null;
  updatedAt: string | null;
}

export interface Env {
  CONFIG_KV: KVNamespace;
  ASSETS: Fetcher;
  /** Worker secret; set via `wrangler secret put ADMIN_SECRET`. */
  ADMIN_SECRET: string;
  /** Isolate config cache TTL in seconds (string var). */
  CONFIG_CACHE_TTL?: string;
}

/** Runtime context for waitUntil, kept structural so tests can fake it. */
export interface WorkerCtx {
  waitUntil(promise: Promise<unknown>): void;
}
