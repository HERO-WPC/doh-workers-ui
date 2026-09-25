// Admin API (/admin/api/*).
//
// Every route requires the ADMIN_SECRET bearer token. The WebUI (static
// assets) is public; all state-changing operations happen here and only
// here. No CORS headers are ever emitted from this module — it is
// same-origin by design, unlike the DoH endpoint.

import {
  clearSessionCookie,
  isAdminAuthorized,
  isAdminCookieAuthorized,
  requestIsHttps,
  sessionCookieValue,
} from "./auth";
import { dnsCache } from "./cache";
import {
  CONFIG_KV_KEY,
  getConfig,
  mergeConfigUpdate,
  parseConfig,
  saveConfig,
  validateUpstreamInput,
  validateUpstreamUrl,
} from "./config";
import { decideEcs, testUpstreamUrl } from "./doh";
import { bareContentType, jsonResponse, methodNotAllowed, textResponse, WORKER_VERSION } from "./httputil";
import { ensureStatsClock, getMetricsStore, isolateStats, reliabilityOf, scoreOf, statsSnapshot, uptimeSeconds } from "./metrics";
import { generatePathToken, buildPath } from "./pathgen";
import { parseResolveTestInput, runResolveTest } from "./resolvetest";
import { fetchAccountUsage } from "./usage";
import type { Config, Env, WorkerCtx } from "./types";

export async function handleAdminApi(request: Request, env: Env, ctx: WorkerCtx): Promise<Response> {
  // Accept a bearer token OR a valid session cookie. The cookie is how the
  // server decides whether page loads get the console (see src/index.ts); it
  // is established by any request that authenticates with a bearer token.
  const [bearerOk, cookieOk] = await Promise.all([
    isAdminAuthorized(request, env.ADMIN_SECRET),
    isAdminCookieAuthorized(request, env.ADMIN_SECRET),
  ]);
  if (!bearerOk && !cookieOk) {
    return jsonResponse({ error: "unauthorized" }, 401, { "www-authenticate": 'Bearer realm="admin"' });
  }

  // Logout: clear the session cookie so the next page load gets the login page.
  // Auth is required above so a cross-site request can't clear someone's session.
  const url = new URL(request.url);
  const route = url.pathname.slice("/admin/api".length) || "/";
  const secure = requestIsHttps(request);
  if (route === "/logout") {
    if (request.method !== "POST") return methodNotAllowed("POST");
    return jsonResponse({ ok: true }, 200, { "set-cookie": clearSessionCookie(secure) });
  }

  const res = await handleAdminApiAuthorized(request, env, ctx);
  // A fresh bearer login (no valid cookie yet) establishes the session.
  // Skip it when the request already authenticated via the cookie, so the
  // cookie is not re-sent (and its expiry not refreshed) on every poll.
  if (bearerOk && !cookieOk) return withSessionCookie(res, env.ADMIN_SECRET, secure);
  return res;
}

/** Append the session Set-Cookie header to an existing response. */
function withSessionCookie(res: Response, secret: string, secure: boolean): Response {
  const headers = new Headers(res.headers);
  headers.set("set-cookie", sessionCookieValue(secret, secure));
  return new Response(res.body, { status: res.status, statusText: res.statusText, headers });
}

async function handleAdminApiAuthorized(request: Request, env: Env, ctx: WorkerCtx): Promise<Response> {
  const url = new URL(request.url);
  const route = url.pathname.slice("/admin/api".length) || "/";
  const method = request.method;

  ensureStatsClock();
  const cfg = await getConfig(env);
  const metrics = getMetricsStore(env.CONFIG_KV);

  // ---- config ----
  if (route === "/config") {
    if (method === "GET") {
      return jsonResponse({ config: cfg, dohUrl: `${url.origin}${cfg.doh.path}` });
    }
    if (method === "PUT") {
      const body = await readJson(request);
      if (!body.ok) return body.response;
      const merged = mergeConfigUpdate(cfg, body.value);
      if (!merged.ok) return jsonResponse({ error: merged.error }, 400);
      const saved = await saveConfig(env, merged.config);
      return jsonResponse({ config: saved, dohUrl: `${url.origin}${saved.doh.path}` });
    }
    return methodNotAllowed("GET, PUT");
  }

  // ---- upstreams ----
  if (route === "/upstreams" || route.startsWith("/upstreams/")) {
    const id = route === "/upstreams" ? null : decodeURIComponent(route.slice("/upstreams/".length));

    if (method === "GET" && !id) {
      return jsonResponse({ upstreams: cfg.upstreams });
    }
    if (method === "POST" && !id) {
      const body = await readJson(request);
      if (!body.ok) return body.response;
      const v = validateUpstreamInput(body.value);
      if (!v.ok) return jsonResponse({ error: v.error }, 400);
      if (cfg.upstreams.some((u) => u.id === v.upstream.id)) {
        return jsonResponse({ error: `upstream id "${v.upstream.id}" already exists` }, 409);
      }
      const next: Config = { ...cfg, upstreams: [...cfg.upstreams, v.upstream] };
      const parsed = parseConfig(next);
      if (!parsed.ok) return jsonResponse({ error: parsed.error }, 400);
      const saved = await saveConfig(env, parsed.config);
      return jsonResponse({ upstream: v.upstream, upstreams: saved.upstreams }, 201);
    }
    if (id && (method === "PUT" || method === "DELETE")) {
      const idx = cfg.upstreams.findIndex((u) => u.id === id);
      if (idx < 0) return jsonResponse({ error: `unknown upstream id "${id}"` }, 404);

      if (method === "DELETE") {
        if (cfg.upstreams.length <= 1) {
          return jsonResponse({ error: "at least one upstream must remain" }, 400);
        }
        const next: Config = { ...cfg, upstreams: cfg.upstreams.filter((u) => u.id !== id) };
        const saved = await saveConfig(env, next);
        return jsonResponse({ upstreams: saved.upstreams });
      }

      // PUT: apply allowed field patches, then validate as a whole.
      const body = await readJson(request);
      if (!body.ok) return body.response;
      const patch = body.value as Record<string, unknown>;
      const current = cfg.upstreams[idx];
      const candidate = {
        ...current,
        ...(patch.name !== undefined ? { name: String(patch.name) } : {}),
        ...(patch.url !== undefined ? { url: String(patch.url).trim() } : {}),
        ...(patch.enabled !== undefined ? { enabled: Boolean(patch.enabled) } : {}),
        ...(patch.priority !== undefined ? { priority: Number(patch.priority) } : {}),
        ...(patch.timeout !== undefined ? { timeout: Number(patch.timeout) } : {}),
      };
      const urlError = validateUpstreamUrl(candidate.url);
      if (urlError) return jsonResponse({ error: urlError }, 400);
      const v = validateUpstreamInput(candidate);
      if (!v.ok) return jsonResponse({ error: v.error }, 400);
      // PUT must not silently reassign ids.
      v.upstream.id = current.id;
      const upstreams = [...cfg.upstreams];
      upstreams[idx] = v.upstream;
      const saved = await saveConfig(env, { ...cfg, upstreams });
      return jsonResponse({ upstream: v.upstream, upstreams: saved.upstreams });
    }
    return methodNotAllowed(id ? "PUT, DELETE" : "GET, POST");
  }

  // ---- test upstream ----
  if (route === "/test-upstream") {
    if (method !== "POST") return methodNotAllowed("POST");
    const body = await readJson(request);
    if (!body.ok) return body.response;
    const value = body.value as { id?: unknown; url?: unknown };
    let target: string | null = null;
    if (typeof value.url === "string") {
      const err = validateUpstreamUrl(value.url.trim());
      if (err) return jsonResponse({ error: err }, 400);
      target = value.url.trim();
    } else if (typeof value.id === "string") {
      const u = cfg.upstreams.find((x) => x.id === value.id);
      if (!u) return jsonResponse({ error: `unknown upstream id "${value.id}"` }, 404);
      target = u.url;
    } else {
      return jsonResponse({ error: "provide either id or url" }, 400);
    }
    const result = await testUpstreamUrl(cfg, target);
    return jsonResponse(result);
  }

  // ---- resolve test(自选域名 + 自选上游,查看 A / AAAA 记录) ----
  if (route === "/resolve-test") {
    if (method !== "POST") return methodNotAllowed("POST");
    const body = await readJson(request);
    if (!body.ok) return body.response;
    const parsed = parseResolveTestInput(body.value, cfg);
    if (!parsed.ok) return jsonResponse({ error: parsed.error }, 400);
    // 直连所选上游,刻意绕过本机缓存与路由:结果必须可归因到该服务商。
    // 不写缓存、不记 metrics,所以跑测试不影响评分与 KV 写额度。
    // ECS 按当前配置(off/auto/fixed)由 decideEcs 决定,与线上查询保持一致。
    // 测试面板请求本身不带客户端 ECS,所以 clientEcs 传 null。
    const clientIp = request.headers.get("cf-connecting-ip");
    const ecs = decideEcs(cfg, { clientEcs: null }, clientIp);
    return jsonResponse(await runResolveTest(parsed.input, { ecs }));
  }

  // ---- regenerate path ----
  if (route === "/regenerate-path") {
    if (method !== "POST") return methodNotAllowed("POST");
    const merged = mergeConfigUpdate(cfg, { doh: { path: buildPath(generatePathToken()) } });
    if (!merged.ok) return jsonResponse({ error: merged.error }, 500);
    const saved = await saveConfig(env, merged.config);
    return jsonResponse({ path: saved.doh.path, dohUrl: `${url.origin}${saved.doh.path}` });
  }

  // ---- usage(KV 用量 + Workers 请求量,含免费额度对照) ----
  if (route === "/usage") {
    if (method !== "GET") return methodNotAllowed("GET");
    // 键清单只在 admin 路径上取:一次 LIST,列出 KV 里实际存了什么。
    const keys: string[] = [];
    try {
      let cursor: string | undefined;
      for (;;) {
        const page = await env.CONFIG_KV.list(cursor ? { cursor } : undefined);
        keys.push(...page.keys.map((k) => k.name));
        if (page.list_complete) break;
        cursor = (page as { cursor?: string }).cursor;
        if (!cursor) break;
      }
    } catch {
      // list 失败不阻塞用量展示
    }
    // 实测存储字节数:逐键读回取长度(键少,读额度 10 万/日,可忽略)。
    let storageBytes: number | null = null;
    if (keys.length > 0 && keys.length <= 100) {
      try {
        const values = await Promise.all(keys.map((k) => env.CONFIG_KV.get(k)));
        storageBytes = keys.reduce((n, k, i) => n + k.length + (values[i]?.length ?? 0), 0);
      } catch {
        // 保持 null
      }
    }
    // 官方口径(GraphQL Analytics):配置了账号 token 才可用。
    let accurate:
      | ({ ok: true } & Awaited<ReturnType<typeof fetchAccountUsage>>)
      | { ok: false; error: string }
      | null = null;
    if (env.CF_ACCOUNT_TOKEN && env.CF_ACCOUNT_ID) {
      try {
        const u = await fetchAccountUsage(env.CF_ACCOUNT_TOKEN, env.CF_ACCOUNT_ID, "doh-workers-ui");
        accurate = { ok: true, ...u };
      } catch (e) {
        const msg = e instanceof Error ? e.message : String(e);
        accurate = { ok: false, error: msg || "unknown error" };
      }
    }
    return jsonResponse({
      note: "official numbers via Cloudflare GraphQL Analytics; KV inventory measured live",
      freeTier: { workersPerDay: 100000, kvWritesPerDay: 1000, kvReadsPerDay: 100000 },
      kv: {
        keyCount: keys.length,
        storageBytes,
        keys: keys.sort(),
      },
      accurate,
    });
  }

  // ---- stats ----
  if (route === "/stats") {
    if (method !== "GET") return methodNotAllowed("GET");
    const upstreams = await Promise.all(
      cfg.upstreams.map(async (u) => {
        const m = await metrics.get(u.id);
        return {
          id: u.id,
          name: u.name,
          url: u.url,
          enabled: u.enabled,
          priority: u.priority,
          timeout: u.timeout,
          score: Math.round(scoreOf(m) * 100) / 100,
          reliability: Math.round(reliabilityOf(m) * 10000) / 10000,
          ok: m.ok,
          fail: m.fail,
          timeoutCount: m.timeout,
          rttEmaMs: m.rttEmaMs,
          lastSuccess: m.lastSuccess,
          lastFailure: m.lastFailure,
        };
      }),
    );
    return jsonResponse({
      note: "isolate-local live counters; all-time/official totals live in /usage",
      isolate: statsSnapshot(),
      l1Cache: dnsCache.stats(),
      upstreams,
    });
  }

  // ---- health ----
  if (route === "/health") {
    if (method !== "GET") return methodNotAllowed("GET");
    let kvOk = true;
    try {
      await env.CONFIG_KV.get(CONFIG_KV_KEY, { cacheTtl: 60 });
    } catch {
      kvOk = false;
    }
    const upstreams = cfg.upstreams.map((u) => {
      const m = metrics.snapshot(u.id);
      return {
        id: u.id,
        name: u.name,
        enabled: u.enabled,
        healthy: m ? m.ok >= m.fail + m.timeout : null,
        rttEmaMs: m?.rttEmaMs ?? null,
      };
    });
    return jsonResponse({
      status: kvOk ? "ok" : "degraded",
      version: WORKER_VERSION,
      configVersion: cfg.version,
      configUpdatedAt: cfg.updatedAt,
      kvReachable: kvOk,
      cache: dnsCache.stats(),
      isolate: { requests: isolateStats.requests, uptimeSeconds: uptimeSeconds() },
      upstreams,
    });
  }

  return jsonResponse({ error: "not found" }, 404);
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

type JsonBody =
  | { ok: true; value: unknown }
  | { ok: false; response: Response };

async function readJson(request: Request): Promise<JsonBody> {
  if (bareContentType(request.headers.get("content-type")) !== "application/json") {
    return { ok: false, response: textResponse(415, "content-type must be application/json") };
  }
  try {
    const value = await request.json();
    return { ok: true, value };
  } catch {
    return { ok: false, response: textResponse(400, "request body is not valid JSON") };
  }
}
