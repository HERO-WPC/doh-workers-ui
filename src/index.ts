// Worker entry point + router.
//
// Route order matters:
//   1. /health            — public liveness (no config, no KV)
//   2. /admin/api/*       — authenticated management API
//   3. /<custom-path>     — the DoH endpoint (config-driven)
//   4. console entry      — /, /index.html, /admin: serve the console only to
//                           a valid session cookie, otherwise a thin login page
//   5. everything else    — Workers Static Assets (public login/code assets)
//
// The DoH path and the admin surface are fully separated: knowing the DoH
// path grants no administrative power, and admin auth never touches DoH.

import { handleAdminApi } from "./admin";
import { isAdminCookieAuthorized } from "./auth";
import { handleDohRequest } from "./doh";
import { getConfig } from "./config";
import { jsonResponse, methodNotAllowed, textResponse, WORKER_VERSION } from "./httputil";
import type { Env } from "./types";

/** Paths that serve the console (or, when unauthenticated, the login page). */
const CONSOLE_ENTRY_PATHS = new Set(["/", "/index.html", "/admin", "/admin/"]);

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    try {
      const url = new URL(request.url);
      const path = url.pathname;

      if (path === "/health") {
        if (request.method !== "GET" && request.method !== "HEAD") {
          return methodNotAllowed("GET, HEAD");
        }
        return jsonResponse({ status: "ok", version: WORKER_VERSION, time: new Date().toISOString() });
      }

      if (path === "/admin/api" || path.startsWith("/admin/api/")) {
        return handleAdminApi(request, env, ctx);
      }

      const cfg = await getConfig(env);

      if (path === cfg.doh.path) {
        return handleDohRequest(request, env, cfg, ctx);
      }

      // WebUI static assets. Unknown paths must produce real 404s — the
      // custom DoH path must be indistinguishable from any junk path.
      //
      // Console entry paths (/, /index.html, /admin, /admin/) are gated
      // server-side: only a valid session cookie gets the real console HTML,
      // everyone else gets a thin login page. This is physical isolation,
      // not a JS visual trick — an unauthenticated curl sees no console DOM.
      //
      // These entry documents vary by auth state, so they must not be cached:
      // the login page at "/" and the console at "/" share a URL and differ
      // only by cookie. Force no-store and strip conditional headers so the
      // browser never serves a stale login page after a successful login.
      if (request.method === "GET" || request.method === "HEAD") {
        if (CONSOLE_ENTRY_PATHS.has(path)) {
          const authorized = await isAdminCookieAuthorized(request, env.ADMIN_SECRET);
          const entry = authorized ? "/index.html" : "/login.html";
          const target = new Request(new URL(entry, url), {
            method: request.method,
            headers: Object.fromEntries(
              [...request.headers.entries()].filter(([k]) => k !== "if-none-match" && k !== "if-modified-since"),
            ),
          });
          const asset = await env.ASSETS.fetch(target);
          const headers = new Headers(asset.headers);
          headers.set("cache-control", "no-store");
          return new Response(asset.body, { status: asset.status, statusText: asset.statusText, headers });
        }
        const asset = await env.ASSETS.fetch(request);
        return asset;
      }

      return textResponse(404, "Not Found");
    } catch (e) {
      // Last-resort guard: malformed input must never crash the Worker.
      console.error("unhandled worker error:", e);
      return textResponse(500, "internal error");
    }
  },
} satisfies ExportedHandler<Env>;
