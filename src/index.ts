// Worker entry point + router.
//
// Route order matters:
//   1. /health            — public liveness (no config, no KV)
//   2. /admin/api/*       — authenticated management API
//   3. /<custom-path>     — the DoH endpoint (config-driven)
//   4. everything else    — Workers Static Assets (WebUI SPA)
//
// The DoH path and the admin surface are fully separated: knowing the DoH
// path grants no administrative power, and admin auth never touches DoH.

import { handleAdminApi } from "./admin";
import { handleDohRequest } from "./doh";
import { getConfig } from "./config";
import { jsonResponse, methodNotAllowed, textResponse, WORKER_VERSION } from "./httputil";
import type { Env } from "./types";

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
      // /admin is the SPA entry point and falls back to index.html.
      if (request.method === "GET" || request.method === "HEAD") {
        const asset = await env.ASSETS.fetch(request);
        if (asset.status !== 404) return asset;
        if (path === "/admin" || path === "/admin/") {
          return env.ASSETS.fetch(new Request(new URL("/index.html", url), { method: "GET" }));
        }
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
