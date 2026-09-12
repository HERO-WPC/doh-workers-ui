// HTTP helpers: content types, CORS, error/status responses.

import type { Upstream } from "./types";

export const DNS_CONTENT_TYPE = "application/dns-message";
export const WORKER_VERSION = "1.0.0";

// DoH is consumed by browser-based clients too (e.g. extensions), so the
// DoH endpoint is public CORS-wise. The Admin API deliberately sets no
// CORS headers and stays same-origin only.
export const DOH_CORS_HEADERS: Record<string, string> = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type",
  "Access-Control-Max-Age": "86400",
};

export function jsonResponse(data: unknown, status = 200, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(data, null, 2), {
    status,
    headers: { "content-type": "application/json; charset=utf-8", ...headers },
  });
}

export function textResponse(status: number, message: string, headers: Record<string, string> = {}): Response {
  return new Response(message, { status, headers: { "content-type": "text/plain; charset=utf-8", ...headers } });
}

export function methodNotAllowed(allow: string): Response {
  return textResponse(405, "Method Not Allowed", { allow });
}

/** Parse a Content-Type header into its bare media type (no parameters). */
export function bareContentType(headerValue: string | null): string {
  if (!headerValue) return "";
  return headerValue.split(";")[0].trim().toLowerCase();
}

export function bearerToken(request: Request): string | null {
  const auth = request.headers.get("authorization");
  if (auth && /^bearer\s+/i.test(auth)) {
    return auth.replace(/^bearer\s+/i, "").trim();
  }
  const token = request.headers.get("x-admin-token");
  return token ? token.trim() : null;
}

export function upstreamDisplayName(u: Upstream): string {
  return `${u.name} (${u.id})`;
}
