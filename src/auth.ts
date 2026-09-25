// Admin authentication.
//
// Two credentials are accepted, and a browser picks one:
//   1. Bearer / x-admin-token header (the raw ADMIN_SECRET). Used by the
//      frontend API calls and by the login page's one-shot validation.
//   2. An HttpOnly session cookie (doh_admin_session). Used to decide, at the
//      server, whether a page load may receive the full console DOM. This is
//      what makes the console *physically* hidden: without it the Worker
//      serves only a thin login page, never the console markup.
//
// The admin secret lives in a Worker Secret (ADMIN_SECRET), never in KV and
// never in Git. Comparison is constant-time: both sides are hashed to fixed
// length with SHA-256 and compared byte-by-byte, so timing leaks nothing.

export const SESSION_COOKIE = "doh_admin_session";
/** How long (seconds) a login session stays valid. 30 days. */
export const SESSION_COOKIE_MAX_AGE = 60 * 60 * 24 * 30;

/**
 * Base cookie attributes. Always HttpOnly (invisible to JS) and SameSite=Strict.
 * `Secure` is applied only over https — over plain http (local `wrangler dev`)
 * browsers reject Secure cookies outright, which would break local login.
 */
function sessionCookieAttrs(secure: boolean): string {
  return "Max-Age=" + SESSION_COOKIE_MAX_AGE + "; Path=/; HttpOnly" + (secure ? "; Secure" : "") + "; SameSite=Strict";
}

export async function constantTimeEquals(a: string, b: string): Promise<boolean> {
  const [ha, hb] = await Promise.all([
    crypto.subtle.digest("SHA-256", new TextEncoder().encode(a)),
    crypto.subtle.digest("SHA-256", new TextEncoder().encode(b)),
  ]);
  const va = new Uint8Array(ha);
  const vb = new Uint8Array(hb);
  let diff = 0;
  for (let i = 0; i < va.length; i++) {
    diff |= va[i] ^ vb[i];
  }
  return diff === 0;
}

export async function isAdminAuthorized(request: Request, expectedSecret: string | undefined): Promise<boolean> {
  if (!expectedSecret) return false;
  const auth = request.headers.get("authorization");
  let token: string | null = null;
  if (auth && /^bearer\s+/i.test(auth)) {
    token = auth.replace(/^bearer\s+/i, "").trim();
  } else {
    token = request.headers.get("x-admin-token");
    if (token) token = token.trim();
  }
  if (!token) return false;
  return constantTimeEquals(token, expectedSecret);
}

// ---------------------------------------------------------------------------
// Session cookie (server-side page gating)
// ---------------------------------------------------------------------------

/** Extract the raw session value from the Cookie header, or null. */
export function readSessionToken(request: Request): string | null {
  const cookie = request.headers.get("cookie");
  if (!cookie) return null;
  for (const part of cookie.split(";")) {
    const eq = part.indexOf("=");
    if (eq < 0) continue;
    if (part.slice(0, eq).trim() === SESSION_COOKIE) {
      const raw = part.slice(eq + 1).trim();
      try {
        return decodeURIComponent(raw);
      } catch {
        return raw;
      }
    }
  }
  return null;
}

/** True when the request carries a valid session cookie matching the secret. */
export async function isAdminCookieAuthorized(request: Request, expectedSecret: string | undefined): Promise<boolean> {
  if (!expectedSecret) return false;
  const token = readSessionToken(request);
  if (!token) return false;
  return constantTimeEquals(token, expectedSecret);
}

/** Build the Set-Cookie header value that establishes an authenticated session. */
export function sessionCookieValue(secret: string, secure = true): string {
  return `${SESSION_COOKIE}=${encodeURIComponent(secret)}; ${sessionCookieAttrs(secure)}`;
}

/** Build the Set-Cookie header value that clears the session (logout). */
export function clearSessionCookie(secure = true): string {
  return `${SESSION_COOKIE}=; Max-Age=0; Path=/; HttpOnly` + (secure ? "; Secure" : "") + "; SameSite=Strict";
}

/** True when the request arrived over TLS (drives the cookie Secure flag). */
export function requestIsHttps(request: Request): boolean {
  return new URL(request.url).protocol === "https:";
}
