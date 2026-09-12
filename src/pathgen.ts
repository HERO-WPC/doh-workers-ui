// Custom DoH path generation & validation.
//
// This is endpoint hiding, NOT authentication: it keeps standard scanners
// from discovering the DoH endpoint. Tokens come from crypto.getRandomValues
// (CSPRNG) — never Math.random, timestamps or counters.

const PATH_TOKEN_RE = /^[A-Za-z0-9_-]{8,64}$/;
const FULL_PATH_RE = /^\/[A-Za-z0-9_-]{8,64}\/dns-query$/;

export const DOH_PATH_SUFFIX = "/dns-query";

export function generatePathToken(): string {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

export function buildPath(token: string): string {
  return `/${token}${DOH_PATH_SUFFIX}`;
}

export function isValidPathToken(token: string): boolean {
  return PATH_TOKEN_RE.test(token);
}

export function isValidDohPath(path: string): boolean {
  return FULL_PATH_RE.test(path);
}

/**
 * Accept either a bare token ("8f7c2d91e43ab67f") or a full path
 * ("/8f7c2d91e43ab67f/dns-query") and normalize to the stored form.
 */
export function normalizeDohPath(input: string): { ok: true; path: string } | { ok: false; error: string } {
  const trimmed = input.trim();
  if (isValidDohPath(trimmed)) return { ok: true, path: trimmed };
  if (isValidPathToken(trimmed)) return { ok: true, path: buildPath(trimmed) };
  return {
    ok: false,
    error: "path must be /<token>/dns-query with a token of 8-64 chars [A-Za-z0-9_-]",
  };
}
