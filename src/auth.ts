// Admin authentication.
//
// The admin secret lives in a Worker Secret (ADMIN_SECRET), never in KV and
// never in Git. Comparison is constant-time: both sides are hashed to fixed
// length with SHA-256 and compared byte-by-byte, so timing leaks nothing.

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
