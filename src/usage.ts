// Accurate account-level usage via Cloudflare GraphQL Analytics.
//
// Enabled when the CF_ACCOUNT_TOKEN + CF_ACCOUNT_ID secrets are set. Queries
// the same datasets the billing dashboard uses (workersInvocationsAdaptive,
// kvOperationsAdaptiveGroups), so numbers match the official console.
// Free-plan analytics only allow a 7-day window per query — the UI pairs
// official today/7-day numbers with the self-reported all-time counters.

export interface AccountUsage {
  fetchedAt: string;
  workers: {
    accountToday: number;
    accountWeek: number;
    scriptToday: number | null;
    scriptWeek: number | null;
    perScript: { name: string; today: number; week: number }[];
  };
  kv: {
    today: { read: number; write: number; delete: number; list: number };
    week: { read: number; write: number; delete: number; list: number };
  };
}

export class AccountUsageError extends Error {}

function utcDayStart(): string {
  // 当日 UTC 零点。此前误用 slice(0,13)(= 当前小时的起点),
  // 导致"今日"只统计最近几分钟,数字严重偏小。
  return new Date().toISOString().slice(0, 10) + "T00:00:00Z";
}

export function buildUsageQuery(accountTag: string): string {
  const now = new Date().toISOString().slice(0, 19) + "Z";
  const today = utcDayStart();
  const week = new Date(Date.now() - 7 * 86400_000).toISOString().slice(0, 19) + "Z";
  const tag = JSON.stringify(accountTag);
  return `query {
  viewer {
    accounts(filter: {accountTag: ${tag}}) {
      wt: workersInvocationsAdaptive(limit: 100, filter: {datetime_geq: "${today}", datetime_leq: "${now}"}) {
        sum { requests }
        dimensions { scriptName }
      }
      ww: workersInvocationsAdaptive(limit: 100, filter: {datetime_geq: "${week}", datetime_leq: "${now}"}) {
        sum { requests }
        dimensions { scriptName }
      }
      kt: kvOperationsAdaptiveGroups(limit: 10, filter: {datetime_geq: "${today}", datetime_leq: "${now}"}) {
        sum { requests }
        dimensions { actionType }
      }
      kw: kvOperationsAdaptiveGroups(limit: 10, filter: {datetime_geq: "${week}", datetime_leq: "${now}"}) {
        sum { requests }
        dimensions { actionType }
      }
    }
  }
}`;
}

type GroupRow = { sum: { requests: number }; dimensions: { scriptName?: string; actionType?: string } };

function kvMap(rows: GroupRow[]): { read: number; write: number; delete: number; list: number } {
  const out = { read: 0, write: 0, delete: 0, list: 0 };
  for (const r of rows) {
    const t = (r.dimensions.actionType ?? "").toLowerCase();
    if (t in out) out[t as keyof typeof out] = r.sum.requests;
  }
  return out;
}

export function parseUsageResponse(payload: unknown, scriptName: string): AccountUsage {
  const data = (payload as { data?: { viewer?: { accounts?: Record<string, never>[] } } }).data;
  const accounts = data?.viewer?.accounts;
  if (!Array.isArray(accounts) || accounts.length === 0) {
    throw new AccountUsageError("GraphQL returned no account data");
  }
  const a = accounts[0] as {
    wt?: GroupRow[]; ww?: GroupRow[]; kt?: GroupRow[]; kw?: GroupRow[];
  };
  const wt = a.wt ?? [];
  const ww = a.ww ?? [];
  const perScript = ww.map((r) => ({
    name: r.dimensions.scriptName ?? "?",
    week: r.sum.requests,
    today: wt.find((x) => x.dimensions.scriptName === r.dimensions.scriptName)?.sum.requests ?? 0,
  }));
  const scriptToday = wt.find((r) => r.dimensions.scriptName === scriptName)?.sum.requests ?? null;
  const scriptWeek = ww.find((r) => r.dimensions.scriptName === scriptName)?.sum.requests ?? null;
  return {
    fetchedAt: new Date().toISOString(),
    workers: {
      accountToday: wt.reduce((n, r) => n + r.sum.requests, 0),
      accountWeek: ww.reduce((n, r) => n + r.sum.requests, 0),
      scriptToday,
      scriptWeek,
      perScript,
    },
    kv: { today: kvMap(a.kt ?? []), week: kvMap(a.kw ?? []) },
  };
}

export async function fetchAccountUsage(
  token: string,
  accountId: string,
  scriptName: string,
): Promise<AccountUsage> {
  const res = await fetch("https://api.cloudflare.com/client/v4/graphql", {
    method: "POST",
    headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
    body: JSON.stringify({ query: buildUsageQuery(accountId) }),
  });
  if (!res.ok) {
    throw new AccountUsageError(`GraphQL HTTP ${res.status}`);
  }
  const payload = (await res.json()) as { data?: unknown; errors?: { message: string }[] };
  if (payload.errors && payload.errors.length > 0) {
    throw new AccountUsageError(payload.errors.map((e) => e.message).join("; "));
  }
  return parseUsageResponse(payload, scriptName);
}
