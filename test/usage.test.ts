// Accurate-usage parsing: mirrors the GraphQL shapes verified against the
// real account (workersInvocationsAdaptive / kvOperationsAdaptiveGroups).

import { describe, expect, it } from "vitest";
import { buildUsageQuery, parseUsageResponse } from "../src/usage";

describe("account usage (GraphQL)", () => {
  it("builds a query bounded to today and 7 days", () => {
    const q = buildUsageQuery("abc123");
    expect(q).toContain('accountTag: "abc123"');
    expect(q).toContain("workersInvocationsAdaptive");
    expect(q).toContain("kvOperationsAdaptiveGroups");
  });

  it("parses per-script workers totals and KV ops by action type", () => {
    const parsed = parseUsageResponse(
      {
        data: {
          viewer: {
            accounts: [
              {
                wt: [
                  { sum: { requests: 307 }, dimensions: { scriptName: "other" } },
                  { sum: { requests: 6803 }, dimensions: { scriptName: "doh-workers-ui" } },
                ],
                ww: [
                  { sum: { requests: 5000 }, dimensions: { scriptName: "other" } },
                  { sum: { requests: 29967 }, dimensions: { scriptName: "doh-workers-ui" } },
                ],
                kt: [
                  { sum: { requests: 3040 }, dimensions: { actionType: "read" } },
                  { sum: { requests: 159 }, dimensions: { actionType: "write" } },
                ],
                kw: [
                  { sum: { requests: 79926 }, dimensions: { actionType: "read" } },
                  { sum: { requests: 1596 }, dimensions: { actionType: "write" } },
                  { sum: { requests: 95 }, dimensions: { actionType: "list" } },
                ],
              },
            ],
          },
        },
      },
      "doh-workers-ui",
    );
    expect(parsed.workers.accountToday).toBe(7110);
    expect(parsed.workers.scriptToday).toBe(6803);
    expect(parsed.workers.scriptWeek).toBe(29967);
    expect(parsed.kv.today).toEqual({ read: 3040, write: 159, delete: 0, list: 0 });
    expect(parsed.kv.week.list).toBe(95);
  });

  it("throws a readable error when GraphQL returns errors", () => {
    expect(() => parseUsageResponse({ errors: [{ message: "boom" }] }, "x")).toThrow();
    expect(() => parseUsageResponse({ data: { viewer: { accounts: [] } } }, "x")).toThrow("no account data");
  });
});

describe("usage query window", () => {
  it("anchors 'today' at UTC midnight, not the current hour", () => {
    const q = buildUsageQuery("acct");
    // 今日窗口必须以 T00:00:00Z 结尾(此前 bug 是当前小时起点)
    const m = q.match(/datetime_geq: "([^"]+)"/);
    expect(m).toBeTruthy();
    expect(m![1].endsWith("T00:00:00Z")).toBe(true);
    expect(m![1]).toBe(new Date().toISOString().slice(0, 10) + "T00:00:00Z");
  });
});
