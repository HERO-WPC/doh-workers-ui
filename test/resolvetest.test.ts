// DNS 解析测试面板:输入校验、直连上游查询、A/AAAA 双类型、失败隔离。
//
// 这一层的契约是"绕过缓存与路由,结果可归因到所选上游",所以测试里既断言
// 记录内容,也断言它确实没有走缓存。

import * as packet from "dns-packet";
import { describe, expect, it } from "vitest";
import {
  buildUpstreamResponseBody,
  DOH_CONTENT_TYPE,
  FakeCtx,
  FakeKV,
  adminHeaders,
  loadModules,
  makeEnv,
  type TestEnv,
  type UpstreamBehavior,
} from "./helpers";
import type { Config, Env, Upstream } from "../src/types";

const m = await loadModules();

// ---------------------------------------------------------------------------
// 本地辅助
// ---------------------------------------------------------------------------

function cfgWith(upstreams: Upstream[]): Config {
  return { ...m.config.generateDefaultConfig(), upstreams };
}

function up(over: Partial<Upstream> = {}): Upstream {
  return {
    id: "cf",
    name: "Cloudflare",
    url: "https://cloudflare-dns.com/dns-query",
    enabled: true,
    priority: 1,
    timeout: 2500,
    ...over,
  };
}

type PerType = Partial<Record<"A" | "AAAA", UpstreamBehavior>>;

/**
 * 按查询类型分派的假上游:同一个 URL 对 A / AAAA 可以有不同行为,
 * 用来测"一个类型失败不影响另一个类型"。
 */
function typeAwareFetch(perType: PerType, seen: string[]) {
  return (async (input: RequestInfo | URL, init?: RequestInit) => {
    const body = Buffer.from((init?.body as Uint8Array) ?? new Uint8Array(0));
    const dec = packet.decode(body) as { questions: { type: string | number }[] };
    const type = String(dec.questions[0]?.type ?? "A");
    seen.push(type);
    const behavior: UpstreamBehavior = perType[type as "A" | "AAAA"] ?? { kind: "answer" };
    const signal = init?.signal ?? undefined;

    if (behavior.kind === "hang") {
      return new Promise<Response>((_resolve, reject) => {
        const timer = setTimeout(() => reject(new Error("fake upstream hung")), 30_000);
        signal?.addEventListener("abort", () => {
          clearTimeout(timer);
          reject(new DOMException("aborted", "AbortError"));
        });
      });
    }
    if (behavior.kind === "httpStatus") {
      return new Response("nope", { status: behavior.status });
    }
    if (behavior.kind === "wrongQuestion") {
      const wrong = packet.encode({
        id: (body[0] << 8) | body[1],
        type: "response",
        flags: 0x8000,
        questions: [{ name: "totally-different.example", type: "A" }],
      } as unknown as packet.Packet);
      return new Response(wrong, { status: 200, headers: { "content-type": DOH_CONTENT_TYPE } });
    }
    return new Response(buildUpstreamResponseBody(body, behavior), {
      status: 200,
      headers: { "content-type": DOH_CONTENT_TYPE },
    });
  }) as unknown as typeof globalThis.fetch;
}

// ---------------------------------------------------------------------------
// 输入校验
// ---------------------------------------------------------------------------

describe("parseResolveTestInput", () => {
  const cfg = cfgWith([up()]);

  it("默认查询 A + AAAA,并去掉末尾的根点", () => {
    const r = m.resolvetest.parseResolveTestInput({ name: "Example.COM.", provider: "cf" }, cfg);
    expect(r.ok).toBe(true);
    if (!r.ok) return;
    expect(r.input.name).toBe("Example.COM");
    expect(r.input.types).toEqual(["A", "AAAA"]);
    expect(r.input.upstream.id).toBe("cf");
  });

  it("接受单个类型、数组、以及数字类型码", () => {
    const a = m.resolvetest.parseResolveTestInput({ name: "a.com", provider: "cf", types: "a" }, cfg);
    expect(a.ok && a.input.types).toEqual(["A"]);

    const both = m.resolvetest.parseResolveTestInput({ name: "a.com", provider: "cf", types: ["AAAA", "A"] }, cfg);
    // 输出顺序固定为 A -> AAAA,与前端展示一致
    expect(both.ok && both.input.types).toEqual(["A", "AAAA"]);

    const nums = m.resolvetest.parseResolveTestInput({ name: "a.com", provider: "cf", types: [1, 28] }, cfg);
    expect(nums.ok && nums.input.types).toEqual(["A", "AAAA"]);
  });

  it("拒绝非对象、空域名、非法字符与超长标签", () => {
    expect(m.resolvetest.parseResolveTestInput(null, cfg).ok).toBe(false);
    expect(m.resolvetest.parseResolveTestInput([], cfg).ok).toBe(false);
    expect(m.resolvetest.parseResolveTestInput({ provider: "cf" }, cfg).ok).toBe(false);
    expect(m.resolvetest.parseResolveTestInput({ name: "  ", provider: "cf" }, cfg).ok).toBe(false);
    expect(m.resolvetest.parseResolveTestInput({ name: "has space.com", provider: "cf" }, cfg).ok).toBe(false);
    expect(m.resolvetest.parseResolveTestInput({ name: "a..b.com", provider: "cf" }, cfg).ok).toBe(false);
    expect(m.resolvetest.parseResolveTestInput({ name: `${"x".repeat(64)}.com`, provider: "cf" }, cfg).ok).toBe(false);
  });

  it("只允许 A 和 AAAA,其它类型一律拒绝", () => {
    expect(m.resolvetest.parseResolveTestInput({ name: "a.com", provider: "cf", types: "MX" }, cfg).ok).toBe(false);
    expect(m.resolvetest.parseResolveTestInput({ name: "a.com", provider: "cf", types: "TXT" }, cfg).ok).toBe(false);
    expect(m.resolvetest.parseResolveTestInput({ name: "a.com", provider: "cf", types: 15 }, cfg).ok).toBe(false);
    expect(m.resolvetest.parseResolveTestInput({ name: "a.com", provider: "cf", types: [] }, cfg).ok).toBe(false);
  });

  it("要求 provider 必须来自配置里的上游列表", () => {
    expect(m.resolvetest.parseResolveTestInput({ name: "a.com" }, cfg).ok).toBe(false);
    const r = m.resolvetest.parseResolveTestInput({ name: "a.com", provider: "nope" }, cfg);
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error).toContain("unknown provider");
  });
});

// ---------------------------------------------------------------------------
// 查询行为
// ---------------------------------------------------------------------------

describe("queryOneType", () => {
  it("A 返回 IPv4 记录,AAAA 返回 IPv6 记录", async () => {
    const seen: string[] = [];
    const fetchImpl = typeAwareFetch({}, seen);

    const a = await m.resolvetest.queryOneType(up(), "example.com", "A", { fetchImpl });
    expect(a.ok).toBe(true);
    expect(a.status).toBe(0);
    expect(a.statusText).toBe("NOERROR");
    expect(a.records).toHaveLength(1);
    expect(a.records![0]).toMatchObject({ type: "A", ttl: 300, data: "93.184.216.34" });
    expect(a.note).toBeUndefined();

    const aaaa = await m.resolvetest.queryOneType(up(), "example.com", "AAAA", { fetchImpl });
    expect(aaaa.ok).toBe(true);
    expect(aaaa.records![0].type).toBe("AAAA");
    expect(aaaa.records![0].data).toContain(":");
    expect(seen).toEqual(["A", "AAAA"]);
  });

  it("查询成功但无记录时标记 NODATA(与 monitor 面板一致)", async () => {
    const fetchImpl = typeAwareFetch({ A: { kind: "answer", noRecords: true } }, []);
    const r = await m.resolvetest.queryOneType(up(), "example.com", "A", { fetchImpl });
    expect(r.ok).toBe(true);
    expect(r.status).toBe(0);
    expect(r.note).toBe("NODATA");
    expect(r.records).toBeUndefined();
  });

  it("NXDOMAIN 保留 rcode 与权威段", async () => {
    const fetchImpl = typeAwareFetch({ A: { kind: "answer", rcode: 3 } }, []);
    const r = await m.resolvetest.queryOneType(up(), "nope.example", "A", { fetchImpl });
    expect(r.ok).toBe(true);
    expect(r.status).toBe(3);
    expect(r.statusText).toBe("NXDOMAIN");
    expect(r.authority?.some((x) => x.type === "SOA")).toBe(true);
    expect(r.note).toBeUndefined();
  });

  it("传输层失败收敛成 ok=false(HTTP 错误 / 响应校验不过 / 超时)", async () => {
    const http = await m.resolvetest.queryOneType(up(), "example.com", "A", {
      fetchImpl: typeAwareFetch({ A: { kind: "httpStatus", status: 503 } }, []),
    });
    expect(http.ok).toBe(false);
    expect(http.error).toContain("503");

    const wrong = await m.resolvetest.queryOneType(up(), "example.com", "A", {
      fetchImpl: typeAwareFetch({ A: { kind: "wrongQuestion" } }, []),
    });
    expect(wrong.ok).toBe(false);

    // 上游超时用配置里的 timeout,所以给一个很小的值让用例跑得快
    const slow = await m.resolvetest.queryOneType(up({ timeout: 150 }), "example.com", "A", {
      fetchImpl: typeAwareFetch({ A: { kind: "hang" } }, []),
    });
    expect(slow.ok).toBe(false);
    expect(slow.timedOut).toBe(true);
  });
});

describe("runResolveTest", () => {
  it("并行查询两个类型,返回 provider 元信息", async () => {
    const seen: string[] = [];
    const r = await m.resolvetest.runResolveTest(
      { name: "example.com", upstream: up(), types: ["A", "AAAA"] },
      { fetchImpl: typeAwareFetch({}, seen) },
    );
    expect(r.name).toBe("example.com");
    expect(r.provider).toEqual({
      id: "cf",
      name: "Cloudflare",
      url: "https://cloudflare-dns.com/dns-query",
      enabled: true,
    });
    expect(r.results.map((x) => x.type)).toEqual(["A", "AAAA"]);
    expect(seen.sort()).toEqual(["A", "AAAA"]);
  });

  it("一个类型失败不影响另一个类型", async () => {
    const r = await m.resolvetest.runResolveTest(
      { name: "example.com", upstream: up({ timeout: 150 }), types: ["A", "AAAA"] },
      { fetchImpl: typeAwareFetch({ AAAA: { kind: "hang" } }, []) },
    );
    const [a, aaaa] = r.results;
    expect(a.ok).toBe(true);
    expect(a.records).toHaveLength(1);
    expect(aaaa.ok).toBe(false);
    expect(aaaa.timedOut).toBe(true);
    expect(aaaa.error).toBeTruthy();
  });

  it("绕过缓存:同一查询连续两次都会真的打上游", async () => {
    const seen: string[] = [];
    const fetchImpl = typeAwareFetch({}, seen);
    const input = { name: "example.com", upstream: up(), types: ["A" as const] };
    await m.resolvetest.runResolveTest(input, { fetchImpl });
    await m.resolvetest.runResolveTest(input, { fetchImpl });
    expect(seen).toEqual(["A", "A"]);
  });
});

// ---------------------------------------------------------------------------
// 管理接口
// ---------------------------------------------------------------------------

describe("POST /admin/api/resolve-test", () => {
  async function call(body: unknown, opts: { method?: string; headers?: Record<string, string>; env?: Env | TestEnv } = {}) {
    const env = (opts.env ?? makeEnv()) as unknown as Env;
    const headers: Record<string, string> = { ...(opts.headers ?? adminHeaders()) };
    if (body !== undefined) headers["content-type"] = "application/json";
    const req = new Request("https://worker.test/admin/api/resolve-test", {
      method: opts.method ?? "POST",
      headers,
      body: body !== undefined ? JSON.stringify(body) : undefined,
    });
    const res = await m.admin.handleAdminApi(req, env, new FakeCtx());
    const json: any = await res.clone().json().catch(() => null);
    return { res, json, env };
  }

  const withFetch = async <T>(fetchImpl: typeof globalThis.fetch, fn: () => Promise<T>): Promise<T> => {
    const prev = globalThis.fetch;
    (globalThis as unknown as { fetch: unknown }).fetch = fetchImpl;
    try {
      return await fn();
    } finally {
      (globalThis as unknown as { fetch: unknown }).fetch = prev;
    }
  };

  it("未认证时 401,且不会打出上游请求", async () => {
    const seen: string[] = [];
    await withFetch(typeAwareFetch({}, seen), async () => {
      const { res } = await call({ name: "example.com", provider: "cloudflare" }, { headers: {} });
      expect(res.status).toBe(401);
    });
    expect(seen).toEqual([]);
  });

  it("返回所选上游的 A / AAAA 记录", async () => {
    await withFetch(typeAwareFetch({}, []), async () => {
      const { res, json } = await call({ name: "example.com", provider: "cloudflare" });
      expect(res.status).toBe(200);
      expect(json.provider.id).toBe("cloudflare");
      expect(json.results).toHaveLength(2);
      expect(json.results[0]).toMatchObject({ type: "A", ok: true, statusText: "NOERROR" });
      expect(json.results[0].records[0].data).toBe("93.184.216.34");
      expect(json.results[1].records[0].type).toBe("AAAA");
    });
  });

  it("非法域名 / 未知上游 / 不支持的类型 -> 400", async () => {
    expect((await call({ name: "bad name", provider: "cloudflare" })).res.status).toBe(400);
    expect((await call({ name: "example.com", provider: "ghost" })).res.status).toBe(400);
    expect((await call({ name: "example.com", provider: "cloudflare", types: "MX" })).res.status).toBe(400);
  });

  it("GET 返回 405,非 JSON content-type 返回 415", async () => {
    const { res } = await call(undefined, { method: "GET" });
    expect(res.status).toBe(405);

    const env = makeEnv() as unknown as Env;
    const req = new Request("https://worker.test/admin/api/resolve-test", {
      method: "POST",
      headers: { ...adminHeaders(), "content-type": "text/plain" },
      body: "example.com",
    });
    const res415 = await m.admin.handleAdminApi(req, env, new FakeCtx());
    expect(res415.status).toBe(415);
  });

  it("不写 KV:一次查询不产生任何写入", async () => {
    const env = makeEnv();
    const store = (env.CONFIG_KV as unknown as FakeKV).store;
    await m.config.getConfig(env as unknown as Env); // 首次调用会初始化配置(1 次写)
    const writesAfterInit = store.size;
    const keysAfterInit = [...store.keys()].sort();

    await withFetch(typeAwareFetch({}, []), async () => {
      const { res } = await call({ name: "example.com", provider: "cloudflare" }, { env });
      expect(res.status).toBe(200);
    });
    expect(store.size).toBe(writesAfterInit);
    expect([...store.keys()].sort()).toEqual(keysAfterInit);
  });
});
