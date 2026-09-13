// 缓存写入参数 wiring 回归测试。
//
// cache.put(url, body, freshFor, staleFor) 的契约是 staleFor 表示"在 freshFor
// 之上"的窗口。doh.ts 曾传入 storeTtl + staleTTL,导致实际 stale 窗口翻倍,
// 且 staleTTL=0 时仍会服务过期数据。cache 单测直接传参,覆盖不到这层 wiring,
// 所以这里用真实请求 + spy 断言写入参数。
import { describe, expect, it, vi } from "vitest";
import { FakeCacheStorage, FakeCtx, buildClientQuery, installCacheApi, loadModules, makeEnv, makeFakeUpstream, toBase64Url } from "./helpers";

const m = await loadModules();

describe("DoH 缓存写入参数", () => {
  it("staleFor 等于配置的 staleTTL(不叠加 storeTtl)", async () => {
    installCacheApi(new FakeCacheStorage());
    const fake = makeFakeUpstream();
    (globalThis as unknown as { fetch: unknown }).fetch = fake.fetch;
    const env = makeEnv();

    const cfg = await m.config.getConfig(env as never);
    const putSpy = vi.spyOn(m.cache.dnsCache, "put");

    const wire = buildClientQuery({ name: "cache-wiring.example", type: "A", ttl: 300 });
    const ctx = new FakeCtx();
    const res = await (m.index.default as unknown as { fetch(r: Request, e: unknown, c: FakeCtx): Promise<Response> }).fetch(
      new Request(`https://worker.test${cfg.doh.path}?dns=${toBase64Url(wire)}`),
      env,
      ctx,
    );
    await ctx.settle();
    expect(res.status).toBe(200);

    expect(putSpy).toHaveBeenCalled();
    const [, , freshFor, staleFor] = putSpy.mock.calls[0] as unknown as [URL, Buffer, number, number];
    expect(staleFor).toBe(cfg.cache.staleTTL);
    // freshFor 应等于最终存储 TTL(被 min/maxTTL 钳制后),且两者不叠加
    expect(freshFor).toBeGreaterThanOrEqual(cfg.cache.minTTL);
    expect(freshFor).toBeLessThanOrEqual(cfg.cache.maxTTL);
    expect(staleFor).toBeLessThan(freshFor + staleFor);
  });
});
