// 家庭感知(family-aware)的 fixed 模式 ECS 选择。
//
// 配置里可同时给 IPv4 与 IPv6 两个固定网段(fixedSubnetV4 / fixedSubnetV6),
// fixed 模式按查询类型自动选:A → IPv4 网段、AAAA → IPv6 网段;
// 客户端自带 ECS 时以其 family 为准;若没有分网段字段,则沿用旧的
// 单一 fixedSubnet(对任意 family 原样生效),保证向后兼容。

import { describe, expect, it } from "vitest";
import { decideEcs, parseFixedSubnet, parseFixedSubnetV4, parseFixedSubnetV6 } from "../src/ecs";
import { parseConfig, generateDefaultConfig } from "../src/config";

function fixedCfg(p: { v4?: string; v6?: string; legacy?: string }) {
  const base = generateDefaultConfig();
  const r = parseConfig({
    ...base,
    ecs: {
      ...base.ecs,
      mode: "fixed",
      ipv4Prefix: 24,
      ipv6Prefix: 56,
      fixedSubnet: p.legacy ?? "",
      fixedSubnetV4: p.v4 ?? "",
      fixedSubnetV6: p.v6 ?? "",
    },
  });
  if (!r.ok) throw new Error(r.error);
  return r.config;
}

describe("parseFixedSubnetV4/V6 严格按 family 解析", () => {
  it("IPv4 CIDR 只被 V4 接受,IPv6 CIDR 只被 V6 接受", () => {
    expect(parseFixedSubnetV4("203.0.113.0/24")).not.toBeNull();
    expect(parseFixedSubnetV4("2001:db8::/48")).toBeNull();
    expect(parseFixedSubnetV6("2001:db8::/48")).not.toBeNull();
    expect(parseFixedSubnetV6("203.0.113.0/24")).toBeNull();
  });

  it("parseFixedSubnet 对两族都可用(向后兼容)", () => {
    expect(parseFixedSubnet("203.0.113.0/24")!.family).toBe(1);
    expect(parseFixedSubnet("2001:db8::/48")!.family).toBe(2);
  });
});

describe("decideEcs fixed: 按查询类型选网段", () => {
  const cfg = fixedCfg({ v4: "203.0.113.0/24", v6: "2001:db8::/48" });

  it("A → IPv4 网段、AAAA → IPv6 网段", () => {
    expect(decideEcs(cfg, { clientEcs: null, qtype: "A" }, null)).toMatchObject({ family: 1, sourcePrefix: 24, address: "203.0.113.0" });
    expect(decideEcs(cfg, { clientEcs: null, qtype: "AAAA" }, null)).toMatchObject({ family: 2, sourcePrefix: 48, address: "2001:db8::" });
  });

  it("客户端自带 ECS 时以其 family 为准", () => {
    const clientV6 = parseFixedSubnet("fd6a:5c2d:5a31::202/64")!;
    expect(decideEcs(cfg, { clientEcs: clientV6, qtype: "A" }, null)!.family).toBe(2);
  });

  it("查询类型不指向地址族时优先 IPv4(再 IPv6)", () => {
    expect(decideEcs(cfg, { clientEcs: null, qtype: "MX" }, null)!.family).toBe(1);
    expect(decideEcs(cfg, { clientEcs: null, qtype: "HTTPS" }, null)!.family).toBe(1);
  });

  it("只填 IPv4 网段:AAAA 查询不注入 ECS", () => {
    const onlyV4 = fixedCfg({ v4: "203.0.113.0/24" });
    expect(decideEcs(onlyV4, { clientEcs: null, qtype: "A" }, null)).toMatchObject({ family: 1 });
    expect(decideEcs(onlyV4, { clientEcs: null, qtype: "AAAA" }, null)).toBeNull();
  });

  it("只填 IPv6 网段:A 查询不注入 ECS", () => {
    const onlyV6 = fixedCfg({ v6: "2001:db8::/48" });
    expect(decideEcs(onlyV6, { clientEcs: null, qtype: "AAAA" }, null)).toMatchObject({ family: 2 });
    expect(decideEcs(onlyV6, { clientEcs: null, qtype: "A" }, null)).toBeNull();
  });
});

describe("decideEcs fixed: 旧 single fixedSubnet 向后兼容", () => {
  it("只有 legacy fixedSubnet(IPv4):A / AAAA 都注入该 IPv4 网段(旧行为)", () => {
    const old = fixedCfg({ legacy: "203.0.113.0/24" });
    expect(decideEcs(old, { clientEcs: null, qtype: "A" }, null)).toMatchObject({ family: 1 });
    expect(decideEcs(old, { clientEcs: null, qtype: "AAAA" }, null)).toMatchObject({ family: 1 });
  });

  it("只有 legacy fixedSubnet(IPv6):A / AAAA 都注入该 IPv6 网段(旧行为)", () => {
    const old = fixedCfg({ legacy: "2001:db8::/48" });
    expect(decideEcs(old, { clientEcs: null, qtype: "A" }, null)).toMatchObject({ family: 2 });
    expect(decideEcs(old, { clientEcs: null, qtype: "AAAA" }, null)).toMatchObject({ family: 2 });
  });

  it("分网段字段存在时,legacy 仅作同族回退", () => {
    const mixed = fixedCfg({ v4: "203.0.113.0/24", legacy: "2001:db8::/48" });
    // A 查询:family=1 → 用 v4 网段(即使 legacy 是 v6)
    expect(decideEcs(mixed, { clientEcs: null, qtype: "A" }, null)).toMatchObject({ family: 1, address: "203.0.113.0" });
    // AAAA 查询:family=2 → 同族回退到 legacy(v6)
    expect(decideEcs(mixed, { clientEcs: null, qtype: "AAAA" }, null)).toMatchObject({ family: 2 });
  });
});

describe("parseConfig 校验 family 正确的 fixed 网段", () => {
  it("接受 IPv6 单一 fixedSubnet(旧字段)", () => {
    const base = generateDefaultConfig();
    const r = parseConfig({ ...base, ecs: { ...base.ecs, mode: "fixed", fixedSubnet: "2001:db8::/48" } });
    expect(r.ok).toBe(true);
  });

  it("接受合法的 fixedSubnetV4 / fixedSubnetV6", () => {
    const base = generateDefaultConfig();
    const ok = parseConfig({ ...base, ecs: { ...base.ecs, mode: "fixed", fixedSubnetV4: "203.0.113.0/24", fixedSubnetV6: "2001:db8::/48" } });
    expect(ok.ok).toBe(true);
  });

  it("把 IPv6 填进 fixedSubnetV4(或 IPv4 填进 V6)时拒绝", () => {
    const base = generateDefaultConfig();
    const v6inV4 = parseConfig({ ...base, ecs: { ...base.ecs, mode: "fixed", fixedSubnetV4: "2001:db8::/48" } });
    expect(v6inV4.ok).toBe(false);
    if (!v6inV4.ok) expect(v6inV4.error).toContain("fixedSubnetV4 must be a valid IPv4 CIDR");

    const v4inV6 = parseConfig({ ...base, ecs: { ...base.ecs, mode: "fixed", fixedSubnetV6: "203.0.113.0/24" } });
    expect(v4inV6.ok).toBe(false);
    if (!v4inV6.ok) expect(v4inV6.error).toContain("fixedSubnetV6 must be a valid IPv6 CIDR");
  });

  it("mode 非 fixed 时不做网段格式强制(与旧行为一致)", () => {
    const base = generateDefaultConfig();
    const r = parseConfig({ ...base, ecs: { ...base.ecs, mode: "off", fixedSubnetV4: "not-a-cidr" } });
    expect(r.ok).toBe(true);
  });
});
