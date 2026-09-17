// ECS 全链路 wire/cache 专项测试。
//
// 验证:ECS spec → buildUpstreamQuery → dns-packet 编码 → 实际 wire 报文里
// 的 OPT option code=8 字段(family/sourcePrefixLength/scope/address 字节数),
// 以及 cache key 的隔离与规范化。
import { describe, expect, it } from "vitest";
import * as packet from "dns-packet";
import { buildUpstreamQuery } from "../src/dnsmsg";
import { canonicalString } from "../src/cachekey";
import { findClientEcs, parseFixedSubnet, withPrefix } from "../src/ecs";

function extractEcs(wire: Buffer): { family: number; sourcePrefixLength: number; scopePrefixLength: number; ip: string } | null {
  const dec = packet.decode(wire) as { additionals?: { type?: string; options?: Array<Record<string, unknown>> }[] };
  for (const rr of dec.additionals ?? []) {
    for (const o of rr.options ?? []) {
      if (o.code === 8 || o.type === "CLIENT_SUBNET") {
        return {
          family: Number(o.family),
          sourcePrefixLength: Number(o.sourcePrefixLength),
          scopePrefixLength: Number(o.scopePrefixLength ?? 0),
          ip: String(o.ip),
        };
      }
    }
  }
  return null;
}

const Q = { qname: "www.baidu.com", qtype: "AAAA", qclass: "IN", cd: false, do: false };

describe("ECS wire 编码(buildUpstreamQuery → 实际报文)", () => {
  it("IPv4 /24:OPT option code 8,family=1,prefix=24,scope=0,3 字节地址", () => {
    const spec = parseFixedSubnet("223.5.5.123/24")!;
    const wire = buildUpstreamQuery(Q, spec);
    const ecs = extractEcs(wire);
    expect(ecs).not.toBeNull();
    expect(ecs!.family).toBe(1);
    expect(ecs!.sourcePrefixLength).toBe(24);
    expect(ecs!.scopePrefixLength).toBe(0);
    // dns-packet 把地址截断到 ceil(24/8)=3 字节,规范化后应能还原出 .0
    expect(ecs!.ip).toBe("223.5.5.0");
  });

  it("IPv6 /56:family=2,prefix=56,scope=0,7 字节地址(剩余位清零)", () => {
    const spec = parseFixedSubnet("240e:e9:6002:1fd:abcd:ef01:2345:6789/56")!;
    const wire = buildUpstreamQuery(Q, spec);
    const ecs = extractEcs(wire);
    expect(ecs).not.toBeNull();
    expect(ecs!.family).toBe(2);
    expect(ecs!.sourcePrefixLength).toBe(56);
    expect(ecs!.scopePrefixLength).toBe(0);
    // /56 → 7 字节;第 7 字节剩余 1 bit 应被清零(6002 → 6000)
    expect(ecs!.ip.startsWith("240e:e9:600")).toBe(true);
    expect(ecs!.ip).not.toContain("abcd");
  });

  it("无 ECS 时不带 OPT/ECS option", () => {
    const wire = buildUpstreamQuery(Q, null);
    expect(extractEcs(wire)).toBeNull();
  });

  it("findClientEcs 能还原上游发来的 ECS option(往返)", () => {
    const spec = parseFixedSubnet("223.5.5.0/24")!;
    const wire = buildUpstreamQuery(Q, spec);
    const dec = packet.decode(wire) as { additionals?: Array<{ type?: unknown; options?: Array<Record<string, unknown>> }> };
    const opt = dec.additionals?.find((r) => String(r.type) === "OPT");
    const back = findClientEcs({ options: (opt?.options ?? []) as never });
    expect(back).not.toBeNull();
    expect(back!.family).toBe(1);
    expect(back!.sourcePrefix).toBe(24);
  });
});

describe("ECS cache key 隔离与规范化", () => {
  const parts = (ecs: ReturnType<typeof parseFixedSubnet>) => ({
    qnameLower: "www.baidu.com", qtype: "AAAA", qclass: "IN", do: false, cd: false, ecs,
  });

  it("无 ECS / 中国 / 美国 三键互不相同", () => {
    const none = canonicalString(parts(null));
    const cn = canonicalString(parts(parseFixedSubnet("223.5.5.0/24")));
    const us = canonicalString(parts(parseFixedSubnet("8.8.8.0/24")));
    expect(none).not.toBe(cn);
    expect(none).not.toBe(us);
    expect(cn).not.toBe(us);
  });

  it("同子网不同主机位归一化到同一键(223.5.5.123/24 == 223.5.5.0/24)", () => {
    const a = canonicalString(parts(parseFixedSubnet("223.5.5.123/24")));
    const b = canonicalString(parts(parseFixedSubnet("223.5.5.0/24")));
    expect(a).toBe(b);
  });

  it("IPv6 不同写法归一化到同一 /56 键", () => {
    const a = parseFixedSubnet("2001:db8:1234:5678::1/56")!;
    const b = parseFixedSubnet("2001:0db8:1234:5678:abcd::1/56")!;
    expect(a.address).toBe(b.address);
    expect(canonicalString(parts(a))).toBe(canonicalString(parts(b)));
  });

  it("不同 /56 必须隔离", () => {
    const a = parseFixedSubnet("240e:e9:6002::/56")!;
    const b = parseFixedSubnet("240e:e9:6100::/56")!;
    expect(a.address).not.toBe(b.address);
    expect(canonicalString(parts(a))).not.toBe(canonicalString(parts(b)));
  });
});

describe("ECS auto 模式对客户端 ECS 的钳制", () => {
  it("effectivePrefix = min(clientPrefix, configMax)(RFC 7871)", () => {
    // 客户端声称 /32,配置上限 /24 → 钳到 /24
    const client = findClientEcs({ options: [{ code: 8, family: 1, sourcePrefixLength: 32, ip: "8.8.8.8" }] })!;
    expect(client.sourcePrefix).toBe(32);
    const clamped = withPrefix(client, 24)!;
    expect(clamped.sourcePrefix).toBe(24);
    expect(clamped.address).toBe("8.8.8.0");
    // 客户端声称 /8 < 上限 → 保持 /8
    const client8 = findClientEcs({ options: [{ code: 8, family: 1, sourcePrefixLength: 8, ip: "8.0.0.1" }] })!;
    const c8 = withPrefix(client8, 24)!;
    expect(c8.sourcePrefix).toBe(8);
  });
});
