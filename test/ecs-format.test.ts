// ECS 子网截断后的地址表示必须规范(RFC 5952).
//
// 原实现在零段位于开头/结尾时会产出 "2001:db8:"、":1"、"" 这类非法字面量,
// 靠下游编码器宽容才没有崩溃;但缓存键、日志与任何回读校验都会出错。
import { describe, expect, it } from "vitest";
import { v6 } from "@leichtgewicht/ip-codec";
import { deriveEcsFromIp, ecsKeyString, parseFixedSubnet } from "../src/ecs";

const CFG = { mode: "auto", ipv4Prefix: 24, ipv6Prefix: 56, fixedSubnet: "" } as const;

describe("ECS IPv6 截断格式化", () => {
  const cases: Array<[string, string]> = [
    // [输入子网, 期望的规范地址]
    ["2001:db8:1234:5678:9abc:def0:1234:5678/56", "2001:db8:1234:5600::"],
    ["2001:db8::1/56", "2001:db8::"],
    ["::1/56", "::"],
    ["fd6a:5c2d:5a31::202/64", "fd6a:5c2d:5a31::"],
    ["2001:db8:0:0:1:0:0:1/128", "2001:db8::1:0:0:1"],
    ["2001:db8:1:2:3:4:5:6/128", "2001:db8:1:2:3:4:5:6"],
  ];

  for (const [subnet, expected] of cases) {
    it(`${subnet} → ${expected}`, () => {
      const spec = parseFixedSubnet(subnet);
      expect(spec).not.toBeNull();
      expect(spec!.address).toBe(expected);
      // 规范形式判据:地址必须是编码器自身的规范输出(往返一致)。
      // 非规范串(如 "2001:db8:"、":1"、"" )在此判据下会失败。
      const bytes = v6.encode(spec!.address);
      expect(v6.decode(bytes)).toBe(spec!.address);
      expect(spec!.address).not.toContain(":::");
    });
  }

  it("IPv4 截断保持点分十进制", () => {
    const spec = parseFixedSubnet("203.0.113.77/24");
    expect(spec!.address).toBe("203.0.113.0");
  });

  it("auto 模式按 ipv6Prefix 截断客户端 IPv6", () => {
    const spec = deriveEcsFromIp("2409:8a20:5a31:c434:162d:27ff:feb3:3239", CFG as never);
    expect(spec!.address).toBe("2409:8a20:5a31:c400::");
    expect(ecsKeyString(spec)).toBe("ecs=2/56:2409:8a20:5a31:c400::");
  });

  it("auto 模式按 ipv4Prefix 截断客户端 IPv4", () => {
    const spec = deriveEcsFromIp("203.0.113.77", CFG as never);
    expect(spec!.address).toBe("203.0.113.0");
    expect(ecsKeyString(spec)).toBe("ecs=1/24:203.0.113.0");
  });
});

// —— IPv6/ECS 专项审计追加用例 ——
describe("IPv6 ECS 边界用例", () => {
  const cases: Array<[string, string]> = [
    ["::1/128", "::1"],
    ["::/0", "::"],
    ["1::/16", "1::"],
    ["2001:db8::/56", "2001:db8::"],
    ["2001:db8:abcd:1234::1/128", "2001:db8:abcd:1234::1"],
    ["ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"],
    ["fe80::1/64", "fe80::"],
    ["fd6a:5c2d:5a31::202/64", "fd6a:5c2d:5a31::"],
    ["2606:4700:3030::ac46:8929/56", "2606:4700:3030::"],
    ["2001:db8:0:0:0:0:0:1/128", "2001:db8::1"],
    ["2001:0db8::/48", "2001:db8::"],
  ];
  for (const [subnet, expected] of cases) {
    it(`${subnet} → ${expected}`, () => {
      const spec = parseFixedSubnet(subnet);
      expect(spec).not.toBeNull();
      expect(spec!.address).toBe(expected);
      // 幂等:再截断一次结果不变
      const again = parseFixedSubnet(`${spec!.address}/${spec!.sourcePrefix}`);
      expect(again!.address).toBe(spec!.address);
    });
  }

  it("IPv4-mapped IPv6 应被拒绝而不是误解析", () => {
    // ::ffff:192.0.2.1 不应被当作 4 个 hex 段静默编出错误字节
    const spec = parseFixedSubnet("::ffff:192.0.2.1/128");
    expect(spec).toBeNull(); // 期望:拒绝
  });
});
