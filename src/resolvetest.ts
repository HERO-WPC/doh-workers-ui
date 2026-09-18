// Admin "DNS 解析测试" 面板的后端逻辑。
//
// 用户在控制台里自己输入域名、自己从上游列表里挑一个 DoH 服务商,看它返回的
// A / AAAA 记录。这个面板回答的是"这个服务商对这个域名看到了什么"——因此它
// **刻意绕过本机的 L1/L2 缓存和路由**:
//   - 走缓存 → 拿到的可能是很久以前别的上游写入的结果,无法归因;
//   - 走路由 → 无法知道最终是哪个上游答的。
// 直接由所选上游应答,结果才可归因。
//
// 因为完全不碰缓存与 metrics,跑测试不会影响正常解析流量、上游评分,也不产生
// 任何 KV 写入(每次调用只消耗 1-2 个上游请求)。

import { buildUpstreamQuery, type DnsRecord } from "./dnsmsg";
import { normalizeQType, renderRdata, validateQueryName } from "./jsonapi";
import { queryUpstream, type FetchLike } from "./upstream";
import type { Config, Upstream } from "./types";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/** 本面板支持的类型:只要 A 和 AAAA。 */
export const RESOLVE_TEST_TYPES = ["A", "AAAA"] as const;
export type ResolveTestType = (typeof RESOLVE_TEST_TYPES)[number];

export interface ResolveRecord {
  name: string;
  type: string;
  ttl: number | null;
  data: string;
}

export interface ResolveTypeResult {
  type: ResolveTestType;
  /** false 表示传输/校验层失败(与 DNS 层的 rcode 错误区分开)。 */
  ok: boolean;
  /** 有效 rcode(含 EDNS 扩展高 8 位)。仅 ok=true 时存在。 */
  status?: number;
  statusText?: string;
  /** 答案段记录(含 CNAME 链,原样展示,不做终结记录补全)。 */
  records?: ResolveRecord[];
  /** 权威段:空答案时用来解释 NODATA / NXDOMAIN。 */
  authority?: ResolveRecord[];
  /** "NODATA" 之类的提示。 */
  note?: string;
  /** 失败原因(超时 / HTTP 错误 / 响应校验不过)。 */
  error?: string;
  timedOut?: boolean;
}

export interface ResolveTestResult {
  name: string;
  provider: { id: string; name: string; url: string; enabled: boolean };
  results: ResolveTypeResult[];
}

export interface ResolveTestInput {
  name: string;
  upstream: Upstream;
  types: ResolveTestType[];
}

// ---------------------------------------------------------------------------
// rcode 文本
// ---------------------------------------------------------------------------

const RCODE_TEXT: Record<number, string> = {
  0: "NOERROR",
  1: "FORMERR",
  2: "SERVFAIL",
  3: "NXDOMAIN",
  4: "NOTIMP",
  5: "REFUSED",
  16: "BADVERS",
};

export function rcodeText(rcode: number): string {
  return RCODE_TEXT[rcode] ?? `RCODE_${rcode}`;
}

// ---------------------------------------------------------------------------
// 输入校验
// ---------------------------------------------------------------------------

/**
 * 校验面板输入。域名规则与 `?name=` 可读查询完全一致(RFC 1035 长度限制、
 * 仅 ASCII、无空标签),所以两个入口不会出现"一个能查一个不能"的分歧。
 */
export function parseResolveTestInput(raw: unknown, cfg: Config): { ok: true; input: ResolveTestInput } | { ok: false; error: string } {
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) {
    return { ok: false, error: "request body must be a JSON object" };
  }
  const body = raw as Record<string, unknown>;

  const rawName = typeof body.name === "string" ? body.name.trim() : "";
  const nameError = validateQueryName(rawName);
  if (nameError) return { ok: false, error: `invalid name: ${nameError}` };
  const name = rawName.replace(/\.$/, "");

  const providerId = typeof body.provider === "string" ? body.provider.trim() : "";
  if (!providerId) return { ok: false, error: "provider is required" };
  const upstream = cfg.upstreams.find((u) => u.id === providerId);
  if (!upstream) return { ok: false, error: `unknown provider "${providerId}"` };

  // types 省略 / "both" -> A + AAAA;否则取 A / AAAA 的任意组合。
  let types: ResolveTestType[];
  if (body.types === undefined || body.types === null || body.types === "both") {
    types = [...RESOLVE_TEST_TYPES];
  } else {
    const list = Array.isArray(body.types) ? body.types : [body.types];
    const wanted: ResolveTestType[] = [];
    for (const item of list) {
      const asText = typeof item === "string" ? item : typeof item === "number" ? String(item) : null;
      if (asText === null) {
        return { ok: false, error: `unsupported type ${JSON.stringify(item)} (only A and AAAA)` };
      }
      const norm = normalizeQType(asText);
      if (!norm || !(RESOLVE_TEST_TYPES as readonly string[]).includes(norm)) {
        return { ok: false, error: `unsupported type ${JSON.stringify(item)} (only A and AAAA)` };
      }
      if (!wanted.includes(norm as ResolveTestType)) wanted.push(norm as ResolveTestType);
    }
    if (wanted.length === 0) return { ok: false, error: "no types selected" };
    // 固定 A -> AAAA 顺序,前端展示稳定。
    types = RESOLVE_TEST_TYPES.filter((t) => wanted.includes(t));
  }

  return { ok: true, input: { name, upstream, types } };
}

// ---------------------------------------------------------------------------
// 查询
// ---------------------------------------------------------------------------

/** 把已校验报文的某个区段转成可展示记录(OPT 不是答案,跳过)。 */
function rrList(records: DnsRecord[] | undefined): ResolveRecord[] {
  const out: ResolveRecord[] = [];
  for (const rr of records ?? []) {
    const type = String(rr.type);
    if (type === "OPT") continue;
    out.push({
      name: rr.name ?? ".",
      type,
      ttl: typeof rr.ttl === "number" ? rr.ttl : null,
      data: renderRdata(rr.type, rr.data),
    });
  }
  return out;
}

/**
 * 直连所选上游查询单个类型。任何失败都收敛成 ok=false 的结果(不抛),
 * 所以一个类型失败不会连累另一个类型。
 */
export async function queryOneType(
  upstream: Upstream,
  name: string,
  type: ResolveTestType,
  opts: { fetchImpl?: FetchLike } = {},
): Promise<ResolveTypeResult> {
  // 随机 TXID + RD=1,不带 EDNS:与线上查询同构,但不注入 ECS —— 面板要展示的是
  // 该服务商对"当前位置的解析器出口"的视图,不是被我们改写过的视图。
  const wire = buildUpstreamQuery({ qname: name, qtype: type, qclass: "IN", cd: false, do: false }, null);

  const attempt = await queryUpstream(
    upstream,
    wire,
    { qname: name, qtype: type, qclass: "IN", opcode: 0 },
    // 用该上游自己配置的超时,不做额外收窄:面板测的就是它"按当前配置"的表现。
    { timeoutMs: upstream.timeout, fetchImpl: opts.fetchImpl },
  );

  if (!attempt.ok || !attempt.answer) {
    return {
      type,
      ok: false,
      error: attempt.error ?? "upstream query failed",
      ...(attempt.timedOut ? { timedOut: true } : {}),
    };
  }

  const answer = attempt.answer;
  const records = rrList(answer.packet.answers);
  const authority = rrList(answer.packet.authorities);
  const result: ResolveTypeResult = {
    type,
    ok: true,
    status: answer.rcode,
    statusText: rcodeText(answer.rcode),
  };
  if (records.length > 0) result.records = records;
  if (authority.length > 0) result.authority = authority;
  // 查询成功但没有该类型记录:与本地 monitor 面板一致的 NODATA 提示。
  if (answer.rcode === 0 && records.length === 0) result.note = "NODATA";
  return result;
}

/** 跑一次解析测试:并行为每个类型直连所选上游查询一次。 */
export async function runResolveTest(input: ResolveTestInput, opts: { fetchImpl?: FetchLike } = {}): Promise<ResolveTestResult> {
  const results = await Promise.all(input.types.map((t) => queryOneType(input.upstream, input.name, t, opts)));
  return {
    name: input.name,
    provider: {
      id: input.upstream.id,
      name: input.upstream.name,
      url: input.upstream.url,
      enabled: input.upstream.enabled,
    },
    results,
  };
}
