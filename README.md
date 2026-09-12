# doh-workers-ui

> 运行在 Cloudflare Workers 上的个人/家庭高性能 DoH( DNS over HTTPS ) Proxy。
> RFC 8484 · Cache API 边缘缓存 · 多上游(故障转移 / 竞速 / 自适应路由) · 自定义路径 · WebUI 管理后台 · KV 配置持久化。

不依赖 VPS、Docker、Node 常驻进程或外部数据库 —— 整个项目 100% 跑在 Cloudflare 边缘:Workers + KV + Cache API + Workers Static Assets。

**架构与设计决策详见 [ARCHITECTURE.md](./ARCHITECTURE.md)**(含五个参考项目的逐项源码分析与取舍理由)。

---

## 目录

1. [项目简介](#项目简介)
2. [架构](#架构)
3. [功能](#功能)
4. [快速部署](#快速部署)
5. [自定义路径](#自定义路径)
6. [WebUI](#webui)
7. [KV](#kv)
8. [Cache](#cache)
9. [多上游](#多上游)
10. [Provider Racing](#provider-racing)
11. [Adaptive Routing](#adaptive-routing)
12. [TTL](#ttl)
13. [Stale-While-Revalidate](#stale-while-revalidate)
14. [ECS](#ecs)
15. [安全](#安全)
16. [隐私](#隐私)
17. [Cloudflare 限制](#cloudflare-限制)
18. [配置说明](#配置说明)
19. [测试](#测试)
20. [DoH 测试命令](#doh-测试命令)
21. [故障排查](#故障排查)
22. [优选 IP 测试](#优选-ip-测试)
23. [License 与第三方项目参考](#license-与第三方项目参考)

---

## 项目简介

这是一个 **轻量 DoH 代理**,不是完整递归解析器,不是 Pihole 克隆,不是公共 DNS 服务平台:

- 客户端发标准 RFC 8484 DoH 请求(GET base64url / POST binary)到你的 Worker;
- Worker 检查自定义路径(防扫描),解析并规范化 DNS 报文;
- 先查两级缓存(isolate 内存 L1 + Cloudflare Cache API L2);
- 未命中经 single-flight 合并并发,再按 adaptive / race / sequential 策略选上游;
- 上游响应经严格校验(Question 回显、TXID、QR、opcode)后才进入缓存;
- TTL 按 [MIN_TTL, MAX_TTL] 钳制 + 确定性 jitter,NXDOMAIN/NODATA 负缓存,SERVFAIL 永不缓存;
- 每个响应按客户端 TXID 重写、按缓存年龄递减 TTL 后返回。

设计原则(优先级从高到低):**协议正确 > 缓存正确 > 上游容错 > 安全 > 性能 > WebUI**。

## 架构

```
Client ──HTTPS──▶ Worker 路由
                   ├── GET  /health              公开健康检查
                   ├── /<custom-path>/dns-query  DoH 管道(GET/POST 同管线)
                   ├── /admin/api/*              Admin API(Bearer 鉴权)
                   └── 其余                      Static Assets(WebUI)
DoH 管道: parse → normalize → ECS 策略 → SHA-256 cache key
        → L1(isolate LRU) → L2(Cache API) → single-flight
        → 上游路由 → 响应校验 → TTL 钳制+jitter → 缓存写(waitUntil) → 响应
```

完整管线图、模块依赖、KV schema、错误码矩阵见 [ARCHITECTURE.md](./ARCHITECTURE.md)。

## 功能

- ✅ RFC 8484 GET + POST,统一 DNS pipeline(非 JSON DNS API)
- ✅ Cloudflare Cache API 边缘缓存 + isolate 内存 L1
- ✅ 多上游,可增删改启停排序,内置 Cloudflare / Google / Quad9
- ✅ Provider Failover(超时 / 非 2xx / 非法响应 / 网络异常均触发)
- ✅ Provider Racing(Promise.any,赢家出即 abort 输家)
- ✅ Adaptive Routing(RTT EMA + Laplace 可靠性评分,评分排序)
- ✅ Request Coalescing(single-flight,失败/超时必清理)
- ✅ TTL 钳制 + 确定性 jitter(基于 cache key 哈希,抗 stampede)
- ✅ Negative Cache(NXDOMAIN/NODATA 按 SOA 负 TTL),SERVFAIL 永不缓存
- ✅ Stale-While-Revalidate(硬上界 staleTTL,后台刷新并入 single-flight)
- ✅ Transaction ID 重写 + 命中按年龄递减 TTL(缓存条目 TXID=0 存储)
- ✅ 响应校验(Question 回显匹配),防缓存污染
- ✅ 自定义路径(CSPRNG 生成 / 手工设置 / 一键重生成,旧路径失效)
- ✅ WebUI(Dashboard / Upstreams / Cache / ECS / 路径,零框架纯静态)
- ✅ Admin API 全量鉴权(Worker Secret,常数时间比较)
- ✅ ECS(off / auto / fixed,默认 off,参与 cache key)
- ✅ 畸形报文防护(空包/过短/坏指针/超长 label/超大 body → 400/413,Worker 不崩)

## 快速部署

```bash
# 0. 要求:Node 18+,npm
npm install

# 1. 创建 KV namespace,把输出的 id 填进 wrangler.jsonc
npx wrangler kv namespace create CONFIG_KV

# 2. 设置管理密码(WebUI / Admin API 用)
npx wrangler secret put ADMIN_SECRET

# 3. 本地开发(可选)
npm run dev          # wrangler dev,WebUI 在 http://localhost:8787

# 4. 测试 + 构建
npm test
npm run build        # wrangler deploy --dry-run

# 5. 部署
npm run deploy
```

部署后:

1. 打开 `https://<your-worker>.workers.dev/`,输入 ADMIN_SECRET 登录;
2. Dashboard 会显示完整的 DoH URL(形如 `https://<your-worker>.workers.dev/<随机路径>/dns-query`);
3. 把该 URL 填入浏览器(如 Chrome 的 Secure DNS)、手机(Private DNS 需 DoT 的话用网关方案)、路由器(OpenWrt/AdGuard Home 支持 DoH)或任何 DoH 客户端。

敏感信息只有 `ADMIN_SECRET`(Worker Secret,不进 Git、不进 KV);KV id 只是非机密资源标识。

## 自定义路径

DoH endpoint 形如:

```
https://dns.example.com/8f7c2d91e43ab67f/dns-query
                        └────── 高熵前缀 ──────┘└─固定─┘
```

- 初始化时自动用 `crypto.getRandomValues()`(CSPRNG,16 字节 hex)生成,绝不使用 Math.random / 时间戳 / 固定串;
- WebUI 可查看 / 复制 / 手工修改(8-64 位 `[A-Za-z0-9_-]`)/ 一键重生成;
- 修改后旧路径 **立即在本 isolate 失效**,全局生效窗口 ≈ 配置缓存 TTL(默认 30s)+ KV 传播(≤60s);
- 非当前路径一律 404;`/dns-query`、`/admin`、`/resolve` 等常见路径 **默认都不是** DoH 入口。

**安全模型(重要)**:自定义路径是 *endpoint hiding*(隐藏标准 endpoint、躲避扫描器),用于个人/家庭场景。
它 **不是强认证** —— 路径会出现在客户端配置、浏览器历史里,知道路径的人都能使用。
管理能力与 DoH 面完全分离,修改配置必须持有 `ADMIN_SECRET`。

## WebUI

Workers Static Assets 提供,无需第二台服务器。登录后五个页面:

| 页面 | 内容 |
|---|---|
| Dashboard | Worker 状态 / 版本 / KV 可达性 / DoH URL(一键复制)/ 运行统计(明确标注"单 isolate 近似值")/ 上游健康与 RTT |
| Upstreams | 添加 / 编辑 / 删除 / 启用禁用 / 优先级 / 超时 / 一键测试(实时 RTT) |
| Cache & Routing | MIN/MAX/STALE TTL、jitter、最大报文、路由模式、raceCount |
| ECS | 模式(off/auto/fixed)、IPv4/IPv6 前缀、固定网段 |
| 自定义路径 | 当前路径 + 完整 DoH URL、复制、手工修改、一键重生成 |

登录态保存在 sessionStorage,关标签即失效;Admin API 无任何 CORS 头,仅同源可用。

## KV

KV **只存两样东西**(DNS 响应永远不进 KV,详见 ARCHITECTURE.md §3.1/3.2):

| Key | 内容 | 写入时机 |
|---|---|---|
| `config` | 完整配置(路径/缓存/路由/ECS/上游),schema 校验后原子覆盖 | 仅 Admin API 保存时 |
| `metrics:<provider-id>` | 单个上游的 ok/fail/timeout 计数、RTT EMA、最近成败时间 | 内存累积,**≥30s 节流**后经 `waitUntil` 异步刷写 |

DNS 请求关键路径 **零 KV IO**:配置加载后在 isolate 内存缓存(默认 30s,`CONFIG_CACHE_TTL` 可调);KV 最终一致性意味着路径修改有生效窗口,如实声明而非伪装实时。

## Cache

两层,职责严格分离:

- **L1**:isolate 内存 LRU(默认 1000 条 / 4MB),机会性,不同 isolate/colo 不共享;
- **L2**:`caches.default`(Cloudflare Cache API),按 colo 存储;命中回填 L1。

规则:

- Cache key = SHA-256(`qname小写|qtype|qclass|do|cd|ecs`),TXID 不参与;
- GET 与 POST 归一化后共享缓存;
- 条目带绝对时间戳元数据,age 从存储时刻起算,反复命中不会"续命";
- fresh(≤TTL)直接返回;stale(≤TTL+staleTTL)返回旧值并后台刷新;超期彻底作废;
- 对客户端一律 `Cache-Control: no-store`(缓存只在自己两层里做,防止共享缓存绕过 TXID 改写)。

## 多上游

```jsonc
{
  "id": "cloudflare", "name": "Cloudflare",
  "url": "https://cloudflare-dns.com/dns-query",
  "enabled": true, "priority": 1, "timeout": 2500
}
```

上游逻辑完全配置化,绝无 `if cloudflare else google` 硬编码。内置三个默认上游(Cloudflare / Google / Quad9),WebUI 增删改。上游 URL 强制 HTTPS、禁止凭据与危险 scheme(SSRF 防护)。

故障转移覆盖:超时(默认 2500ms,可按上游配置)、HTTP 非 2xx、Content-Type 不对、报文畸形、Question 回显不匹配。

## Provider Racing

`routing.mode = "race"`(或 adaptive)时,前 `raceCount`(1-4,默认 2)个上游并发竞速,**第一个合法响应胜出,其余立即 abort**(输家不浪费 egress,也不记为失败以免污染评分)。

为什么 raceCount 有上限?每次竞速消耗 subrequest(免费版每请求 50 个),且 2~3 个上游已覆盖最优 RTT,再多只是烧资源 —— 详见 ARCHITECTURE.md §3.7。

## Adaptive Routing

默认模式。综合每个上游的:

- **可靠性** = `(ok+1) / (ok+fail+timeout+2)`(Laplace 平滑,新上游 = 0.5)
- **RTT EMA** = `旧值×0.7 + 本次×0.3`(未知默认 150ms)
- **score** = `reliability × 1000 / rtt`

按 score 降序取前 raceCount 个竞速,其余按序作 failover 候选。所有尝试(成败、输赢)都记账;指标 KV 写入与 DNS 热路径完全解耦(≥30s 节流刷写)。

## TTL

- 真实 TTL 优先:取答案区最小 TTL;
- NXDOMAIN/NODATA:SOA 负 TTL = `min(SOA.ttl, SOA.MINIMUM)`,无 SOA 回退 MIN_TTL;
- 钳制 `[minTTL, maxTTL]`(默认 [10, 600]);
- **确定性 jitter**:因子由 cache key 哈希末 4 hex 推导(±jitterPercent%),同 key 在所有 isolate 上得到相同因子 —— 抗 cache stampede 且可复现,不像随机 jitter 每请求漂移;
- TTL=5s 不会被拉长到 10 分钟(TTL 只会在钳制+jitter 范围内变化,且永不突破 MAX_TTL);
- SERVFAIL/REFUSED/FORMERR **不缓存**。

## Stale-While-Revalidate

fresh 过期但仍在 `staleTTL`(默认 86400s)内:立即返回旧值并 `waitUntil` 后台刷新。刷新走同一 single-flight Map,不会雷群。stale 有 **硬上界**(fresh+stale),上游全挂也不会无限期供旧数据。

## ECS

| 模式 | 行为 |
|---|---|
| `off`(默认) | 剥离客户端 ECS,不注入。缓存 key 统一,命中率最大 |
| `auto` | 从 `CF-Connecting-IP` 截断派生(IPv4 /24、IPv6 /56,可配)注入;客户端自带 ECS 时钳制到不超过配置粒度 |
| `fixed` | 注入管理员固定网段(如 `203.0.113.0/24`) |

ECS 永远参与 cache key,绝不出现"带 ECS 的答案被无 ECS 请求命中"。默认关闭的理由(ECS 碎片化缓存 + 泄露粗粒度位置)见 ARCHITECTURE.md §3.4。

## 安全

- **DoH 面 / Admin 面完全分离**:知道 DoH 路径拿不到任何管理能力;Admin API 每个端点都要求 `Authorization: Bearer $ADMIN_SECRET`,常数时间比较(SHA-256 后逐字节异或);
- Admin API 不返回 CORS 头(仅同源 WebUI);DoH 端点才有 `Access-Control-Allow-Origin: *`;
- 上游 URL 强制 HTTPS、禁凭据、禁 `file:`/`ftp:`/`data:` 等 scheme;
- 报文防护:空包/过短(<12B)/超长(>65535B)/坏指针/超深压缩指针/截断 question 全部拒绝(dns-packet 抛错即 400),POST body 超限 413,Content-Type 错 415,方法错 405;
- 缓存污染防御:上游响应的 TXID / QR / opcode / Question(name+type+class)必须与请求一致才可入缓存;
- 客户端响应 `no-store`,中间缓存不可能跨客户端串 TXID。

## 隐私

- **默认不持久化任何 DNS 查询内容**:不记 QNAME、不记客户端 IP、不存完整 DNS 报文;
- 无日志系统、无查询日志存储;`observability` 仅用于 Workers 自身错误采样;
- provider metrics 只有聚合计数(次数、RTT 均值),无域名、无时间序列明细;
- ECS 默认 off,不向上游泄露任何位置信息;auto 模式也只发送截断后的网段。

## Cloudflare 限制

如实声明(设计如何应对见 ARCHITECTURE.md §七):

- **Cache API 是 per-colo 的**:put 只影响当前数据中心,没有全球失效 API。命中率是每 colo 的,不存在"全球统一缓存";
- **isolate 随时回收**:single-flight、L1、isolate 统计都是机会性优化,正确性只依赖 L2 + 上游;
- **KV 最终一致**:配置/路径修改全局生效有窗口(缓存 TTL + ≤60s 传播);
- **subrequest 限额**(免费 50/请求):一次 miss = 1~raceCount 次上游 fetch + 1 次 cache.put,raceCount ≤ 4 保证余量;
- **统计是 per-isolate 的**:WebUI 如实标注"近似值",不伪装全局实时计数。

## 配置说明

完整配置(KV `config` key,由 WebUI/Admin API 管理,通常无需手写):

```jsonc
{
  "version": 1,
  "doh":    { "path": "/8f7c2d91e43ab67f/dns-query" },
  "cache":  { "minTTL": 10, "maxTTL": 600, "staleTTL": 86400, "jitterPercent": 10, "maxBody": 65535 },
  "routing":{ "mode": "adaptive", "raceCount": 2 },
  "ecs":    { "mode": "off", "ipv4Prefix": 24, "ipv6Prefix": 56, "fixedSubnet": "" },
  "upstreams": [
    { "id": "cloudflare", "name": "Cloudflare", "url": "https://cloudflare-dns.com/dns-query", "enabled": true, "priority": 1, "timeout": 2500 },
    { "id": "google",     "name": "Google",     "url": "https://dns.google/dns-query",         "enabled": true, "priority": 2, "timeout": 2500 }
  ]
}
```

Wrangler 侧(`wrangler.jsonc`):

| 绑定/变量 | 说明 |
|---|---|
| `CONFIG_KV` | KV namespace(存 config + metrics) |
| `ASSETS` | Static Assets 绑定(`public/`,SPA fallback) |
| `ADMIN_SECRET` | Worker Secret:`npx wrangler secret put ADMIN_SECRET` |
| `CONFIG_CACHE_TTL` | 配置 isolate 缓存秒数(默认 30) |

Admin API 一览(全部需鉴权,方法不符 405):

```
GET    /admin/api/config            PUT    /admin/api/config
GET    /admin/api/upstreams         POST   /admin/api/upstreams
PUT    /admin/api/upstreams/:id     DELETE /admin/api/upstreams/:id
POST   /admin/api/test-upstream     POST   /admin/api/regenerate-path
GET    /admin/api/stats             GET    /admin/api/health
GET    /health (公开,仅存活信息)
```

## 测试

```bash
npm test        # vitest,121 个断言组
npm run typecheck
npm run build   # wrangler deploy --dry-run
```

覆盖矩阵(测试文件对应 `test/`):

- **DoH**:GET / POST / Content-Type / binary wire / 畸形包(空、过短、截断、坏指针、多 question、QR 位)
- **DNS**:A / AAAA / CNAME / TXT / MX / NS / SOA / HTTPS(SVCB,opaque 透传) / NXDOMAIN / NODATA / TXID 重写 / TTL 老化
- **Cache**:HIT / MISS / TTL / stale / 过期 / 负缓存 / cache key(QTYPE/DO/CD/ECS 区分、QNAME 大小写不敏感)/ 确定性 jitter 边界 / LRU / Cache API 故障降级
- **Upstream**:正常 / 500 / 非 2xx / 错误 Content-Type / 畸形响应 / Question 不匹配 / 超时 / 外部 abort
- **Routing**:priority 顺序 / failover / racing + 输家 abort / raceCount / adaptive 评分排序 / 输赢记账
- **Custom Path**:正确路径 / 错误路径 404 / 修改路径 / regenerate / 旧路径失效
- **Admin**:未认证 401 / 认证 / 配置改写持久化 / provider 增删改 / 重复 id 409 / 405 / 415 / 400
- **Security**:超大 body 413 / 畸形 DNS 400 / 非法 upstream URL(http、file、凭据)/ 全上游失败 502 / 无认证不可改配置

## DoH 测试命令

部署后把 `<HOST>` 和 `<PATH>` 换成你的域名与自定义路径:

```bash
# 1. 标准 DoH GET(A 记录)
curl -s "https://<HOST>/<PATH>/dns-query?dns=$(printf '\xab\xcd\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01' | base64 | tr '+/' '-_' | tr -d '=')" \
  | xxd | head

# 2. 标准 DoH POST
printf '\xab\xcd\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01' > /tmp/q.bin
curl -s -H "content-type: application/dns-message" --data-binary @/tmp/q.bin \
  "https://<HOST>/<PATH>/dns-query" | xxd | head

# 3. 用 dig 直接测 DoH(需要 dig 9.18+)
dig +https @<HOST> -p 443 example.com A

# 4. 错误路径(应为 404)
curl -s -o /dev/null -w "%{http_code}\n" "https://<HOST>/dns-query?dns=abcd"

# 5. 错误 Content-Type(应为 415)
curl -s -o /dev/null -w "%{http_code}\n" -H "content-type: application/json" \
  --data-binary @/tmp/q.bin "https://<HOST>/<PATH>/dns-query"

# 6. 缓存命中(第二次请求看 x-doh-cache: HIT)
curl -s -D - -o /dev/null "https://<HOST>/<PATH>/dns-query?dns=<base64url>" | grep -i x-doh-cache

# 7. 公开健康检查
curl -s https://<HOST>/health

# 8. Admin(替换 secret)
curl -s -H "Authorization: Bearer <ADMIN_SECRET>" https://<HOST>/admin/api/stats
```

第 1/2 条中手工构造的是标准 example.com A 查询报文(TXID 0xabcd)。

## 故障排查

| 现象 | 排查 |
|---|---|
| DoH 一直 404 | 部署后先打开一次 WebUI/Dashboard(触发 KV 初始化);确认访问的路径与 Dashboard 显示一致;KV id 是否正确填入 wrangler.jsonc |
| 改了路径旧路径还能用 | 设计如此:全局生效需 ≈30s 缓存 + ≤60s KV 传播;确认客户端真的更新了 URL |
| Admin 一直 401 | `wrangler secret put ADMIN_SECRET` 是否执行;请求头是否 `Authorization: Bearer <secret>`;secret 为空时默认全部拒绝 |
| 缓存从不 HIT | Cache API 是 per-colo 的,跨地区测试各自都是 MISS 属正常;同一 colo 连续两次同查询应 HIT(注意 TXID/qtype/DO/ECS 必须一致才共享 key) |
| 上游经常 502/504 | WebUI → Upstreams → 测试各上游;检查本机/区域对上游的连通性;适当调大 per-upstream timeout |
| 想要更激进的延迟 | `routing.mode: race`、调大 `raceCount`(≤4)、降低 staleTTL;subrequest 消耗会上升 |
| KV 不可用 | Worker 自动降级为默认配置继续服务(日志有告警);恢复后自动接回 |
| 免费版额度 | 每请求 subrequest = 竞速数 + failover 次数 + 1(cache.put),默认配置最坏 ~5,余量充足 |

## 优选 IP 测试

`tools/test-cf-ip.mjs` 用于测试一批候选 IP 能否作为 **Cloudflare 边缘反代**加速你的 DoH 访问(即"优选 IP"):向 `IP:port` 发起 TLS,SNI/Host 填你的域名,然后三重校验——① TLS 握手成功且证书属于你的域名;② `GET /health` 返回本 Worker 的 JSON;③ 真实 DoH 查询返回 200 且带 `x-doh-cache` 头。三关全过才算可用,避免"端口通但不是你的服务"的假阳性。

```bash
# 直接测几个 IP
node tools/test-cf-ip.mjs 104.16.0.1 172.64.0.1

# 测自定义路径的 Worker(Git Bash 下路径省略前导 /,避免 MSYS 路径转换)
node tools/test-cf-ip.mjs --in 优选IP.csv --path <你的密钥路径>/dns-query --rounds 3 --out 可用IP.txt

# 主要选项
#   --in <文件>        输入:CSV(含 ip/port 列)/ JSON 数组(字符串或 {ip,port} 对象)/ 纯文本行
#   --domain <域名>    目标域名(默认 query-ui.example.com,按需修改)
#   --path <路径>      DoH 路径(默认 /dns-query;自定义路径必须传)
#   --rounds N         DoH 测速轮数(默认 2)  --concurrency N(默认 8)  --timeout ms(默认 5000)
#   --out <文件>       把全部可用 IP 写入文件
```

测出可用 IP 后的使用方法:

- **Windows**:管理员编辑 `C:\Windows\System32\drivers\etc\hosts`,加一行 `<优选IP>  <你的域名>`(如 `104.16.0.1  query-ui.example.com`);
- **路由器 / AdGuard Home**:为该域名配置自定义解析指向优选 IP;
- 只影响这一个域名,不影响其他网站;`workers.dev` 域名无法这样绑定,必须是绑定到 Worker 的自定义域名。

注意事项:

1. **优选 IP 会失效**(对端服务器调整、SNI 路由变化),建议定期重测并保留多个备选;
2. 非 Cloudflare 网段的 IP(扫描得到的"反代 IP")绝大多数过不了校验,属预期——工具的作用就是实测筛出极少数真正可用的;
3. 若要自行海选,可对 Cloudflare 官方网段(104.16.0.0/13、172.64.0.0/13 等)测速后用本工具验证;
4. `--out` 输出只包含"当前可用",不构成任何持久承诺,对端服务与你无任何协议关系。

### 对外分发:让所有人零配置获得优选加速

优选 IP 写在 hosts 里只对本机生效。要让所有用户都走优选 IP,利用 zone 的 DNS 控制权做"灰云 A 记录 + Worker 路由":

1. **DNS**:在 zone 上为加速主机名(如 `fast.example.com`)添加多条 **A 记录,Proxy status = DNS only(灰云)**,直指优选 IP——多条自动轮询,单个失效客户端自动尝试下一个;
2. **路由**:`wrangler.jsonc` 里给 Worker 加路由 `{ "pattern": "fast.example.com/*", "zone_name": "example.com" }` 并部署;
3. 用户使用 `https://fast.example.com/<自定义路径>/dns-query` 即可——DNS 直接解析到优选 IP,优选服务器按 SNI 把流量送回 CF 边缘,路由触发 Worker 执行。

注意:

- 加速主机名 **不能** 同时绑定为 Worker Custom Domain(Custom Domain 强制橙云、解析到 CF 边缘,与灰云 A 记录冲突;误绑需到 Worker 的 Settings → Domains & Routes 里删除);
- 保留一个橙云 Custom Domain 作为**保底入口**:优选 IP 全部失效时它仍走 CF 默认边缘,不受影响;
- 优选 IP 失效时只需改 DNS 记录,所有用户即时生效(无需任何人改本地配置);
- 优选服务器是第三方,DoH 全程 HTTPS,其仅能看到 SNI 域名与流量大小,无查询内容泄露。

## License 与第三方项目参考

本项目代码以 **MIT** 发布(见 LICENSE)。

参考项目(仅借鉴设计思路与公开公式,未复制代码;各自的 License 如实标注):

| 项目 | 借鉴点 | License |
|---|---|---|
| [DoHflare](https://github.com/racpast/DoHflare) | 两级缓存、确定性 TTL jitter、TXID 归零重写、ECS 截断、写侧纪律 | AGPL-3.0(+NOTICE)——**因此本仓库一行代码都未复制** |
| [DoHp](https://github.com/Rainman69/DoHp) | POST→GET 归一化、racing、评分公式(EMA + Laplace)、KV 读缓存 | MIT |
| [doh-cf-workers](https://github.com/tina-hello/doh-cf-workers) | 流式转发、计费友好的 fetch 模式、Accept 头语义 | 0BSD |
| [serverless-dns](https://github.com/serverless-dns/serverless-dns) | 双层缓存 write-through、header 携带缓存元数据、命中时 TXID/TTL 重写 | MPL-2.0 |
| [doh-proxy](https://github.com/dot1mav/doh-proxy) | 真实查询健康探测、Dashboard 状态阈值、X-DoH-Upstream 透明头 | MIT |

第三方依赖:

- [dns-packet](https://github.com/mafintosh/dns-packet)(**MIT**)—— DNS wire format 编解码(RFC 1035 压缩指针、EDNS0、标准 RR 类型;SVCB/HTTPS 等以 opaque 方式无损透传)。引入理由:报文解析是本项目风险最高的手写区域,dns-packet 经大规模生产验证且体量小;这是唯一的运行时依赖。

各参考项目的详细源码分析(采用/改进/不采用)见 [ARCHITECTURE.md](./ARCHITECTURE.md) 第一节。
