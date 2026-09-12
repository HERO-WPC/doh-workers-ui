# ARCHITECTURE.md — Cloudflare Workers DoH Proxy

> 定位:**个人/家庭高性能 Cloudflare DoH Proxy**。不是公共 DNS 平台,不是 Pihole 克隆,不是完整递归解析器。
>
> 核心功能:RFC 8484 DoH + Cache API 缓存 + 多上游(故障转移/Racing/自适应路由)+ 自定义路径 + WebUI + KV 配置持久化。

---

## 一、参考项目分析(Phase 1 结论)

以下结论基于对五个项目 **实际源码** 的阅读(README、核心逻辑、配置、测试),而非仅 README。

### 1. DoHflare(racpast/DoHflare)— License: **AGPL-3.0 + 附加 NOTICE 条款**

单文件 Worker(`src/_worker.js`,约 1300 行),无第三方依赖,无测试。

**值得采用(技术思路):**

| 技术 | 细节 |
|---|---|
| 两级缓存 | isolate 内存 LRU(L1,双上限 2000 条 / 8MB)+ Cache API(L2),L2 命中回填 L1 |
| 确定性 TTL jitter | jitter 因子由 cache key 哈希推导(取哈希末 4 位 hex → ±jitterPercent%),同一 key 在所有 isolate 上得到相同 jitter,天然抗 cache stampede |
| TXID 处理正确 | 生成 cache key 前把报文前 2 字节(TXID)归零;所有响应路径统一经 `patchTransactionId` 用请求者 TXID 覆写缓存数据 |
| ECS 隐私截断 | IPv4 截到 /24、IPv6 截到 /56 才注入;客户端已带 ECS 则透传不改;对无 ECS 客户端从响应中剥离 ECS |
| 写侧纪律 | Cache API 写入前:确定性采样、热 key 强制写、写冷却期、isolate 级写入限速、in-flight 锁;写操作全部 `waitUntil` 异步化,不阻塞响应 |

**值得改进(我们做得更好):**
- 32 位 FNV-1a cache key(仅 ~1600 万空间)且命中时不做全文比对,**碰撞会返回错误域名的记录**。我们改用 SHA-256(128+ bit 有效空间)。
- L2 读写都被 5% 采样门控,冷节点 95% 的域名永远进不了全局缓存。我们改为:读总是尝试,只对写做管控(实际上单飞 + 必写已足够)。
- 每次 L2 命中都返回完整 TTL 并重置 L1 过期时间,数据可被无限"续命"。我们改用 **绝对过期时间戳 + 命中时按 age 递减 TTL**。
- TTL 只有下限钳制(max=1),7 天 TTL 原样进缓存;我们加 MAX_TTL 钳制。
- 对客户端发 `Cache-Control: public, max-age=N`,叠加 per-client TXID 改写后,中间共享缓存可能把 A 客户端的 TXID 答案给 B 客户端。我们对客户端一律 `no-store`,缓存只在自己的两层里做。
- 每请求对报文做 4 次独立全量解析(ECS 校验/注入/TTL 提取/ECS 剥离),CPU 浪费;我们单次解析产出结构化视图。
- `peek()` 降级路径绕过硬过期检查,可服务任意老数据;我们的 stale 有硬上界。

**不应该采用:**
- **AGPL-3.0 + NOTICE**(要求保留署名、修改版必须可区分、仅限研究教育用途)→ **只借鉴设计思路,一行代码都不复制**。
- 单文件巨石架构 + 内嵌 base64 favicon 的 HTML 模板字符串。
- 硬编码区域相关默认值(fallback ECS `119.29.29.0` 等)写死在代码里。
- 零测试。

### 2. DoHp(Rainman69/DoHp)— License: **MIT**

单 Worker(`src/worker.js` 约 590 行)+ 着陆页 + 1 个黑盒 e2e 测试。

**值得采用:**
- **POST→GET 缓存归一化**:POST body base64url 编码后与 GET 走同一条缓存键路径,二进制 POST 流量变得可缓存且与 GET 共享条目。
- **TTL 来自真实 DNS 应答并钳制**:`clampTTL = min(600, max(10, ttl))`,无可用 TTL 时回退 120s。
- **Stale-while-revalidate**:stale 命中立即返回并 `waitUntil` 后台刷新。
- **Provider racing**:按分数排序,`Promise.any` 竞速前 N 个,全部失败再对剩余者做顺序回退;每个上游独立超时。
- **自适应评分公式**(简单可解释):`reliability = (ok+1)/(ok+fails+1)`(Laplace 平滑,未知 → 0.5);RTT 用 EMA(`rtt = rtt*0.7 + sample*0.3`);`score = weight × reliability × 1000 / rtt`。
- **KV 读缓存**:metrics 读结果在 isolate 内存缓存 15s,排序基本不打 KV。
- 上游 fetch 的 TXID 固定为 0 使相同查询字节级一致(可缓存)。

**值得改进:**
- **每次 cache miss 都对同一个 KV key 做 read-modify-write**(核心反模式,正是本规范禁止的)。读有 15s 缓存、写却无节流——模式正好颠倒。我们改为:内存累积 + 写后异步批量刷写(节流),KV 绝不进 DNS 热路径。
- race 赢家决出后 **输家的 fetch 不取消**,白烧 egress 直到各自超时。我们共享 AbortController,赢家决出即 abort 输家。
- race 输家的失败 **不记入 metrics**,可靠性统计失真。我们把每次尝试(无论输赢)都记账。
- 单一 JSON blob 存所有 provider metrics + `expirationTtl: 3600` 滚动续期 → 多 isolate 丢失更新、历史静默清零。我们按 `metrics:<provider-id>` 分 key 存。
- stale 刷新无 single-flight → 热 key 过期瞬间雷群。我们把刷新也并入 single-flight。
- stale 无硬上界,上游全挂时可无限期 STALE。
- IPv6 压缩正则解析是有损的,不要学。

**不应该采用:**
- per-request KV 写入模式(同上)。
- 13KB 内嵌字符串着陆页。
- 无依据的 `cf: { cacheTtl: 60 }` upstream fetch 微优化。

### 3. doh-cf-workers(tina-hello/doh-cf-workers)— License: **0BSD**

56 行透明反向代理,**完全不解析 DNS 报文**。

**值得采用:**
- 返回 fetch Promise 而非在 handler 内 await(Workers 计时/计费优化)。
- POST body 直接传 `request.body` 流,不先 buffer。
- `Accept: application/dns-message` 头语义正确。
- 0BSD,无任何署名约束。

**值得改进(本项目全部修复):**
- 零输入校验(不验 base64url、不限制报文长度、畸形包直接转发上游)。
- 字符串拼接构造上游 URL,query 参数可被破坏。
- 无超时、无重试、无错误处理(上游挂了 → 未处理 rejection → CF 500)。
- 所有不匹配请求共用一个 404:错误的 Content-Type 应为 415,错误方法应为 405,缺 `dns` 参数应为 400。
- Content-Type 比较区分大小写且不容忍参数(`application/dns-message; charset=utf-8` 被拒)。
- 路径前缀匹配漏洞:`/dns-query-evil` 能穿过 `path = '/dns-query'`。
- 上游 URL 硬编码在源码里。
- 无测试(package.json 的 test 是 `exit 1`)。

**不应该采用:**"一切皆 404" 的路由模型;把它当 RFC 8484 语义参考(它只是管道参考)。

### 4. serverless-dns(serverless-dns)— License: **MPL-2.0**

完整递归解析器 + 过滤引擎(数万行),直接读源码确认其缓存设计(`src/plugins/dns-op/cache.js`、`cache-api.js`、`cache-util.js`、`resolver.js`):

**值得采用:**
- **双层缓存 write-through**:`DnsCache` 先查 LFU 内存缓存,miss 查 Cache API,命中后回填内存层(`cache.js:37-64`);写入时两层同写,且 Cache API 写通过 dispatcher 交给 `waitUntil`(`cache.js:87-108`)。
- **缓存元数据放在自定义响应头里**(`x-rdnscache-metadata`:JSON {expiry, ...}),缓存体就是原始 DNS 报文(`cache-util.js:144-162`)。我们采用同样的 header-carrying-metadata 方案。
- **Cache key 归一化**:`normalizeName(qname) + ":" + qtype + (":dnssec" if DO)`,TXID 不参与 key(`cache-util.js:120-127`)。
- **命中时 TXID + TTL 重写**:`updatedAnswer()` = `updateQueryId()`(改回客户端 TXID)+ `updateTtl()`(按剩余时间重算 TTL,过期则给随机 min..max 值打散)(`cache-util.js:109-118, 256-261`)。
- 缓存前 dropOPT;畸形缓存条目解析失败时视为 miss 而非抛异常(`cache.js:141-146, 183-189`)。
- "答案条目不被问题条目覆盖" 的写保护(`cache.js:92-101`)。
- 插件管线式的职责分离(exec → parse → cache → resolve)。

**值得改进:**
- cache key 不含 ECS/CD(它有块列表场景的特殊取舍);我们的 key 必须覆盖 QNAME/QTYPE/QCLASS/DO/CD/ECS。
- TTL 是 `min(answers) + 固定 cacheTtl` 的绝对过期,负缓存的 SOA MINIMUM 有 TODO 未实现;我们完整实现负缓存 TTL。
- 1/6 掷骰子的随机重验证太玄学;我们用确定性 stale 窗口。

**不应该采用(整体):**
- 过滤/块列表引擎、blocklist trie、RethinkDNS 生态绑定——与本项目的轻量定位无关。
- 它的 DoT/UDP 传输层(Workers 上不需要)。
- 整体架构照搬(它要支持 Node/Firefox/Deno 多运行时,抽象层过厚)。

### 5. doh-proxy(dot1mav/doh-proxy)— License: **MIT**

两个独立 Worker 脚本(`index.js` Cloudflare / `arvan.js` Arvan),无缓存、无测试。

**值得采用:**
- 用 **真实 DoH 查询** 做健康探测(example.com A 的预编译 wire-format 查询,测的是端到端路径而非合成 ping)。
- 上游 schema 简洁(`{name, url}` 数组,可用 env 覆盖)。
- Dashboard 交互设计:状态色阈值(<400ms 绿 / 400-800ms 黄 / >800ms 红)、内置 DoH 测试器(浏览器端构造 DNS 报文发 GET/POST)、`X-DoH-Upstream` 透明头。

**值得改进:**
- 零缓存;健康检查随机打一个上游且结果不存储;随机路由无视健康状态;单样本 RTT 无 EMA。

**不应该采用:**
- **整个 `arvan.js`(Arvan Edge Functions 前端)**:厂商锁定、源码内占位符、Persian RTL UI——本项目 100% 只依赖 Cloudflare。
- 无管理 API、无鉴权的 dashboard。

### 6. 参考项目结论 → 本项目架构来源

| 本项目模块 | 主要借鉴 | 主要规避 |
|---|---|---|
| DoH 管道 | doh-cf-workers 的管道形态 + serverless-dns 的解析/校验纪律 | 前者的零校验、后者的体量 |
| 缓存 | DoHflare 两级缓存 + 确定性 jitter;serverless-dns 的 header 元数据 / TXID/TTL 命中重写 / write-through | 32 位 key、L2 采样门控、TTL 续命、`public` 缓存头 |
| 上游/路由 | DoHp 的 racing + 评分公式 + POST→GET 归一化 | per-request KV 写、输家不取消/不记账、单 blob metrics |
| 健康检查/Dashboard | doh-proxy 的真实探测 + UI 阈值 | Arvan 依赖、无鉴权 |
| 协议正确性 | 全部五者的教训汇总(校验矩阵见下) | — |

所有参考项目只借鉴 **思路与公式**,不复制代码(尤其 DoHflare 的 AGPL 附加条款)。唯一引入的第三方运行时依赖是 `dns-packet`(MIT,理由见下)。

---

## 二、总体架构

```
                         ┌────────────────────────────────────────────────┐
 Client ──HTTPS──▶ Worker│  路由层 (src/index.ts)                          │
                         │   ├── GET  /health            → 公开健康        │
                         │   ├── /<custom-path>/dns-query → DoH 管道       │
                         │   ├── /admin/api/*            → Admin API(鉴权)│
                         │   └── 其余                    → Static Assets   │
                         └──────────────┬─────────────────────────────────┘
                                        ▼
              DoH 管道 (src/doh.ts)
   ① 请求解析      GET: base64url 解码 dns 参数 / POST: application/dns-message body
                   大小上限 MAX_DNS_BODY(默认 65535B,超限 413);Content-Type 错 → 415
   ② 报文解析      dns-packet 解码 + 严格校验(空包/过短/坏指针/超长 label → 400 FORMERR)
   ③ 查询归一化    单 question 强制;QNAME 小写;TXID 归零;opcode 仅 QUERY(其余 NOTIMP)
                   ECS 按 mode 处理(off:剥离 / auto:从客户端 IP 截断注入 / fixed:注入固定网段)
   ④ Cache Key     SHA-256("qname|qtype|qclass|do|cd|ecs") → 合成 URL
                   POST 与 GET 在此汇合(DoHp 思路)
   ⑤ L1 查询       isolate LRU(Map,容量 + 字节双上限)——机会性
        ├ HIT(fresh)──▶ TXID 改写 + TTL 递减 ──▶ 返回
        └ STALE(fresh 过期但 < staleTTL)──▶ 立即返回 stale + waitUntil 后台刷新(并入 single-flight)
   ⑥ L2 查询       caches.default.match(合成 URL)→ 命中回填 L1 → 同上
   ⑦ Single-flight 同 key 并发请求共享同一 upstream Promise(模块级 Map,失败/超时必清理)
   ⑧ 上游路由       mode = sequential | race | adaptive
                   sequential:按 priority 顺序故障转移
                   race:前 raceCount 个 Promise.any 竞速(共享 AbortController,赢家出即断输家)
                   adaptive:按评分排序后按 raceCount 竞速(默认)
                   每次尝试独立超时;4xx/5xx/超时/非法响应均触发下一个候选
   ⑨ 响应校验       QR=1、opcode 匹配、qdcount=1、Question(name/type/class)与请求一致;
                   不一致 → 判该上游失败,换下一个(防缓存污染)
   ⑩ TTL 计算      取答案/授权区最小非 OPT TTL;NXDOMAIN/NODATA 用 SOA TTL∧MINIMUM;
                   clamp [minTTL, maxTTL] + 确定性 jitter(由 cache key 哈希推导)
   ⑪ 缓存写入      TXID 归零重编码,绝对过期时间戳放自定义 header,
                   Cache-Control: max-age=fresh+stale;cache.put 走 waitUntil;
                   SERVFAIL/REFUSED/FORMERR 不缓存
   ⑫ 响应客户端     TXID 改写、所有记录 TTL 按 age 递减、Cache-Control: no-store、CORS:*

                         ┌──────────────────────────────────────┐
 WebUI (public/,SPA) ──▶ │ Admin API (src/admin.ts, Bearer 鉴权) │──▶ KV
                         │ config CRUD / upstreams CRUD         │
                         │ stats / health / test-upstream       │
                         │ regenerate-path                      │
                         └──────────────────────────────────────┘
```

### 技术栈

- TypeScript + Cloudflare Workers 模块语法(ES Modules)
- Wrangler 4 + Workers Static Assets(assets binding,WebUI 无需第二台服务器)
- Cache API(L2)、isolate 内存(L1)、KV(仅配置与 provider metrics)
- 第三方运行时依赖 **仅 `dns-packet`(MIT)**:DNS wire format(RFC 1035 压缩指针、EDNS0、全部 RR 类型含 HTTPS/SVCB)是本项目风险最高的手写区域,dns-packet 经过大规模生产验证且体量小(~50KB)。其余(缓存、路由、评分、鉴权、校验)全部手写,无其他依赖。

---

## 三、关键设计决策(必须回答的问题)

### 3.1 为什么用 Cache API 而不是 KV 保存 DNS 响应?

- **规模与速率**:DNS 响应 QPS 高、条目多、生命周期短(TTL 10~600s)。KV 写入有每秒每 key 1 次的配额,put 是全局异步传播(最终一致,约 60s),且按操作计费——把 DNS 响应放 KV 等于把热路径绑到一个为低频配置读写设计的存储上。
- **语义匹配**:Cache API 就是为"短生命周期、按 key 高频读"设计的边缘缓存,`caches.default.put/match` 与同 colo 的后续请求共享,读写在边缘本地完成,无传播延迟,不占 KV 配额。
- **TTL 语义**:Cache API 的 `Cache-Control: max-age` 天然表达"存多久",配合 `Age` 头可直接计算条目年龄,正好支撑我们的 fresh/stale 判定。
- 本项目 KV 只存三个东西:`config`(单 key JSON)、`metrics:<provider-id>`(低频写)、以及它们的内存缓存。**DNS 报文永不进 KV。**

### 3.2 为什么用 KV 保存配置?

- 配置变更极低频(管理员改一次,成千上万次查询),KV 的最终一致性和配额对此完全够用。
- Workers 模块级全局变量跨请求可能存活但 **不保证**,配置必须有一个持久真相源;KV 是不需要 D1/DO 的最轻选项。
- 读侧:配置加载后在 isolate 内存缓存(默认 30s,可调),KV 读取 **绝不进入 DNS 请求关键路径**;代价是路径修改的全局生效存在最长约 "config 缓存 TTL + KV 传播(≤60s)" 的窗口,这是 KV 最终一致性的固有属性,文档如实声明。

### 3.3 为什么自定义路径只是 endpoint hiding,不是强认证?

- 它防护的是 **扫描器与随机探测**:公网上每天都有对 `/dns-query`、`/resolve` 等标准路径的扫描,高熵路径让 DoH endpoint 在扫描噪音中不可见。
- 它不能防护 **定向攻击**:路径会出现在 DNS 客户端配置、TLS SNI 之后的 HTTP 层、浏览器历史、 Referer 与日志里;知道路径的任何人都能无限使用。
- 因此 README 明确写:自定义路径 = 隐藏标准 endpoint、防普通扫描,个人/家庭用途;**不等价于身份认证**。管理面(可修改配置)另用 `ADMIN_SECRET` Bearer 鉴权,与 DoH 面完全分离(见 3.8)。
- 路径生成用 `crypto.getRandomValues()`(CSPRNG,16 字节 → 16 进制 32 字符),拒绝 Math.random/时间戳/固定串;手工设置限定 `[A-Za-z0-9_-]{8,64}`。修改后旧路径在 config 缓存过期后失效(单 isolate 即时,全局 ≤ 缓存 TTL + KV 传播),非当前路径一律 404。

### 3.4 为什么 ECS 默认关闭?

- ECS 把"一个域名一个答案"变成"一个域名 × N 个网段 N 个答案",**cache key 按 ECS 前缀碎片化**,命中率显著下降——对个人/家庭场景,命中率损失通常大于 CDN 调度收益。
- 注入 ECS 还会把用户网段信息泄露给上游。
- 因此 `ecs.mode` 提供 `off`(默认:剥离客户端 ECS,保证缓存统一)/ `auto`(从 CF-Connecting-IP 截断 IPv4/24、IPv6/56 注入,且进 cache key)/ `fixed`(注入管理员固定网段)。三档均参与 cache key,绝不出现"带 ECS 的答案与不带 ECS 的请求共享缓存"。

### 3.5 为什么请求合并(single-flight)只能是 opportunistic?

- single-flight 依赖模块级 `Map`,而 Workers isolate 是 **按需创建、随时回收** 的:冷启动后 Map 为空,不同 colo、甚至同 colo 的不同 isolate 之间互不可见。
- 它只能降低 **同一 isolate 内** 的并发重复回源,是概率性优化,不是正确性保证。全局去重由 Cache API 天然承担(miss 后第一个写入者生效,其余请求读缓存)。
- 实现上必须保证:Promise 失败/超时/成功都要从 Map 清除(finally),否则泄漏会放大到 isolate 生命周期;stale 后台刷新也并入同一 Map 防雷群。

### 3.6 为什么不能假定 Cache API 是全球统一共享数据库?

- `caches.default` 是 **每 colo(每数据中心)独立** 的:put 只写入处理该请求的 colo,其他 colo 首次访问仍是 miss。
- 写入传播无 SLA、无失效 API;同一 colo 内也可能因容量被驱逐。
- 因此设计上:缓存命中是 **性能优化**,miss 是 **常态路径**;任何上游都必须随时能服务全量流量;metrics/health 不依赖缓存状态;文档不宣称"全球命中率"。

### 3.7 为什么 racing 不能无限增加 provider?

- Workers **subrequest 限制**(免费版 50/请求,付费 1000):每个 racing 候选 + 每次故障转移 + cache.put 都消耗额度;raceCount 无上界会把一次 miss 变成十几次 subrequest,还可能在免费额度下直接 1102 报错。
- racing 的收益边际递减:前 2~3 个上游已覆盖最优 RTT,第 8 个上游的 fetch 只会在它超时前占用连接与 CPU,还互相抢出口带宽。
- 同时竞速的上游越多,**输家的浪费请求越多**(即使有 abort,也有竞态窗口)。所以 `raceCount` 钳制为 1~4(默认 2),racing 只取评分最高的前 N 个,其余按序作 failover 候选。

### 3.8 DoH 面与 Admin 面为什么必须完全分离?

- DoH 路径的知识 ≠ 管理员身份。`/<custom-path>/dns-query` 永远只处理 DNS,不可能触达配置;`/admin/api/*` 一律要求 `Authorization: Bearer $ADMIN_SECRET`(Worker Secret,不在 KV、不进 Git),比较用常数时间算法。
- CORS 分别设置:DoH 响应 `Access-Control-Allow-Origin: *`(浏览器端 DoH 客户端需要);Admin API **不返回任何 CORS 头**(仅同源 WebUI 使用),即使持有 secret 的浏览器跨站调用也会被浏览器侧拦截。
- 方法严格匹配:Admin API 非定义方法 → 405;未认证 → 401;错误体 → 400。

### 3.9 其余值得记录的决策

- **对客户端 `Cache-Control: no-store`**:我们自己管理两级缓存;对外发可缓存头会让中间共享缓存绕过 TXID 改写,产生跨客户端串号。
- **确定性 jitter**(DoHflare 思路,自行实现):jitter 因子 = f(cache key SHA-256 末 4 hex),同 key 恒定,跨 isolate 一致,防 stampede 又可复现;结果仍被 [minTTL, maxTTL] 钳制。
- **上游请求 TXID 用随机值**(DoH 走 TLS,TXID 不承担 UDP 的防伪造职责),缓存条目 TXID 归零存储。
- **SERVFAIL/REFUSED 不缓存**(不把上游瞬时故障固化),NXDOMAIN/NODATA 按 SOA 负 TTL 缓存。
- **Provider metrics 写后批量刷**:内存累积,距上次刷写 ≥30s 时经 `waitUntil` 异步落 KV,失败静默(下次再试);DNS 请求关键路径零 KV IO。
- **统计的诚实性**:counters 是 **per-isolate** 的,`/admin/api/stats` 如实标注"单 isolate 近似值",不伪装全局精确计数。

---

## 四、模块划分

```
src/
├── index.ts      Worker 入口 + 路由(method/path 分发,405/404)
├── doh.ts        RFC 8484 GET/POST 入口 → 统一管线
├── dnsmsg.ts     报文解析/校验/归一化/TXID/TTL/RR 遍历(封装 dns-packet)
├── ecs.ts        EDNS Client Subnet 构造/解析/剥离
├── cachekey.ts   归一化 cache key(canonical string → SHA-256 → 合成 URL)
├── cache.ts      L1 LRU + L2 Cache API + fresh/stale 判定 + 命中改写
├── upstream.ts   上游 fetch(超时/中断)、响应校验、健康探测
├── routing.ts    sequential/race/adaptive 候选排序与执行、故障转移
├── metrics.ts    provider 评分数据结构、EMA/Laplace、KV 写后批量刷、isolate 统计
├── config.ts     默认值、schema 校验、KV 读写、isolate 配置缓存
├── auth.ts       常数时间 secret 比较
├── admin.ts      /admin/api/* 处理器
├── pathgen.ts    CSPRNG 路径生成与校验
├── httputil.ts   错误响应、CORS、Content-Type 处理
└── types.ts      Env / Config / Upstream / Metrics 类型
public/           WebUI(纯静态 SPA:index.html + app.js + style.css,无框架)
test/             vitest:协议、缓存、上游、路由、鉴权、admin、e2e(注入 fake fetch/KV/caches)
```

依赖方向(单向,无环):`index → doh → {dnsmsg, ecs, cachekey, cache, routing} → {upstream, metrics, config}`;`admin → {config, metrics, upstream, auth, pathgen}`。DNS/Cache/Upstream/Config/Admin 职责分离。

## 五、KV Schema

| Key | 值 | 写入时机 |
|---|---|---|
| `config` | `{version, updatedAt, doh{path}, cache{minTTL,maxTTL,staleTTL,jitterPercent,maxBody}, routing{mode,raceCount,timeout}, ecs{mode,ipv4Prefix,ipv6Prefix,fixedSubnet}, upstreams[{id,name,url,enabled,priority,timeout}]}` | 仅 Admin API 写;isolate 内存缓存 30s |
| `metrics:<provider-id>` | `{ok, fail, timeout, rttEma, lastSuccess, lastFailure, updatedAt}` | 内存累积,≥30s 节流异步刷写 |

配置经 schema 校验(手写校验器):非法值回退默认/整段拒绝,保证坏配置不会让 Worker 崩溃;每次保存原子覆盖 `config` 单 key。

## 六、错误码矩阵

| 场景 | 状态 |
|---|---|
| GET 缺 dns 参数 / base64 非法 / 报文畸形 | 400 |
| POST Content-Type 非 application/dns-message | 415 |
| 报文超过 MAX_DNS_BODY(GET/POST 同限) | 413 |
| 非当前自定义路径 / 未知路径 | 404 |
| Admin 未认证 / secret 错误 | 401 |
| Admin 方法不匹配 | 405 |
| opcode 非 QUERY(可解析时) | DNS NOTIMP 响应 |
| 全部上游失败 | 502 |
| 上游全超时 | 504 |
| 未捕获内部错误 | 500(兜底,畸形输入永远到不了这里) |

## 七、Cloudflare 限制对照

| 限制 | 本项目的应对 |
|---|---|
| subrequest 上限(免费 50/req) | miss = 1~raceCount 次 upstream fetch + 1 次 cache.put;raceCount ≤ 4;failover 候选数即上游数,正常 ≤ 3~5 |
| isolate 随时回收 | single-flight/L1/统计全部声明为机会性;正确性只依赖 L2 + 上游 |
| Cache API per-colo | miss 是常态路径;文档如实说明命中率是 per-colo 的 |
| KV 最终一致(读 ~60s 传播) | 配置缓存 30s;路径修改的失效窗口如实写进 README |
| CPU 时间 | dns-packet 单次解码 + 少量字节操作;racing 用 abort 及时止损 |
| 无后台常驻 | 健康探测是 **请求驱动** 的(admin 面板打开时手动/按需探测),不制造无谓上游流量;metrics 刷写挂在请求的 waitUntil 上 |
