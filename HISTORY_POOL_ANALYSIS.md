# 历史可用节点池机制分析（vs Delta-Kronecker/Vpn-Gate）

> 分析对象：`vpngate.py` 引入"历史池"机制的提议
> 参考仓库：https://github.com/Delta-Kronecker/Vpn-Gate（已通读其 main.py + workflow 源码）
> 日期：2026-10-12

## 一句话结论

**机制方向正确（历史池 + 每轮重测 + 提交回仓库持久化是成立的容错模式），但有两处事实错误和一个缺失前提：① 被引用的 Delta-Kronecker/Vpn-Gate 实际上既没有检测环节、也没有历史池合并逻辑；② "池子持续累积"若不配淘汰机制，会因为 VPN Gate 节点短生命周期导致检测量线性膨胀，最终撑爆 30 分钟检测周期。**

## 1. 事实核查：Delta-Kronecker/Vpn-Gate 到底做了什么

| 用户表述 | 该仓库实际代码 | 判定 |
|---|---|---|
| "每次检测完，把 success=true 的节点写进池" | `main.py` **没有任何连通性检测**（无 Worker、无 SSTP 握手）。只是抓官方主页的 `SSTP Hostname` 字符串 + 各镜像 CSV 里的**全部** HostName（不区分 proto tcp/udp，非 SSTP 的也一律加 `:443` 收录） | ❌ 不符 |
| "写进历史可用池文件，下一轮合并检测" | `final_hosts_map = {}` 每轮从零构建；写文件用 `open(OUTPUT_FILE, 'w')` **整文件覆盖重写**；全文无一处读取旧 `sstp_hosts.txt` 的代码 | ❌ 不符 |
| "节点不会因某次恰好失败而永久消失" | 它根本没有 success/fail 概念，节点消失仅因为当轮镜像 CSV 里没有 | ❌ 不符 |
| "提交回仓库" | ✅ workflow 确实 `git add sstp_hosts.txt && git push`（每 24h 一轮 cron `0 0 */1 * *`） | ✅ 唯一相符 |

**关键纠偏**：该仓库 README 声称 "accumulative database, remembers servers from previous scans"，**与代码实现不符**（营销话术）。它的列表看起来大，是因为聚合了官方主页 + 多个镜像 CSV 的并集（镜像同步滞后导致集合更宽），而不是跨轮记忆。**照抄它没有可直接复用的历史池代码——这个机制需要自己实现。**

另外注意：它把所有 CSV 节点（含 UDP-only）默认 `:443` 当 SSTP 收录，从本项目视角（`vpngate.py` 严格过滤 `proto tcp`）看，那份列表质量很粗、大量节点根本无法走 SSTP。

## 2. 机制本身：成立的部分（对本项目的真实收益）

| # | 收益 | 说明 | 量级预期 |
|---|---|---|---|
| 1 | 对抗单轮检测假阴性 | Worker 检测有噪声（CHECK_TIMEOUT 90s、Cloudflare→节点路由抖动、节点瞬时负载）。当轮恰好失败 → 从 chains/sub 消失 → 下轮 CSV 里有它但不在候选集外……不，当前它仍在 CSV 里会重测；真正受益的是**CSV 采样间隙漏掉的节点**（见#2） | 可用节点数 +10~30% |
| 2 | 覆盖官方 CSV 采样抖动 | 官方 api/iphone CSV 约每 5 分钟更新且只列"当前在线"，30 分钟一轮的采样会漏掉两次采样间隙进出的中继；镜像源本身也有滞后/截断 | 少量但真实 |
| 3 | 提高订阅编号稳定性 | 本项目 chains.txt/hosts.txt 的设计是"名字固定、$sstp:// 地址自动换"（`build_chains_text`）。节点频繁消失会导致编号错位，历史池显著减少闪断 | 直接改善用户体验 |
| 4 | 数据源故障降级 | 官方 API + 镜像全挂时（当前直接 `die`），历史池可作为应急候选集继续检测产出 | 灾备价值 |

**机制要点确认**：用户设计里"历史池 + 当轮新节点**一起检测**"这一条是对的——池内节点不是免检白名单，而是每轮重测对象。历史池扩大的是**候选集**，进产物（chains/sub）仍必须**当轮 success=true**。这个区分是整个机制正确性的核心。

## 3. 缺失前提：不淘汰必然翻车（膨胀数学）

VPN Gate 中继是志愿者家宽电脑，**平均在线时长仅数小时到数天**，host 是 DDNS（`xxx.opengw.net`），IP 随时会变。

| 池规模 | 32 并发 × 90s 超时最坏耗时 | vs 30 分钟周期 |
|---|---|---|
| 300（当前量级） | ~14 分钟 | ✅ 可行 |
| 600 | ~28 分钟 | ⚠️ 贴边 |
| 1000 | ~47 分钟 | ❌ 必然超时，workflow `timeout-minutes: 30` 直接杀 |
| 3000（永不淘汰 10 天后） | ~140 分钟 | ❌ 完全不可行 |

若按"永不淘汰"实现：每天出现过几百个 SSTP 节点全部永久进池，池子单调增长，几周内检测轮耗时超过周期，机制自我崩溃。**这就是 Delta-Kronecker 实际上只做覆盖重写的隐含原因。**

## 4. 落地必须处理的 4 个细节

| # | 细节 | 错误做法 | 正确做法 |
|---|---|---|---|
| 1 | Worker 抖动误杀 | 任何失败都计淘汰 | `check_one` 已区分 `worker_error`（HTTP 非 200/网络异常）与明确 `success=false`。**只有后者计入 fail_streak**；worker_error 不计——否则 Worker 抖一轮就把全池刷光 |
| 2 | 淘汰策略 | 只进不出 | 双条件：连续失败 ≥ N 轮（建议 6 = 3 小时）**或** `now - last_success_at > TTL`（建议 24h），二选一触发即移除 |
| 3 | 元数据过期 | 沿用入池时的 ip/国家 | host 是 DDNS，IP/出口国家每轮用当轮检测结果刷新；住宅/机房分类也随之更新 |
| 4 | 持久化方式 | 每 30 分钟 commit main | 见下表对比 |

### 持久化方案对比

| 方案 | 优点 | 缺点 | 建议 |
|---|---|---|---|
| commit 到 main（Delta-Kronecker 做法） | 最可靠 | 每天 48 个 commit，一年 ~17,500 个，git 历史膨胀；需把 workflow `contents: read` 改 `write` | 可用但要定期 squash |
| commit 到独立分支 `pool` | main 历史干净 | 同样膨胀，checkout 要拉分支 | 备选 |
| actions/cache（key 按周滚动） | 不污染 git 历史 | cache 有 7 天未访问清退策略——但 30 分钟一跑每轮都刷新，不会触发 | ✅ 推荐 |
| artifacts 传递 | 简单 | artifact 保留期默认 90 天且管理繁琐 | 不推荐 |

## 5. 推荐实现设计（可直接改 vpngate.py）

```
pool.json 结构:
[
  {
    "host": "vpn123.opengw.net", "port": 443, "ip": "1.2.3.4",
    "country": "Japan", "country_code": "JP", "residential": "residential",
    "first_seen": "...", "last_success_at": "...",
    "fail_streak": 0, "success_count": 12, "latency_ms_ema": 820
  }
]

流程改动 (main):
  1) 池加载: public/ 检测前读 pool.json (cache 恢复), 过滤已过 TTL 的
  2) 候选集 = 当轮 CSV 节点 ∪ 池内存活节点   ← 新增合并
  3) 检测后逐节点更新: success -> fail_streak=0, last_success_at=now, 刷新 ip/国家/分类
                        明确失败 -> fail_streak+=1
                        worker_error -> 不变
  4) 淘汰: fail_streak >= POOL_FAIL_STREAK(6) 或 now - last_success_at > POOL_TTL(24h)
  5) 产物仍只用当轮 success 节点 (现有 build_outputs 不动)
  6) 写回 pool.json 供下轮恢复

workflow 改动 (check.yml):
  - actions/cache: key 按"年中周"滚动, path: pool.json
  - 环境变量: POOL_FAIL_STREAK / POOL_TTL / POOL_MAX_NODES(硬上限保护, 超出按 fail_streak 降序+last_success_at 升序淘汰)
```

## 6. 最终判定

| 判断项 | 结论 |
|---|---|
| "历史池 + 当轮节点一起检测"机制本身 | ✅ 正确，是标准的跨轮重试模式 |
| "提交回仓库持久化" | ✅ 可行（建议换 actions/cache） |
| "节点不会因某次恰好失败而永久消失" | ✅ 成立（前提是 worker_error 不计淘汰） |
| "参考 Delta-Kronecker/Vpn-Gate 的做法" | ❌ 该仓库实际无检测、无历史池、每轮覆盖重写；README 的 "accumulative" 与代码不符，无可抄代码 |
| "池子会持续累积" | ⚠️ 半对：会累积但**必须配淘汰**（fail_streak + TTL），否则检测量膨胀撑爆 30 分钟周期，机制自我崩溃 |
