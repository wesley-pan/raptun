# Raptun 设计文档

> **Raptun = RaptorQ + QUIC Tunnel**
> 下一代 kcptun 类隧道工具:用原生 QUIC(Quinn)取代 `yamux + KCP` 两层叠罗汉的
> 多路复用 + 可靠传输方案,用 RaptorQ 喷泉码在**不可靠数据报路径**上做主动前向纠错(FEC),
> 专治高丢包 / 高延迟链路下的尾延迟。

- 版本:v0.2(对齐实现,2026-07-11)
- 参考实现:[Quinn](https://github.com/quinn-rs/quinn)、[cberner/raptorq](https://github.com/cberner/raptorq)
- 对标项目:[kcptun](https://github.com/sspanel/kcptun)(yamux + KCP 架构)

本文档是 Raptun 的**唯一权威设计文档**,已对齐 `crates/` 下的可编译实现;凡与代码不一致处以代码为准,尚未实现的能力明确标注为"路线图项"。构建/编译说明见 [`BUILD.md`](BUILD.md)。

---

## 目录

- [1. 设计动机](#1-设计动机)
- [2. 总体架构](#2-总体架构)
- [3. 核心决策:FEC 加在哪一层](#3-核心决策fec-加在哪一层)
- [4. 双路径数据平面](#4-双路径数据平面)
- [5. 数据平面 wire format 与编解码流程](#5-数据平面-wire-format-与编解码流程)
- [6. 极端网络下的收敛性设计](#6-极端网络下的收敛性设计)
- [7. 自适应 FEC 策略](#7-自适应-fec-策略)
- [8. 多路复用:删掉 yamux](#8-多路复用删掉-yamux)
- [9. 控制协议](#9-控制协议)
- [10. 安全模型](#10-安全模型)
- [11. 代码架构](#11-代码架构)
- [12. 参数详解](#12-参数详解)
- [13. 性能与容量规划](#13-性能与容量规划)
- [14. 实施路线图](#14-实施路线图)
- [15. 风险与已知限制](#15-风险与已知限制)
- [16. 与 kcptun 对照总结](#16-与-kcptun-对照总结)
- [17. 附录:术语与参考](#17-附录术语与参考)

---

## 1. 设计动机

kcptun 的经典架构是 `yamux over KCP`:

```
本地 TCP → yamux 逻辑流 → KCP(ARQ 可靠字节流) → UDP
```

KCP 在 UDP 之上用 ARQ 重传模拟出一条可靠有序字节流,yamux 再在其上做多路复用。这套组合在 QUIC 普及前是合理选择,但两个协议不是为彼此协同设计的,各自独立维护状态机、互不知情。它遗留三个未解决的根本问题,Raptun 逐一针对:

| kcptun 的问题 | 根因 | Raptun 的解法 |
|---|---|---|
| **队头阻塞仍在** | KCP 对上层只暴露单一可靠字节流(和 TCP 内核语义一样,只是重传搬到用户态),yamux 在其上复用多流,一个包丢了所有逻辑流都要等 KCP 重传 | QUIC 原生多流,每流独立丢包恢复;业务数据进一步下沉到 datagram,天然无跨流阻塞 |
| **两套互不知情的状态机** | KCP 的 ARQ 状态与 yamux 的帧 / 窗口状态各自为政,无法协同做流控 / 拥塞决策,只能在应用层"盲猜"窗口 | QUIC 把可靠性、流控、拥塞控制统一到一个协议栈;FEC 直接读 Quinn 的精确遥测 |
| **纠错方式弱且僵** | kcptun FEC(若开启)是固定比例异或校验,纠错能力弱、不自适应,且与 ARQ 割裂、无平滑降级 | RaptorQ 喷泉码,数学恢复概率近乎最优,repair 比例随链路自适应,FEC 与兜底重传统一为一条降级链 |

---

## 2. 总体架构

```
┌────────────────────── Raptun Client ──────────────────────┐
│  本地 TCP / SOCKS5 accept                                   │
│        │                                                    │
│        ├──── 控制流 (QUIC bi-stream #0) ────────────┐       │
│        │     握手 / 鉴权 / 目标协商 / FEC 参数协商    │       │
│        │                                            │       │
│        └──── 数据 ──▶ RaptorQ 编码器 ──▶ QUIC datagram(不可靠)│
│                        (源块切分 + repair)          │       │
│                        每隧道信令流:NACK / 可靠重传  │       │
│                              │                      │       │
│                       ┌──────▼──────┐               │       │
│                       │ Quinn Endpoint │ ◀── TLS1.3 / 拥塞控制 / 迁移 │
│                       └──────┬──────┘               │       │
└──────────────────────────────┼─────────────────────┼───────┘
                               │ 单条 UDP 连接         │
┌──────────────────────────────┼─────────────────────┼───────┐
│                       ┌──────▼──────┐               │       │
│                       │ Quinn Endpoint │             │       │
│                       └──────┬──────┘               │       │
│        ┌──── RaptorQ 解码器 ◀┘  (block 状态机重组)   │       │
│        │                                            │       │
│        └──▶ Session Manager ──▶ 转发到目标 TCP 服务  │       │
│                          Raptun Server                      │
└─────────────────────────────────────────────────────────────┘
```

自底向上分四层,职责单一:

1. **传输层(Quinn / QUIC)**:UDP 收发、TLS 1.3、拥塞控制、路径 MTU 探测、连接迁移。完全交给 Quinn。
2. **多路复用层(QUIC Stream)**:把多条逻辑代理连接映射为独立 stream,替代 yamux。
3. **FEC 层(raptun-fec)**:业务数据切分为 RaptorQ source block、生成 repair symbol、经 datagram 发送;接收端重组解码、必要时触发兜底。
4. **应用层(raptun-core / client / server)**:本地 accept、目标转发、会话生命周期。

---

## 3. 核心决策:FEC 加在哪一层

这是整个设计里**最容易做错**的地方。三个选项只有一个正确:

| 方案 | 结果 | 采纳 |
|---|---|---|
| ❌ FEC 叠在 QUIC **可靠 stream** 上 | QUIC 已经重传保证可靠,再加冗余 = 稳态持续浪费带宽,两套可靠性机制冗余工作,零净收益 | 否 |
| ❌ 完全裸 UDP 自己做 | 等于重写 QUIC,放弃 TLS / 拥塞控制 / 连接迁移,得不偿失 | 否 |
| ✅ FEC 建在 QUIC **不可靠 datagram (RFC 9221)** 上 | 用 RaptorQ 的应用层可靠性**替换**掉 stream 的可靠性,两者不叠加 | **是,默认路径** |

### 3.1 为什么 datagram 路径既正确又安全

QUIC datagram(Quinn 经 `send_datagram`/`read_datagram` 暴露)有两个决定性性质:

1. **不重传** → 丢包恢复完全交给 RaptorQ,能做到**零额外 RTT 自愈**:接收端收齐任意 K 个 symbol(源符号或修复符号)即可重建,不必等 ACK 缺口。而 QUIC 原生 stream 的重传本质是 ACK 驱动的被动模式,至少多 1 个 RTT。
2. **仍受拥塞控制约束** → repair symbol 占用 cwnd,所以 FEC 冗余**不会**把链路打爆,拥塞控制器替你兜底。这消除了"盲目加冗余导致拥塞崩溃"的第一层风险。

此外 RaptorQ 是**系统码(systematic code)**:源符号本身就是未编码的原始数据,只要全部源符号送达,接收端直接拼接即用、无需跑解码算法,无损网络下几乎零额外 CPU 开销。

**代价**:RaptorQ 是概率性重建(收到 K+h 个符号后成功概率 1 − 1/256^(h+1)),存在极小解码失败概率,需设计兜底(见 §6);且需自管 source block 的收集 / 超时 / 清理。

代码对应:`raptun-fec/src/encoder.rs`、`raptun-core/src/fec.rs`。

### 3.2 决策矩阵

| 方案 | 恢复延迟 | 带宽开销 | 实现复杂度 | 采纳 |
|---|---|---|---|---|
| A:stream 之上叠 FEC | 与纯 stream 相近 | 稳态持续浪费 | 中 | 否 |
| B:datagram + FEC 替代 stream 可靠性 | 接近零额外 RTT | 按需(自适应比例) | 中高(需自管 block 生命周期) | 是,默认 |
| 控制信令走原生 stream | 与 QUIC 原生一致 | 极低 | 低 | 是,控制路径 |
| block 级 NACK + 可靠重传兜底 | 极端场景退化为多 RTT | 仅极端场景触发 | 中 | 是,兜底 |

---

## 4. 双路径数据平面

明确按"能否容忍偶发失败"分流,不一刀切:

| 流量类型 | 承载方式 | 可靠性来源 |
|---|---|---|
| 控制信令(握手 / 鉴权 / 目标协商 / FEC 参数协商) | QUIC **bi-stream #0** | QUIC 原生 ACK + 重传(确定性) |
| 每隧道信令(NACK / 可靠重传 / 块计数) | 每隧道**独立 bi-stream** | QUIC 原生 ACK + 重传(确定性) |
| 业务数据(被代理的 TCP) | QUIC **unreliable datagram** + RaptorQ | RaptorQ FEC(主) + 兜底降级(备,见 §6) |

控制流量占比极小,多 1 个 RTT 不影响体验,所以用确定性可靠传输最稳妥。

**运行时路径选择**:默认走 datagram + FEC。`--fec off` 或 `--datagram false` 会让业务数据退回可靠 QUIC stream(`run.rs` 据此在 `tunnel_bi` 与 FEC 隧道间二选一),适用于长期极低丢包链路或调试。协议里已定义 `FecReconfig` 用于**运行时**动态调 repair ratio / block size,但连接建立后不重连即时切换**尚未接入**(路线图项)。

---

## 5. 数据平面 wire format 与编解码流程

### 5.1 Symbol 头(20 字节)

每个经 QUIC datagram 发送的 symbol 携带一个 **20 字节固定头**(RaptorQ 库只管编解码数学,元数据由 Raptun 封装,见 `raptun-proto/src/datagram.rs`,`SYMBOL_HEADER_LEN = 8+8+3+1 = 20`):

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        stream_id (u64)                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        block_id (u64)                         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          esi (u24)          |  flags (u8) |   symbol data ... |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

- **stream_id (u64)**:逻辑代理连接 ID,接收端据此把乱序 datagram 解复用到对应连接(见 §8)。客户端为每条隧道分配(当前从 2 起步的偶数序列),先在该隧道信令流上告知服务端,两端注册同一路由。
- **block_id (u64)**:该连接内 source block 序号,单调递增。
- **esi (u24)**:RaptorQ Encoding Symbol ID(源符号 ESI < K,修复符号 ESI ≥ K)。24 位足够——RFC6330 单块上限 56403。
- **flags (u8)**:`REPAIR`(修复符号)、`BLOCK_HINT_LAST`(当前冗余预算下该块最后一个符号的提示)。
- **symbol data(变长)**:编码符号数据。

**关于 OTI**:不在头里携带 Object Transmission Information——两端从协商好的 `symbol_size` 与 K **确定性各自推导**(`raptun-fec/src/codec.rs::oti_for`,单源块、alignment=1),无需上线传输。

### 5.2 块几何:定长 + 长度前缀

块几何固定:K 个符号、每符号 `symbol_size` 字节。一个块的原始负载布局为:

```
[u32 真实长度前缀][负载字节][零填充 ...]   ← 共 K × symbol_size 字节
```

长度前缀让接收端在重建出定长填充块后能裁掉填充、恢复精确原始字节。定长几何还让接收端能为只见过修复符号的块正确构造解码器(它总知道 `block_length = K × symbol_size`)。

### 5.3 编解码流程

**发送端**(`FecSender` + `run.rs` 上行任务):

```
1. 从 TCP 读入(每次 read 得到一个"突发")
2. 每个 read 突发立即成块发送(按块容量切分),不等"攒够满块"——
   否则远小于块容量的小消息会长期滞留缓冲,拖高交互延迟
3. RaptorQ SourceBlockEncoder:先取 K 个源符号(systematic),再生成
   repair_count 个修复符号(= 自适应比例 × K)
4. 每符号加 20B 头打包成 datagram 发出(源符号 ESI 0..K,修复 ESI K..)
5. 发送方保留每块的 encoder(NACK 时续发新修复符号)与原始 payload
   (降级时可靠重传整块)
6. 上行 EOF 后经隧道信令流发 BlockCount 告知总块数
```

**接收端**(`FecReceiver` + 下行任务 + 周期 control tick):

```
1. 收 datagram → 解析头 → 连接级读循环用 DatagramHub 按 stream_id 解复用到
   每条隧道;路由注册前到达的早期符号会短暂缓冲并在注册时回放(消除启动竞态)
2. 每块一个 BlockManager 累积符号 → RaptorQ SourceBlockDecoder。
   systematic 特性:无丢包、K 个源符号齐全时直接返回,基本不跑高斯消元
3. 收满 K(含修复补位)即重建定长块,裁掉长度前缀得原始负载
4. 块间保序:接收端维护交付指针,只有更低序号块都已交付才向下游 flush,
   一次可能 flush 掉被解锁的一串连续块
5. 周期 control tick(默认 20ms)仲裁未完成块 → 发 Nack 或 ReliableRequest(见 §6)
```

**块间保序**:RaptorQ 只保证单块内乱序容忍,块之间的顺序由 Raptun 维护(业务数据是有序字节流,不能因 Block 2 先重建就先写下游)。接收端维护按 block_id 排序的重组窗口,类似 TCP 重排序缓冲。

---

## 6. 极端网络下的收敛性设计

> **核心问题**:高丢包 + 高抖动 + 乱序三者叠加时,FEC + NACK 兜底能否自适应收敛,而不是自我雪崩?

### 6.1 朴素设计为何会雪崩

若按"某 block 超过一个 RTT 没收齐就发 NACK"的朴素定时器设计,极端网络下有三条正反馈崩溃路径:

1. **高抖动 → RTT 估计失真 → NACK 风暴**:抖动的本质是 RTT 方差极大,大批"正在路上、只是晚到"的 symbol 被误判为丢失 → 发 NACK → 发送方增发 repair → 挤占带宽 → 真的拥塞 → 更多 block 收不齐 → 更多 NACK → 雪崩。
2. **NACK 走在同一条烂链路上**:反馈回路延迟 = 数据 RTT + 控制流自身重传延迟,链路越烂越不好使。
3. **两个控制环共振**:慢环(自适应比例)和快环(block NACK)同时加冗余 → 同一份冗余加了两次 → 过度冗余 → 拥塞 → 继续加码。

### 6.2 收敛判据

Raptun 兜底机制收敛 **当且仅当**:

```
新增冗余速率 (repair injection rate) ≤ 链路可用余量 (available bw − goodput)
```

修正设计用四个机制把左边强行钳在右边之下:

| 机制 | 代码位置 | 钳住不等式哪一侧 |
|---|---|---|
| in-flight repair ≤ 40% cwnd(硬上限) | `raptun-fec/src/budget.rs` | 给左边设物理天花板 |
| 拥塞态熄火快环 | `decoder.rs` `tick_stalled` | cwnd 被砍时右边变小,同步让左边变小 |
| 证据驱动 NACK(非定时器) | `decoder.rs` `tick_filling` | 消除"晚到误判"造成的左边虚高 |
| 幂等增发(报进度而非报丢失) | `fec.rs` `TunnelSignal::Nack` | 消除重复索要造成的左边翻倍 |

### 6.3 接收端 block 状态机

代码:`raptun-fec/src/decoder.rs` 的 `BlockManager`。

```
                    symbol 到达
        ┌─────────────────────────────────┐
        │                                 ▼
   ┌─────────┐  收齐 K 个    ┌──────────┐
   │ Filling │──────────────▶│ Decoded  │ ──▶ 交付,释放 budget
   └────┬────┘  (零 RTT)     └──────────┘
        │
        │ 进入 Stalled 需三条同时成立(否则抖动 / 乱序会误判):
        │   ① 已见过更高块号            (序进度判据,抗乱序)
        │   ② 已过 srtt + 4·rttvar       (抖动自适应宽限)
        │   ③ 仍差 symbol
        │   —— 另有硬期限逃生:超过 max(8·grace, 500ms) 无视 ① 也停滞
        ▼
   ┌─────────┐   拥塞态 / 预算耗尽? ──是──▶ Degraded(可靠重传)
   │ Stalled │───────────────┐
   └────┬────┘               │否 + 预算足够
        │                     ▼
        └────▶ Degraded   ┌──────────┐
                          │ NackSent │  (幂等:上报 have)
                          └────┬─────┘
              repair 到达 ─────┘ ─▶ 回 Filling
              NACK 丢失 / 超时 ──▶ 回 Stalled 重新仲裁
```

**三条 AND 条件**是抗抖动 / 乱序的关键:单看时间会把晚到的包误判为丢失,必须叠加"序进度"这个正交信号。序进度用"**已见过更高块号**"判定(不是交付指针)——这样才能正确覆盖头块:头块阻塞交付、其交付指针永远越不过自身,若用交付指针作判据头块将永不停滞。**硬期限逃生**确保无更高块的孤块 / 尾块(如短流或单块流重丢)不会永久悬挂。

**幂等增发**:NACK 携带"已收 M 个",发送方精确增发 `K − M` 个**新**repair symbol(喷泉码可无限生成新符号,`emit_additional_repair`)。重复 NACK 只会请求更少的新符号,永不冗余爆炸。

### 6.4 兜底降级(收敛下界,已实现)

两级,都跑在**每条隧道自己的可靠信令 bi-stream** 上(`TunnelSignal`),而非全局控制流:

- **第一级:block 级 NACK** —— 补发修复符号(见上)。受 `RepairBudget` 约束:在途修复不得超 cwnd 的 40%,超预算或拥塞态时不发(拥塞时加修复只会更堵),转第二级。
- **第二级:可靠重传降级** —— FEC 无法推进时(预算耗尽 / 拥塞态 / 整块全丢无符号 / 超硬期限),接收端发 `ReliableRequest { block }`,发送方用保留的原始 payload 回传 `ReliableData { block, bytes }`(走可靠信令流,QUIC 保证送达),接收端原样注入有序重组缓冲。整块全丢(无 manager、tick 看不见)的空洞用"已知总块数 / 已见最高块号"上界补偿检测。

牺牲该 block 的延迟,换取**永不死锁**——极端退化时 Raptun 收敛到"一条带 FEC 前缀的可靠 QUIC 连接",不劣于纯 QUIC(收敛性下界)。

### 6.5 收敛性结论(分档)

| 网络状况 | 行为 | 收敛点 |
|---|---|---|
| 中等丢包 / 抖动 | FEC 主路径免 RTT 恢复,NACK 几乎不触发 | 低延迟理想态 |
| 高丢包但非拥塞(跨境 / 卫星随机丢包) | 自适应推高 repair 比例,证据驱动 NACK 精确补差 | 高冗余但仍免 RTT(Raptun 最能打的区间) |
| 高抖动 + 乱序 | 序进度判据 + `rtt+4·rttvar` 宽限期避免误判 | 恢复延迟随抖动上升,但**不雪崩** |
| 拥塞丢包(链路真塞满) | 预算上限 + 熄火快环 + 降级重传 | 主动退化,**不劣于纯 QUIC** |

> **必须承认的上界**:FEC 只能对抗随机损伤,对抗不了带宽枯竭。任何号称"极端拥塞下还能低延迟"的设计都是错的——带宽真不够时,唯一正确的动作就是别加冗余。Raptun 的收敛目标是"随网络恶化平滑退化,最坏退回纯 QUIC",而非"任何情况都低延迟"。

---

## 7. 自适应 FEC 策略

代码:`raptun-fec/src/strategy.rs`(`FecStrategy`)、`raptun-core/src/telemetry.rs`(`RegimeClassifier`)。

FEC 不是免费午餐,且**并非总是有益**:

- 对**随机丢包**(卫星、拥挤移动网、策略性丢包)→ FEC 大胜,主动补冗余免 RTT 恢复。
- 对**拥塞丢包**(链路真的满了)→ FEC 有害,repair 挤占本该给真实数据的 cwnd,越纠越堵。

因此控制器最重要的职责是**区分两种丢包,对各自反向调节**:

| 观测(`RegimeClassifier::classify`) | 判定区制 | 动作(`FecStrategy::update`) |
|---|---|---|
| cwnd 稳定 / 增长但仍在丢 | `Random` | 慢环上调 repair 至 `loss × safety_margin` |
| cwnd 相对上一 tick 跌 > 12.5% | `Congestion` | 慢环下调至 `min`,快环熄火,绝不加码 |
| 平滑丢包率 < 0.5% | `Quiescent` | 衰减至 `min`,保留最小冗余 |

比例朝目标走 EWMA 一步(步长 `gain`),永不跳变;变化超过 1% 才值得通过 `FecReconfig` 通告对端。**这正是 Raptun 相对 kcptun 的核心优势**——直接读 Quinn 精确遥测区分随机 vs 拥塞,而 kcptun 跑在 KCP 之上看不到底层真实拥塞状态,只能盲猜。

**边界场景**:丢包率突增时 EWMA 收敛有滞后,短期冗余不足由 block 级 NACK 兜底(草案设想的"NACK 频率触发快响应"为路线图项);丢包率长期为零时 ratio 收敛到 `min`(默认 2%)而非归零,保留最小冗余应对突发。

---

## 8. 多路复用:删掉 yamux

QUIC stream 原生等价 yamux 的每个能力,不需要重写:

| yamux 概念 | QUIC 原生对应 |
|---|---|
| SYN 开流 | `open_bi()` / `open_uni()`(创建 / 销毁廉价) |
| 每流独立窗口流控 | 内建 per-stream flow control |
| FIN 半关闭 | `send.finish()` |
| RST 硬重置 | stream reset(携带错误码) |
| GoAway 优雅关连接 | `Connection::close()` + idle timeout |
| 队头阻塞 | 协议层规避(跨流独立恢复);业务数据进一步下沉 datagram,彻底绕开 stream 排队 |

每来一条本地 TCP 连接,`open_bi()` 开一条 QUIC stream 做元数据协商 + 承载该隧道信令,数据走对应的 datagram + FEC 通道,用 `stream_id` 关联 source block。这一层几乎零自研成本。

---

## 9. 控制协议

Raptun 有两套消息,分别走两条可靠路径。

### 9.1 全局控制流消息(`raptun-proto::control::Message`,走 bi-stream #0)

| 消息 | 方向 | 用途 | 现状 |
|---|---|---|---|
| `Hello { version, auth_token, fec }` | C → S | 发起连接,携带版本、鉴权 token、建议 FEC 参数 | ✅ 握手用 |
| `HelloAck { version, fec }` | S → C | 确认,回传协商后(可能被钳制)的 FEC 参数 | ✅ 握手用 |
| `OpenTarget { stream_id, target }` | C → S | 为某逻辑连接请求代理目标(`host:port`) | 🟡 已定义;当前 TCP 模式用服务端固定 `--target`,SOCKS5 逐连接目标为路线图项 |
| `OpenTargetAck { stream_id }` / `OpenTargetErr { stream_id, reason }` | S → C | 确认 / 拒绝 | 🟡 已定义 |
| `FecReconfig { stream_id, fec }` | 双向 | 运行时调 FEC 参数 | 🟡 已定义,运行时下发未接入 |
| `BlockNack { stream_id, block, have, need }` | Recv → Send | 请求补发 repair | 🟡 协议预留(FEC 路径实际用 `TunnelSignal`) |
| `Ping { nonce }` / `Pong { nonce }` | 双向 | 应用层 RTT 采样 | 🟡 已定义,未接入(现用 QUIC 自身 RTT) |
| `Goodbye` | 双向 | 优雅关闭 | 🟡 已定义 |

### 9.2 每隧道信令消息(`raptun-core::fec::TunnelSignal`,走该隧道的 bi-stream)

| 消息 | 方向 | 用途 |
|---|---|---|
| `BlockCount { total }` | Send → Recv | 上行 EOF 后告知总块数,让接收端知道何时收全 |
| `Nack { block, have, need }` | Recv → Send | 请求为停滞块续发 `need` 个新 repair symbol(幂等) |
| `ReliableRequest { block }` | Recv → Send | FEC 放弃该块,请求可靠重传其字节(收敛下界) |
| `ReliableData { block, bytes }` | Send → Recv | 回传该块原始字节,接收端原样注入有序缓冲 |

FEC 数据路径的 NACK / 降级实际走 9.2;9.1 里的 `BlockNack` 为协议预留。

### 9.3 握手时序

```
Client                                          Server
  │──────────── QUIC 握手 (TLS 1.3) ───────────────▶│
  │◀─────────────── 握手完成 ───────────────────────│
  │────────── Hello (token, 版本, FEC能力) ─────────▶│
  │                                                 │  验证 PSK(常量时间)
  │◀───────── HelloAck (协商后参数, 钳制) ───────────│
  │  (本地 TCP accept 到新连接)                       │
  │─── 开隧道 bi-stream, 告知 stream_id ────────────▶│
  │═══════ 业务数据 (datagram + RaptorQ) ═══════════▶│
  │◀══════ 每隧道信令 (BlockCount/Nack/Reliable) ═══▶│
```

`OpenTarget` / `FecParams` 实际定义:

```rust
pub struct OpenTarget { pub stream_id: u64, pub target: String }  // 目标服务端解析
pub struct FecParams  { pub symbol_size: u16, pub block_size: u16, pub repair_ppm: u16 }
// block_size==0 表示 auto(当前回退 16);repair_ppm 为千分数(150 = 15%)
```

---

## 10. 安全模型

代码:`raptun-core/src/tls.rs`。QUIC 强制 TLS 1.3,ALPN = `raptun/1`。

- **加密**:信道加密与服务端认证由 TLS 1.3 内建,Raptun 不自研任何数据路径加密——相对 kcptun(通常需在 KCP 之上自叠一层弱加密)的显著简化。
- **证书(TOFU + 指纹固定,不依赖公开 CA)**:服务端 `--self-signed` 启动时用 `rcgen` 生成自签证书并打印 SHA-256 指纹(当前每次启动新生成、不持久化——持久化复用是路线图项);也支持 `--cert`/`--key` 加载 PEM。客户端 `--fingerprint` 预置指纹,用自定义 `ServerCertVerifier` 校验服务端叶证书指纹(不匹配即拒,防 MITM);签名验证仍走标准 webpki 算法,故指纹固定不削弱握手。`--insecure` 跳过校验(仅测试)。
- **鉴权(`--psk`)**:应用层鉴权,**不是第二层加密**(信道已加密)。只用于认证客户端、拒绝未授权连接消耗资源,**常量时间比较**(`psk_matches`)防计时侧信道。不设则匿名。草案设想的"带时间戳 + HMAC 签名 token"(防重放)为路线图加固项。
- **抗主动探测**:QUIC 明文 ClientHello 部分特征已被公开研究用于识别,受限网络场景可参考业界混淆思路——列为 Phase 5 可选,不进 MVP。

---

## 11. 代码架构

Cargo workspace,依赖单向向下,无环:

```
raptun/
├── Cargo.toml               # workspace 清单 + 统一依赖版本 + [profile.release]
├── crates/
│   ├── raptun-proto/        # 叶子 crate,零重依赖
│   │   ├── codec.rs         #   Encode/Decode trait + 长度前缀工具
│   │   ├── control.rs       #   全局控制流消息(§9.1)
│   │   └── datagram.rs      #   20 字节 symbol 头(§5.1)+ bitflags_lite 宏
│   ├── raptun-fec/          # ★ 核心创新点,与传输解耦
│   │   ├── codec.rs         #   RaptorQBlockEncoder/DecoderImpl(定长块 + 长度前缀)
│   │   ├── encoder.rs       #   StreamEncoder / BlockEncoder trait / symbol 打包
│   │   ├── decoder.rs       #   BlockManager 状态机(收敛性核心)
│   │   ├── link.rs          #   LinkState + LossRegime(遥测快照)
│   │   ├── budget.rs        #   RepairBudget(in-flight 40% cwnd 硬刹车)
│   │   └── strategy.rs      #   FecStrategy(自适应比例慢环)
│   ├── raptun-core/         # Quinn/TLS + 会话编排
│   │   ├── config.rs        #   RuntimeConfig / FecConfig / TransportConfig
│   │   ├── tls.rs           #   自签证书 / 指纹固定 verifier / PSK 校验
│   │   ├── endpoint.rs      #   TransportConfig → Quinn 映射
│   │   ├── telemetry.rs     #   Quinn stats → LinkState + RegimeClassifier
│   │   ├── session.rs       #   握手 + 控制流分帧 + 遥测
│   │   ├── fec.rs           #   FecSender/FecReceiver/DatagramHub/TunnelSignal
│   │   └── run.rs           #   run_client / run_server + FEC 隧道四任务
│   ├── raptun-client/       # 本地 TCP/SOCKS5 accept + CLI
│   └── raptun-server/       # 目标转发 + CLI
├── docs/                    # 本文档 + BUILD.md
├── smoke_test.sh            # 真实二进制端到端冒烟
└── netem_bench.sh           # Linux tc netem 真机极端网络压测(需 root)
```

### 11.1 关键设计取舍:trait 抽象隔离外部 crate

编码 / 解码通过两个 trait 屏蔽 RaptorQ,链路遥测用纯数据结构 `LinkState`(不含 Quinn 类型),让收敛状态机可用假 codec 做纯单元测试、FEC crate 完全传输无关可独立测试:

```rust
// raptun-fec/src/encoder.rs
pub trait BlockEncoder {
    fn k(&self) -> u32;
    fn emit(&self, stream_id: u64, block_id: u64, repair_count: u32) -> Vec<EncodedSymbol>;
    fn emit_additional_repair(&self, stream_id: u64, block_id: u64,
                              already_sent_repair: u32, extra: u32) -> Vec<EncodedSymbol>;
}
// raptun-fec/src/decoder.rs
pub trait RaptorQBlockDecoder {
    fn add_symbol(&mut self, esi: u32, payload: &[u8]) -> Option<Vec<u8>>;
}
```

超时 / NACK 决策由 `BlockManager::tick(&TickCtx) -> DecoderAction`(`Idle`/`SendNack`/`RequestReliableRetransmit`/`Deliver`)驱动,`FecReceiver::tick` 汇总成要发的 `TunnelSignal`。

### 11.2 编译与测试状态

- `cargo test` —— **44 passed**(`--features test-hooks` 时 **46**,含丢包恢复 + 降级兜底端到端 + 极端网络收敛测试)。
- `cargo build` / `cargo clippy --all-targets` —— **0 error, 0 warning**(两种 feature 配置均是)。构建说明见 [`BUILD.md`](BUILD.md)。
- `smoke_test.sh` —— 真实二进制端到端穿隧,日志确认走 `data path: unreliable datagrams + RaptorQ FEC`。
- **Phase 1**:真实 Quinn endpoint、TLS 1.3 自签 + 指纹固定、控制流握手(PSK 鉴权)、逐连接双向 TCP 转发。
- **Phase 2**:datagram + RaptorQ FEC(默认路径),按 `stream_id` 解复用、按块序重组。
- **Phase 3**:NACK 控制环 —— control tick 采样遥测、刷新预算、仲裁停滞块、发 NACK、发送方补 repair。
- **收敛下界(可靠重传降级)**:`ReliableRequest`/`ReliableData` 已闭合,流永不死锁(见 §6.4)。闭环单测(零预算强制走可靠路径)+ `test-hooks` 端到端(1/3 丢包 + 零主动 repair + 零预算,FEC 无进展仍完整往返)。
- **极端网络(§6)**:`tests/netem.rs` 进程内确定性仿真(虚拟时钟 + 种子 PRNG)证明 30% 丢包 + 150ms 抖动 + 25% 乱序下完整按序收敛,P99 有界、NACK 不雪崩、in-flight ≤ 40% cwnd、拥塞档零 NACK;`netem_bench.sh` 在 Linux 真机 qdisc 上跑同组场景(需 root)。
- **待办(Phase 4+)**:SOCKS5、连接迁移打磨、证书持久化 / PEM-CA 信任、`FecReconfig` 运行时下发、动态 K、滥用加固。

---

## 12. 参数详解

### 12.1 kcptun 参数的处置

| kcptun 参数 | Raptun 处置 | 原因 |
|---|---|---|
| `--key` / `--crypt` | ❌ 删,换 `--psk`/`--cert`/`--fingerprint` | QUIC/TLS 内建加密 |
| `--mode`(fast/normal) | ❌ 删,换 `--cc` | KCP ARQ 档位没了,改用 QUIC 拥塞控制 |
| `--nodelay/--interval/--resend/--nc` | ❌ 删 | KCP ARQ 微调,QUIC 自管重传 |
| `--sndwnd`/`--rcvwnd` | 🔁 `--stream-rwnd`/`--conn-rwnd` | KCP 窗口 → QUIC flow control |
| `--datashard`/`--parityshard` | 🔁 `--fec` + 自适应比例 | RS 固定比例 → RaptorQ 自适应 |
| `--smuxver/--smuxbuf` | ❌ 删 | yamux/smux 没了,QUIC 原生多流 |
| `--mtu` | ✅ 保留(约束 datagram/symbol 大小) | |
| `--sockbuf`/`--dscp`/`--keepalive` | ✅ 保留 | |
| `--snmplog` | 🔁 `--metrics` | 换成 Prometheus |

### 12.2 客户端 / 服务端参数表

> 完整默认值见 `raptun-client/src/cli.rs` 与 `raptun-server/src/cli.rs`。

**连接**

| 参数 | 默认 | 说明与影响 |
|---|---|---|
| `-l, --localaddr` (client) | `127.0.0.1:12948` | 本地监听地址 |
| `-r, --remoteaddr` (client) | 必填 | Raptun server UDP 地址 |
| `-l, --listen` (server) | `0.0.0.0:29900` | 服务端 UDP 监听地址 |
| `-r, --target` (server) | 可选 | TCP 转发目标;SOCKS5 模式下由 client 逐连接指定 |
| `--listen-mode` (client) | `tcp` | `tcp`(定向转发) / `socks5`(逐连接目标,路线图项) |

**安全**

| 参数 | 默认 | 说明与影响 |
|---|---|---|
| `--psk` | 无(env `RAPTUN_PSK`) | 应用层鉴权密钥(**非加密**)。不设则匿名 |
| `--cert` | 无 | 信任 / 提供的证书(PEM) |
| `--fingerprint` (client) | 无 | 服务端证书 SHA-256 指纹,TOFU 固定。与 `--cert` 互斥 |
| `--self-signed` (server) | false | 启动时自签并打印指纹供客户端固定 |
| `--client-auth` (server) | `psk` | `none`/`psk`/`mtls` |
| `--insecure` (client) | false | 跳过证书校验,**仅测试**,有 MITM 风险 |
| `--sni` (client) | `raptun` | TLS SNI |

**FEC(Raptun 核心差异)**

| 参数 | 默认 | 说明与影响 |
|---|---|---|
| `--fec` | `raptorq` | `off`/`raptorq`/`xor`。off = 走可靠 stream |
| `--fec-mode` (client) | `adaptive` | `adaptive`(读遥测自调,推荐) / `fixed`(调试) |
| `--fec-ratio` (client) | `0.15` | fixed 模式的固定冗余比例 |
| `--fec-min` (client) | `0.02` | 自适应下限。留常备冗余吸收首个突发丢包 |
| `--fec-max` | `0.50` | 自适应上限 / **服务端硬顶**。限制最坏带宽放大 |
| `--symbol-size` | `1200`(协商钳到 ≤ 1100) | RaptorQ 符号大小,双端必须一致。见 §5.1 |
| `--block-size` (client) | auto(回退 16) | 源块 K。动态 K 为路线图项 |

**传输(QUIC)**

| 参数 | 默认 | 说明与影响 |
|---|---|---|
| `--cc` | `bbr` | 拥塞控制 `bbr`/`cubic`/`newreno`。bbr 在高 BDP 链路更好 |
| `--mtu` | `1350` | UDP 载荷上限。留余量兼容 1400~1500 MTU |
| `--datagram` | `true` | 业务数据走 datagram+FEC;false 退回可靠 stream(**关 FEC 逃生舱**) |
| `--stream-rwnd` | `2 MiB` | 单流接收窗口 |
| `--conn-rwnd` | `16 MiB` | 连接级接收窗口 |
| `--sockbuf` | `4 MiB` | UDP socket 缓冲 |
| `--keepalive` | `10s` | 心跳间隔,0 关 |
| `--idle-timeout` | `30s` | 空闲断连 |
| `--migration` | `true` | QUIC 连接迁移,移动网络 IP 切换不断线(kcptun 无) |
| `--0rtt` | `true` | 0-RTT 重连 |
| `--dscp` | `0` | QoS 标记 |

**服务端限额与运维**

| 参数 | 默认 | 说明 |
|---|---|---|
| `--max-conns` | `4096` | 最大并发连接 |
| `--max-streams` | `1024` | 单连接最大并发流 |
| `-c, --config` | 无 | TOML/JSON 配置文件。**优先级:CLI > env > 文件 > 默认** |
| `--metrics` | 无 | Prometheus 端点 |
| `--pprof` (server) | 无 | 性能剖析端点 |
| `--log-level` | `info` | 日志级别 |
| `--quiet` | false | 静默 |

### 12.3 内部关键参数(非 CLI,代码内)

| 参数 | 位置 | 默认 | 影响 |
|---|---|---|---|
| `SAFE_MAX_SYMBOL_SIZE` | `session.rs` | 1100 | symbol 协商上限,保证 `symbol+20B 头` 落在 datagram 上限内 |
| `safety_margin` | `strategy.rs` | 1.3 | 随机丢包态目标比例 = loss × 该值 |
| `gain` | `strategy.rs` | 0.25 | 每 tick 向目标收敛的 EWMA 步长 |
| `repair_cwnd_fraction` | `budget.rs` | 0.40 | in-flight repair 占 cwnd 上限。收敛性物理刹车 |
| `stall_grace` | `link.rs` | `srtt+4·rttvar` | 判定停滞前的宽限期 |
| 硬期限逃生 | `decoder.rs` | `max(8·grace, 500ms)` | 无更高块的孤块 / 尾块降级期限 |
| 拥塞判定阈值 | `telemetry.rs` | cwnd 跌 > 12.5% | 区分拥塞 vs 随机丢包 |
| control tick 周期 | `run.rs` | 20ms | 仲裁停滞块的节奏 |
| NEXT_STREAM_ID 起点 | `run.rs` | 2(偶数序列) | 客户端为隧道分配的逻辑 stream_id |

---

## 13. 性能与容量规划

需要重点验证的维度:

| 维度 | 关注点 | 验证方式 |
|---|---|---|
| RaptorQ 编解码吞吐 | 小 block(低延迟场景 K 小)下相对开销是否可接受 | `tests/netem.rs` / 后续基准做 K 值吞吐延迟矩阵 |
| 尾延迟 | 高丢包下 datagram+FEC 相比纯 stream 的 P99 改善 | 网络仿真(丢包 1/5/10/20% 梯度)+ 延迟分布 |
| 带宽效率 | 自适应比例相比固定比例节省的冗余带宽 | 固定 20% vs 自适应,变丢包率场景总流量对比 |
| CPU 开销 | 无损网络下 systematic 快路径是否真零解码开销 | Profiling 验证"直接拼接跳过解码"命中率 |
| 并发扩展性 | 单 QUIC 连接承载大量逻辑连接(多 stream_id)的调度开销 | 1000+ 并发逻辑连接的延迟 / 内存曲线 |

---

## 14. 实施路线图

| Phase | 目标 | 状态 |
|---|---|---|
| **1 MVP** | Quinn 跑通 + control 握手;数据走纯 QUIC stream 不接 FEC,建基线 | ✅ 已完成(回环测试 + `smoke_test.sh`) |
| **2 接 FEC** | `raptun-fec` datagram 打包 / 重组解码 + 兜底 | ✅ 已完成(`fec_e2e.rs` + 丢包恢复单元测试;默认走 FEC) |
| **3 NACK 控制环 + 自适应** | control tick 接 `stats()`,刷新预算、仲裁、发 NACK、补 repair;区分随机 vs 拥塞 | ✅ 已完成(闭环单测 + `test-hooks` 端到端) |
| **3b 可靠重传降级(收敛下界)** | `ReliableRequest`/`ReliableData` + 保留块 payload + 序进度 / 硬期限判据 | ✅ 已完成(零预算单测 + `test-hooks` 不可恢复丢包端到端) |
| **★ 极端网络关卡** | 30% 丢包 + 150ms 抖动 + 25% 乱序三重叠加 | ✅ 已完成(`tests/netem.rs` 进程内 + `netem_bench.sh` 真机) |
| **4 生产化** | 证书持久化 / 鉴权 / 配置 / CLI 完善 + 连接迁移 + 压测画像 | 🟡 部分完成 |
| **5 可选** | QUIC 指纹混淆抗主动探测 | 未开始 |

> **最大风险**:RaptorQ 实时编解码在小 block + 高吞吐下的性能(低延迟场景 K 必须小,GF(256) 高斯消元相对开销上升)。若顶不住,给"极低延迟档"配 `--fec xor` 作为可选路径。

---

## 15. 风险与已知限制

| 风险 | 说明 | 缓解方向 |
|---|---|---|
| RaptorQ 实时编解码性能 | 高吞吐 + 小 block 时 CPU 可能成瓶颈 | 已提供 `--fec off` 降级开关;必要时引入 `--fec xor` |
| 小 block 下 FEC 效率下降 | 极低延迟(游戏)要求 K 很小,喷泉码渐进最优性不明显 | 评估异或类 FEC 作为超低延迟可选路径 |
| datagram 路径 MTU 依赖 | symbol size 不当会隐性分片 | `SAFE_MAX_SYMBOL_SIZE=1100` 保守起始;动态 MTU 探测为路线图项 |
| 概率性解码失败 | 理论极低概率(1 − 1/256^(h+1)) | 已由 NACK + 可靠重传降级覆盖(§6.4) |
| 降级重传传整块 | 重丢时可靠通道重传整块(含已收部分),带宽非最优 | 可优化为只传缺口子集(路线图) |
| 硬期限用绝对时间 | 极慢链路(RTT 秒级)可能偏早触发降级 | 让期限随 RTT 缩放(路线图) |
| 块间保序内存开销 | 高并发大量逻辑连接时重组缓冲占内存 | 设缓冲上限 + 背压,纳入 Phase 4 压测 |

---

## 16. 与 kcptun 对照总结

| 维度 | kcptun(yamux over KCP) | Raptun(QUIC + RaptorQ) |
|---|---|---|
| 多路复用 | yamux,应用层手工分帧 | QUIC 原生 stream,协议内建 |
| 队头阻塞 | 存在(KCP 单流抽象) | 数据平面走 datagram,天然无跨流阻塞 |
| 可靠性机制 | KCP ARQ(被动重传) | 控制流:QUIC ACK 重传;数据流:RaptorQ 主动 FEC + 兜底降级 |
| 纠错方式 | 简单异或 FEC,固定比例 | RaptorQ 喷泉码,自适应比例,数学恢复概率近最优 |
| 流控 / 拥塞感知 | 应用层看不到底层真实状态 | 直接复用 Quinn 精确遥测 |
| 加密 | 自行实现(通常较弱) | TLS 1.3 内建 |
| 连接迁移 | 不支持(IP 变即断) | QUIC 原生支持 |
| 实现复杂度 | 两套协议叠加,状态机复杂 | 依赖两个成熟 crate,自研集中在 FEC 封装层 |

---

## 17. 附录:术语与参考

### 17.1 术语表

| 术语 | 说明 |
|---|---|
| Source Symbol | RaptorQ 编码前的原始数据分片 |
| Repair Symbol | RaptorQ 生成的冗余修复符号 |
| Source Block | 一组 K 个 source symbol 构成的编码单元 |
| ESI | Encoding Symbol ID,标识符号在编码空间中的位置 |
| Systematic Code | 系统码,编码输出包含未经变换的原始数据本身 |
| HoL Blocking | 队头阻塞,因排队顺序限制导致后续数据被迫等待 |

### 17.2 参考资料

- Quinn: https://github.com/quinn-rs/quinn
- cberner/raptorq: https://github.com/cberner/raptorq
- RFC 6330(RaptorQ)、RFC 9000(QUIC)、RFC 9221(QUIC 不可靠数据报扩展)
- kcptun(参考架构): https://github.com/sspanel/kcptun

---

*本文档与 `crates/` 下的代码同步维护。修改协议或收敛逻辑时,请同时更新 §3~9 与对应单元测试。*
