# Raptun 高吞吐拥塞与稳定性优化：分析报告与执行计划

> 本文档汇总 2026-08-10 对 raptun 代码库与服务端日志的分析，明确当前协议在高吞吐大流（4K 视频、下载、测速）下触发整隧道拥塞并重连的根因，并给出分阶段的优化执行计划。

---

## 1. 背景与观测到的现象

### 1.1 用户侧现象

- 客户端一旦跑起**单条大流量 TCP 流**（超清视频、下载、测速），很快出现：
  - 整隧道延迟飙升、卡顿；
  - 其他并发流（SSH、网页等）一同受影响；
  - 最终连接掉线，只能等待 raptun-client 重连。

### 1.2 服务端日志特征（2026-08-10 截取）

关键模式：

1. **突发高丢包，但 Quinn `congestion_events` 并不高**

   ```text
   09:12:43 loss_pct="81.56" sent_pkts=180033 lost_pkts=40189 congestion_events=5
   09:12:45 loss_pct="52.32" sent_pkts=195469 lost_pkts=48265 congestion_events=5
   09:12:47 loss_pct="33.69" sent_pkts=207234 lost_pkts=52229 congestion_events=6
   ```

   2 秒内发了约 18 万包、丢了 4 万包，但 Quinn 只报告了个位数 congestion event。说明 Quinn/BRR 并没有把这识别为“经典拥塞”，包是在**本地或中间网络缓冲区被尾部丢弃**的。

2. **重连后先干净，再逐步恶化**

   ```text
   09:13:58 loss_pct="0.02"  sent_pkts=20126  lost_pkts=5
   ...
   09:15:13 loss_pct="21.21" sent_pkts=154869 lost_pkts=8923
   ...
   09:36:09 loss_pct="47.81" sent_pkts=644249 lost_pkts=32880
   ```

   重连后丢包率先是 0%，随后几分钟内从 0% → 7% → 12% → 20% → 47% 逐渐爬升，直到再次雪崩。这是典型的**发送缓冲持续灌满 → 尾部丢包 → 修复风暴 → 更剧烈丢包**的循环。

3. **丢的都是满载 datagram**

   `lost_bytes / lost_packets ≈ 1200 B`，说明 MTU 大小的数据包被成批丢掉。由于 FEC 数据路径把每个 TCP 流切成 block，每个 block 又切成 K+repair 个 datagram，一次尾部丢包会直接废掉整个 block，触发 NACK 和 repair，进一步挤占缓冲。

---

## 2. 协议与代码现状

### 2.1 数据路径

```
App TCP ──► raptun-client ──► QUIC datagrams + RaptorQ FEC ──► raptun-server ──► Target TCP
                │                                                    │
                └─ 控制：QUIC reliable bi-stream #0 / per-tunnel signaling stream
```

- Raptun 是 **L4 TCP 终结代理**，不是 L3 VPN，内层 TCP 不会在 QUIC 上再跑一层拥塞控制。
- 业务数据默认走 **unreliable QUIC datagrams + RaptorQ FEC**。
- 每个本地 TCP 连接映射到一个 `stream_id`，但**所有 tunnel 共享同一条 QUIC 连接**。

### 2.2 关键模块与文件

| 文件 | 职责 | 相关代码 |
|---|---|---|
| `crates/raptun-proto/src/datagram.rs` | datagram header: `stream_id` + `block_id` + `esi` + flags | 16 字节头 |
| `crates/raptun-fec/src/budget.rs` | `RepairBudget`、`SendWindow` | 连接级窗口/预算 |
| `crates/raptun-fec/src/strategy.rs` | 自适应 FEC 比例控制器 | `FecStrategy::update` |
| `crates/raptun-fec/src/decoder.rs` |  per-block 状态机 | `BlockManager` / NACK / degraded |
| `crates/raptun-core/src/run.rs` | 客户端/服务端主循环、per-tunnel task、FEC 数据泵 | `:145-148`, `:1146-1173`, `:1617-1653` |
| `crates/raptun-core/src/endpoint.rs` | Quinn endpoint 构建、缓冲配置 | `:20-29`, `:35-103` |
| `crates/raptun-core/src/telemetry.rs` | 从 Quinn 采样到 `LinkState` | `:178-189` |
| `crates/raptun-core/src/fec.rs` | `DatagramHub`、`FecSender`、`FecReceiver`、`TunnelSignal` | `:243-432`, `:475-966` |
| `crates/raptun-client/src/cli.rs` / `crates/raptun-server/src/cli.rs` | CLI 与默认参数 | `:484`, `:475` 硬编码 `repair_cwnd_fraction=0.40` |

---

## 3. 根因分析

### 3.1 本地缓冲过大 → Bufferbloat

| 缓冲层级 | 当前值 | 说明 |
|---|---|---|
| Quinn datagram send buffer | 8 MiB | `endpoint.rs:29` |
| OS UDP send buffer (`SO_SNDBUF`) | 4 MiB | `config.rs:159` / `endpoint.rs:115-123` |
| 合计本地发送队列 | **~12 MiB** | 对多数家庭/云链路相当于数秒数据 |

后果：

- BBR 看到本地缓冲一直在“成功发送”，以为链路带宽很大，持续高速注入。
- 当本地队列最终溢出（或中间网络队列溢出）时，**成片的 datagram 同时丢失**。
- 由于 Quinn 的 loss detector 把这些当作普通丢包而非 persistent congestion，`congestion_events` 不高，cwnd 不会被迅速压低。

### 3.2 单条大流独占共享资源

- `SendWindow`、`RepairBudget`、datagram send buffer 都是**连接级共享**的（`run.rs:145-148`）。
- 上游发送逻辑只判断整连接 `has_room()`，没有 per-tunnel 上限（`run.rs:1146-1173`）。
- 虽然每个 block 发完后有 `tokio::task::yield_now().await`（`run.rs:1183`），但只能缓解，不能阻止单条视频流占满缓冲并把其他流的包挤到队尾。

### 3.3 FEC 拥塞判定过慢

`telemetry.rs:178-189` 的 `RegimeClassifier` 规则：

- 只有 `cwnd_bytes < prev_cwnd - prev_cwnd/8`（跌幅 >12.5%）时才判为 `Congestion`。
- 本地大缓冲把 cwnd 撑着，跌幅达不到阈值。
- 于是高丢包被误判为 `Random Loss`，`FecStrategy`（`strategy.rs:129-148`）继续把 repair ratio 往上拉，最高可到 `fec_max=0.50`。
- 修复流量最高又被允许占 cwnd 的 40%（`repair_cwnd_fraction=0.40`），进一步挤压有效数据。

### 3.4 可靠回退通道成为瓶颈

- 当 block 因 budget 不足或拥塞进入 `Degraded` 后，走 `ReliableRequest` / `ReliableData` 回退（`fec.rs:895-904`）。
- `ReliableData`（~20 KiB）和 NACK/Credit/BlockAck 共享**同一条 per-tunnel signaling stream**。
- `rel_data_tx` 队列只有 4 slot（`run.rs:946`），拥塞时大量 fallback 请求被丢弃，恢复慢。
- 大块 fallback 数据阻塞 small control signal，Credit 延迟返回，发送端 `SendWindow` 误以为没 room，TCP read 暂停，进一步降低有效吞吐。

### 3.5 重连与死连接检测偏慢

- 客户端退避：`500 ms` 起，最大 `30 s`（`run.rs:72-86`）。
- `idle_timeout = 30 s`（`config.rs:161`）。
- 没有主动 watchdog：只有在 Quinn 最终判定连接死亡后才重连，期间应用已经卡死。

---

## 4. 已落地的优化（P0–P2）

`docs/optimizations-tcp-over-quic.md` 中已实现：

| 优化项 | 内容 | 状态 |
|---|---|---|
| P0: Dead config 修复 | `socket_buffer` 真正设置 `SO_RCVBUF/SO_SNDBUF`；`allow_migration`/`allow_0rtt` 生效 | 已合并 |
| P1: Bounded channels | `rel_req` / `rel_data` 改为有界队列（32 / 4） | 已合并 |
| P2-a: Datagram yield | 每个 block 发完后 `yield_now()` | 已合并 |
| P2-b: MTU 配置 | `initial_mtu()` / `pad_to_mtu(true)` | 已合并 |

这些改动已经让配置生效、内存不再无界、burst 有所缓解，但**没有解决连接级 FIFO 调度、本地缓冲过大、拥塞误判**这几个根本问题。

---

## 5. 优化执行计划

### Phase 1：缓冲与参数调优（低侵入，1–2 天）

目标：先把本地队列从“秒级”压到“RTT 级”，并给运维可配置的杠杆。

| # | 改动 | 具体位置 | 验收标准 |
|---|---|---|---|
| 1.1 | **降低 datagram send buffer 默认值并暴露 CLI** | `endpoint.rs:29` 常量 → `TransportConfig` + CLI flag | 默认从 8 MiB 降到 **2 MiB**；可配 |
| 1.2 | **降低 `sockbuf` 默认值并暴露 CLI** | `config.rs:159` + `cli.rs` / `server/cli.rs` | 默认从 4 MiB 降到 **512 KiB**；可配 |
| 1.3 | **降低 `repair_cwnd_fraction` 默认值并暴露 CLI** | `cli.rs:484` / `server/cli.rs:475` 硬编码 → flag | 默认从 0.40 降到 **0.20**；建议范围 0.10–0.40 |
| 1.4 | **缩短重连退避** | `run.rs:72-86` | 初始 100–200 ms，最大 **5 s**，加随机抖动 |
| 1.5 | **缩短 dead 检测** | `config.rs:161` / CLI | `idle_timeout` 默认降到 **10 s**，`keepalive` 默认 **3 s** |
| 1.6 | **改进拥塞判定** | `telemetry.rs:178-189` | 当 `loss_rate > 10%` 且 cwnd 未涨时直接判 `Congestion` |

**预期效果**：单条大流的本地队列更贴近真实链路，BBR pacing 更准确，突发丢包率下降。

### Phase 2：公平调度与流隔离（中侵入，3–5 天）

目标：确保一条大流不能饿死其他 tunnel。

| # | 改动 | 具体位置 | 验收标准 |
|---|---|---|---|
| 2.1 | **连接级 DatagramPacer** | 新增模块，替换 `run.rs:1617-1653` 的直接 `send_datagram_paced` | 每个 tunnel 有自己的有界发送队列；一个连接级任务按 round-robin / WFQ 取出并调用 `send_datagram_wait` |
| 2.2 | **控制信号高优先级队列** | 同上 | NACK / Credit / BlockAck 优先于数据 datagram 发送 |
| 2.3 | **`SendWindow` 加 per-tunnel 上限** | `budget.rs:114-189` / `run.rs:1146-1173` | 单 tunnel 最大 in-flight block 数 = `max(ceiling / active_tunnels, MIN_PER_TUNNEL)` |

**预期效果**：4K 视频流占满带宽时，SSH/网页流的延迟毛刺显著降低。

### Phase 3：协议结构优化（中–高侵入，5–7 天）

目标：消除 degraded fallback 时的 head-of-line blocking，并暴露更多 CC 参数。

| # | 改动 | 具体位置 | 验收标准 |
|---|---|---|---|
| 3.1 | **ReliableData 分离到独立 bi-stream** | `fec.rs:47-91` 协议扩展；`run.rs:751-868` tunnel 建立 | 每个 FEC tunnel 拥有 `sig_stream`（小控制）和 `reliable_stream`（fallback 数据） |
| 3.2 | **扩大 fallback 队列** | `run.rs:941-946` | `rel_data_tx` 从 4 提到 **32**；`rel_req_tx` 从 32 提到 **64**（在独立 stream 落地前作为缓冲） |
| 3.3 | **暴露 BBR 参数** | `endpoint.rs:42` + `config.rs` + CLI | 支持 `bbr_initial_cwnd`、`bbr_min_rtt_filter_window` 等（以 quinn 0.11 实际字段为准） |

**预期效果**：高丢包场景下 fallback 不再阻塞 Credit，连接恢复速度提升。

### Phase 4：监控、watchdog 与回归验证（持续）

| # | 改动 | 具体位置 | 验收标准 |
|---|---|---|---|
| 4.1 | **Client watchdog** | `run.rs:342-400` heartbeat | 当 `loss_pct > 30%` 且 `cwnd` 低于阈值持续 N 秒，主动 `conn.close()` 触发快速重连 |
| 4.2 | **Prometheus 指标** | 现有 `monitor.rs` | 导出 per-tunnel 吞吐、丢包、`SendWindow` 占用、`RepairBudget` 占用、buffer 队列深度 |
| 4.3 | **netem 回归测试** | `tests/netem.rs` | 100 Mbps / 50 ms：单流吞吐 > 80 Mbps，loss < 2%；并发 10 条流时小流延迟 < 100 ms 抖动 |
| 4.4 | **负载测试** | `docs/loadtest-2026-08-02-1000tunnels.md` | 1000 tunnels 下 CPU/RSS 不劣化 |

---

## 6. 配置建议（供测试使用）

在代码改动前，可以先通过现有 CLI 参数做一轮验证：

```bash
# 服务端
raptun-server \
  --fec-max 0.25 \
  --sockbuf 524288 \
  --stream-rwnd 8388608 \
  --conn-rwnd 67108864 \
  --keepalive 3 \
  --idle-timeout 10

# 客户端
raptun-client \
  --fec-ratio 0.05 \
  --fec-max 0.25 \
  --sockbuf 524288 \
  --stream-rwnd 8388608 \
  --conn-rwnd 67108864 \
  --keepalive 3 \
  --idle-timeout 10 \
  --block-size 64
```

> 注意：`--block-size 64` 需要两端一致；`--sockbuf` 降低后若出现吞吐明显下降，可逐步加到 1 MiB，但建议不要回到 4 MiB。

---

## 7. 风险与回退

| 风险 | 缓解 |
|---|---|
| 降低 buffer 后吞吐下降 | 参数可配，先在小范围测试，再逐步推广；保留 `--datagram false` 回退到可靠 stream 的逃生通道 |
| DatagramPacer 引入额外延迟 | 使用 round-robin 简单调度，控制包走高优队列；单流测试确认 p99 延迟 |
| ReliableData 独立 stream 改动协议 | 保留旧协议兼容期，或 bump protocol version；server 根据 client version 决定是否开第二条 stream |
| BBR 参数暴露后配置错误 | 添加合理范围校验，默认保持当前行为 |

---

## 8. 验收标准（Definition of Done）

1. **稳定性**：单条 4K 视频或满速下载持续 10 分钟，其他并发 tunnel 的 RTT/丢包不受影响（小流延迟增加 < 20%）。
2. **吞吐**：在 100 Mbps / 50 ms 的 netem 场景下，单流吞吐 ≥ 80 Mbps；1 Gbps 内网场景下单流吞吐 ≥ 800 Mbps。
3. **恢复速度**：连接异常后，应用感知到的中断时间 < 5 秒。
4. **可观测性**：Prometheus 能实时看到 `send_window_utilization`、`repair_budget_utilization`、`datagram_queue_depth`。
5. **回归**：所有现有单元测试与 `loopback` / `netem` / `critical_dos` 测试通过。

---

## 9. 参考文档

- `docs/DESIGN.md` — 总体架构
- `docs/optimizations-tcp-over-quic.md` — 已实施的 P0–P2 优化
- `docs/TROUBLESHOOTING_STALLS.md` — 现有 stall 诊断思路
- `docs/loadtest-2026-08-02-1000tunnels.md` — 1000 tunnel 负载测试基线
- `docs/PLAN_FEC_REORDER_RESILIENCE.md` — FEC 与重排序相关设计
