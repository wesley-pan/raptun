# 提升抗乱序能力：FEC ACK 驱动释放 + Quinn 乱序调参 + 主动冗余喷发

## 实现状态

| 模块 | 状态 | 验证 |
|---|---|---|
| M2 Quinn 乱序调参 | ✅ 已实现 | cwnd 传输中 2× 提升（77→134KB vs 34→59KB），空闲 cwnd 5.8MB vs 3.3MB，5MB 交付 vs 0B |
| M1 BlockAck + ACK 驱动释放 | ✅ 已实现 | 信令编解码、drain_acks 接线、retire_block 双向驱动、netem 测试覆盖 |
| M3 主动冗余喷发 | ✅ 已实现 | `FecSender::proactive_topups`、upstream RTT/4 ticker、LinkState 共享、congestion 刹车、单元测试 |

**验证数据**（`stress/run.sh 1 30 100 50 0`，jitter=50ms, loss=0%）：
- 无 M2：传输 0 字节，cwnd 34–59KB，idle 3.3MB
- 有 M2：传输 5MB，cwnd 77–134KB，idle 5.8MB，black_holes=0
- 基线（jitter=0）：传输 15MB，cwnd 27–45MB，loss_pct=0%

## 背景与诊断结论（为什么做这三件事）

诊断已证明（`stress/results/20260719-215147` 等）：

- **RaptorQ 解码层已是喷泉码**：`BlockManager::on_symbol` → `codec.add_symbol(esi, payload)`，凑够 K 即解码，与顺序无关。乱序下 FEC 不停滞。
- **真正乱序瓶颈在 QUIC 层**：relay.py 每包独立 `call_later` 分配 50–150ms 延迟，制造 ~100ms 乱序，超出 Quinn 默认 `packet_threshold=3` / `time_threshold=1.125·RTT` → 迟到包被判 `lost_packets`（虚高到 78%）→ `black_holes_detected=406` → cwnd 在 13KB↔3.3MB 振荡 → throughput 崩塌。jitter=0 对照实验 loss 归零、cwnd 稳定 43–56MB。
- **发送端 block 释放只靠 `SENDER_RETAIN_BYTES=4MB` 字节窗口被动淘汰**（`fec.rs:393 evict_old_blocks`）；`retire_block`（`fec.rs:429`）已定义、文档写明"once the receiver confirms it decoded (via an ack)"，**但从未被调用**。
- **`Credit { delivered }`** 已是累计交付 ACK（`fec.rs:74-80`，= `next_deliver`），但仅用于 `SendWindow` 流控，未驱动释放。
- **流结束 session 释放已工作**：`run_fec_tunnel` 返回时 `FecSender`/`FecReceiver` 随任务 drop。

结论：用户思路（喷泉码不等待乱序包 → 持续收修复包 → 解码即确认 → 释放资源）中，前半已具备，**缺口是发送端无 ACK 驱动主动释放 + QUIC 层乱序误判 + 主动补喷不依赖 NACK 往返**。

## 设计总览

三大模块，互为补充，**建议分阶段落地**（模块2 最先，直接对症；模块1 次之；模块3 最后）：

| 模块 | 改什么 | 解决什么 |
|---|---|---|
| M1 BlockAck 信令 + ACK 驱动释放 | 新增 `BlockAck{block}`，解码即发，发送端 `retire_block` | 发送端内存及时释放；为 M3 提供"已解码"停喷信号 |
| M2 Quinn 乱序调参 | 调 `packet_threshold`/`time_threshold`/`persistent_congestion_threshold`/`min_mtu`/`initial_rtt` | 消除乱序误判 lost、止住 cwnd 振荡（根因） |
| M3 主动冗余喷发 | 未 ACK 块超时主动 `additional_repair`，不等 NACK | 解码不依赖 NACK 往返；对齐"持续收修复包到解码" |

**不改**：RaptorQ 解码算法、按序交付（`next_deliver`/`drain_ready`）、NACK/`ReliableRequest` 兜底、`Credit` 流控（保留）、`evict_old_blocks`（作 M1 的兜底保留）。

---

## M1：BlockAck 信令 + ACK 驱动释放

### 信令（`crates/raptun-core/src/fec.rs`）

- `TunnelSignal` 新增变体 `BlockAck { block: BlockId }`，`TAG_BLOCKACK: u8 = 7`（现有 tag 到 6=Credit，追加）。
- `encode`/`decode` 加分支：1 字节 tag + 8 字节 block_id（9 字节，定长，`decode` 返回 `Some((BlockAck{block}, 9))`）。
- 语义：**接收端某 block 解码成功（进 `ready`）即发**，不等按序交付。这正是选 `BlockAck` 而非复用 `Credit` 的理由——`Credit.delivered` 只在按序交付推进时更新，乱序解码的块（如 block 5 先于 block 4 解码）不会推进 `next_deliver`，无法及时释放；`BlockAck` 逐块确认，不受按序交付阻塞。

### 接收端：解码即记 ACK（`fec.rs` FecReceiver）

- `FecReceiver` 加字段 `pending_acks: Vec<BlockId>`。
- `on_symbol`（`fec.rs:506`）：在 `Deliver { bytes }` 分支把 block 推进 `ready` 的同时，`pending_acks.push(block_id)`。
- `on_reliable_block`（`fec.rs:680`）：可靠重传完成同样 `pending_acks.push(block_id)`（可靠完成的块也该释放发送端 `encoders`/`repair_sent`）。
- 加方法 `pub fn drain_acks(&mut self) -> Vec<BlockId>`：取走并清空 `pending_acks`。
- 下行任务（`run.rs:935-962` tick 分支，以及 `on_symbol`/`on_reliable_block` 后）调 `drain_acks()`，对每个 block `down_sig.send(TunnelSignal::BlockAck { block })`。可靠信令流保证不丢。

### 发送端：收到 ACK 即 retire（`run.rs` up 任务）

- 新增 channel `let (ack_tx, mut ack_rx) = mpsc::unbounded_channel::<u64>();`。
- 信号 reader（`run.rs:710-729`）加 `TunnelSignal::BlockAck { block } => ack_tx.send(block)`。
- up 任务 `tokio::select!`（`run.rs:757` 与 post-EOF `849`）加分支 `Some(block) = ack_rx.recv() => { sender.retire_block(block); }`。
- `retire_block`（`fec.rs:429`）已实现：移除 `encoders`/`repair_sent`/`payloads`。retire 后 `additional_repair`/`reliable_payload` 对该块返回空——正确，块已解码无需再补。

### 保留 `evict_old_blocks` 作兜底

`BlockAck` 走可靠流不丢，但 up 的 post-EOF 循环仍需服务可能的 late NACK/`ReliableRequest`（对端某块卡住），故 4MB 窗口保留防止已退役块被重请求时无 payload。M1 不改 `SENDER_RETAIN_BYTES`（保守；M3 落地后可评估下调）。

### M1 测试

- `blockack_round_trips`（`fec.rs`）：编解码往返。
- `blockack_emitted_on_decode_not_delivery`（`fec.rs`）：解码 block 5 但 block 4 未解码时，`drain_acks()` 仍含 5（不卡按序交付）。
- `retired_block_serves_no_repair`（`fec.rs`）：`retire_block(N)` 后 `additional_repair(N, ..)` 返回空、`reliable_payload(N)` 返回 `None`。
- `blockack_releases_sender_under_reorder`（`tests/fec_e2e.rs`，`test-hooks`）：注入乱序/丢包，多块流完成后断言发送端 `encoders`/`payloads` 已清空（ACK 驱动释放，非等 4MB 窗口）。
- 回归：现有 `sender_retention_is_bounded` 等仍通过。

---

## M2：Quinn TransportConfig 乱序调参

### 可调参数（`crates/raptun-core/src/endpoint.rs` `build_transport`）

诊断映射到 Quinn 0.11.16 `TransportConfig` setter：

| setter | 默认 | 调整为 | 作用 |
|---|---|---|---|
| `packet_threshold` (158) | 3 | 8（可配） | 包级重排阈值，乱序包不被判 lost（核心） |
| `time_threshold` (165) | 1.125 | 2.0（可配） | 时间级丢包阈值更宽松 |
| `persistent_congestion_threshold` (247) | 3 | 5（可配） | 避免误判持续拥塞导致 cwnd 崩塌 |
| `initial_rtt` (171) | 33ms | 由配置给（默认保持） | 避免初始过激丢包判定 |
| `min_mtu` (206) | — | 1200 | 防 MTU 黑洞误检测触发 cwnd 重置 |
| `black_hole_cooldown`（MtuDiscoveryConfig, 722） | 默认 | 调大 | 降低黑洞反复触发频率 |

### 配置暴露（`crates/raptun-core/src/config.rs` `TransportConfig`）

新增字段（均带默认值，向后兼容）：
```
reorder_packet_threshold: u32        // default 8
reorder_time_threshold: f32          // default 2.0
persistent_congestion_threshold: u32 // default 5
min_mtu: u16                         // default 1200
initial_rtt: Duration                // default Quinn's
```
`build_transport` 读取并 `t.packet_threshold(..)` 等。CLI/TOML 暴露（`raptun-{client,server}` 的 `--help` 与 example toml 加说明）。

### M2 测试

- `transport_builds_with_reorder_tuning`（`endpoint.rs`）：自定义各阈值，`build_transport` 成功且字段生效（读回 `QuinnTransport`）。
- 默认值单测：不传时回落 Quinn 默认/本项目默认。
- 集成验证：`stress/run.sh 1 30 100 50 0`（复现乱序场景），调参后 `metrics.csv` 的 `loss_pct` 回归低位、`cwnd` 不再 13KB↔MB 振荡、`black_holes` 显著下降。此为人工验收点（非单测）。

### 风险

`packet_threshold`/`time_threshold` 调大 → 真实丢包检测延迟上升（重传更晚）。默认值保守（8/2.0），且可配。乱序为主的环境收益远大于延迟代价。

---

## M3：主动冗余喷发（proactive top-up）

### 动机

当前主动修复仅在 `encode_one_block` 时按 `FecStrategy.current()` 比例发一次；后续补充完全依赖接收端 NACK（一个 RTT 往返）。乱序/高 loss 下，接收端可能凑不齐 K，NACK 又受 `grace`/`budget` 仲裁延迟。用户要"继续接收后续修复的包到解码"——发送端应**主动持续补喷**，不等 NACK。

### FecSender 增强（`crates/raptun-fec/src/fec.rs`，注：实际在 `crates/raptun-core/src/fec.rs` 的 `FecSender`）

- 加字段 `block_sent_at: HashMap<BlockId, Instant>`（`encode_one_block` 时记录首次发出时间）。
- 加方法 `pub fn proactive_topups(&self, now: Instant, rtt: Duration, budget: &RepairBudget) -> Vec<(BlockId, u32)>`：
  - 遍历仍保留且未 ACK 的块（`encoders` 有、`block_sent_at` 有）。
  - 对 `now - sent_at > rtt`（一轮 RTT 未收到 `BlockAck`）的块，建议补发 `extra = max(1, k.saturating_sub(received_estimate))`（接收端 `have` 未知，用保守的"补到 K"上界的 1/4，受预算 cap）。
  - `budget.try_reserve(extra)` 通过才纳入；累计每块 proactive 次数 ≤ `PROACTIVE_TOPUP_CAP`（如 3），超过就交给 NACK/`ReliableRequest`。
  - 返回待补 `(block, extra)` 列表。
- `retire_block` 一并清 `block_sent_at`（M1 收到 ACK 即清）。

### up 任务接线（`run.rs`）

- up 任务加一个 `tokio::time::interval(rtt/4)` 定时器分支（与现有 `select!` 合并）：
  - `sample = read_telemetry(..)` 取 rtt（或用 `conn.rtt()`）。
  - `for (block, extra) in sender.proactive_topups(now, rtt, &budget) { for dg in sender.additional_repair(block, extra) { send_datagram_paced(..).await } }`。
- 与 NACK 分支共存：NACK 是接收端主动求助（快路径，带 `have` 精确），proactive top-up 是发送端主动兜底（不等 NACK）。两者都经 `RepairBudget`，不会叠加爆喷。

### 带宽保护

- `RepairBudget`（≤40% cwnd）仍是硬上限，proactive 与 NACK 共享。
- `PROACTIVE_TOPUP_CAP` 限每块 proactive 次数。
- `FecStrategy.max`（0.5）限单次 `additional_repair` 量级。
- regime=Congestion 时 `proactive_topups` 返回空（拥塞时不主动加喷，沿用现有降级策略）——读 `LinkState`。

### M3 测试

- `proactive_topup_fires_after_rtt_without_ack`（`fec.rs`）：编码块后未 ACK，过 1 RTT `proactive_topups` 返回该块；收到 `BlockAck`（retire）后返回空。
- `proactive_topup_respects_budget_and_cap`：预算耗尽/超 cap 时不补。
- `proactive_topup_silent_under_congestion`：Congestion regime 返回空。
- e2e（`test-hooks`）：高乱序下，禁用 NACK（或加大 `grace`）仅靠 proactive top-up 仍能完成解码交付，验证"不依赖 NACK 往返"。

---

## 分阶段落地与验收

1. **阶段一 = M2**（最先，直接对症）：调 Quinn 阈值，跑 `stress/run.sh 1 30 100 50 0` 验收 `loss_pct` 回归、`cwnd` 稳定、`black_holes` 下降。立竿见影。
2. **阶段二 = M1**：BlockAck + `retire_block` 接线，单测 + e2e 验发送端及时释放。
3. **阶段三 = M3**：proactive top-up，单测 + e2e 验不依赖 NACK 解码。
4. 每阶段：`cargo test --workspace` + `cargo test --features test-hooks` + `cargo clippy --all-targets -Dwarnings` + `cargo fmt --check` 全绿；stress 人工验收。

## 风险与回滚

- 三模块独立，可分别 revert。
- M2 配置字段带默认值，现有部署行为不变（默认即调参后的值；如需原 Quinn 默认可显式置 0/None 回退）。
- M3 受 `RepairBudget` + `PROACTIVE_TOPUP_CAP` 双重限流，最坏退化为现有 NACK 路径。
- M1 `BlockAck` 每块一帧（9B），大流（如 5MB≈280 块）约 2.5KB 走可靠流，可接受；如成瓶颈后续可改批量 `BlockAck { highest_contiguous_decoded }`。

## 不在本次范围

- 修 `stress/relay.py` 的 jitter 模型（harness 缺陷，另案——但 M2 落地后即使 relay 乱序，QUIC 层也能容忍）。
- 改 RaptorQ 解码算法本身。
- 改按序交付（`next_deliver`）语义。
- Python 绑定 / 可视化。

## 涉及文件

- `crates/raptun-core/src/fec.rs` — `TunnelSignal::BlockAck` 编解码；`FecReceiver.pending_acks`/`drain_acks`；`FecSender.block_sent_at`/`proactive_topups`/`retire_block` 接线。
- `crates/raptun-core/src/run.rs` — `ack_tx/ack_rx` channel；reader 分发 `BlockAck`；up 任务 `retire_block` 分支与 proactive 定时器分支。
- `crates/raptun-core/src/endpoint.rs` — `build_transport` 加乱序阈值 setter。
- `crates/raptun-core/src/config.rs` — `TransportConfig` 新字段 + 默认值。
- `crates/raptun-fec/src/decoder.rs` — 无需改（状态机不变）。
- `crates/raptun-core/tests/{fec_e2e,netem}.rs` — 新 e2e + 回归。
- `raptun-{client,server}` CLI + example toml — 新配置项暴露。
