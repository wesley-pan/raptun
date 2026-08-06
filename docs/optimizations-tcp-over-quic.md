# TCP-over-QUIC 性能与稳定性优化方案

> 基于 2026-08-04 multi-tunnel test session 发现的架构问题，结合 TCP-over-QUIC 经典五大问题（双重拥塞控制、双重可靠性、多流调度、流量控制背压、MTU 分片）对 Raptun 代码库的深度审计结果。

---

## 架构前提

Raptun 是 **L4 TCP 终结代理**（类似 HTTP/3），不是 L3 VPN 隧道：

```
App TCP → raptun-client → [QUIC datagrams + FEC] → raptun-server → Target TCP
```

- TCP 在代理两端终结，只有字节流 payload 跑在 QUIC 上
- 不存在"内层 TCP over 外层 QUIC"的嵌套 → 双重拥塞控制和双重可靠性在架构上已被消解
- 数据路径：QUIC Datagram（不可靠） + RaptorQ FEC
- 信令路径：QUIC Bi-Stream（可靠）

---

## 优化项 P0: 修复 3 个 Dead Config Fields

### 问题

`TransportConfig` 中有 3 个字段被 CLI 和配置文件解析，但从未应用到 Quinn：

| 字段 | 默认值 | 预期行为 | 实际情况 |
|---|---|---|---|
| `socket_buffer` | 4 MiB | 设置 UDP socket 的 `SO_RCVBUF`/`SO_SNDBUF` | **从未应用** — `endpoint.rs` 的 `build_transport()` 不读它 |
| `allow_migration` | `true` | 控制 QUIC 连接迁移 | **从未应用** — 未传给 `ServerConfig::migration()` |
| `allow_0rtt` | `true` | 启用 TLS 1.3 0-RTT | **从未应用** — 未设置 `rustls::ClientConfig::enable_early_data` |

**影响**：高吞吐场景下 OS 默认 UDP buffer（通常 212 KiB）成为瓶颈；连接迁移和 0-RTT 的配置形同虚设。

### 修复方案

**1. socket_buffer → SO_RCVBUF / SO_SNDBUF**

新增 `socket2` 依赖，在 `build_client_endpoint` 和 `build_server_endpoint` 中：
- 用 `socket2::Socket` 创建 UDP socket
- 调用 `socket.set_recv_buffer_size(req)` / `socket.set_send_buffer_size(req)`
- 读取实际生效值，若被 OS 截断则 `tracing::debug!` 提示检查 `sysctl rmem_max/wmem_max`
- 转换为 `std::net::UdpSocket` 后传给 `quinn::Endpoint::new()`

```rust
// endpoint.rs
fn apply_socket_buffers(socket: &socket2::Socket, requested: u32) {
    let req = requested as usize;
    if let Err(e) = socket.set_recv_buffer_size(req) {
        tracing::warn!(error = %e, requested, "failed to set SO_RCVBUF");
    }
    if let Err(e) = socket.set_send_buffer_size(req) {
        tracing::warn!(error = %e, requested, "failed to set SO_SNDBUF");
    }
    match (socket.recv_buffer_size(), socket.send_buffer_size()) {
        (Ok(rcv), Ok(snd)) if rcv < req || snd < req => {
            tracing::debug!(requested, actual_rcv = rcv, actual_snd = snd,
                "socket buffer smaller than requested (check sysctl rmem_max/wmem_max)");
        }
        _ => {}
    }
}
```

**2. allow_migration → ServerConfig::migration()**

```rust
// endpoint.rs: build_server_endpoint
server_cfg.migration(cfg.allow_migration);
```

**3. allow_0rtt → rustls enable_early_data**

```rust
// tls.rs: client_config
pub fn client_config(trust: &ServerTrust, allow_0rtt: bool) -> Result<quinn::ClientConfig> {
    // ...
    crypto.enable_early_data = allow_0rtt;
    // ...
}
```

### 修改文件

| 文件 | 变更 |
|---|---|
| `Cargo.toml` (workspace) | 新增 `socket2 = "0.6"` |
| `crates/raptun-core/Cargo.toml` | 新增 `socket2.workspace = true` |
| `crates/raptun-core/src/endpoint.rs` | 重构 `build_client_endpoint` / `build_server_endpoint` 使用 `socket2`，新增 `apply_socket_buffers`，应用 `migration()` 和 `initial_mtu()` |
| `crates/raptun-core/src/tls.rs` | `client_config()` 新增 `allow_0rtt` 参数 |
| `crates/raptun-core/src/run.rs` | 更新 `build_*_endpoint` 调用传入 `&config.transport` |
| `crates/raptun-core/tests/*.rs` | 更新所有测试调用（18 处） |

### 验证结果

```
cargo test -p raptun-core --lib: 41/41 passed
cargo test -p raptun-core --test loopback: 3/3 passed
cargo test -p raptun-core --test critical_dos: 0/0 (compile-gated)
cargo build --release: clean
```

---

## 优化项 P1: 关键信号通道改为 bounded（背压安全）

### 问题

每个 FEC tunnel 创建 **8 个 `mpsc::unbounded_channel`**（`run.rs:894-917`）。其中两个携带大 payload：

- `rel_data_tx/rx` — `ReliableData { block, bytes }` 每消息最大 ~20 KiB
- `rel_req_tx/rx` — `ReliableRequest { block }` 每消息 8 bytes

无背压意味着：如果接收端 TCP 写阻塞导致消费变慢，unbounded channel 允许无限堆积。极端情况下（全退化到可靠模式），内存可无限增长。

### 修复方案

将 `rel_req` 和 `rel_data` 改为 bounded channel：

| Channel | 容量 | 理由 |
|---|---|---|
| `rel_req` | 32 | 最多 32 个 pending request，足够覆盖正常丢包 |
| `rel_data` | 4 | 每消息 ~20 KiB，4 slots = ~80 KiB max queued |

发送端改用 `try_send`，channel 满时 `tracing::debug!` 并丢弃（tick 机制会重新请求）：

```rust
TunnelSignal::ReliableRequest { block } => {
    if let Err(e) = rel_req_tx.try_send(block) {
        tracing::debug!(block, error = %e, "rel_req channel full; tick will retry");
    }
}
TunnelSignal::ReliableData { block, bytes } => {
    if let Err(e) = rel_data_tx.try_send((block, bytes)) {
        tracing::debug!(block, error = %e, "rel_data channel full; tick will retry");
    }
}
```

**安全性**：丢弃消息不会导致数据丢失 — FEC tick 每 20ms 重新仲裁 stalled blocks，会重新发出 `ReliableRequest`。

### 修改文件

| 文件 | 变更 |
|---|---|
| `crates/raptun-core/src/run.rs:904-911` | `rel_req` 和 `rel_data` 改为 `mpsc::channel(n)` |
| `crates/raptun-core/src/run.rs:1011-1020` | `.send()` → `.try_send()` + debug log |

### 验证结果

```
cargo build -p raptun-core: clean
cargo test -p raptun-core --lib: 41/41 passed
```

---

## 优化项 P2-a: Datagram 发送 yield（跨 tunnel 公平性）

### 问题

FEC 路径中，每个 block 编码后立即批量发送 K+repair 个 datagram：

```rust
for dg in sender.encode_one_block(chunk, repair) {
    send_datagram_paced(&up_conn, dg).await;  // K=16 + 8 repair = 24 datagrams
}
```

一个高吞吐 tunnel 的 burst 在 datagram send buffer（8 MiB）中排成长队，其他 tunnel 的 datagram 被排在后面 → 延迟敏感 tunnel（SSH、游戏）出现毛刺。

### 修复方案

在每个 block 的 datagram burst 后添加 `tokio::task::yield_now().await`，让 tokio runtime 有机会调度其他 tunnel 的 task：

```rust
for dg in sender.encode_one_block(chunk, repair) {
    send_datagram_paced(&up_conn, dg).await;
}
tokio::task::yield_now().await;  // let other tunnels interleave
```

**效果**：不能完全保证公平（需要 WFQ），但能缓解"一个 tunnel 的 burst 占满 buffer"的问题。

### 修改文件

| 文件 | 变更 |
|---|---|
| `crates/raptun-core/src/run.rs:1131-1140` | block encode 循环后添加 `yield_now()` |

### 验证结果

```
cargo build -p raptun-core: clean
cargo test -p raptun-core --lib: 41/41 passed
```

---

## 优化项 P2-b: 显式配置 Quinn MTU 参数

### 问题

`cfg.mtu`（默认 1350）被 CLI 和配置文件解析，但 **从未传给 Quinn 的任何 MTU API**。Quinn 用自己的 PMTU discovery 默认值（初始 MTU = 1200，远低于配置的 1350）。`max_symbol_payload()` 函数只在测试中使用。

### 修复方案

在 `build_transport()` 中应用两个 Quinn API：

```rust
t.initial_mtu(cfg.mtu);     // PMTU discovery 起点从 1200 → 1350
t.pad_to_mtu(true);         // 小包填充到 MTU，改善丢包检测和 PMTU 探测
```

**效果**：
- Quinn PMTU discovery 从更准确的起点开始探测，减少初始阶段的 conservative 行为
- `pad_to_mtu(true)` 确保小包也参与 PMTU 探测和丢包检测

### 修改文件

| 文件 | 变更 |
|---|---|
| `crates/raptun-core/src/endpoint.rs:95-100` | 新增 `initial_mtu()` 和 `pad_to_mtu()` |

### 验证结果

```
cargo build -p raptun-core: clean
cargo test -p raptun-core --lib: 41/41 passed
```

---

## 未来优化项（已识别，未实施）

### F1: ReliableData 分离到独立 QUIC Stream（P1-1 延期）

**问题**：`ReliableData`（~20 KiB/消息）和小型控制信号（NACK、Credit、BlockAck）共享同一条 QUIC bi-stream。当隧道退化到全可靠模式时，大 payload 阻塞小信号 → Credit 延迟 → 发送端 flow-control gate 误判 → TCP read 暂停。

**方案**：每个 FEC tunnel 开两条 bi-stream：
- `sig_stream`：NACK, Credit, BlockAck, BlockCount, HighWater（小消息）
- `reliable_stream`：ReliableRequest, ReliableData（大 payload）

**延期原因**：需要修改 tunnel 建立协议（announce 第二条 stream）、writer/reader 拆分、stream 生命周期管理。P1-2 的 bounded channel 已将 HoL blocking 窗口限制在 ~80 KiB（4 条 ReliableData），风险可控。

### F2: 跨 Tunnel WFQ Pacer（P3）

**问题**：Quinn 默认 round-robin 调度所有 stream，大流量 tunnel 占满 cwnd，延迟敏感 tunnel 被饿死。

**方案**：在 `DatagramHub` 发送端实现加权公平队列（WFQ），按 tunnel 权重（端口号/手动配置）调度 datagram 发送顺序。

**工作量**：3-5 天，需要新的 `FairPacer` 结构和全面的并发测试。

### F3: BBR 参数暴露（P3）

**问题**：BBR 使用 Quinn 的 `BbrConfig::default()`，无任何可调参数。高延迟链路（卫星、跨境）需要调整 `min_rtt_filter` 窗口大小。

**方案**：在 `TransportConfig` 中暴露 `bbr_min_rtt_window`、`bbr_initial_cwnd` 等参数，传给 `BbrConfig`。

---

## 变更汇总

| 优化项 | 风险 | 收益 | 文件数 | 状态 |
|---|---|---|---|---|
| P0: Dead config 修复 | 低 | 高 | 6 | **已实施** |
| P1: Bounded channels | 低 | 中 | 1 | **已实施** |
| P2-a: Datagram yield | 低 | 中 | 1 | **已实施** |
| P2-b: Quinn MTU 配置 | 低 | 低-中 | 1 | **已实施** |
| F1: ReliableData 分离 | 中 | 高 | 3+ | 延期 |
| F2: WFQ Pacer | 高 | 高 | 5+ | 未来 |
| F3: BBR 参数 | 中 | 中 | 2 | 未来 |
