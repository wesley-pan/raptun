# 两类连接卡死问题的分析与修复

本文记录 Raptun 客户端/服务端在实际运行中出现的两类"卡死"问题——从现象、分析推理、根因定位，到修复方案、回归测试的完整过程。

两个问题看似相似(都表现为"连接不通"),但根因分处不同层次:

| # | 现象 | 层次 | 根因 | PR |
|---|------|------|------|----|
| 1 | 服务端重启后客户端永不重连,刷 `open signaling bi: timed out` | QUIC 连接生命周期 | 连接只建一次,断了不重拨 | [#1](https://github.com/wesley-pan/raptun/pull/1) |
| 2 | 跑一段时间后应用层中断,但抓包仍有包往来 | FEC 数据路径 | 三处数据泵缺陷导致死锁/劣化 | [#2](https://github.com/wesley-pan/raptun/pull/2) |

---

## 问题一:服务端重启后客户端不重连

### 现象

服务端终端重启后,客户端不会重连,持续刷警告:

```
WARN raptun_core::run: client tunnel closed with error error=QUIC endpoint error: open signaling bi: timed out
WARN raptun_core::run: client tunnel closed with error error=QUIC endpoint error: open signaling bi: timed out
...
```

### 分析推理

从错误信息 `open signaling bi: timed out` 入手——这是在**已建立的 QUIC 连接上**打开新的双向流(bi-stream)超时。关键推理链:

1. 报错来自 `handle_client_conn_fec` 里的 `conn.open_bi()`(`run.rs`),说明客户端**仍持有一个 `conn` 对象**并尝试用它。
2. 但服务端已重启,这个 `conn` 对应的 QUIC 连接实际已死。在死连接上 `open_bi()` 只会超时。
3. 每个新的本地 TCP 连接都会触发一次 `open_bi()` → 都超时 → 无限刷警告。

于是定位到 `run_client` 的结构:

```rust
// 修复前:连接只建立一次,之后进入永久 accept 循环
pub async fn run_client(...) -> Result<()> {
    let conn = endpoint.connect(server_addr, sni)?.await?;   // ← 只此一次
    let (_ctrl, fec) = handshake_client(&conn, &config).await?;
    let listener = TcpListener::bind(local_addr).await?;
    let conn = Arc::new(conn);
    loop {
        let (tcp, peer) = listener.accept().await?;           // ← 永远用同一个死 conn
        tokio::spawn(handle_client_conn_fec(&conn, ...));
    }
}
```

**根因:客户端在启动时建立一次 QUIC 连接,之后无限循环接受本地 TCP 连接并复用这个连接。连接一旦死亡(服务端重启、空闲超时等),没有任何代码路径去重新拨号。**

### 修复方案

把 `run_client` 重构成一个**监督循环(supervision loop)**:

- 本地监听器**只绑定一次**(保持本地端口在重连间稳定)。
- 循环体:`connect + handshake` → `serve_connection` 服务隧道直到连接掉线 → 带**指数退避**重连(500ms → 30s,健康连接后重置)。
- `serve_connection` 用 `tokio::select!` 让 `listener.accept()` 与 `conn.closed()` 竞争,这样连接掉线时能**立即感知并返回重连**,而不是永久阻塞在 `accept()`。

```rust
// 修复后:监督循环
loop {
    let conn = match connect_and_handshake(&endpoint, server_addr, sni, &config).await {
        Ok(conn) => { backoff = Duration::from_millis(500); conn }
        Err(e) => {
            tracing::warn!(error = %e, retry_in = ?backoff, "connect/handshake failed; retrying");
            tokio::time::sleep(backoff).await;
            backoff = (backoff * 2).min(MAX_BACKOFF);
            continue;
        }
    };
    serve_connection(conn, &listener, &config).await?;   // 返回即代表连接已死
    tracing::warn!(%server_addr, "server connection lost; reconnecting");
}
```

```rust
// serve_connection 内部:accept 与连接掉线竞争
let (tcp, peer) = tokio::select! {
    accepted = listener.accept() => accepted?,
    closed = conn.closed() => {
        tracing::debug!(reason = %closed, "quic connection closed while idle");
        return Ok(());   // 触发上层重连
    }
};
```

### 回归测试

`client_reconnects_after_server_restart`(`fec_e2e.rs`):

1. 建服务端 → 客户端连上 → 完成一次往返。
2. `abort()` 掉服务端任务,等端口释放。
3. 用**相同地址、相同 pinned 证书**重启服务端。
4. 断言第二次往返成功(客户端已重连)。

针对旧代码该测试会挂起→超时→返回空(失败),修复后通过。

**过程中踩的坑:** 首次测试失败,排查发现是测试配置里 `keepalive(10s) > idle_timeout(3s)`——keepalive 必须小于 idle timeout,否则连接建立就非法。修正配置后通过。

---

## 问题二:运行一段时间后应用层中断(抓包仍有包)

### 现象

客户端运行一段时间后,服务端和客户端之间"卡死":**抓包还能看到数据包往来,但应用层数据中断**。

### 分析推理

"抓包有包但应用层不通"是关键线索:

- **传输层存活** → QUIC keepalive / ACK 在正常跑,所以抓包一直有流量。
- **应用层中断** → 承载业务数据的 **FEC 数据泵**卡住了。

这排除了连接层问题(问题一),把注意力集中到 `crates/raptun-fec`(纯状态机)和 `crates/raptun-core/src/fec.rs`(数据泵 + 隧道信令)。逐条审查预算生命周期、发送/接收端清理、按序交付逻辑——这是"先好后坏"型 bug 的常见藏身处。查出三个真实缺陷:

#### Finding 1 — `RepairBudget` 预算泄漏(`decoder.rs`)

修复预算是"在途修复符号"的全局刹车,ceiling 很小(`cwnd × 40% / symbol_size`,通常就几个符号)。审查 `try_reserve`/`release` 的调用点发现:

- **预留**发生在 `tick_stalled`:NACK 时 `budget.try_reserve(need)` → 进入 `NackSent`。
- **释放**只有**一处**:`tick_nack_sent` 里 NACK 超时无进展时。

两条**成功路径从不释放**:
- `on_symbol` 里 `NackSent → Done`(修复符号解码了 block)——未释放。
- `on_symbol` 里 `NackSent → Filling`(修复符号到达但还没凑齐)——未释放。

**推理:** 预算每隧道共享且 ceiling 极小。几个经 NACK 恢复的 block 之后,`in_flight` 永久超过 ceiling,此后 `try_reserve` 永远失败 → **每个**卡住的 block 都被迫走慢速可靠重传。这是单调劣化,恰好对应"跑一阵越来越糟"。

#### Finding 2 — 空闲流上完全丢失的 block 永不恢复(`fec.rs`)——硬卡死根因

交付严格按 block 顺序(`next_deliver`)。无 manager 的 block(即它的**所有** datagram 都丢了)只能靠 `tick` 里的"完全丢失扫描"恢复:

```rust
let upper = { let by_seen = self.highest_seen; let by_total = self.total_blocks.unwrap_or(0); by_seen.max(by_total) };
for block_id in self.next_deliver..upper {   // ← 上界是开区间,不含 upper
```

`highest_seen` 只在有符号到达时前进,`total_blocks` 只在 EOF(`BlockCount`)时设置。对**长连接的交互式流量**:

1. 发一批数据,其**最后一个 block 完全丢失**(一次丢包突发把它的 source+repair datagram 全丢了)。
2. 后面没有更高的 block(对端此刻在等应答),所以 `highest_seen` 到不了那个 block;没有 EOF 所以 `total_blocks` 一直是 `None`。
3. `upper` 等于丢失 block 的 id,循环 `next_deliver..upper` **排除**了它。接收端根本不知道该 block 存在,永远不会发 `ReliableRequest`。
4. 后续所有 block 堆在 `ready` 里等这个缺口 → 应用永久冻结,而 QUIC keepalive 让抓包一直有包。**与现象完全吻合。**

(部分收到的尾块能被 `tick_filling` 的 `past_hard_deadline` 逃逸救回;所以只有**整块消失**时才触发本 bug——而真实丢包突发正会造成整块消失。)

#### Finding 3 — 发送端 block 状态无界增长(`fec.rs`)

`FecSender::encode_one_block` 每个 block 都往 `encoders`/`repair_sent`/`payloads` 插入,`retire_block` 是**唯一**清理函数却**从未被调用**。长连接上这些 map 无限增长(每个保留完整 block 载荷 + 编码器),独立地导致"越跑内存越大/越慢"。

### 修复方案

#### Finding 1 修复:所有成功路径都归还预算

给 `BlockManager` 加 `reserved` 字段追踪本 block 持有的预留量,抽出 `release_reservation` 辅助函数,在 `on_symbol` 的解码成功、修复到达、以及 NACK 超时三条路径都调用:

```rust
fn release_reservation(&mut self, budget: &RepairBudget) {
    if self.reserved > 0 {
        budget.release(self.reserved);
        self.reserved = 0;   // 幂等:只释放一次
    }
}
```

`on_symbol` 因此需要 `&RepairBudget` 参数,该签名变化沿 `FecReceiver::on_symbol` 传导到 `run.rs` 下行任务(预算本就在那里持有)。

#### Finding 2 修复:新增 `HighWater` 可靠信令

问题本质是接收端**无从得知一个整块丢失的 block 存在**。修复靠发送端在**可靠信令流**(不会丢)上通告其已发块数的运行高水位:

- 新增 `TunnelSignal::HighWater { blocks }`(tag 5,与 `BlockCount` 区别在于它是**运行值而非终值**)。
- 发送端每次读突发后 `up_sig.send(HighWater { blocks: total_blocks })`——每突发一帧,不是每 block。
- 接收端 `set_high_water` 把它并入"完全丢失扫描"的上界,让扫描能触达该 block 并可靠请求它。

关键设计点:`HighWater` **非终结**,下行任务的完成判定 `highest_delivered() >= total` 仍只看 `BlockCount`,所以 `HighWater` 不会误触发流结束。上界计算也修正为正确处理"count vs id"语义:

```rust
let upper = {
    let by_seen = if self.managers.is_empty() && self.highest_seen == 0 { 0 } else { self.highest_seen + 1 };
    let by_high_water = self.high_water;               // 发送端通告的运行块数
    let by_total = self.total_blocks.unwrap_or(0);
    by_seen.max(by_high_water).max(by_total)
};
```

#### Finding 3 修复:发送端滑动窗口保留

加 `SENDER_RETAIN_BLOCKS = 1024` 常量,`encode_one_block` 时淘汰落后发送前沿超过窗口的旧 block。用 `oldest_retained` 低水位边界保证淘汰是 O(evicted) 而非全表扫描:

```rust
fn evict_old_blocks(&mut self) {
    if self.next_block <= SENDER_RETAIN_BLOCKS { return; }
    let cutoff = self.next_block - SENDER_RETAIN_BLOCKS;
    for block_id in self.oldest_retained..cutoff {
        self.encoders.remove(&block_id);
        self.repair_sent.remove(&block_id);
        self.payloads.remove(&block_id);
    }
    self.oldest_retained = self.oldest_retained.max(cutoff);
}
```

窗口足够大(1024 块)覆盖多个 RTT 的在途块;凡是收敛的场景中,落后超过该窗口的块必已被交付或已被可靠重传,继续保留只增长内存。

### 回归测试

新增/修改了以下测试,每个对应一个缺陷:

| 测试 | 位置 | 验证 |
|------|------|------|
| `budget_is_released_when_repair_decodes_the_block` | `decoder.rs` | 修复解码 block 时预算归零(核心回归) |
| `budget_is_released_when_repair_arrives_without_decoding` | `decoder.rs` | 修复到达但未解码时也释放预留 |
| `entirely_lost_block_recovered_via_high_water_when_idle` | `fec.rs` | 无 `HighWater` 时整块丢失不可见;有了之后触发可靠恢复,流收敛 |
| `sender_retention_is_bounded` | `fec.rs` | 发超窗后旧块被淘汰(返回 `None`),新块保留,map 有界 |
| `tunnel_signal_round_trips` | `fec.rs` | 补充 `HighWater` 编解码往返 |

**签名变更的连带修改:** `on_symbol` 增加 `&RepairBudget` 参数后,批量更新了所有调用点——`decoder.rs`/`fec.rs` 的单测(引入 `noop_budget`/`test_budget` 辅助)、`netem.rs` 仿真测试(补 `HighWater` match 分支)、`fec_e2e.rs` 的 `fec_pump_direct_smoke`。

---

## 验证结果

两个修复分别在独立分支(均从 `main` 拉出,互不依赖):

- **问题一:** `fix/client-reconnect-after-server-restart` → PR #1
- **问题二:** `fix/fec-data-path-stall` → PR #2

最终验证(问题二分支):

```
cargo test --workspace          → 48 passed (11 suites)
cargo test --features test-hooks --test fec_e2e  → 5 passed(含两个诱导丢包端到端恢复测试)
cargo clippy --workspace --all-targets           → 0 errors
cargo fmt --all -- --check                        → clean
```

## 涉及文件

**问题一:**
- `crates/raptun-core/src/run.rs` — `run_client` 重构为监督循环 + `connect_and_handshake` / `serve_connection`
- `crates/raptun-core/tests/fec_e2e.rs` — 重连回归测试

**问题二:**
- `crates/raptun-fec/src/decoder.rs` — 预算预留追踪与全路径释放
- `crates/raptun-core/src/fec.rs` — `HighWater` 信令、完全丢失扫描上界修正、发送端滑动窗口保留
- `crates/raptun-core/src/run.rs` — 上行任务发 `HighWater`、下行任务收 `HighWater` 并传递预算
- `crates/raptun-core/tests/{fec_e2e,netem}.rs` — 调用点适配与信令分支

## 经验小结

1. **从错误信息的确切措辞倒推调用点**:`open signaling bi: timed out` 直接指向"在已有连接上开流",而非"建连失败",这决定了问题一在连接生命周期层而非握手层。
2. **"传输存活 + 应用中断"是数据路径死锁的强信号**:抓包有包排除了连接层,把范围锁定到 FEC 状态机。
3. **共享资源的释放要覆盖所有退出路径**:Finding 1 的预算泄漏正是因为只处理了超时这一条退出路径。
4. **按序交付的系统里,"不知道缺口存在"比"知道但没数据"更危险**:Finding 2 的接收端连缺口都感知不到,必须由可靠边信道显式告知存在性。
5. **只增不减的容器在长连接里迟早爆**:Finding 3 的 `retire_block` 写了却没接线,是典型的"预留了清理接口但忘了调用"。
