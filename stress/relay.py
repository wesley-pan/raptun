#!/usr/bin/env python3
"""UDP delay/loss relay — a userspace stand-in for kernel link shaping.

macOS `pf` skips loopback by default (`set skip on lo0`), so dnctl/dummynet
never intercepts 127.0.0.1 traffic and cannot shape the tunnel. This relay sits
between the raptun client and server on loopback and shapes the UDP datagrams
itself: each packet is held for a propagation delay (plus optional jitter) and
dropped with a given probability, in BOTH directions.

  client  --->  relay(:LISTEN)  --->  server(:TARGET)
          <---                  <---

Delay is applied per-packet via the event loop (call_later), so packets are
held concurrently — not serialized — modelling propagation delay without
throttling throughput. Unlike macOS dummynet, jitter IS available here because
the relay picks each packet's delay itself.

Assumes a single client UDP source (the raptun client uses one socket for its
QUIC connection), which is the stress harness's topology.

Usage:
  relay.py <listen_port> <server_port> <delay_ms> <jitter_ms> <loss_pct>
"""
import asyncio
import sys


class Shaper:
    def __init__(self, delay_ms, jitter_ms, loss):
        self.delay = delay_ms / 1000.0
        self.jitter = jitter_ms / 1000.0
        self.loss = loss
        self._ctr = 0x9E3779B97F4A7C15

    def _rand(self):
        # xorshift* on a counter: fast, no imports, good enough for sampling.
        x = self._ctr
        x ^= x >> 12
        x ^= (x << 25) & (2**64 - 1)
        x ^= x >> 27
        self._ctr = x & (2**64 - 1)
        return ((x * 0x2545F4914F6CDD1D) & (2**64 - 1)) / float(2**64)

    def drop(self):
        return self.loss > 0 and self._rand() < self.loss

    def delay_for(self):
        if self.jitter <= 0:
            return self.delay
        return max(0.0, self.delay + (self._rand() * 2 - 1) * self.jitter)


class Relay:
    """Bidirectional shaped UDP relay between a single client and the server."""

    def __init__(self, server_addr, up, down):
        self.server_addr = server_addr
        self.up = up      # shaper: client -> server
        self.down = down  # shaper: server -> client
        self.client_transport = None  # socket the client talks to
        self.server_transport = None  # socket we talk to the server on
        self.client_addr = None
        self.loop = asyncio.get_event_loop()
        self.stats = {"c2s": 0, "s2c": 0, "drop_up": 0, "drop_down": 0}

    # client -> server
    def on_client_packet(self, data, addr):
        self.client_addr = addr
        if self.up.drop():
            self.stats["drop_up"] += 1
            return
        self.loop.call_later(
            self.up.delay_for(),
            lambda: self.server_transport.sendto(data, self.server_addr),
        )
        self.stats["c2s"] += 1

    # server -> client
    def on_server_packet(self, data, addr):
        if self.down.drop():
            self.stats["drop_down"] += 1
            return
        if self.client_addr is None:
            return
        ca = self.client_addr
        self.loop.call_later(
            self.down.delay_for(),
            lambda: self.client_transport.sendto(data, ca),
        )
        self.stats["s2c"] += 1


class _ClientSide(asyncio.DatagramProtocol):
    def __init__(self, relay):
        self.relay = relay

    def connection_made(self, transport):
        self.relay.client_transport = transport

    def datagram_received(self, data, addr):
        self.relay.on_client_packet(data, addr)


class _ServerSide(asyncio.DatagramProtocol):
    def __init__(self, relay):
        self.relay = relay

    def connection_made(self, transport):
        self.relay.server_transport = transport

    def datagram_received(self, data, addr):
        self.relay.on_server_packet(data, addr)


async def main():
    listen_port = int(sys.argv[1])
    server_port = int(sys.argv[2])
    delay_ms = float(sys.argv[3])
    jitter_ms = float(sys.argv[4])
    loss_pct = float(sys.argv[5])

    loop = asyncio.get_event_loop()
    relay = Relay(
        ("127.0.0.1", server_port),
        Shaper(delay_ms, jitter_ms, loss_pct / 100.0),
        Shaper(delay_ms, jitter_ms, loss_pct / 100.0),
    )

    await loop.create_datagram_endpoint(
        lambda: _ClientSide(relay), local_addr=("127.0.0.1", listen_port)
    )
    await loop.create_datagram_endpoint(
        lambda: _ServerSide(relay), local_addr=("127.0.0.1", 0)
    )

    print(
        f"relay up: :{listen_port} <-> server :{server_port} "
        f"delay={delay_ms}ms jitter={jitter_ms}ms loss={loss_pct}%",
        flush=True,
    )
    # Periodically report actual shaped counts so the run can compare the loss
    # the relay INJECTED against the loss the client's telemetry REPORTS.
    while True:
        await asyncio.sleep(5)
        s = relay.stats
        up_tot = s["c2s"] + s["drop_up"]
        down_tot = s["s2c"] + s["drop_down"]
        up_loss = 100.0 * s["drop_up"] / max(1, up_tot)
        down_loss = 100.0 * s["drop_down"] / max(1, down_tot)
        print(
            f"relay stats: c2s={s['c2s']} (drop {s['drop_up']}, {up_loss:.1f}%) "
            f"s2c={s['s2c']} (drop {s['drop_down']}, {down_loss:.1f}%)",
            flush=True,
        )


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
