# Building Raptun

This guide covers compiling Raptun across operating systems and target
architectures. For what the project *does*, see [`../README.md`](../README.md)
and [`DESIGN.md`](DESIGN.md).

## TL;DR

```bash
cargo build --release        # optimized binaries in target/release/
cargo test                   # 44 tests (portable, no root, no network shaping)
cargo test --features test-hooks   # 46 tests (adds deterministic loss-injection e2e)
cargo clippy --all-targets   # lints
cargo fmt --all -- --check   # format check
```

The build is pure Cargo — there is no `configure`, `make`, or code-gen step.
`cargo build` fetches and compiles all dependencies (quinn, rustls, rcgen,
raptorq) into `target/`.

## Prerequisites (all platforms)

| Tool | Minimum | Why |
|---|---|---|
| **Rust toolchain** | 1.75 (edition 2021; `rust-version` in `Cargo.toml`) | the whole build |
| **C compiler** | any working `cc`/MSVC | [`ring`](https://github.com/briansmith/ring) (rustls' crypto backend) has C/assembly |
| **Perl** | 5.x | `ring`'s build script generates assembly with it |
| **Git** | any | fetching the crate registry / this repo |

Install Rust via [rustup](https://rustup.rs):

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
rustc --version   # verify >= 1.75
```

> **Why a C compiler and Perl?** Raptun's TLS goes through `rustls` with the
> `ring` backend. `ring` is not pure Rust — it builds C and per-architecture
> assembly, so a host toolchain and Perl must be on `PATH`. This is the single
> most common cause of a failed first build. (Switching to the pure-Rust
> `aws-lc-rs`/`rustls` combos or a `*-ring`-free provider is possible but not
> wired up here.)

## Verified / expected support matrix

| Target | Status | Notes |
|---|---|---|
| `aarch64-apple-darwin` (Apple Silicon) | ✅ **built & tested here** | `cargo build --release` + all 46 tests pass |
| `x86_64-apple-darwin` (Intel Mac) | 🟢 expected | same toolchain as above |
| `x86_64-unknown-linux-gnu` | 🟢 expected | primary deployment target; also where `netem_bench.sh` runs |
| `aarch64-unknown-linux-gnu` | 🟢 expected | |
| `x86_64-unknown-linux-musl` | 🟢 expected (static) | needs `musl-gcc`; see below |
| `x86_64-pc-windows-msvc` | 🟢 expected | needs VS Build Tools; see below |
| `*-pc-windows-gnu` | 🟡 likely | MinGW toolchain; less exercised |
| `wasm32-*` | ❌ unsupported | `quinn-udp` needs real UDP sockets; the tunnel is inherently networked |
| `no_std` | ❌ unsupported (binaries) | client/server need `std` + tokio. `raptun-proto`/`raptun-fec` are `std`-oriented here too |

"Expected" means the code is portable Rust with no OS-specific `cfg` in Raptun's
own crates (only its dependencies branch on OS), so it should build once the
platform toolchain below is present. Only `aarch64-apple-darwin` has been
compiled and tested in this repo to date — treat other rows as "should work,
verify on first build."

## macOS

Verified host. Install the Command Line Tools (provides `clang` and `perl`):

```bash
xcode-select --install     # if `cc` is missing
cargo build --release
cargo test --features test-hooks
```

`tc netem` does not exist on macOS, so `netem_bench.sh` refuses to run and points
you at the portable in-process emulation instead:

```bash
cargo test -p raptun-core --test netem -- --nocapture
```

## Linux

Install a C toolchain and Perl, then build:

```bash
# Debian / Ubuntu
sudo apt-get update && sudo apt-get install -y build-essential perl pkg-config
# Fedora / RHEL
sudo dnf install -y gcc perl
# Arch
sudo pacman -S --needed base-devel perl

cargo build --release
cargo test --features test-hooks
```

Linux is the only platform that can run the real network-shaping benchmark
(needs root / `CAP_NET_ADMIN` and `iproute2`):

```bash
sudo apt-get install -y iproute2 python3
sudo ./netem_bench.sh       # shapes loopback with tc netem, runs the real binaries
```

### Static musl binary (portable, no libc dependency)

```bash
rustup target add x86_64-unknown-linux-musl
sudo apt-get install -y musl-tools    # provides musl-gcc
cargo build --release --target x86_64-unknown-linux-musl
# → target/x86_64-unknown-linux-musl/release/raptun-{client,server}
```

## Windows

Use the MSVC toolchain (recommended):

1. Install [Visual Studio Build Tools](https://visualstudio.microsoft.com/downloads/)
   with the "Desktop development with C++" workload (provides the MSVC `cl.exe`
   linker that `ring` needs).
2. Install Perl — [Strawberry Perl](https://strawberryperl.com/) is the usual
   choice; ensure `perl` is on `PATH`.
3. Install Rust via rustup (defaults to `x86_64-pc-windows-msvc`).

```powershell
cargo build --release
cargo test --features test-hooks
```

`netem_bench.sh` is a bash script and will not run natively; use WSL2 (a real
Linux kernel, so `tc netem` works there) or the portable `cargo test … netem`.

## Cross-compilation

For reproducible cross-builds without host toolchain juggling, use
[`cross`](https://github.com/cross-rs/cross) (Docker-backed):

```bash
cargo install cross
cross build --release --target aarch64-unknown-linux-gnu
cross build --release --target x86_64-unknown-linux-musl
```

`cross` ships images with the C compiler + Perl that `ring` requires, so it
side-steps the most common cross-compile failure.

## Feature flags

Raptun's crates expose a few Cargo features; the tunnel builds with defaults and
you rarely need to touch these:

| Crate | Feature | Effect |
|---|---|---|
| `raptun-core` | `test-hooks` | Compiles in deterministic datagram-loss injection used by the loss/degrade e2e tests. **Never enable in production** — it can silently drop traffic. |
| `raptun-proto` | `serde_support` | Optional `serde` derives on control messages (debug/config dumps). The on-wire codec is hand-rolled and does not need it. |

Build with a feature:

```bash
cargo build -p raptun-core --features test-hooks   # tests only
```

## Build outputs

| Path | What |
|---|---|
| `target/debug/raptun-client`, `raptun-server` | debug binaries (`cargo build`) |
| `target/release/raptun-client`, `raptun-server` | optimized binaries (`cargo build --release`) |
| `target/<triple>/release/…` | cross / alternate-target binaries |

The release profile enables thin LTO and a single codegen unit (see
`[profile.release]` in `Cargo.toml`), trading longer compile time for a faster,
smaller binary.

## Troubleshooting first-build failures

| Symptom | Cause | Fix |
|---|---|---|
| `error: failed to run custom build command for ring` / `perl … not found` | Perl missing | install Perl (see per-OS sections) |
| linker / `cc`/`cl.exe` not found | no C toolchain | install build-essential / Xcode CLT / VS Build Tools |
| `error: package requires rustc 1.75` | toolchain too old | `rustup update` |
| `netem_bench.sh` prints "tc netem is Linux-only" | running on macOS/Windows | use `cargo test … --test netem`, or WSL2/Linux |
| test hangs at a `--features test-hooks` e2e | leftover binaries holding a port | `pkill -9 -f raptun` then retry |
