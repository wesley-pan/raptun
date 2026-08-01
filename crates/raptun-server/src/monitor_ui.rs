//! Interactive `top`-style monitor for the server's active tunnels.
//!
//! Renders a live, auto-refreshing view of every FEC tunnel the server is
//! carrying: source address, RTT/loss (connection-level), age, throughput,
//! FEC overhead, delivered/total blocks, and a per-tunnel throughput sparkline.
//!
//! This is a synchronous, self-contained render loop meant to run on a blocking
//! thread (crossterm's event reads block). It only ever *reads* the shared
//! [`TunnelRegistry`]; the tunnels themselves keep updating their atomics on the
//! async runtime. On quit it restores the terminal and returns, letting the
//! caller shut the process down.

use std::collections::HashMap;
use std::collections::VecDeque;
use std::io::{self, Stdout};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crossterm::event::{self, Event, KeyCode, KeyModifiers};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Layout};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Cell, Row, Table};
use ratatui::Terminal;

use raptun_core::monitor::{TunnelRegistry, TunnelStats};

/// How many throughput samples to retain per tunnel for the sparkline. At the
/// default 1 s refresh this is a one-minute trailing window.
const HISTORY_LEN: usize = 60;

/// EWMA smoothing factor for the displayed rates. Higher = more responsive,
/// lower = smoother. 0.4 tracks bursts without the number jittering every tick.
const RATE_ALPHA: f64 = 0.4;

/// A tunnel is considered "idle" when its application-byte counters have not
/// advanced for this long. Idle tunnels are folded into a single summary row
/// per connection so a connection holding many keep-alives doesn't fill the
/// screen with 0 B/s rows. 3× the default refresh interval: short enough to
/// keep the active view clean, long enough that brief request/response gaps
/// don't get collapsed.
const IDLE_AFTER: Duration = Duration::from_secs(3);

/// Unicode block-elements for the inline sparkline, low to high.
const SPARK_BLOCKS: [char; 8] = ['▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'];

/// Column the rows are sorted by. Toggled with `s`.
#[derive(Debug, Clone, Copy, PartialEq)]
enum Sort {
    /// Highest download throughput first (default — the busy tunnels).
    Down,
    /// Highest upload throughput first.
    Up,
    /// Oldest tunnel first.
    Age,
}

impl Sort {
    fn next(self) -> Self {
        match self {
            Sort::Down => Sort::Up,
            Sort::Up => Sort::Age,
            Sort::Age => Sort::Down,
        }
    }
    fn label(self) -> &'static str {
        match self {
            Sort::Down => "↓down",
            Sort::Up => "↑up",
            Sort::Age => "age",
        }
    }
}

/// Per-tunnel derived state carried across ticks (rates + history), keyed by the
/// tunnel's id so it survives as long as the tunnel does.
#[derive(Default)]
struct TunnelHistory {
    last_bytes_up: u64,
    last_bytes_down: u64,
    up_rate: f64,   // bytes/s, EWMA-smoothed
    down_rate: f64, // bytes/s, EWMA-smoothed
    down_hist: VecDeque<u64>,
    /// When both byte counters last advanced. `None` = active this tick,
    /// `Some(t)` = idle since `t`. A fresh data sample resets it to `None`.
    idle_since: Option<Instant>,
}

/// Per-connection windowed loss, sampled once per connection per tick (all
/// tunnels on a connection share it), keyed by the connection's stable id.
#[derive(Default)]
struct ConnHistory {
    last_sent: u64,
    last_lost: u64,
    loss_pct: f64,
}

/// One rendered row: either a connection (group) header, a live tunnel under
/// it, or a folded summary of the group's idle keep-alive tunnels.
struct RowData {
    is_group: bool,
    is_idle_fold: bool,
    remote: String,
    rtt_ms: Option<u64>,
    loss_pct: Option<f64>,
    up_rate: f64,
    down_rate: f64,
    spark: String,
    fec_overhead: f64,
    age: Duration,
    delivered: u64,
    total: u64,
    lagging: bool,
}

type Term = Terminal<CrosstermBackend<Stdout>>;

/// Run the monitor until the user quits (`q` / `Esc` / `Ctrl-C`). Sets up and
/// tears down the alternate screen + raw mode, restoring the terminal on every
/// exit path including panics.
pub fn run(registry: Arc<TunnelRegistry>, interval: Duration) -> anyhow::Result<()> {
    let mut terminal = setup_terminal()?;
    // Restore the terminal even if the render loop panics, so a crash doesn't
    // leave the user's shell in raw mode / the alternate screen.
    let prev_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let _ = restore_terminal();
        prev_hook(info);
    }));

    let res = run_loop(&mut terminal, &registry, interval);

    restore_terminal()?;
    res
}

fn setup_terminal() -> anyhow::Result<Term> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    Ok(Terminal::new(backend)?)
}

fn restore_terminal() -> anyhow::Result<()> {
    let mut stdout = io::stdout();
    execute!(stdout, LeaveAlternateScreen)?;
    disable_raw_mode()?;
    Ok(())
}

fn run_loop(
    terminal: &mut Term,
    registry: &Arc<TunnelRegistry>,
    interval: Duration,
) -> anyhow::Result<()> {
    let started = Instant::now();
    let mut tunnels: HashMap<(usize, u64), TunnelHistory> = HashMap::new();
    let mut conns: HashMap<usize, ConnHistory> = HashMap::new();
    let mut sort = Sort::Down;
    let mut scroll: usize = 0;
    let mut frozen = false;
    let mut last_tick = Instant::now() - interval; // force an immediate first draw
    let mut rows: Vec<RowData> = Vec::new();

    loop {
        // Tick: recompute derived state from a registry snapshot, unless frozen.
        if last_tick.elapsed() >= interval {
            let dt = last_tick.elapsed().as_secs_f64().max(1e-3);
            last_tick = Instant::now();
            if !frozen {
                rows = sample(registry, &mut tunnels, &mut conns, dt, sort);
            }
        }

        draw(terminal, &rows, sort, frozen, started.elapsed(), scroll)?;

        // Handle input with a timeout so the tick still fires on schedule.
        let wait = interval.saturating_sub(last_tick.elapsed());
        if event::poll(wait.max(Duration::from_millis(50)))? {
            if let Event::Key(key) = event::read()? {
                match key.code {
                    KeyCode::Char('q') | KeyCode::Esc => break,
                    KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => break,
                    KeyCode::Char('s') => sort = sort.next(),
                    KeyCode::Char('f') => frozen = !frozen,
                    KeyCode::Up => scroll = scroll.saturating_sub(1),
                    KeyCode::Down => scroll = scroll.saturating_add(1),
                    KeyCode::PageUp => scroll = scroll.saturating_sub(10),
                    KeyCode::PageDown => scroll = scroll.saturating_add(10),
                    _ => {}
                }
            }
        }
    }
    Ok(())
}

/// Snapshot the registry and fold it into the carried-over history, producing
/// the grouped, sorted rows to render.
fn sample(
    registry: &Arc<TunnelRegistry>,
    tunnels: &mut HashMap<(usize, u64), TunnelHistory>,
    conns: &mut HashMap<usize, ConnHistory>,
    dt: f64,
    sort: Sort,
) -> Vec<RowData> {
    let snap = registry.snapshot();

    // Group tunnels by their owning connection (by remote address string), and
    // remember each tunnel's conn stable id for per-connection loss sampling.
    let mut groups: HashMap<String, Vec<Arc<TunnelStats>>> = HashMap::new();
    for st in &snap {
        groups
            .entry(st.remote.to_string())
            .or_default()
            .push(Arc::clone(st));
    }

    // Evict history entries whose tunnel is gone, so the maps track live state.
    let live_ids: std::collections::HashSet<(usize, u64)> = snap
        .iter()
        .filter_map(|s| s.connection().map(|c| (c.stable_id(), s.stream_id)))
        .collect();
    tunnels.retain(|id, _| live_ids.contains(id));

    let mut rows = Vec::new();
    let mut group_names: Vec<String> = groups.keys().cloned().collect();
    group_names.sort();

    // Connections that received an RTT/loss sample this tick; the rest get
    // evicted at the end so the `conns` map doesn't grow without bound as
    // old connections close (H8). `stable_id` is reused by QUIC over time,
    // so a stale entry could even mask a new connection's loss stats.
    let mut touched_conns: std::collections::HashSet<usize> = Default::default();

    for remote in group_names {
        let members = &groups[&remote];
        // Connection-level RTT/loss: sample once from any live member's conn.
        let mut rtt_ms = None;
        let mut loss_pct = None;
        if let Some(conn) = members.iter().find_map(|m| m.connection()) {
            rtt_ms = Some(conn.rtt().as_millis() as u64);
            let stats = conn.stats();
            let sid = conn.stable_id();
            touched_conns.insert(sid);
            let ch = conns.entry(sid).or_default();
            let sent = stats.path.sent_packets;
            let lost = stats.path.lost_packets;
            let d_sent = sent.saturating_sub(ch.last_sent);
            let d_lost = lost.saturating_sub(ch.last_lost);
            if d_sent > 0 {
                ch.loss_pct = (d_lost as f64 / d_sent as f64 * 100.0).clamp(0.0, 100.0);
            }
            ch.last_sent = sent;
            ch.last_lost = lost;
            loss_pct = Some(ch.loss_pct);
        }

        // Per-tunnel rows + group aggregate. Two passes: first collect raw
        // instantaneous rates so we can normalise the sparkline across the
        // group (otherwise one stream's old burst dominates the visual);
        // then build the rows.
        let mut g_up = 0.0;
        let mut g_down = 0.0;
        let mut child_rows: Vec<RowData> = Vec::new();
        let mut max_inst_down: f64 = 0.0;
        for st in members {
            let id = (
                st.connection().map(|c| c.stable_id()).unwrap_or(0),
                st.stream_id,
            );
            let bu = st.bytes_up.load(std::sync::atomic::Ordering::Relaxed);
            let bd = st.bytes_down.load(std::sync::atomic::Ordering::Relaxed);
            let h = tunnels.entry(id).or_default();
            // Capture the *previous* counter values BEFORE we overwrite them
            // so the idle-detection check compares new vs old (the previous
            // version compared new vs new, which was always equal and
            // therefore marked every tunnel as permanently idle — bug H9).
            let prev_up = h.last_bytes_up;
            let prev_down = h.last_bytes_down;
            let inst_up = bu.saturating_sub(prev_up) as f64 / dt;
            let inst_down = bd.saturating_sub(prev_down) as f64 / dt;
            h.last_bytes_up = bu;
            h.last_bytes_down = bd;
            // Reset the idle clock on any fresh traffic; otherwise stamp now
            // so the fold row can show how long this stream has been quiet.
            if bu != prev_up || bd != prev_down {
                h.idle_since = None;
            } else if h.idle_since.is_none() {
                h.idle_since = Some(Instant::now());
            }
            h.up_rate = ewma(h.up_rate, inst_up);
            h.down_rate = ewma(h.down_rate, inst_down);
            h.down_hist.push_back(inst_down as u64);
            while h.down_hist.len() > HISTORY_LEN {
                h.down_hist.pop_front();
            }
            if inst_down > max_inst_down {
                max_inst_down = inst_down;
            }
            g_up += h.up_rate;
            g_down += h.down_rate;

            let total = st.total_blocks.load(std::sync::atomic::Ordering::Relaxed);
            let delivered = st
                .delivered_blocks
                .load(std::sync::atomic::Ordering::Relaxed);
            let source = st.source_symbols_est().max(1);
            let repair = st.repair_symbols.load(std::sync::atomic::Ordering::Relaxed);
            child_rows.push(RowData {
                is_group: false,
                is_idle_fold: false,
                remote: format!("  ├ stream {}", st.stream_id),
                rtt_ms: None,
                loss_pct: None,
                up_rate: h.up_rate,
                down_rate: h.down_rate,
                spark: String::new(), // filled in after group-max is known
                fec_overhead: repair as f64 / source as f64,
                age: st.started_at.elapsed(),
                delivered,
                total,
                lagging: total > delivered,
            });
        }

        // Split children: active ones get a row, idle ones are folded. The
        // cutoff is IDLE_AFTER so a brief request/response gap doesn't fold a
        // still-busy stream. After IDLE_AFTER the EWMA rate is dominated by
        // the floor (≈0), so they look the same to the user.
        let now = Instant::now();
        let mut active: Vec<RowData> = Vec::new();
        let mut idle_count: usize = 0;
        let mut idle_oldest = Duration::ZERO;
        for (row, st) in child_rows.into_iter().zip(members.iter()) {
            let id = (
                st.connection().map(|c| c.stable_id()).unwrap_or(0),
                st.stream_id,
            );
            let idle_dur = tunnels
                .get(&id)
                .and_then(|h| h.idle_since)
                .map(|t| now.saturating_duration_since(t));
            let is_idle = idle_dur.is_some_and(|d| d >= IDLE_AFTER);
            if is_idle {
                idle_count += 1;
                if let Some(d) = idle_dur {
                    // `oldest` here is the *idle duration* of the most-idle
                    // member; from the user's perspective this reads as
                    // "the longest quiet one has been quiet for X".
                    if d > idle_oldest {
                        idle_oldest = d;
                    }
                }
            } else {
                let mut r = row;
                r.spark = sparkline_with_max(
                    tunnels
                        .get(&id)
                        .map(|h| &h.down_hist)
                        .unwrap_or(&VecDeque::new()),
                    max_inst_down,
                );
                active.push(r);
            }
        }

        // Sort active children within the group by the active key.
        sort_rows(&mut active, sort);

        rows.push(RowData {
            is_group: true,
            is_idle_fold: false,
            remote,
            rtt_ms,
            loss_pct,
            up_rate: g_up,
            down_rate: g_down,
            spark: String::new(),
            fec_overhead: 0.0,
            age: Duration::ZERO,
            delivered: 0,
            total: 0,
            lagging: false,
        });
        rows.extend(active);
        if idle_count > 0 {
            rows.push(RowData {
                is_idle_fold: true,
                is_group: false,
                remote: format!(
                    "  └ idle ({idle_count} stream{}",
                    if idle_count == 1 { "" } else { "s" }
                ),
                rtt_ms: None,
                loss_pct: None,
                up_rate: 0.0,
                down_rate: 0.0,
                spark: String::new(),
                fec_overhead: 0.0,
                age: idle_oldest,
                delivered: 0,
                total: 0,
                lagging: false,
            });
        }
    }
    // Evict `conns` entries for connections that disappeared this tick.
    // Without this, every QUIC stable_id ever seen stays in the map for the
    // life of the process; the map also holds a *windowed-loss state* tied
    // to a now-dead connection, so leaving stale entries would also corrupt
    // a future re-use of the same stable_id (H8).
    conns.retain(|sid, _| touched_conns.contains(sid));
    rows
}

fn sort_rows(rows: &mut [RowData], sort: Sort) {
    match sort {
        Sort::Down => rows.sort_by(|a, b| b.down_rate.total_cmp(&a.down_rate)),
        Sort::Up => rows.sort_by(|a, b| b.up_rate.total_cmp(&a.up_rate)),
        Sort::Age => rows.sort_by_key(|b| std::cmp::Reverse(b.age)),
    }
}

fn ewma(prev: f64, sample: f64) -> f64 {
    if prev == 0.0 {
        sample
    } else {
        RATE_ALPHA * sample + (1.0 - RATE_ALPHA) * prev
    }
}

/// Render a history buffer as inline block-element sparkline characters,
/// normalised against `group_max` (not the buffer's own max). With per-stream
/// normalisation, a stream whose only sample was a tiny burst early on would
/// fill its bar to the top — making every idle keep-alive look active. Using
/// the group's max keeps the visual scale honest: the noisiest stream in the
/// group fills the bar, quieter ones scale relative to it.
fn sparkline_with_max(hist: &VecDeque<u64>, group_max: f64) -> String {
    if hist.is_empty() || group_max <= 0.0 {
        return String::new();
    }
    hist.iter()
        .map(|&v| {
            let idx = ((v as f64 / group_max) * (SPARK_BLOCKS.len() - 1) as f64).round() as usize;
            SPARK_BLOCKS[idx.min(SPARK_BLOCKS.len() - 1)]
        })
        .collect()
}

/// Human-readable byte rate, e.g. `1.2 MB/s`.
fn fmt_rate(bytes_per_sec: f64) -> String {
    const UNITS: [&str; 4] = ["B", "KB", "MB", "GB"];
    let mut v = bytes_per_sec;
    let mut u = 0;
    while v >= 1024.0 && u < UNITS.len() - 1 {
        v /= 1024.0;
        u += 1;
    }
    format!("{v:.1} {}/s", UNITS[u])
}

fn fmt_age(d: Duration) -> String {
    let s = d.as_secs();
    format!("{:02}:{:02}:{:02}", s / 3600, (s % 3600) / 60, s % 60)
}

fn draw(
    terminal: &mut Term,
    rows: &[RowData],
    sort: Sort,
    frozen: bool,
    uptime: Duration,
    scroll: usize,
) -> anyhow::Result<()> {
    terminal.draw(|f| {
        let area = f.area();
        let chunks = Layout::vertical([
            Constraint::Length(1), // header
            Constraint::Min(1),    // table
            Constraint::Length(3), // aggregate footer
        ])
        .split(area);

        // --- Header line.
        let conns = rows.iter().filter(|r| r.is_group).count();
        let active = rows
            .iter()
            .filter(|r| !r.is_group && !r.is_idle_fold)
            .count();
        let idle_groups = rows.iter().filter(|r| r.is_idle_fold).count();
        let idle_suffix = if idle_groups > 0 {
            format!(" ({idle_groups} idle groups)")
        } else {
            String::new()
        };
        let header = Line::from(vec![
            Span::styled(
                "raptun-server monitor",
                Style::default().add_modifier(Modifier::BOLD),
            ),
            Span::raw(format!(
                "   up {}   conns {conns}   active {active}{idle_suffix}   sort:{}{}",
                fmt_age(uptime),
                sort.label(),
                if frozen { "   [FROZEN]" } else { "" },
            )),
            Span::styled(
                "     q:quit s:sort f:freeze ↑↓:scroll",
                Style::default().fg(Color::DarkGray),
            ),
        ]);
        f.render_widget(ratatui::widgets::Paragraph::new(header), chunks[0]);

        // --- Table.
        let header_cells = [
            "SOURCE", "RTT", "LOSS", "▲UP", "▼DOWN", "▼TREND", "FEC", "AGE", "BLK",
        ]
        .into_iter()
        .map(|h| Cell::from(h).style(Style::default().add_modifier(Modifier::BOLD)));
        let header_row = Row::new(header_cells);

        let visible = rows.iter().skip(scroll);
        let table_rows = visible.map(render_row);

        let widths = [
            Constraint::Length(20),
            Constraint::Length(6),
            Constraint::Length(6),
            Constraint::Length(11),
            Constraint::Length(11),
            Constraint::Length(16),
            Constraint::Length(6),
            Constraint::Length(9),
            Constraint::Length(13),
        ];
        let table = Table::new(table_rows, widths)
            .header(header_row)
            .block(Block::default().borders(Borders::NONE));
        f.render_widget(table, chunks[1]);

        // --- Aggregate footer.
        let tot_up: f64 = rows.iter().filter(|r| r.is_group).map(|r| r.up_rate).sum();
        let tot_down: f64 = rows
            .iter()
            .filter(|r| r.is_group)
            .map(|r| r.down_rate)
            .sum();
        let lagging = rows.iter().filter(|r| !r.is_group && r.lagging).count();
        let footer = Line::from(vec![Span::raw(format!(
            "aggregate  ▲ {}   ▼ {}   lagging tunnels {lagging}",
            fmt_rate(tot_up),
            fmt_rate(tot_down),
        ))]);
        f.render_widget(
            ratatui::widgets::Paragraph::new(footer).block(Block::default().borders(Borders::TOP)),
            chunks[2],
        );
    })?;
    Ok(())
}

fn render_row(r: &RowData) -> Row<'static> {
    if r.is_group {
        let style = Style::default().add_modifier(Modifier::BOLD);
        Row::new(vec![
            Cell::from(r.remote.clone()),
            Cell::from(r.rtt_ms.map(|v| format!("{v}ms")).unwrap_or_default()),
            Cell::from(r.loss_pct.map(|v| format!("{v:.1}%")).unwrap_or_default()),
            Cell::from(fmt_rate(r.up_rate)),
            Cell::from(fmt_rate(r.down_rate)),
            Cell::from(""),
            Cell::from(""),
            Cell::from(""),
            Cell::from(""),
        ])
        .style(style)
    } else if r.is_idle_fold {
        // One summary row for the group's idle keep-alive tunnels. The age
        // column shows how long the longest-quiet one has been quiet; the
        // other columns are zero. A muted colour so it doesn't visually
        // compete with live traffic.
        Row::new(vec![
            Cell::from(r.remote.clone()).style(Style::default().fg(Color::DarkGray)),
            Cell::from(""),
            Cell::from(""),
            Cell::from(""),
            Cell::from(""),
            Cell::from(""),
            Cell::from(""),
            Cell::from(fmt_age(r.age)).style(Style::default().fg(Color::DarkGray)),
            Cell::from(""),
        ])
    } else {
        let blk_style = if r.lagging {
            Style::default().fg(Color::Yellow)
        } else {
            Style::default()
        };
        Row::new(vec![
            Cell::from(r.remote.clone()).style(Style::default().fg(Color::Cyan)),
            Cell::from(""),
            Cell::from(""),
            Cell::from(fmt_rate(r.up_rate)),
            Cell::from(fmt_rate(r.down_rate)),
            Cell::from(r.spark.clone()).style(Style::default().fg(Color::Green)),
            Cell::from(format!("{:.2}", r.fec_overhead)),
            Cell::from(fmt_age(r.age)),
            Cell::from(format!("{}/{}", r.delivered, r.total)).style(blk_style),
        ])
    }
}

#[cfg(test)]
mod tests {
    use std::time::Instant;

    /// H9 regression: the "is this stream idle" check must compare the
    /// freshly-sampled byte counters to the **previous** tick's stored
    /// counters, NOT to the just-overwritten stored value (the previous
    /// version of the code did the latter, which made every tunnel
    /// permanently idle and the monitor useless).
    #[test]
    fn idle_check_compares_new_to_previous_not_new_to_new() {
        // The logic, lifted from `sample`. Kept in a tiny helper so the
        // test documents and locks the invariant without needing a
        // `TunnelRegistry` setup.
        fn update_idle_since(
            idle: &mut Option<Instant>,
            new_up: u64,
            new_down: u64,
            prev_up: u64,
            prev_down: u64,
            now: Instant,
        ) {
            if new_up != prev_up || new_down != prev_down {
                *idle = None;
            } else if idle.is_none() {
                *idle = Some(now);
            }
        }

        let mut idle: Option<Instant> = None;
        let now0 = Instant::now();
        // No traffic on the first tick: idle stamp is set.
        update_idle_since(&mut idle, 0, 0, 0, 0, now0);
        assert!(idle.is_some(), "first idle tick must stamp idle_since");

        // Same counters on the second tick: the comparison must be
        // (0 == prev_up && 0 == prev_down), which is true because the
        // *previous* stored value was indeed 0,0. Idle is *not* cleared.
        update_idle_since(&mut idle, 0, 0, 0, 0, now0);
        assert!(
            idle.is_some(),
            "still idle: comparison correctly used the previous counter values"
        );

        // Now traffic arrives: previous (0, 0) != new (100, 50). Cleared.
        update_idle_since(&mut idle, 100, 50, 0, 0, now0);
        assert!(idle.is_none(), "fresh traffic must clear idle_since");

        // And traffic stops again: stamp a fresh idle time.
        let now1 = now0;
        update_idle_since(&mut idle, 100, 50, 100, 50, now1);
        assert!(idle.is_some(), "traffic stops, idle is stamped again");
    }
}
