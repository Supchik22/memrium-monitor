//! Memrium Monitor: the processes of the machine and how busy it is, on Chebrium. A thread reads `/proc` once a second
//! (`memrium_de::sysmon`) and wakes the window; between readings nothing is drawn.
//! Type to filter the list, Up / Down to choose, Delete to end the process (Shift+Delete forces it).

use chebrium::app::{self, App, Config, Host};
use chebrium::draw::Align;
use chebrium::input::{Key, KeyMods};
use chebrium::ui::{inside, Ui};
use memrium_de::fsops::human_size;
use memrium_de::sysmon::{self, format_rate, format_uptime, GpuUse, ProcInfo, Sampler, Snapshot};
use chebrium::picture::Pic;
use memrium_de::apps::{self, IconIndex};
use std::collections::{HashMap, HashSet};
use std::sync::{
    mpsc::{channel, Receiver},
    Arc,
};

const TOP_H: f32 = 52.0;
const HEAD_H: f32 = 28.0;
const ROW_H: f32 = 30.0;
const BAR_H: f32 = 52.0;
const SCROLL_KEY: u64 = 90_000;
/// readings kept for the graphs (one a second)
const HISTORY: usize = 60;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Col {
    Name,
    Pid,
    User,
    Cpu,
    Mem,
    State,
    Energy,
    Gpu,
}

impl Col {
    fn label(self) -> &'static str {
        match self {
            Col::Name => "Name",
            Col::Pid => "PID",
            Col::User => "User",
            Col::Cpu => "CPU",
            Col::Mem => "Memory",
            Col::State => "Status",
            Col::Energy => "Energy",
            Col::Gpu => "GPU",
        }
    }
}

/// The columns to the right of the name, laid out from the right edge: (column, anchor x, alignment, width) and the room
/// left for the name. A narrow window drops Status, then User.
fn layout(w: f32) -> (Vec<(Col, f32, Align, f32)>, f32) {
    let mut edge = w - 24.0;
    let mut out = Vec::new();
    for (col, width, align) in [(Col::State, 80.0, Align::Left), (Col::Mem, 80.0, Align::Right), (Col::Energy, 60.0, Align::Right), (Col::Gpu, 84.0, Align::Left), (Col::Cpu, 56.0, Align::Right), (Col::User, 90.0, Align::Left), (Col::Pid, 52.0, Align::Right)] {
        if (col == Col::State && w < 980.0) || (col == Col::User && w < 800.0) {
            continue;
        }
        let left = edge - width;
        out.push((col, if align == Align::Right { edge } else { left }, align, width));
        edge = left - 12.0;
    }
    (out, (edge - 48.0).max(60.0))
}

/// the amber of the dedicated card, which costs the battery
const DGPU: [f32; 3] = [0.98, 0.70, 0.20];
const IGPU: [f32; 3] = [0.30, 0.62, 1.0];

/// "dGPU" / "iGPU 12%": which card a program has open.
fn gpu_label(p: &ProcInfo) -> Option<String> {
    match p.gpu {
        GpuUse::None => None,
        GpuUse::Dedicated => Some("dGPU".into()),
        GpuUse::Integrated if p.gpu_busy >= 1.0 => Some(format!("iGPU {:.0}%", p.gpu_busy.min(100.0))),
        GpuUse::Integrated => Some("iGPU".into()),
    }
}

/// What the reading thread sends: the look at the system, and the icons of programs it has not met before.
struct Update {
    snap: Snapshot,
    icons: Vec<(String, Arc<Pic>)>,
}

/// Finds a program's own icon: through the desktop files (a process called `kate` belongs to the entry that starts
/// `kate`), then by its name in the icon theme.
struct IconFinder {
    index: IconIndex,
    by_name: HashMap<String, String>,
}

impl IconFinder {
    fn new() -> IconFinder {
        let mut by_name = HashMap::new();
        for a in apps::scan() {
            if a.icon.is_empty() {
                continue;
            }
            // the program the entry starts: the first word that is not `env` or a VAR=value
            let exec = a.exec.split_whitespace().find(|w| *w != "env" && !w.contains('=')).unwrap_or("").trim_matches('"');
            let keys = [exec.rsplit('/').next().unwrap_or("").to_string(), a.id.clone(), a.id.rsplit('.').next().unwrap_or("").to_string(), a.wm_class.clone(), a.name.clone()];
            for k in keys.iter().filter(|k| !k.is_empty()) {
                by_name.entry(k.to_lowercase()).or_insert_with(|| a.icon.clone());
            }
        }
        IconFinder { index: IconIndex::build(), by_name }
    }

    fn find(&self, process: &str) -> Option<Arc<Pic>> {
        let lower = process.to_lowercase();
        let candidates = [self.by_name.get(&lower).cloned(), Some(process.to_string()), Some(lower.clone())];
        candidates.into_iter().flatten().find_map(|c| self.index.load(&c, 40)).map(|img| Arc::new(Pic::from_rgba(img.width(), img.height(), img.as_raw())))
    }
}

/// The icon to draw when a process has no icon of its own.
fn generic_icon(p: &ProcInfo) -> &'static str {
    let n = p.name.as_str();
    if p.ppid == 2 || p.pid == 2 || n.starts_with("kworker") || n.starts_with("ksoftirqd") || n.starts_with("irq/") || n.starts_with("migration/") || n.starts_with("rcu_") {
        "settings"
    } else if matches!(n, "bash" | "fish" | "zsh" | "sh" | "dash" | "nu" | "tmux" | "screen" | "login") {
        "terminal"
    } else if p.user == "root" {
        "layers"
    } else {
        "app-window"
    }
}

struct Monitor {
    rx: Option<Receiver<Update>>,
    icons: HashMap<String, Arc<Pic>>,
    snap: Snapshot,
    /// indices into `snap.procs`, filtered and sorted
    view: Vec<usize>,
    tab: usize,
    sort: Col,
    desc: bool,
    filter: String,
    sel: Option<u32>,
    scroll: f32,
    note: String,
    cpu_hist: Vec<f32>,
    mem_hist: Vec<f32>,
    rx_hist: Vec<f32>,
    tx_hist: Vec<f32>,
    temp_hist: Vec<f32>,
    /// watts the battery gave, and whether the dedicated card was awake (100) or asleep (0), a reading a second
    watt_hist: Vec<f32>,
    dgpu_hist: Vec<f32>,
    dirty: bool,
    /// rows (top, bottom) to bring into view on the next frame
    reveal: Option<(f32, f32)>,
}

fn push(hist: &mut Vec<f32>, v: f32) {
    hist.push(v);
    if hist.len() > HISTORY {
        hist.remove(0);
    }
}

impl Monitor {
    fn new() -> Monitor {
        Monitor { rx: None, icons: HashMap::new(), snap: Snapshot::default(), view: Vec::new(), tab: 0, sort: Col::Cpu, desc: true, filter: String::new(), sel: None, scroll: 0.0, note: String::new(), cpu_hist: Vec::new(), mem_hist: Vec::new(), rx_hist: Vec::new(), tx_hist: Vec::new(), temp_hist: Vec::new(), watt_hist: Vec::new(), dgpu_hist: Vec::new(), dirty: true, reveal: None }
    }

    fn rebuild(&mut self) {
        let f = self.filter.to_lowercase();
        let mut v: Vec<usize> = (0..self.snap.procs.len()).filter(|&i| f.is_empty() || self.snap.procs[i].name.to_lowercase().contains(&f) || self.snap.procs[i].user.to_lowercase().contains(&f) || self.snap.procs[i].pid.to_string() == f).collect();
        let p = &self.snap.procs;
        let (sort, desc) = (self.sort, self.desc);
        v.sort_by(|&a, &b| {
            let (x, y): (&ProcInfo, &ProcInfo) = (&p[a], &p[b]);
            let o = match sort {
                Col::Name => x.name.to_lowercase().cmp(&y.name.to_lowercase()),
                Col::Pid => x.pid.cmp(&y.pid),
                Col::User => x.user.cmp(&y.user),
                Col::Cpu => x.cpu.total_cmp(&y.cpu),
                Col::Mem => x.mem.cmp(&y.mem),
                Col::State => x.state_name().cmp(y.state_name()),
                Col::Energy => x.energy.total_cmp(&y.energy),
                Col::Gpu => (x.gpu as u8, x.gpu_busy).partial_cmp(&(y.gpu as u8, y.gpu_busy)).unwrap_or(std::cmp::Ordering::Equal),
            };
            let o = if desc { o.reverse() } else { o };
            o.then(x.pid.cmp(&y.pid))
        });
        self.view = v;
        self.dirty = false;
    }

    fn take_snapshots(&mut self) -> bool {
        let mut got = false;
        let mut latest = None;
        if let Some(rx) = &self.rx {
            while let Ok(u) = rx.try_recv() {
                self.icons.extend(u.icons);
                latest = Some(u.snap);
            }
        }
        if let Some(s) = latest {
            push(&mut self.cpu_hist, s.cpu);
            push(&mut self.mem_hist, if s.mem.total > 0 { 100.0 * s.mem.used() as f32 / s.mem.total as f32 } else { 0.0 });
            push(&mut self.rx_hist, s.rx as f32);
            push(&mut self.tx_hist, s.tx as f32);
            push(&mut self.temp_hist, s.temps.first().map_or(0.0, |t| t.celsius));
            push(&mut self.watt_hist, s.battery.as_ref().map_or(0.0, |b| b.watts));
            push(&mut self.dgpu_hist, if s.gpus.iter().any(|g| !g.integrated && g.power.as_deref() == Some("active")) { 100.0 } else { 0.0 });
            self.snap = s;
            self.dirty = true;
            got = true;
        }
        got
    }

    fn selected(&self) -> Option<&ProcInfo> {
        self.sel.and_then(|pid| self.snap.procs.iter().find(|p| p.pid == pid))
    }

    fn end_selected(&mut self, force: bool) {
        let Some(p) = self.selected().cloned() else { return };
        self.note = match sysmon::signal(p.pid, force) {
            Ok(()) => format!("{} {} ({})", if force { "Force quit" } else { "Asked to quit:" }, p.name, p.pid),
            Err(e) => format!("Could not end {}: {e}", p.name),
        };
    }

    fn move_sel(&mut self, d: i32) {
        if self.view.is_empty() {
            return;
        }
        let at = self.sel.and_then(|pid| self.view.iter().position(|&i| self.snap.procs[i].pid == pid));
        let to = match at {
            Some(a) => (a as i32 + d).clamp(0, self.view.len() as i32 - 1) as usize,
            None => if d > 0 { 0 } else { self.view.len() - 1 },
        };
        self.sel = Some(self.snap.procs[self.view[to]].pid);
        let (top, bottom) = (to as f32 * ROW_H, (to + 1) as f32 * ROW_H);
        self.reveal = Some((top, bottom));
    }
}

fn fit(ui: &mut Ui<'_>, text: &str, size: f32, bold: bool, max: f32) -> String {
    if ui.measure_raw(text, size, bold) <= max {
        return text.to_string();
    }
    let mut s = text.to_string();
    while !s.is_empty() && ui.measure_raw(&format!("{s}…"), size, bold) > max {
        s.pop();
    }
    format!("{s}…")
}

impl App for Monitor {
    fn start(&mut self, waker: app::Waker) {
        let (tx, rx) = channel();
        self.rx = Some(rx);
        std::thread::Builder::new()
            .name("sampler".into())
            .spawn(move || {
                let mut s = Sampler::new();
                // the first look goes out at once; the icons are found (it takes a moment) from the second on
                if tx.send(Update { snap: s.sample(), icons: Vec::new() }).is_err() {
                    return;
                }
                waker.wake();
                let finder = IconFinder::new();
                let mut tried: HashSet<String> = HashSet::new();
                loop {
                    std::thread::sleep(std::time::Duration::from_millis(1000));
                    let snap = s.sample();
                    let icons: Vec<(String, Arc<Pic>)> = snap.procs.iter().filter(|p| tried.insert(p.name.clone())).filter_map(|p| finder.find(&p.name).map(|pic| (p.name.clone(), pic))).collect();
                    if tx.send(Update { snap, icons }).is_err() {
                        return;
                    }
                    waker.wake();
                }
            })
            .ok();
    }

    fn tick(&mut self, host: &mut Host) {
        if self.take_snapshots() {
            host.redraw = true;
        }
    }

    fn key(&mut self, key: Key, mods: KeyMods, host: &mut Host) {
        host.redraw = true;
        if self.tab != 0 {
            return;
        }
        match key {
            Key::Down => self.move_sel(1),
            Key::Up => self.move_sel(-1),
            Key::PageDown => self.move_sel(10),
            Key::PageUp => self.move_sel(-10),
            Key::Delete => self.end_selected(mods.shift),
            Key::Backspace => {
                self.filter.pop();
                self.dirty = true;
            }
            Key::Esc => {
                if self.filter.is_empty() {
                    self.sel = None;
                } else {
                    self.filter.clear();
                    self.dirty = true;
                }
            }
            Key::Char(c) if !mods.ctrl && !mods.alt && !c.is_control() => {
                self.filter.push(c);
                self.dirty = true;
            }
            _ => {}
        }
    }

    fn draw(&mut self, ui: &mut Ui<'_>, size: [f32; 2], host: &mut Host) {
        let [w, h] = size;
        if self.dirty {
            self.rebuild();
        }
        host.title = None;
        let (ink, accent) = (ui.ink, ui.accent);

        // ---- the tabs
        let mut tab = self.tab;
        if ui.segmented([16.0, 10.0, 260.0, 32.0], &["Processes", "Performance"], &mut tab) {
            self.tab = tab;
        }
        let up = format_uptime(self.snap.uptime);
        ui.text_raw(w - 18.0, TOP_H / 2.0 + 4.5, &format!("Up {up}   Load {:.2}  {:.2}  {:.2}", self.snap.load[0], self.snap.load[1], self.snap.load[2]), 12.0, false, ink, 0.55, Align::Right);
        ui.fill([0.0, TOP_H - 1.0, w, 1.0], 0.0, ink, 0.08);

        if self.tab == 0 {
            self.processes(ui, size);
        } else {
            self.performance(ui, size);
        }
        let _ = (accent, h);
    }
}

impl Monitor {
    fn processes(&mut self, ui: &mut Ui<'_>, size: [f32; 2]) {
        let [w, h] = size;
        let (ink, accent) = (ui.ink, ui.accent);
        let list = [0.0, TOP_H + HEAD_H, w, (h - TOP_H - HEAD_H - BAR_H).max(ROW_H)];
        let (cols, name_max) = layout(w);

        // scroll
        let n = self.view.len();
        let max_scroll = (n as f32 * ROW_H + 8.0 - list[3]).max(0.0);
        if ui.scroll != 0.0 && inside(ui.mouse, list) {
            self.scroll += ui.scroll;
        }
        if let Some((top, bottom)) = self.reveal.take() {
            if top < self.scroll {
                self.scroll = top;
            } else if bottom + 8.0 > self.scroll + list[3] {
                self.scroll = bottom + 8.0 - list[3];
            }
        }
        self.scroll = self.scroll.clamp(0.0, max_scroll);
        let scroll = ui.ease(SCROLL_KEY, self.scroll, 18.0);

        // rows
        let first = (scroll / ROW_H).floor().max(0.0) as usize;
        let last = (((scroll + list[3]) / ROW_H).ceil() as usize + 1).min(n);
        let mut clicked_row = false;
        ui.push_clip(list);
        for i in first..last {
            let p = self.snap.procs[self.view[i]].clone();
            let r = [list[0] + 8.0, list[1] - scroll + 4.0 + i as f32 * ROW_H, list[2] - 16.0, ROW_H - 2.0];
            let hov = ui.hit(r) && inside(ui.mouse, list);
            let selected = self.sel == Some(p.pid);
            let wash = ui.ease(30_000 + i as u64, if hov { 1.0 } else { 0.0 }, 22.0);
            if selected {
                ui.fill(r, 8.0, accent, 0.28);
            } else if wash > 0.01 {
                ui.fill(r, 8.0, ink, 0.07 * wash);
            }
            let cy = r[1] + r[3] / 2.0 + 4.6;
            let icon_box = [r[0] + 10.0, r[1] + (r[3] - 20.0) / 2.0, 20.0, 20.0];
            match self.icons.get(&p.name) {
                Some(pic) => ui.picture(icon_box, pic, [0.0, 0.0, pic.w as f32, pic.h as f32], 1.0),
                None => ui.glyph(icon_box[0] + 10.0, icon_box[1] + 10.0, 16.0, generic_icon(&p), ink, 0.45),
            }
            let name = fit(ui, &p.name, 13.0, false, name_max - 30.0);
            ui.text_raw(r[0] + 40.0, cy, &name, 13.0, false, ink, 0.95, Align::Left);
            for &(col, x, align, width) in &cols {
                match col {
                    Col::Pid => ui.text_raw(x, cy, &p.pid.to_string(), 12.5, false, ink, 0.6, align),
                    Col::User => {
                        let user = fit(ui, &p.user, 12.5, false, width);
                        ui.text_raw(x, cy, &user, 12.5, false, ink, 0.7, align);
                    }
                    // the processor share is shaded by how much it is
                    Col::Cpu => ui.text_raw(x, cy, &format!("{:.1}%", p.cpu), 12.5, p.cpu >= 25.0, ink, 0.55 + 0.4 * (p.cpu / 100.0).clamp(0.0, 1.0), align),
                    Col::Energy => {
                        let hot = p.energy >= 25.0;
                        ui.text_raw(x, cy, &format!("{:.1}", p.energy), 12.5, hot, if p.energy >= 50.0 { DGPU } else { ink }, 0.55 + 0.4 * (p.energy / 50.0).clamp(0.0, 1.0), align);
                    }
                    Col::Gpu => {
                        if let Some(label) = gpu_label(&p) {
                            let (colour, on) = if p.gpu == GpuUse::Dedicated { (DGPU, true) } else { (IGPU, false) };
                            let tw = ui.measure_raw(&label, 11.5, on);
                            if on {
                                ui.fill([x - 6.0, cy - 12.5, tw + 12.0, 18.0], 9.0, colour, 0.25);
                            }
                            ui.text_raw(x, cy, &label, 11.5, on, if on { colour } else { ink }, if on { 1.0 } else { 0.6 }, align);
                        }
                    }
                    Col::Mem => ui.text_raw(x, cy, &human_size(p.mem), 12.5, false, ink, 0.8, align),
                    Col::State => ui.text_raw(x, cy, p.state_name(), 12.0, false, ink, if p.state == 'Z' { 0.9 } else { 0.55 }, align),
                    Col::Name => {}
                }
            }
            if ui.click && hov {
                clicked_row = true;
                self.sel = if selected && ui.double { None } else { Some(p.pid) };
            }
        }
        ui.pop_clip();
        if ui.click && inside(ui.mouse, list) && !clicked_row {
            self.sel = None;
        }
        if n == 0 {
            let msg = if self.filter.is_empty() { "Reading the processes…" } else { "No process matches" };
            ui.text(w / 2.0, list[1] + 60.0, msg, 14.0, false, ink, 0.45, Align::Center);
        }

        // column header (over the rows)
        ui.fill([0.0, TOP_H, w, HEAD_H], 0.0, [1.0, 1.0, 1.0], 0.0);
        ui.fill([8.0, TOP_H + HEAD_H - 1.0, w - 16.0, 1.0], 0.0, ink, 0.10);
        let mut sort_to = None;
        let mut heads = vec![(Col::Name, 48.0, Align::Left, 80.0)];
        heads.extend(cols.iter().map(|&(c, x, a, wd)| (c, x, a, wd)));
        for (col, x, align, width) in heads {
            let label = col.label();
            let rx = if align == Align::Right { x - width } else { x };
            let hov = ui.hit([rx - 4.0, TOP_H, width + 8.0, HEAD_H]);
            let on = self.sort == col;
            ui.text(x, TOP_H + 18.5, label, 11.5, true, ink, if on { 0.9 } else if hov { 0.8 } else { 0.5 }, align);
            if on {
                let ax = if align == Align::Right { x - ui.measure(label, 11.5, true) - 10.0 } else { x + ui.measure(label, 11.5, true) + 10.0 };
                ui.glyph(ax, TOP_H + 14.0, 12.0, if self.desc { "chevron-down" } else { "chevron-up" }, ink, 0.8);
            }
            if ui.click && hov {
                sort_to = Some(col);
            }
        }
        if let Some(c) = sort_to {
            if self.sort == c {
                self.desc = !self.desc;
            } else {
                self.sort = c;
                self.desc = matches!(c, Col::Cpu | Col::Mem | Col::Energy | Col::Gpu);
            }
            self.dirty = true;
        }

        // bottom bar: the filter, the status and the buttons
        let bar = [0.0, h - BAR_H, w, BAR_H];
        ui.fill(bar, 0.0, ink, 0.045);
        ui.fill([0.0, bar[1], w, 1.0], 0.0, ink, 0.08);
        let total_threads: u32 = self.snap.procs.iter().map(|p| p.threads).sum();
        let status = if !self.note.is_empty() {
            self.note.clone()
        } else if !self.filter.is_empty() {
            format!("Filter “{}”: {} of {} processes", self.filter, self.view.len(), self.snap.procs.len())
        } else {
            format!("{} processes · {} threads · type to filter", self.snap.procs.len(), total_threads)
        };
        let status = fit(ui, &status, 12.0, false, (w - 360.0).max(60.0));
        ui.text_raw(18.0, bar[1] + BAR_H / 2.0 + 4.5, &status, 12.0, false, ink, 0.6, Align::Left);
        let can = self.selected().is_some();
        let (end, kill) = ([w - 16.0 - 130.0 - 8.0 - 110.0, bar[1] + 10.0, 110.0, 32.0], [w - 16.0 - 130.0, bar[1] + 10.0, 130.0, 32.0]);
        if can {
            if ui.button(end, "         End process", false) {
                self.end_selected(false);
            }
            if ui.button(kill, "        Force quit", true) {
                self.end_selected(true);
            }
        } else {
            for (r, label) in [(end, "         End process"), (kill, "        Force quit")] {
                ui.fill(r, 8.0, ink, 0.05);
                ui.text(r[0] + r[2] / 2.0, r[1] + r[3] / 2.0 + 4.5, label, 12.5, false, ink, 0.3, Align::Center);
            }
        }
        // the icons sit in the room the spaces in the labels leave
        let (a, b) = (if can { ink } else { ink }, if can { [1.0; 3] } else { ink });
        ui.glyph(end[0] + 19.0, end[1] + end[3] / 2.0, 14.0, "x", a, if can { 0.9 } else { 0.3 });
        ui.glyph(kill[0] + 22.0, kill[1] + kill[3] / 2.0, 14.0, "power", b, if can { 1.0 } else { 0.3 });
    }

    fn performance(&mut self, ui: &mut Ui<'_>, size: [f32; 2]) {
        let [w, h] = size;
        let ink = ui.ink;
        let pad = 16.0;
        let cols = if w >= 760.0 { 2.0 } else { 1.0 };
        let cw = (w - pad * (cols + 1.0)) / cols;
        let top = TOP_H + pad;
        let avail = h - top - pad;
        let rows = if cols > 1.0 { 3.0 } else { 5.0 };
        let ch = ((avail - pad * (rows - 1.0)) / rows).max(120.0);
        let card = |i: usize| -> [f32; 4] {
            let (c, r) = if cols > 1.0 { (i as f32 % 2.0, (i / 2) as f32) } else { (0.0, i as f32) };
            [pad + c * (cw + pad), top + r * (ch + pad), cw, ch]
        };

        // processor
        let c = card(0);
        self.card(ui, c, "Processor", &format!("{:.0}%", self.snap.cpu));
        graph(ui, [c[0] + 16.0, c[1] + 58.0, c[2] - 32.0, (c[3] - 58.0 - 44.0).max(30.0)], &self.cpu_hist, 100.0, [0.30, 0.62, 1.0]);
        let cores = self.snap.cores.clone();
        let cy = c[1] + c[3] - 32.0;
        let bw = ((c[2] - 32.0) / cores.len().max(1) as f32 - 4.0).clamp(4.0, 40.0);
        for (i, v) in cores.iter().enumerate() {
            let x = c[0] + 16.0 + i as f32 * (bw + 4.0);
            if x + bw > c[0] + c[2] - 16.0 {
                break;
            }
            ui.fill([x, cy - 22.0, bw, 22.0], 3.0, ink, 0.08);
            let fh = 22.0 * (v / 100.0).clamp(0.0, 1.0);
            ui.fill([x, cy - fh, bw, fh.max(1.0)], 3.0, [0.30, 0.62, 1.0], 0.9);
        }
        ui.text_raw(c[0] + 16.0, c[1] + c[3] - 4.0, &format!("{} cores", cores.len()), 11.0, false, ink, 0.5, Align::Left);

        // memory
        let m = card(1);
        let used = self.snap.mem.used();
        self.card(ui, m, "Memory", &format!("{} of {}", human_size(used), human_size(self.snap.mem.total)));
        graph(ui, [m[0] + 16.0, m[1] + 58.0, m[2] - 32.0, (m[3] - 58.0 - 44.0).max(30.0)], &self.mem_hist, 100.0, [0.35, 0.78, 0.45]);
        let swap = if self.snap.mem.swap_total > 0 { format!("Swap {} of {}", human_size(self.snap.mem.swap_used()), human_size(self.snap.mem.swap_total)) } else { "No swap".to_string() };
        ui.text_raw(m[0] + 16.0, m[1] + m[3] - 14.0, &format!("Cached {}   {}", human_size(self.snap.mem.cached + self.snap.mem.buffers), swap), 11.5, false, ink, 0.6, Align::Left);

        // network
        let nw = card(2);
        self.card(ui, nw, "Network", &format!("↓ {}   ↑ {}", format_rate(self.snap.rx), format_rate(self.snap.tx)));
        let peak = self.rx_hist.iter().chain(self.tx_hist.iter()).copied().fold(10_000.0f32, f32::max);
        let area = [nw[0] + 16.0, nw[1] + 58.0, nw[2] - 32.0, (nw[3] - 58.0 - 24.0).max(30.0)];
        graph(ui, area, &self.rx_hist, peak, [0.30, 0.62, 1.0]);
        graph(ui, area, &self.tx_hist, peak, [0.95, 0.60, 0.20]);
        ui.text_raw(nw[0] + 16.0, nw[1] + nw[3] - 10.0, &format!("Scale {}", format_rate(peak as f64)), 11.5, false, ink, 0.5, Align::Left);

        // temperatures
        let tc = card(3);
        let hottest = self.snap.temps.first().map_or(String::new(), |t| format!("{} {:.0} °C", t.name, t.celsius));
        self.card(ui, tc, "Temperatures", &hottest);
        if self.snap.temps.is_empty() {
            ui.text(tc[0] + tc[2] / 2.0, tc[1] + tc[3] / 2.0 + 14.0, "No temperature sensors found", 12.5, false, ink, 0.45, Align::Center);
        } else {
            // a tall card also gets the history of the first sensor
            let mut y0 = tc[1] + 58.0;
            if tc[3] >= 250.0 {
                let gh = (tc[3] * 0.32).clamp(50.0, 90.0);
                graph(ui, [tc[0] + 16.0, y0, tc[2] - 32.0, gh], &self.temp_hist, 100.0, heat(self.snap.temps[0].celsius));
                y0 += gh + 12.0;
            }
            let row_h = 24.0;
            let ncol = if tc[2] >= 400.0 { 2 } else { 1 };
            let per_col = (((tc[1] + tc[3] - 22.0 - y0) / row_h) as usize).max(1);
            let colw = (tc[2] - 32.0 - 20.0 * (ncol - 1) as f32) / ncol as f32;
            let shown = (per_col * ncol).min(self.snap.temps.len());
            let (name_w, val_w) = ((colw * 0.42).clamp(70.0, 150.0), 44.0);
            for (i, t) in self.snap.temps.iter().take(shown).enumerate() {
                let (c, r) = (i / per_col, i % per_col);
                let x = tc[0] + 16.0 + c as f32 * (colw + 20.0);
                let y = y0 + r as f32 * row_h;
                let name = fit(ui, &t.name, 12.0, false, name_w);
                ui.text_raw(x, y + 14.5, &name, 12.0, false, ink, 0.8, Align::Left);
                // the bar runs from 20 to 100 °C and takes the colour of the heat
                let track = [x + name_w + 8.0, y + 8.0, (colw - name_w - val_w - 16.0).max(20.0), 6.0];
                ui.fill(track, 3.0, ink, 0.10);
                let frac = ((t.celsius - 20.0) / 80.0).clamp(0.0, 1.0);
                ui.fill([track[0], track[1], (track[2] * frac).max(6.0), track[3]], 3.0, heat(t.celsius), 0.95);
                let hot = t.celsius >= 70.0;
                ui.text_raw(x + colw, y + 14.5, &format!("{:.0} °C", t.celsius), 12.0, hot, if hot { heat(t.celsius) } else { ink }, if hot { 1.0 } else { 0.85 }, Align::Right);
            }
            if shown < self.snap.temps.len() {
                ui.text_raw(tc[0] + tc[2] - 16.0, tc[1] + tc[3] - 6.0, &format!("+{} more", self.snap.temps.len() - shown), 10.5, false, ink, 0.45, Align::Right);
            }
        }

        // power: what the battery gives, and whether the dedicated card is awake
        let pc = card(4);
        self.power_card(ui, pc);

        // who costs the most energy
        if cols > 1.0 {
            let t = card(5);
            self.card(ui, t, "Energy impact", "");
            let mut top: Vec<&ProcInfo> = self.snap.procs.iter().filter(|p| p.energy >= 0.05).collect();
            top.sort_by(|a, b| b.energy.total_cmp(&a.energy));
            let rows = (((t[3] - 62.0) / 24.0).max(1.0) as usize).min(top.len());
            for (i, p) in top.iter().take(rows).enumerate() {
                let y = t[1] + 74.0 + i as f32 * 24.0;
                let name = fit(ui, &p.name, 12.5, false, t[2] - 220.0);
                ui.text_raw(t[0] + 16.0, y, &name, 12.5, false, ink, 0.9, Align::Left);
                if let Some(label) = gpu_label(p) {
                    let (colour, on) = if p.gpu == GpuUse::Dedicated { (DGPU, true) } else { (IGPU, false) };
                    ui.text_raw(t[0] + t[2] - 16.0 - 80.0, y, &label, 11.5, on, if on { colour } else { ink }, if on { 1.0 } else { 0.6 }, Align::Right);
                }
                ui.text_raw(t[0] + t[2] - 16.0, y, &format!("{:.1}", p.energy), 12.5, p.energy >= 25.0, ink, 0.55 + 0.4 * (p.energy / 50.0).clamp(0.0, 1.0), Align::Right);
            }
            if top.is_empty() {
                ui.text(t[0] + t[2] / 2.0, t[1] + t[3] / 2.0 + 14.0, "Nothing is using energy", 12.5, false, ink, 0.45, Align::Center);
            }
        }
    }

    /// The battery's draw over the last minute, a strip that is amber while the dedicated card is awake, and who keeps it so.
    fn power_card(&self, ui: &mut Ui<'_>, r: [f32; 4]) {
        let ink = ui.ink;
        let value = match &self.snap.battery {
            Some(b) if b.discharging() && b.watts > 0.05 => format!("{:.1} W · {}%", b.watts, b.percent),
            Some(b) => format!("{} · {}%", b.status, b.percent),
            None => "No battery".to_string(),
        };
        self.card(ui, r, "Power", &value);
        let strip_h = 10.0;
        let line_h = 20.0;
        let hybrid = memrium_de::gpu::hybrid(&self.snap.gpus);
        let below = if hybrid { strip_h + 10.0 + 2.0 * line_h } else { 8.0 };
        let area = [r[0] + 16.0, r[1] + 58.0, r[2] - 32.0, (r[3] - 58.0 - below - 8.0).max(24.0)];
        let peak = self.watt_hist.iter().copied().fold(15.0f32, f32::max);
        graph(ui, area, &self.watt_hist, peak, [0.98, 0.45, 0.35]);
        ui.text_raw(area[0] + 6.0, area[1] + 13.0, &format!("{} W", peak.round()), 10.5, false, ink, 0.4, Align::Left);
        if !hybrid {
            return;
        }
        // the dedicated card: awake (amber) or asleep, a second a pixel column
        let strip = [area[0], area[1] + area[3] + 8.0, area[2], strip_h];
        ui.fill(strip, 3.0, ink, 0.08);
        let bw = strip[2] / HISTORY as f32;
        let shift = HISTORY - self.dgpu_hist.len();
        ui.push_clip(strip);
        for (i, v) in self.dgpu_hist.iter().enumerate() {
            if *v > 0.0 {
                ui.fill([strip[0] + (shift + i) as f32 * bw, strip[1], bw + 0.5, strip[3]], 0.0, DGPU, 0.9);
            }
        }
        ui.pop_clip();
        let dgpu = self.snap.gpus.iter().find(|g| !g.integrated);
        let awake = dgpu.is_some_and(|g| g.power.as_deref() == Some("active"));
        let share = if self.dgpu_hist.is_empty() { 0.0 } else { self.dgpu_hist.iter().filter(|v| **v > 0.0).count() as f32 / self.dgpu_hist.len() as f32 };
        let name = dgpu.map_or("Dedicated GPU", |g| g.name.as_str());
        let state = if awake { "awake" } else { "asleep" };
        let y1 = strip[1] + strip_h + 16.0;
        let head = fit(ui, &format!("{name}: {state}"), 12.0, awake, r[2] - 32.0 - 90.0);
        ui.text_raw(strip[0], y1, &head, 12.0, awake, if awake { DGPU } else { ink }, if awake { 1.0 } else { 0.75 }, Align::Left);
        ui.text_raw(strip[0] + strip[2], y1, &format!("awake {:.0}% of the minute", share * 100.0), 11.5, false, ink, 0.55, Align::Right);
        // the programs holding it open
        let mut holders: Vec<&ProcInfo> = self.snap.procs.iter().filter(|p| p.gpu == GpuUse::Dedicated).collect();
        holders.sort_by(|a, b| b.cpu.total_cmp(&a.cpu).then(a.pid.cmp(&b.pid)));
        let mut names: Vec<&str> = Vec::new();
        for p in &holders {
            if !names.contains(&p.name.as_str()) {
                names.push(&p.name);
            }
        }
        let used = if names.is_empty() { "No program uses it".to_string() } else { format!("Used by {}", names.join(", ")) };
        let used = fit(ui, &used, 11.5, false, strip[2]);
        ui.text_raw(strip[0], y1 + line_h, &used, 11.5, false, ink, 0.6, Align::Left);
    }

    fn card(&self, ui: &mut Ui<'_>, r: [f32; 4], title: &str, value: &str) {
        let ink = ui.ink;
        let accent = ui.accent;
        ui.fill(r, 14.0, ink, 0.05);
        let icon = match title {
            "Processor" => "gauge",
            "Memory" => "layers",
            "Network" => "wifi",
            "Temperatures" => "flame",
            "Power" => "zap",
            "Energy impact" => "gauge",
            _ => "list",
        };
        ui.glyph(r[0] + 26.0, r[1] + 24.0, 16.0, icon, accent, 1.0);
        ui.text(r[0] + 42.0, r[1] + 28.0, title, 13.0, true, ink, 0.9, Align::Left);
        ui.text_raw(r[0] + r[2] - 16.0, r[1] + 28.0, value, 13.0, false, ink, 0.75, Align::Right);
    }
}

/// The colour of a temperature: cool blue, then green, amber and red as it climbs.
fn heat(c: f32) -> [f32; 3] {
    const STOPS: [(f32, [f32; 3]); 4] = [(30.0, [0.30, 0.62, 1.0]), (55.0, [0.35, 0.78, 0.45]), (75.0, [0.98, 0.70, 0.20]), (92.0, [1.0, 0.32, 0.28])];
    if c <= STOPS[0].0 {
        return STOPS[0].1;
    }
    for w in STOPS.windows(2) {
        let ((t0, a), (t1, b)) = (w[0], w[1]);
        if c <= t1 {
            let f = (c - t0) / (t1 - t0);
            return [a[0] + (b[0] - a[0]) * f, a[1] + (b[1] - a[1]) * f, a[2] + (b[2] - a[2]) * f];
        }
    }
    STOPS[3].1
}

/// An area graph of the last readings (`top` is the value at the upper edge), one thin bar a reading.
fn graph(ui: &mut Ui<'_>, r: [f32; 4], hist: &[f32], top: f32, colour: [f32; 3]) {
    let ink = ui.ink;
    ui.fill(r, 8.0, ink, 0.05);
    for i in 1..4 {
        ui.fill([r[0], r[1] + r[3] * i as f32 / 4.0, r[2], 1.0], 0.0, ink, 0.06);
    }
    if hist.is_empty() || top <= 0.0 {
        return;
    }
    let bw = r[2] / HISTORY as f32;
    let shift = HISTORY - hist.len();
    ui.push_clip(r);
    for (i, v) in hist.iter().enumerate() {
        let hh = (r[3] * (v / top).clamp(0.0, 1.0)).max(if *v > 0.0 { 1.5 } else { 0.0 });
        ui.fill([r[0] + (shift + i) as f32 * bw, r[1] + r[3] - hh, bw - 0.5, hh], 1.0, colour, 0.55);
    }
    ui.pop_clip();
}

fn main() {
    app::run(Config::new("Memrium Monitor", "memrium-monitor").size(960, 620).min_size(640, 380), Monitor::new());
}
