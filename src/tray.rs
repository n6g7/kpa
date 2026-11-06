//! The tray icon (`docs/plan.md` step 4, `docs/design.md` § Tray): a
//! StatusNotifierItem over D-Bus, via `ksni`.
//!
//! Follows the same two-part shape as `policy.rs`, adapted to what's
//! actually hard to test here. `policy.rs` splits into a pure core
//! (`Policy`) tested against the `Locks`/`SleepInhibitor` traits, and a
//! D-Bus half (`watch_forever`) that can't be exercised without a bus. The
//! tray's equivalent split is [`aggregate_color`]/[`fallback_icon`]/
//! [`item_status`]/[`tool_tip`]/[`build_menu`] — pure functions of a
//! `DatabaseStatus` snapshot, tested below with no `ksni`, no D-Bus, and
//! no `Server` at all — versus [`run`],
//! which owns the one thing that can't be faked that way: `ksni`'s own
//! service loop. There's no tray-side equivalent of `Locks`/`SleepInhibitor`
//! because `ksni` itself is already the abstraction boundary to the bus;
//! inventing a second trait in front of it would just be a passthrough.
//!
//! **How the tray reaches `Server`.** [`TrayItem`] holds the same
//! `Arc<Server>` `run_serve` already has and calls `Server::snapshot`,
//! `Unlock::unlock`, `Lock::lock` on it directly — `unlock`/`lock` are the
//! exact calls `proto::dispatch` makes for the socket protocol's own
//! `unlock`/`lock` ops. That makes the tray and the socket two *callers* of
//! one locking implementation, not two implementations of it. The
//! alternative the task considered — the tray as its own client of the Unix
//! socket, reusing `main.rs`'s request-sending code — was rejected: the
//! tray runs inside `kpa serve`'s own process (`run_serve` starts it the
//! same way it starts `policy::start`), so going back out through a socket
//! to reach state already in the same address space would add a
//! serialization round trip for no isolation benefit, and a second way to
//! reach `Server` alongside the wire protocol where the design only needs
//! one.
//!
//! `Server::snapshot`, not the `status` op's own `Status::status`, is what
//! the tray reads its display from — see that method's doc for why: the
//! wire `status` op deliberately runs the freshness guard as a side
//! effect, and running that from an autonomous background poll rather than
//! in response to a real client request turned out to have a real cost
//! (below).
//!
//! **What the tray ever holds.** Only what `Server::snapshot` returns — a
//! database's configured name, whether it's locked, and its entry count —
//! plus the *code* of the most recent failed `unlock` (never `detail`,
//! which can carry a prompt's I/O error text; see `UnlockError::fields`).
//! No password, no protected field, nothing `list` would withhold reaches
//! this module (`docs/threat-model.md` G-3, T-4). The menu triggers
//! `Lock`/`Unlock` the same way any other same-session D-Bus client
//! reaching the tray's menu could (`docs/threat-model.md` T-15) — that
//! residual is already accepted there, and nothing here widens it:
//! activating a menu item can lock a database or raise an unlock prompt,
//! never read one.
//!
//! **Why polling.** Locks can happen with nobody touching the tray at all —
//! a screen lock, `idle_timeout`, the freshness guard — so something has to
//! notice and tell `ksni` to refresh. [`run`] does that on a fixed tick,
//! the same shape as `server::watch_idle`'s own tick: cheap, because
//! `Server::snapshot` is an in-memory read, not a vault read or even a
//! `stat`, and simple, because it means every state change reaches the
//! tray the same way instead of needing a bespoke notification path for
//! each of the several places a database can lock. A direct menu action
//! (lock, or a finished unlock) also pokes `ksni` right away, so those feel
//! instant rather than waiting for the next tick.
//!
//! **Host-compatibility notes, from testing against more than one host.**
//! The first manual test (`docs/plan.md` step 4) only read back this
//! module's own D-Bus properties and menu layout with `busctl` — which
//! confirms the wiring, but not that anything legible actually gets drawn.
//! Watching a second, more common host's own traffic (`busctl monitor`
//! around registration, then reading that host's own source for how it
//! turns the properties it fetched into pixels) found real gaps:
//!
//! - `icon_name` is deliberately left unset (empty string, the default).
//!   Some hosts' icon-pixmap fallback only ever triggers when `icon_name`
//!   is empty to begin with — not when it's set but fails to resolve
//!   through the current icon theme — so a host like that, given a
//!   non-empty name it can't resolve, shows its own "broken icon"
//!   placeholder and never looks at `icon_pixmap` at all. An empty name
//!   is also the one choice that can't go stale if a given icon theme
//!   turns out to be missing whatever freedesktop names this build might
//!   otherwise pick. [`fallback_icon`] draws a padlock glyph directly
//!   into an ARGB32 bitmap, at two sizes, so every host renders the same
//!   recognizable shape regardless of which icon theme it has installed.
//! - `Tray::MENU_ON_ACTIVATE` is left at the default (`false`): a host
//!   decides on its own terms when to show this module's menu — on a
//!   left click, a right click, both, or neither — never on a signal from
//!   kpa. What this module controls is answering the dbusmenu protocol
//!   correctly once asked: a correct `GetLayout` response and a working
//!   handler behind each item, on the `/MenuBar` object path, regardless
//!   of how or whether a given host ever asks.
//! - [`item_status`] never returns `ksni::Status::Passive` for any state,
//!   including "all locked" (the state the icon starts in, and spends
//!   most of its time in): `docs/plan.md` step 4 asks for lock state to
//!   be "visible at a glance" in every state, which rules out `Passive`
//!   — that value's own doc says a host is likely to hide an item
//!   entirely in that state — for any of them.

use std::sync::Arc;
use std::thread;
use std::time::Duration;

use ksni::blocking::{Handle, TrayMethods};
use ksni::menu::{StandardItem, SubMenu};
use ksni::{MenuItem, ToolTip};

use crate::proto::{
    DatabaseStatus, Lock, LockRequest, Response, Unlock, UnlockError, UnlockRequest,
};
use crate::server::{self, Server};

/// How often the tray re-checks `Server::snapshot` for a change nothing
/// told it about directly — see this module's doc for why polling at all.
/// Matches the lower end of `server::watch_idle`'s own tick, which is
/// already the project's answer to "how often is it fine to notice a lock
/// state change a tick late."
const POLL_INTERVAL: Duration = Duration::from_secs(1);

/// Start the tray service. Like `policy::start`, this runs for the life of
/// the daemon and has nothing for `run_serve` to join.
pub fn start(server: Arc<Server>) {
    thread::spawn(move || run(server));
}

fn run(server: Arc<Server>) {
    let item = TrayItem {
        server,
        handle: None,
        last_error: None,
    };
    let handle = match item.spawn() {
        Ok(handle) => handle,
        // No `org.kde.StatusNotifierWatcher` on the session bus (no tray
        // host running), or no session bus at all. Not fatal: kpa's
        // availability isn't a security goal (`docs/threat-model.md` § 2),
        // and every other op already works with no tray in the picture.
        Err(err) => {
            server::log(format_args!("tray not started: {err}"));
            return;
        }
    };

    // `TrayItem` needs its own handle to refresh itself once a background
    // `unlock` finishes (see `TrayItem::start_unlock`) — but that handle
    // doesn't exist until `spawn` has already consumed the item that would
    // hold it. Set once, from the outside, through the handle itself.
    let for_item = handle.clone();
    handle.update(move |item| item.handle = Some(for_item));

    loop {
        thread::sleep(POLL_INTERVAL);
        // `None` means the service has shut down (`Tray::watcher_offline`
        // returning `false`, or the process exiting through the "Quit"
        // menu item below) — nothing left to poll.
        if handle.update(|_| {}).is_none() {
            return;
        }
    }
}

/// The `ksni::Tray` implementor. Plain fields, no internal locking: every
/// method `ksni::Tray` calls, and every `Handle::update` closure, runs
/// under `ksni`'s own lock on this value — see `docs/design.md`'s "Threads
/// over async" note; this is the one place that choice shows up in the
/// code, as "no extra `Mutex` needed" rather than as async/await.
struct TrayItem {
    server: Arc<Server>,
    /// Set once, right after `spawn` (see `run`). `None` only in the brief
    /// window before that, since nothing can reach `TrayItem::start_unlock`
    /// before `ksni` itself is driving this value.
    handle: Option<Handle<TrayItem>>,
    /// The database and wire error code of the most recent failed
    /// `unlock`, cleared by the next successful `unlock` or explicit
    /// `lock` of any database. Drives the "error" icon state
    /// `docs/design.md` § Tray asks for — there's no such notion on
    /// `DatabaseStatus` itself, since it describes current state, not
    /// history. A cancelled prompt (the user declining, not a failure)
    /// does not set this.
    last_error: Option<(String, &'static str)>,
}

impl ksni::Tray for TrayItem {
    // Left at the default (`false`) — see this module's doc for why
    // `Tray::MENU_ON_ACTIVATE` isn't the right lever here: the host, not
    // kpa, decides when to show the menu.

    fn id(&self) -> String {
        "kpa".to_string()
    }

    fn title(&self) -> String {
        "kpa".to_string()
    }

    // `icon_name` is deliberately not overridden — see this module's doc
    // for why an unset name, not a freedesktop-spec name this build picked,
    // is the one choice that reaches every host's `icon_pixmap` fallback.
    fn icon_pixmap(&self) -> Vec<ksni::Icon> {
        fallback_icon(&self.server.snapshot(), self.last_error.is_some())
    }

    fn status(&self) -> ksni::Status {
        item_status(&self.server.snapshot(), self.last_error.is_some())
    }

    fn tool_tip(&self) -> ToolTip {
        tool_tip(&self.server.snapshot(), self.last_error.as_ref())
    }

    fn menu(&self) -> Vec<MenuItem<Self>> {
        build_menu(&self.server.snapshot(), self.last_error.as_ref())
    }
}

impl TrayItem {
    /// "Lock all" and each per-database "Lock" item. Fast — `Lock::lock`
    /// only ever holds `Server`'s bookkeeping mutex — so this runs straight
    /// in the menu callback; `ksni` refreshes the displayed menu once it
    /// returns, with no need to call `Handle::update` here (unlike
    /// `start_unlock`, below, whose slow part happens well after its own
    /// callback has already returned).
    fn trigger_lock(&mut self, db: Option<&str>) {
        let request = LockRequest {
            db: db.map(str::to_string),
        };
        let result = self.server.lock(&request);
        server::log_response(&Response::Lock(result));
        self.last_error = None;
    }

    /// "Unlock…"'s per-database items. Unlocking waits on a human and a
    /// KDF (`docs/design.md` § Protocol) — seconds, not milliseconds — so
    /// it runs on its own thread rather than the menu callback, matching
    /// the advice on `ksni::menu::StandardItem::activate`. The clone of
    /// `self.handle` is what lets that thread tell `ksni` to refresh once
    /// it's done; everything it touches afterwards (`Arc<Server>`, the
    /// cloned `Handle`) is `Send` on its own, so none of `TrayItem` itself
    /// needs to cross the thread boundary.
    fn start_unlock(&mut self, name: &str) {
        let server = Arc::clone(&self.server);
        let handle = self.handle.clone();
        let name = name.to_string();
        let _ = thread::Builder::new().spawn(move || {
            let result = server.unlock(&UnlockRequest { db: name.clone() });
            server::log_response(&Response::Unlock(result.clone()));
            let Some(handle) = handle else { return };
            handle.update(move |item| {
                item.last_error = match &result {
                    Ok(_) | Err(UnlockError::PromptCancelled { .. }) => None,
                    Err(err) => Some((name, unlock_error_code(err))),
                };
            });
        });
    }
}

/// A short, stable label for `TrayItem::last_error` — deliberately not
/// `UnlockError`'s `Debug` output, which would also print `detail` for
/// `PromptFailed` (a prompt's own I/O error text; harmless, but this way
/// the tray carries nothing beyond what a client could already read off
/// the wire via `UnlockError::fields`'s `ErrorCode`).
fn unlock_error_code(err: &UnlockError) -> &'static str {
    match err {
        UnlockError::UnknownDb { .. } => "unknown_db",
        UnlockError::PromptCancelled { .. } => "prompt_cancelled",
        UnlockError::PromptFailed { .. } => "io",
        UnlockError::WrongCredentials { .. } => "wrong_credentials",
        UnlockError::NotFound { .. } => "not_found",
        UnlockError::Corrupt { .. } => "corrupt",
        UnlockError::Io { .. } => "io",
        UnlockError::InProgress { .. } => "unlock_in_progress",
        UnlockError::LockedDuringUnlock { .. } => "locked",
        UnlockError::Stale { .. } => "stale",
    }
}

/// Whether at least one configured database is unlocked right now. The one
/// fact `aggregate_color`/`item_status`/`tool_tip` all start from.
fn any_unlocked(databases: &[DatabaseStatus]) -> bool {
    databases.iter().any(|db| !db.locked)
}

/// The StatusNotifierItem `Status` property (not to be confused with this
/// crate's own `proto::Status`): how urgently a host should surface the
/// item. An error is `NeedsAttention` — its own documented use is exactly
/// this, "wants to incentive the direct user intervention." Every other
/// state is `Active`, deliberately never `Passive`: that value's own
/// documented meaning is "it is likely that visualizations will choose to
/// hide it" — the opposite of `docs/plan.md` step 4's "lock state is
/// visible at a glance," which has to hold for "all locked" too, since
/// that's the state the daemon starts in and spends most of its time in.
fn item_status(_databases: &[DatabaseStatus], has_error: bool) -> ksni::Status {
    // The parameter stays, unused, so every state-to-display function in
    // this module takes the same `(databases, has_error)` shape at its
    // call sites, rather than this one alone dropping it.
    if has_error {
        ksni::Status::NeedsAttention
    } else {
        ksni::Status::Active
    }
}

/// `docs/design.md` § Tray: "Tooltip lists each configured database and
/// its state." One line per database, plus a trailing line naming the
/// most recent unlock failure, if any — never anything beyond the name and
/// the wire error code already covered by `TrayItem::last_error`'s doc.
fn tool_tip(databases: &[DatabaseStatus], last_error: Option<&(String, &'static str)>) -> ToolTip {
    let mut lines: Vec<String> = databases
        .iter()
        .map(|db| match db.entries {
            Some(n) => format!("{}: unlocked ({n} entries)", db.name),
            None => format!("{}: locked", db.name),
        })
        .collect();
    if let Some((name, code)) = last_error {
        lines.push(format!("{name}: unlock failed ({code})"));
    }
    ToolTip {
        // Empty, not a named icon — same reasoning as `Tray::icon_name`,
        // see this module's doc.
        icon_name: String::new(),
        icon_pixmap: fallback_icon(databases, last_error.is_some()),
        title: "kpa".to_string(),
        description: lines.join("\n"),
    }
}

/// `docs/design.md` § Tray: "Icon reflects aggregate state: all locked /
/// some unlocked / error," as a color, in that priority. `fallback_icon`
/// is what actually turns this into something a host can draw — see this
/// module's doc for why that's a generated bitmap rather than a named
/// freedesktop icon.
fn aggregate_color(databases: &[DatabaseStatus], has_error: bool) -> (u8, u8, u8) {
    if has_error {
        (0xd6, 0x33, 0x3b) // red
    } else if any_unlocked(databases) {
        (0xe6, 0xa8, 0x17) // amber
    } else {
        (0x6b, 0x7b, 0x8c) // slate blue
    }
}

/// Which glyph [`draw_padlock`] draws, chosen from aggregate state the same
/// way [`aggregate_color`] chooses a color: an error always wins, then any
/// database being unlocked, then all-locked as the remaining case.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum LockShape {
    /// Every configured database locked: a closed padlock, its shackle
    /// fully seated in the body.
    Closed,
    /// At least one database unlocked: the shackle's free end lifted away
    /// from the body, leaving a visible gap — distinct from `Closed` even
    /// with color stripped out.
    Open,
    /// An unresolved error: the closed padlock's keyhole replaced by an
    /// exclamation mark, distinct from `Closed` even with color stripped
    /// out.
    Error,
}

fn lock_shape(databases: &[DatabaseStatus], has_error: bool) -> LockShape {
    if has_error {
        LockShape::Error
    } else if any_unlocked(databases) {
        LockShape::Open
    } else {
        LockShape::Closed
    }
}

/// Shortest distance from point `p` to the segment `a`-`b`. The one piece
/// of geometry [`in_shackle`] needs that a bounding-box test can't give it:
/// the open shackle's lifted end is a diagonal stroke, not an
/// axis-aligned rectangle.
fn dist_to_segment((px, py): (f32, f32), (ax, ay): (f32, f32), (bx, by): (f32, f32)) -> f32 {
    let (abx, aby) = (bx - ax, by - ay);
    let len_sq = abx * abx + aby * aby;
    let t = if len_sq > 0.0 {
        (((px - ax) * abx + (py - ay) * aby) / len_sq).clamp(0.0, 1.0)
    } else {
        0.0
    };
    let (cx, cy) = (ax + t * abx, ay + t * aby);
    (px - cx).hypot(py - cy)
}

/// The padlock body: a rectangle, normalized to a unit square ([`draw_padlock`]
/// maps every pixel into this space before testing it against the glyph).
fn in_body(u: f32, v: f32) -> bool {
    (0.27..0.73).contains(&u) && (0.47..0.85).contains(&v)
}

/// The shackle: an arc (`dome`, a half-ring) over the body, with a leg
/// descending from each end to meet it. `LockShape::Open` drops the right
/// leg and replaces it with a stroke lifted up and away, leaving a gap
/// between the arc and the body — the one structural difference from
/// `Closed` a host can't lose by rendering the icon in grayscale.
fn in_shackle(u: f32, v: f32, shape: LockShape) -> bool {
    let (cx, cy) = (0.5, 0.33);
    let r = (u - cx).hypot(v - cy);
    let dome = v <= cy && (0.105..=0.19).contains(&r);
    let left_leg = (0.31..0.395).contains(&u) && (0.33..0.50).contains(&v);
    let right_leg = (0.605..0.69).contains(&u) && (0.33..0.50).contains(&v);
    let lifted_end = dist_to_segment((u, v), (0.62, 0.30), (0.84, 0.10)) <= 0.05;
    match shape {
        LockShape::Closed | LockShape::Error => dome || left_leg || right_leg,
        LockShape::Open => dome || left_leg || lifted_end,
    }
}

/// The cut-out inside the body: a round keyhole for `Closed`/`Open`, an
/// exclamation mark for `Error` — both read as a hole (the background
/// shows through), never a second color, so the glyph stays a single-tone
/// ARGB32 shape.
fn in_hole(u: f32, v: f32, shape: LockShape) -> bool {
    match shape {
        LockShape::Closed | LockShape::Open => (u - 0.5).hypot(v - 0.62) <= 0.055,
        LockShape::Error => {
            let bar = (0.47..0.53).contains(&u) && (0.54..0.68).contains(&v);
            let dot = (u - 0.5).hypot(v - 0.76) <= 0.035;
            bar || dot
        }
    }
}

fn in_padlock(u: f32, v: f32, shape: LockShape) -> bool {
    (in_body(u, v) || in_shackle(u, v, shape)) && !in_hole(u, v, shape)
}

/// Renders one size of the padlock glyph described by [`in_padlock`] into
/// an ARGB32 bitmap, in `color`. Generated rather than loaded from a file:
/// the shape is a few hundred bytes of arithmetic per size, which costs
/// less than shipping and loading an asset file for three fixed
/// color/shape combinations.
fn draw_padlock(size: i32, (r, g, b): (u8, u8, u8), shape: LockShape) -> ksni::Icon {
    let denom = (size - 1).max(1) as f32;
    let mut data = Vec::with_capacity((size * size * 4) as usize);
    for y in 0..size {
        for x in 0..size {
            let (u, v) = (x as f32 / denom, y as f32 / denom);
            if in_padlock(u, v, shape) {
                // ARGB32, network byte order (`ksni::Icon`'s own doc):
                // opaque alpha, then the color.
                data.extend_from_slice(&[0xff, r, g, b]);
            } else {
                data.extend_from_slice(&[0, 0, 0, 0]);
            }
        }
    }
    ksni::Icon {
        width: size,
        height: size,
        data,
    }
}

/// A padlock glyph in `aggregate_color`'s color and [`lock_shape`]'s shape,
/// for `Tray::icon_pixmap` and `ToolTip::icon_pixmap` — see this module's
/// doc for why `icon_name` alone isn't enough. Two sizes, smallest first,
/// so a host that wants a sharper image at a larger panel size has one
/// without upscaling the smaller bitmap.
fn fallback_icon(databases: &[DatabaseStatus], has_error: bool) -> Vec<ksni::Icon> {
    let color = aggregate_color(databases, has_error);
    let shape = lock_shape(databases, has_error);
    [22, 44]
        .into_iter()
        .map(|size| draw_padlock(size, color, shape))
        .collect()
}

/// `docs/design.md` § Tray: "Menu: Unlock…, Lock all, a per-database
/// submenu, Quit." A free function, not a `TrayItem` method, so it can be
/// exercised in tests against a plain `&[DatabaseStatus]` — the closures it
/// builds take `&mut TrayItem` as `ksni::menu::StandardItem::activate`
/// requires, but building them needs no live `TrayItem` to close over, just
/// the database's name.
fn build_menu(
    databases: &[DatabaseStatus],
    last_error: Option<&(String, &'static str)>,
) -> Vec<MenuItem<TrayItem>> {
    let unlock_targets = databases
        .iter()
        .map(|db| {
            let name = db.name.clone();
            MenuItem::Standard(StandardItem {
                label: db.name.clone(),
                enabled: db.locked,
                activate: Box::new(move |item: &mut TrayItem| item.start_unlock(&name)),
                ..Default::default()
            })
        })
        .collect();

    let mut items = vec![
        MenuItem::SubMenu(SubMenu {
            label: "Unlock…".to_string(),
            enabled: databases.iter().any(|db| db.locked),
            submenu: unlock_targets,
            ..Default::default()
        }),
        MenuItem::Standard(StandardItem {
            label: "Lock all".to_string(),
            enabled: any_unlocked(databases),
            activate: Box::new(|item: &mut TrayItem| item.trigger_lock(None)),
            ..Default::default()
        }),
    ];

    // No separator (and no empty gap) when there are no configured
    // databases to list.
    if !databases.is_empty() {
        items.push(MenuItem::Separator);
    }
    for db in databases {
        let name = db.name.clone();
        let icon = if last_error.is_some_and(|(err_db, _)| err_db == &db.name) {
            "dialog-error"
        } else if db.locked {
            "security-high"
        } else {
            "security-medium"
        };
        items.push(MenuItem::SubMenu(SubMenu {
            label: db.name.clone(),
            icon_name: icon.to_string(),
            submenu: vec![MenuItem::Standard(StandardItem {
                label: "Lock".to_string(),
                enabled: !db.locked,
                activate: Box::new(move |item: &mut TrayItem| item.trigger_lock(Some(&name))),
                ..Default::default()
            })],
            ..Default::default()
        }));
    }

    items.push(MenuItem::Separator);
    items.push(MenuItem::Standard(StandardItem {
        label: "Quit".to_string(),
        // The daemon's own exit, not a database lock: a tray app's "Quit"
        // ends the application. Each database's own `Drop` (nothing
        // currently implements one, matching `docs/design.md` § Lock
        // policy's list of what's zeroized) runs no differently than it
        // would for `kill`, which is already how `kpa serve` stops today.
        activate: Box::new(|_: &mut TrayItem| std::process::exit(0)),
        ..Default::default()
    }));

    items
}

#[cfg(test)]
mod tests {
    use super::*;

    fn locked(name: &str) -> DatabaseStatus {
        DatabaseStatus {
            name: name.to_string(),
            locked: true,
            entries: None,
        }
    }

    fn unlocked(name: &str, entries: usize) -> DatabaseStatus {
        DatabaseStatus {
            name: name.to_string(),
            locked: false,
            entries: Some(entries),
        }
    }

    #[test]
    fn the_icon_is_secure_when_every_database_is_locked() {
        let databases = [locked("personal"), locked("work")];
        assert_eq!(aggregate_color(&databases, false), (0x6b, 0x7b, 0x8c));
        // Never `Passive` — see `item_status`'s doc for why "all locked"
        // must stay as visible as every other state.
        assert_eq!(item_status(&databases, false), ksni::Status::Active);
    }

    #[test]
    fn the_icon_is_less_secure_once_anything_is_unlocked() {
        let databases = [locked("personal"), unlocked("work", 3)];
        assert_eq!(aggregate_color(&databases, false), (0xe6, 0xa8, 0x17));
        assert_eq!(item_status(&databases, false), ksni::Status::Active);
    }

    #[test]
    fn no_configured_databases_reads_as_all_locked() {
        assert_eq!(aggregate_color(&[], false), (0x6b, 0x7b, 0x8c));
    }

    /// `Tray::icon_name` stays empty regardless of state — see this
    /// module's doc for why a host's `icon_pixmap` fallback is the one
    /// `TrayItem` relies on, never a named icon.
    #[test]
    fn tray_never_advertises_a_named_icon() {
        use crate::config::Config;

        let item = TrayItem {
            server: Arc::new(Server::new(
                Config::parse("").expect("empty config is valid"),
            )),
            handle: None,
            last_error: None,
        };
        assert_eq!(ksni::Tray::icon_name(&item), "");
        assert_eq!(tool_tip(&[], None).icon_name, "");
    }

    /// The fallback icon is never empty, is the size it claims, has an
    /// opaque body and a transparent corner, and changes with aggregate
    /// state — the whole reason it exists is to be visible without
    /// relying on a host's icon theme at all.
    #[test]
    fn the_fallback_icon_is_a_padlock_that_tracks_state() {
        let locked_icon = &fallback_icon(&[locked("personal")], false)[0];
        assert_eq!((locked_icon.width, locked_icon.height), (22, 22));
        assert_eq!(locked_icon.data.len(), 22 * 22 * 4);

        let corner = 0; // pixel (0, 0)
        assert_eq!(
            locked_icon.data[corner], 0,
            "a corner should be transparent, outside the padlock"
        );
        let body = (22 * 16 + 11) * 4; // pixel (11, 16), inside the body
        assert_eq!(
            locked_icon.data[body], 0xff,
            "the lock body should be opaque"
        );

        let unlocked_icon = &fallback_icon(&[unlocked("personal", 1)], false)[0];
        let error_icon = &fallback_icon(&[locked("personal")], true)[0];
        assert_ne!(locked_icon.data, unlocked_icon.data);
        assert_ne!(locked_icon.data, error_icon.data);
        assert_ne!(unlocked_icon.data, error_icon.data);
    }

    /// `fallback_icon` returns a larger size in addition to 22×22, for a
    /// host that wants a sharper image at a larger panel size.
    #[test]
    fn the_fallback_icon_includes_a_larger_size() {
        let sizes: Vec<(i32, i32)> = fallback_icon(&[locked("personal")], false)
            .iter()
            .map(|icon| (icon.width, icon.height))
            .collect();
        assert_eq!(sizes, vec![(22, 22), (44, 44)]);
    }

    /// The three glyph shapes differ structurally, not just by color — a
    /// host rendering them in grayscale (or a colorblind user) must still
    /// be able to tell "closed", "open", and "error" apart.
    #[test]
    fn the_three_lock_shapes_have_different_silhouettes_in_the_same_color() {
        let same_color = (0x11, 0x22, 0x33);
        let closed = draw_padlock(22, same_color, LockShape::Closed);
        let open = draw_padlock(22, same_color, LockShape::Open);
        let error = draw_padlock(22, same_color, LockShape::Error);
        assert_ne!(
            closed.data, open.data,
            "an open shackle must look different from a closed one"
        );
        assert_ne!(
            closed.data, error.data,
            "the error glyph must look different from the closed one"
        );
        assert_ne!(open.data, error.data);
    }

    #[test]
    fn lock_shape_follows_the_same_priority_as_aggregate_color() {
        assert_eq!(lock_shape(&[locked("personal")], false), LockShape::Closed);
        assert_eq!(
            lock_shape(&[unlocked("personal", 1)], false),
            LockShape::Open
        );
        // An error wins even when something is unlocked.
        assert_eq!(
            lock_shape(&[unlocked("personal", 1)], true),
            LockShape::Error
        );
    }

    /// `Status::Passive` means "likely to be hidden" per its own doc — the
    /// opposite of always being visible at a glance, so no state this
    /// module can be in should ever produce it.
    #[test]
    fn no_state_is_ever_passive() {
        for databases in [
            [].as_slice(),
            &[locked("personal")],
            &[unlocked("personal", 1)],
            &[locked("personal"), unlocked("work", 1)],
        ] {
            for has_error in [false, true] {
                assert_ne!(item_status(databases, has_error), ksni::Status::Passive);
            }
        }
    }

    #[test]
    fn an_error_overrides_the_lock_state_in_the_icon() {
        // Even with everything unlocked, an unresolved error still wins —
        // it's the thing most worth the user's attention.
        let databases = [unlocked("personal", 3)];
        assert_eq!(aggregate_color(&databases, true), (0xd6, 0x33, 0x3b));
        assert_eq!(item_status(&databases, true), ksni::Status::NeedsAttention);
    }

    #[test]
    fn the_tooltip_lists_every_database_and_its_state() {
        let databases = [locked("personal"), unlocked("work", 12)];
        let tip = tool_tip(&databases, None);
        assert_eq!(tip.title, "kpa");
        assert_eq!(
            tip.description,
            "personal: locked\nwork: unlocked (12 entries)"
        );
    }

    #[test]
    fn the_tooltip_names_a_failed_unlock_without_its_detail() {
        let databases = [locked("personal")];
        let error = ("personal".to_string(), "wrong_credentials");
        let tip = tool_tip(&databases, Some(&error));
        assert!(
            tip.description
                .ends_with("personal: unlock failed (wrong_credentials)")
        );
    }

    /// Every `UnlockError` variant maps to a code, and never to `Debug`
    /// output that could carry `PromptFailed`'s `detail`.
    #[test]
    fn every_unlock_error_variant_has_a_short_code() {
        let db = || "personal".to_string();
        let cases: [(UnlockError, &str); 10] = [
            (UnlockError::UnknownDb { db: db() }, "unknown_db"),
            (
                UnlockError::PromptCancelled { db: db() },
                "prompt_cancelled",
            ),
            (
                UnlockError::PromptFailed {
                    db: db(),
                    detail: "secret stuff".to_string(),
                },
                "io",
            ),
            (
                UnlockError::WrongCredentials { db: db() },
                "wrong_credentials",
            ),
            (UnlockError::NotFound { db: db() }, "not_found"),
            (UnlockError::Corrupt { db: db() }, "corrupt"),
            (UnlockError::Io { db: db() }, "io"),
            (UnlockError::InProgress { db: db() }, "unlock_in_progress"),
            (UnlockError::LockedDuringUnlock { db: db() }, "locked"),
            (UnlockError::Stale { db: db() }, "stale"),
        ];
        for (err, code) in cases {
            let got = unlock_error_code(&err);
            assert_eq!(got, code, "{err:?}");
            assert!(
                !got.contains("secret"),
                "a code must never carry an error's own detail text"
            );
        }
    }

    fn labels(items: &[MenuItem<TrayItem>]) -> Vec<&str> {
        items
            .iter()
            .map(|item| match item {
                MenuItem::Standard(i) => i.label.as_str(),
                MenuItem::SubMenu(i) => i.label.as_str(),
                MenuItem::Separator => "---",
                MenuItem::Checkmark(_) | MenuItem::RadioGroup(_) => unreachable!(),
            })
            .collect()
    }

    #[test]
    fn the_menu_has_the_documented_shape() {
        let databases = [locked("personal"), unlocked("work", 3)];
        let menu = build_menu(&databases, None);

        assert_eq!(
            labels(&menu),
            vec![
                "Unlock…",
                "Lock all",
                "---",
                "personal",
                "work",
                "---",
                "Quit"
            ]
        );

        let MenuItem::SubMenu(unlock) = &menu[0] else {
            panic!("expected a submenu");
        };
        assert!(unlock.enabled, "something is locked, so Unlock… is usable");
        assert_eq!(labels(&unlock.submenu), vec!["personal", "work"]);
        let MenuItem::Standard(personal) = &unlock.submenu[0] else {
            panic!("expected a standard item");
        };
        assert!(personal.enabled, "personal is locked, so it's unlockable");
        let MenuItem::Standard(work) = &unlock.submenu[1] else {
            panic!("expected a standard item");
        };
        assert!(!work.enabled, "work is already unlocked");

        let MenuItem::Standard(lock_all) = &menu[1] else {
            panic!("expected a standard item");
        };
        assert!(
            lock_all.enabled,
            "work is unlocked, so Lock all has something to do"
        );

        let MenuItem::SubMenu(personal_sub) = &menu[3] else {
            panic!("expected a submenu");
        };
        let MenuItem::Standard(personal_lock) = &personal_sub.submenu[0] else {
            panic!("expected a standard item");
        };
        assert_eq!(personal_lock.label, "Lock");
        assert!(!personal_lock.enabled, "personal is already locked");

        let MenuItem::SubMenu(work_sub) = &menu[4] else {
            panic!("expected a submenu");
        };
        let MenuItem::Standard(work_lock) = &work_sub.submenu[0] else {
            panic!("expected a standard item");
        };
        assert!(
            work_lock.enabled,
            "work is unlocked, so Lock has something to do"
        );
    }

    #[test]
    fn nothing_locked_disables_unlock_and_nothing_unlocked_disables_lock_all() {
        let all_locked = [locked("personal")];
        let menu = build_menu(&all_locked, None);
        let MenuItem::Standard(lock_all) = &menu[1] else {
            panic!("expected a standard item");
        };
        assert!(!lock_all.enabled);

        let all_unlocked = [unlocked("personal", 1)];
        let menu = build_menu(&all_unlocked, None);
        let MenuItem::SubMenu(unlock) = &menu[0] else {
            panic!("expected a submenu");
        };
        assert!(!unlock.enabled);
    }

    #[test]
    fn the_erroring_databases_submenu_gets_the_error_icon() {
        let databases = [locked("personal"), locked("work")];
        let error = ("work".to_string(), "wrong_credentials");
        let menu = build_menu(&databases, Some(&error));

        let MenuItem::SubMenu(personal_sub) = &menu[3] else {
            panic!("expected a submenu");
        };
        assert_eq!(personal_sub.icon_name, "security-high");

        let MenuItem::SubMenu(work_sub) = &menu[4] else {
            panic!("expected a submenu");
        };
        assert_eq!(work_sub.icon_name, "dialog-error");
    }

    #[test]
    fn with_no_configured_databases_the_menu_still_has_lock_all_and_quit() {
        let menu = build_menu(&[], None);
        assert_eq!(labels(&menu), vec!["Unlock…", "Lock all", "---", "Quit"]);
    }

    /// `TrayItem` itself answers `ksni::Tray`'s queries by calling into a
    /// real (if fixture-free) `Server` — the one piece of wiring the pure
    /// functions above don't cover on their own.
    #[test]
    fn tray_item_reflects_a_real_servers_status() {
        use crate::config::Config;

        let config = Config::parse("[[database]]\nname = \"personal\"\npath = \"personal.kdbx\"\n")
            .expect("valid config");
        let item = TrayItem {
            server: Arc::new(Server::new(config)),
            handle: None,
            last_error: None,
        };

        assert_eq!(ksni::Tray::icon_name(&item), "");
        assert_eq!(ksni::Tray::icon_pixmap(&item)[0].width, 22);
        assert_eq!(ksni::Tray::tool_tip(&item).description, "personal: locked");
        assert_eq!(
            labels(&ksni::Tray::menu(&item)),
            vec!["Unlock…", "Lock all", "---", "personal", "---", "Quit"]
        );
    }

    #[test]
    fn a_stored_error_reaches_tray_item_s_icon() {
        use crate::config::Config;

        let config = Config::parse("").expect("empty config is valid");
        let item = TrayItem {
            server: Arc::new(Server::new(config)),
            handle: None,
            last_error: Some(("personal".to_string(), "wrong_credentials")),
        };

        assert_eq!(
            ksni::Tray::icon_pixmap(&item)[0].data,
            fallback_icon(&[], true)[0].data
        );
    }
}
