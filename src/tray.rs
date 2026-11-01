//! The tray icon (`docs/plan.md` step 4, `docs/design.md` § Tray): a
//! StatusNotifierItem over D-Bus, via `ksni`.
//!
//! Follows the same two-part shape as `policy.rs`, adapted to what's
//! actually hard to test here. `policy.rs` splits into a pure core
//! (`Policy`) tested against the `Locks`/`SleepInhibitor` traits, and a
//! D-Bus half (`watch_forever`) that can't be exercised without a bus. The
//! tray's equivalent split is [`icon_name`]/[`item_status`]/[`tool_tip`]/
//! [`build_menu`] — pure functions of a `DatabaseStatus` snapshot, tested
//! below with no `ksni`, no D-Bus, and no `Server` at all — versus [`run`],
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
    // A left click opens the menu rather than calling `activate` (which
    // this never overrides, so it would otherwise do nothing) — there's no
    // single primary action for a tray that watches several databases at
    // once, so the menu is it.
    const MENU_ON_ACTIVATE: bool = true;

    fn id(&self) -> String {
        "kpa".to_string()
    }

    fn title(&self) -> String {
        "kpa".to_string()
    }

    fn status(&self) -> ksni::Status {
        item_status(&self.server.snapshot(), self.last_error.is_some())
    }

    fn icon_name(&self) -> String {
        icon_name(&self.server.snapshot(), self.last_error.is_some()).to_string()
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
/// fact `icon_name`/`item_status`/`tool_tip` all start from.
fn any_unlocked(databases: &[DatabaseStatus]) -> bool {
    databases.iter().any(|db| !db.locked)
}

/// `docs/design.md` § Tray: "Icon reflects aggregate state: all locked /
/// some unlocked / error." All three names are from the freedesktop icon
/// naming spec's own "Status" and "Dialog" categories, so any icon theme
/// that follows the spec has them — no bundled icon file, no
/// desktop-specific name.
fn icon_name(databases: &[DatabaseStatus], has_error: bool) -> &'static str {
    if has_error {
        "dialog-error"
    } else if any_unlocked(databases) {
        "security-medium"
    } else {
        "security-high"
    }
}

/// The StatusNotifierItem `Status` property (not to be confused with this
/// crate's own `proto::Status`): how urgently a host should surface the
/// item. An error is `NeedsAttention` — its own documented use is exactly
/// this, "wants to incentive the direct user intervention" — some database
/// unlocked is `Active`, and all locked is `Passive`, since there's nothing
/// for the user to act on.
fn item_status(databases: &[DatabaseStatus], has_error: bool) -> ksni::Status {
    if has_error {
        ksni::Status::NeedsAttention
    } else if any_unlocked(databases) {
        ksni::Status::Active
    } else {
        ksni::Status::Passive
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
        icon_name: icon_name(databases, last_error.is_some()).to_string(),
        title: "kpa".to_string(),
        description: lines.join("\n"),
        ..Default::default()
    }
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
        assert_eq!(icon_name(&databases, false), "security-high");
        assert_eq!(item_status(&databases, false), ksni::Status::Passive);
    }

    #[test]
    fn the_icon_is_less_secure_once_anything_is_unlocked() {
        let databases = [locked("personal"), unlocked("work", 3)];
        assert_eq!(icon_name(&databases, false), "security-medium");
        assert_eq!(item_status(&databases, false), ksni::Status::Active);
    }

    #[test]
    fn no_configured_databases_reads_as_all_locked() {
        assert_eq!(icon_name(&[], false), "security-high");
    }

    #[test]
    fn an_error_overrides_the_lock_state_in_the_icon() {
        // Even with everything unlocked, an unresolved error still wins —
        // it's the thing most worth the user's attention.
        let databases = [unlocked("personal", 3)];
        assert_eq!(icon_name(&databases, true), "dialog-error");
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

        assert_eq!(ksni::Tray::icon_name(&item), "security-high");
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

        assert_eq!(ksni::Tray::icon_name(&item), "dialog-error");
    }
}
