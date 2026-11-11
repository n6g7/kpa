//! The tray icon (`docs/plan.md` step 4, `docs/design.md` § Tray): a
//! StatusNotifierItem over D-Bus, via `ksni`.
//!
//! [`lock_shape`], [`fallback_icon`], [`item_status`], [`tool_tip`] and
//! [`build_menu`] are pure functions of a `DatabaseStatus` snapshot,
//! tested below with no bus; [`run`] owns `ksni`'s service loop and the
//! once-a-second poll that catches locks nothing told it about directly.
//!
//! [`TrayItem`] calls `Server`/`Lock`/`Unlock` directly, as a second
//! caller of the socket protocol's own locking code. It holds only what
//! `Server::snapshot` returns, plus the last failed unlock's error code.
//!
//! `icon_name` stays empty everywhere (item, tooltip, menu items);
//! [`fallback_icon`] decodes PNGs rasterized ahead of time from
//! `assets/tray/*.svg` by `assets/tray/render.sh`. `MENU_ON_ACTIVATE`
//! stays unset — the host shows the menu on its own terms — and
//! [`item_status`] never returns `Passive`, which real hosts hide or dim.

use std::sync::Arc;
use std::thread;
use std::time::Duration;

use ksni::blocking::{Handle, TrayMethods};
use ksni::menu::{StandardItem, SubMenu};
use ksni::{MenuItem, OfflineReason, ToolTip};

use crate::log;
use crate::origin::Origin;
use crate::proto::{
    DatabaseStatus, Lock, LockRequest, Response, Unlock, UnlockError, UnlockRequest,
};
use crate::server::{self, Server};

/// How often [`run`] re-checks `Server::snapshot`.
const POLL_INTERVAL: Duration = Duration::from_secs(1);

/// Starts the tray service; runs for the daemon's life.
pub fn start(server: Arc<Server>) {
    thread::spawn(move || run(server));
}

fn run(server: Arc<Server>) {
    let item = TrayItem {
        server,
        handle: None,
        last_error: None,
    };
    // `assume_sni_available` routes a missing StatusNotifierWatcher to
    // `TrayItem::watcher_offline` instead of failing `spawn` outright, so
    // `kpa serve` started ahead of a tray host (e.g. by systemd) keeps
    // waiting instead of giving up on the tray for the daemon's life.
    let handle = match item.assume_sni_available(true).spawn() {
        Ok(handle) => handle,
        // No session bus at all, or a D-Bus error other than the missing
        // watcher. Not fatal: the tray isn't a security goal
        // (`docs/threat-model.md` § 2); it just never appears.
        Err(err) => {
            log::warn(format_args!("tray not started: {err}"));
            return;
        }
    };

    log::debug(format_args!("tray service started"));

    // Give the item its own handle, so a finished background unlock
    // (`TrayItem::start_unlock`) can tell `ksni` to refresh.
    let for_item = handle.clone();
    handle.update(move |item| item.handle = Some(for_item));

    loop {
        thread::sleep(POLL_INTERVAL);
        // `None` means the service shut down (watcher gone, or "Quit").
        if handle.update(|_| {}).is_none() {
            return;
        }
    }
}

/// The `ksni::Tray` implementor. No internal locking: `ksni` already
/// serializes every call and `Handle::update` closure on this value.
struct TrayItem {
    server: Arc<Server>,
    /// Set once, right after `spawn`.
    handle: Option<Handle<TrayItem>>,
    /// The database and wire error code of the most recent failed
    /// `unlock`, cleared by the next `lock`/`unlock`. Never `detail`
    /// (`UnlockError::fields`) and never set by a cancelled prompt.
    last_error: Option<(String, &'static str)>,
}

impl ksni::Tray for TrayItem {
    fn id(&self) -> String {
        "kpa".to_string()
    }

    fn title(&self) -> String {
        "kpa".to_string()
    }

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

    // A watcher coming and going (no tray host at all, or a panel
    // restarting) is a normal lifecycle event, not a failure: `run`'s
    // poll loop keeps the service alive either way, and `ksni`
    // re-registers the item on its own once a watcher reappears. Only a
    // real "Quit" (`build_menu`'s `std::process::exit`) ends the daemon.
    fn watcher_online(&self) {
        log::info(format_args!("tray registered"));
    }

    fn watcher_offline(&self, reason: OfflineReason) -> bool {
        match reason {
            OfflineReason::No => {
                log::info(format_args!("no tray host; waiting for one"));
            }
            OfflineReason::Error(err) => {
                log::info(format_args!("no tray host yet: {err}"));
            }
            // `OfflineReason` is `#[non_exhaustive]`; treat anything
            // future versions of `ksni` add the same as `No`.
            _ => {
                log::info(format_args!("no tray host; waiting for one"));
            }
        }
        true
    }
}

impl TrayItem {
    /// "Lock all" and "Lock". Runs inline: `Lock::lock` only holds
    /// `Server`'s bookkeeping mutex, so `ksni` can refresh right after.
    fn trigger_lock(&mut self, db: Option<&str>) {
        let request = LockRequest {
            db: db.map(str::to_string),
        };
        let result = self.server.lock(&request);
        server::log_response(&Response::Lock(result));
        self.last_error = None;
    }

    /// "Unlock". Runs on its own thread, since it waits on a human and a
    /// KDF; the cloned handle lets that thread refresh `ksni` once done.
    fn start_unlock(&mut self, name: &str) {
        let server = Arc::clone(&self.server);
        let handle = self.handle.clone();
        let name = name.to_string();
        let _ = thread::Builder::new().spawn(move || {
            // The tray's menu is clicked at the desk.
            let result = server.unlock(
                &UnlockRequest {
                    db: name.clone(),
                    password: None,
                },
                Origin::Desktop,
            );
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

/// A stable label for `TrayItem::last_error` — never `Debug`, which could
/// leak `PromptFailed`'s `detail`.
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
        UnlockError::NoDisplay => "no_display",
    }
}

fn any_unlocked(databases: &[DatabaseStatus]) -> bool {
    databases.iter().any(|db| !db.locked)
}

/// Error → `NeedsAttention`; otherwise always `Active`, never `Passive`
/// (which real hosts hide or dim — see this module's doc).
fn item_status(_databases: &[DatabaseStatus], has_error: bool) -> ksni::Status {
    if has_error {
        ksni::Status::NeedsAttention
    } else {
        ksni::Status::Active
    }
}

/// One line per database, plus a trailing line for the last failed unlock.
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
        icon_name: String::new(),
        icon_pixmap: fallback_icon(databases, last_error.is_some()),
        title: "kpa".to_string(),
        description: lines.join("\n"),
    }
}

/// Which embedded padlock PNG [`fallback_icon`] decodes, named after the
/// `assets/tray/<name>.svg` it comes from.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum LockShape {
    Locked,
    Unlocked,
    Error,
}

fn lock_shape(databases: &[DatabaseStatus], has_error: bool) -> LockShape {
    if has_error {
        LockShape::Error
    } else if any_unlocked(databases) {
        LockShape::Unlocked
    } else {
        LockShape::Locked
    }
}

/// Embedded PNGs per state, smallest size first — see `assets/tray/render.sh`.
const LOCKED_PNGS: [&[u8]; 3] = [
    include_bytes!("../assets/tray/locked-22.png"),
    include_bytes!("../assets/tray/locked-32.png"),
    include_bytes!("../assets/tray/locked-44.png"),
];
const UNLOCKED_PNGS: [&[u8]; 3] = [
    include_bytes!("../assets/tray/unlocked-22.png"),
    include_bytes!("../assets/tray/unlocked-32.png"),
    include_bytes!("../assets/tray/unlocked-44.png"),
];
const ERROR_PNGS: [&[u8]; 3] = [
    include_bytes!("../assets/tray/error-22.png"),
    include_bytes!("../assets/tray/error-32.png"),
    include_bytes!("../assets/tray/error-44.png"),
];

/// Decodes one embedded PNG into the ARGB32 `ksni::Icon` StatusNotifierItem
/// wants (alpha first, network byte order). Always RGBA8 — `render.sh`'s
/// own output — so a decode or color-type failure means a stale `.png`.
fn decode_icon(png: &[u8]) -> ksni::Icon {
    let mut reader = png::Decoder::new(png)
        .read_info()
        .expect("every embedded tray PNG is well-formed");
    let mut buf = vec![0; reader.output_buffer_size()];
    let info = reader
        .next_frame(&mut buf)
        .expect("every embedded tray PNG decodes to its own header");
    assert_eq!(
        info.color_type,
        png::ColorType::Rgba,
        "assets/tray/render.sh always produces RGBA8 PNGs"
    );
    let mut data = Vec::with_capacity(buf.len());
    let (pixels, _) = buf[..info.buffer_size()].as_chunks::<4>();
    for &[r, g, b, a] in pixels {
        data.extend_from_slice(&[a, r, g, b]);
    }
    ksni::Icon {
        width: info.width as i32,
        height: info.height as i32,
        data,
    }
}

/// The tray's padlock glyph, in [`lock_shape`]'s state, at three sizes
/// (smallest first) for `Tray::icon_pixmap` and `ToolTip::icon_pixmap`.
fn fallback_icon(databases: &[DatabaseStatus], has_error: bool) -> Vec<ksni::Icon> {
    let pngs = match lock_shape(databases, has_error) {
        LockShape::Locked => &LOCKED_PNGS,
        LockShape::Unlocked => &UNLOCKED_PNGS,
        LockShape::Error => &ERROR_PNGS,
    };
    pngs.iter().map(|png| decode_icon(png)).collect()
}

/// `docs/design.md` § Tray: one submenu per database (Lock, Unlock —
/// only the applicable one enabled), then Lock all, then Quit. A free
/// function so it's testable against a plain `&[DatabaseStatus]`.
fn build_menu(
    databases: &[DatabaseStatus],
    last_error: Option<&(String, &'static str)>,
) -> Vec<MenuItem<TrayItem>> {
    let mut items: Vec<MenuItem<TrayItem>> = databases
        .iter()
        .map(|db| {
            let lock_name = db.name.clone();
            let unlock_name = db.name.clone();
            let label = if last_error.is_some_and(|(err_db, _)| err_db == &db.name) {
                format!("{} (unlock failed)", db.name)
            } else {
                db.name.clone()
            };
            MenuItem::SubMenu(SubMenu {
                label,
                submenu: vec![
                    MenuItem::Standard(StandardItem {
                        label: "Lock".to_string(),
                        enabled: !db.locked,
                        activate: Box::new(move |item: &mut TrayItem| {
                            item.trigger_lock(Some(&lock_name))
                        }),
                        ..Default::default()
                    }),
                    MenuItem::Standard(StandardItem {
                        label: "Unlock".to_string(),
                        enabled: db.locked,
                        activate: Box::new(move |item: &mut TrayItem| {
                            item.start_unlock(&unlock_name)
                        }),
                        ..Default::default()
                    }),
                ],
                ..Default::default()
            })
        })
        .collect();

    if !databases.is_empty() {
        items.push(MenuItem::Separator);
    }
    items.push(MenuItem::Standard(StandardItem {
        label: "Lock all".to_string(),
        enabled: any_unlocked(databases),
        activate: Box::new(|item: &mut TrayItem| item.trigger_lock(None)),
        ..Default::default()
    }));
    items.push(MenuItem::Separator);
    items.push(MenuItem::Standard(StandardItem {
        label: "Quit".to_string(),
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
    fn the_icon_is_locked_when_every_database_is_locked() {
        let databases = [locked("personal"), locked("work")];
        assert_eq!(lock_shape(&databases, false), LockShape::Locked);
        assert_eq!(item_status(&databases, false), ksni::Status::Active);
    }

    #[test]
    fn the_icon_is_unlocked_once_anything_is_unlocked() {
        let databases = [locked("personal"), unlocked("work", 3)];
        assert_eq!(lock_shape(&databases, false), LockShape::Unlocked);
        assert_eq!(item_status(&databases, false), ksni::Status::Active);
    }

    #[test]
    fn no_configured_databases_reads_as_all_locked() {
        assert_eq!(lock_shape(&[], false), LockShape::Locked);
    }

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

    #[test]
    fn the_fallback_icon_is_a_padlock_that_tracks_state() {
        let locked_icon = &fallback_icon(&[locked("personal")], false)[0];
        assert_eq!((locked_icon.width, locked_icon.height), (22, 22));
        assert_eq!(locked_icon.data.len(), 22 * 22 * 4);

        let corner = 0; // pixel (0, 0): transparent, outside the padlock.
        assert_eq!(locked_icon.data[corner], 0);
        let body = (22 * 16 + 11) * 4; // pixel (11, 16): inside the body.
        assert_eq!(locked_icon.data[body], 0xff);

        let unlocked_icon = &fallback_icon(&[unlocked("personal", 1)], false)[0];
        let error_icon = &fallback_icon(&[locked("personal")], true)[0];
        assert_ne!(locked_icon.data, unlocked_icon.data);
        assert_ne!(locked_icon.data, error_icon.data);
        assert_ne!(unlocked_icon.data, error_icon.data);
    }

    #[test]
    fn the_fallback_icon_includes_larger_sizes() {
        let sizes: Vec<(i32, i32)> = fallback_icon(&[locked("personal")], false)
            .iter()
            .map(|icon| (icon.width, icon.height))
            .collect();
        assert_eq!(sizes, vec![(22, 22), (32, 32), (44, 44)]);
    }

    #[test]
    fn every_embedded_png_decodes_to_its_own_size() {
        for pngs in [&LOCKED_PNGS, &UNLOCKED_PNGS, &ERROR_PNGS] {
            for (bytes, want) in pngs.iter().zip([22, 32, 44]) {
                let icon = decode_icon(bytes);
                assert_eq!((icon.width, icon.height), (want, want));
                assert_eq!(icon.data.len(), (want * want * 4) as usize);
            }
        }
    }

    #[test]
    fn lock_shape_follows_the_documented_priority() {
        assert_eq!(lock_shape(&[locked("personal")], false), LockShape::Locked);
        assert_eq!(
            lock_shape(&[unlocked("personal", 1)], false),
            LockShape::Unlocked
        );
        // An error wins even when something is unlocked.
        assert_eq!(
            lock_shape(&[unlocked("personal", 1)], true),
            LockShape::Error
        );
    }

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
        let databases = [unlocked("personal", 3)];
        assert_eq!(lock_shape(&databases, true), LockShape::Error);
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

    /// Never `Debug`, which could leak `PromptFailed`'s `detail`.
    #[test]
    fn every_unlock_error_variant_has_a_short_code() {
        let db = || "personal".to_string();
        let cases: [(UnlockError, &str); 11] = [
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
            (UnlockError::NoDisplay, "no_display"),
        ];
        for (err, code) in cases {
            let got = unlock_error_code(&err);
            assert_eq!(got, code, "{err:?}");
            assert!(!got.contains("secret"));
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
            vec!["personal", "work", "---", "Lock all", "---", "Quit"]
        );

        let MenuItem::SubMenu(personal_sub) = &menu[0] else {
            panic!("expected a submenu");
        };
        assert_eq!(labels(&personal_sub.submenu), vec!["Lock", "Unlock"]);
        let MenuItem::Standard(personal_lock) = &personal_sub.submenu[0] else {
            panic!("expected a standard item");
        };
        assert!(!personal_lock.enabled, "personal is already locked");
        let MenuItem::Standard(personal_unlock) = &personal_sub.submenu[1] else {
            panic!("expected a standard item");
        };
        assert!(
            personal_unlock.enabled,
            "personal is locked, so it's unlockable"
        );

        let MenuItem::SubMenu(work_sub) = &menu[1] else {
            panic!("expected a submenu");
        };
        let MenuItem::Standard(work_lock) = &work_sub.submenu[0] else {
            panic!("expected a standard item");
        };
        assert!(
            work_lock.enabled,
            "work is unlocked, so Lock has something to do"
        );
        let MenuItem::Standard(work_unlock) = &work_sub.submenu[1] else {
            panic!("expected a standard item");
        };
        assert!(!work_unlock.enabled, "work is already unlocked");

        let MenuItem::Standard(lock_all) = &menu[3] else {
            panic!("expected a standard item");
        };
        assert!(
            lock_all.enabled,
            "work is unlocked, so Lock all has something to do"
        );
    }

    #[test]
    fn nothing_unlocked_disables_lock_all() {
        let all_locked = [locked("personal")];
        let menu = build_menu(&all_locked, None);
        assert_eq!(
            labels(&menu),
            vec!["personal", "---", "Lock all", "---", "Quit"]
        );
        let MenuItem::Standard(lock_all) = &menu[2] else {
            panic!("expected a standard item");
        };
        assert!(!lock_all.enabled);
    }

    #[test]
    fn the_erroring_database_s_submenu_label_names_the_failure() {
        let databases = [locked("personal"), locked("work")];
        let error = ("work".to_string(), "wrong_credentials");
        let menu = build_menu(&databases, Some(&error));

        let MenuItem::SubMenu(personal_sub) = &menu[0] else {
            panic!("expected a submenu");
        };
        assert_eq!(personal_sub.label, "personal");

        let MenuItem::SubMenu(work_sub) = &menu[1] else {
            panic!("expected a submenu");
        };
        assert_eq!(work_sub.label, "work (unlock failed)");
    }

    #[test]
    fn with_no_configured_databases_the_menu_still_has_lock_all_and_quit() {
        let menu = build_menu(&[], None);
        assert_eq!(labels(&menu), vec!["Lock all", "---", "Quit"]);
    }

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
            vec!["personal", "---", "Lock all", "---", "Quit"]
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

    /// No session bus, a missing watcher, and any future `OfflineReason`
    /// `ksni` might add must all keep the daemon alive — only a real
    /// "Quit" from the menu may end it.
    #[test]
    fn a_missing_tray_host_never_shuts_the_service_down() {
        use crate::config::Config;

        let item = TrayItem {
            server: Arc::new(Server::new(
                Config::parse("").expect("empty config is valid"),
            )),
            handle: None,
            last_error: None,
        };

        assert!(ksni::Tray::watcher_offline(&item, OfflineReason::No));
        assert!(ksni::Tray::watcher_offline(
            &item,
            OfflineReason::Error(ksni::Error::WontShow)
        ));
        assert!(ksni::Tray::watcher_offline(
            &item,
            OfflineReason::Error(ksni::Error::Watcher(zbus::fdo::Error::ServiceUnknown(
                "The name org.kde.StatusNotifierWatcher was not provided by any .service files"
                    .to_string()
            )))
        ));
    }
}
