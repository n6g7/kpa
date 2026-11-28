//! The tray icon: a StatusNotifierItem over D-Bus, via `ksni`.
//!
//! A front end like the others: it calls the core ([`Databases`]) directly,
//! and asks for an unlock password on screen through the screen unlock
//! prompt the daemon shares. It has no requester: a click can't be traced to
//! a caller (a same-user process with session-bus access can trigger a menu
//! entry, `docs/threat-model.md` T-15), so a requester's cgroup would decide
//! nothing real. Its one gate is [`display_allows_prompt`]; lock needs none.
//!
//! [`lock_shape`], [`fallback_icon`], [`item_status`], [`tool_tip`] and
//! [`build_menu`] are pure functions of the databases' [`Snapshot`]s, tested
//! below with no bus. [`Tray::run`] owns `ksni`'s service loop.
//!
//! The tray learns of every lock and unlock, whatever caused it, as an
//! observer ([`Changed`]) that only sends on a channel. The loop wakes and
//! has `ksni` read the databases again. The observer must not call
//! `Handle::update` itself: `update` waits for the lock `ksni` holds while it
//! runs a menu callback, and a menu "Lock" runs [`Databases::lock`], which
//! tells the observer.
//!
//! `icon_name` stays empty everywhere (item, tooltip, menu items);
//! [`fallback_icon`] decodes PNGs rasterized ahead of time from
//! `assets/tray/*.svg` by `assets/tray/render.sh`. `MENU_ON_ACTIVATE`
//! stays unset — the host shows the menu on its own terms — and
//! [`item_status`] never returns `Passive`, which real hosts hide or dim.

use std::sync::Arc;
use std::sync::mpsc::{Receiver, Sender};
use std::thread;

use ksni::blocking::{Handle, TrayMethods};
use ksni::menu::{StandardItem, SubMenu};
use ksni::{MenuItem, OfflineReason, ToolTip};
use zeroize::Zeroizing;

use crate::authz::display_allows_prompt;
use crate::cancel::CancelToken;
use crate::databases::{
    Begin, BeginError, Databases, Observer, Snapshot, UnknownDb, UnlockFailure, VaultError,
};
use crate::display_session::DisplayHandle;
use crate::log;
use crate::prompt::{Prompt, PromptOutcome, Question};

/// Tells the tray's loop that a database was unlocked or locked, by anything.
/// Registered with the core before it is shared.
pub struct Changed(Sender<()>);

impl Changed {
    pub fn new(sender: Sender<()>) -> Changed {
        Changed(sender)
    }

    /// A tray that is gone has nobody to tell.
    fn tell(&self) {
        let _ = self.0.send(());
    }
}

impl Observer for Changed {
    fn unlocked(&self, _: &Databases, _: &str, _: &CancelToken) {
        self.tell();
    }

    fn locked(&self, _: &Databases, _: &str, _: &CancelToken) {
        self.tell();
    }
}

/// The tray: its item, and the channel [`Changed`] sends on.
pub struct Tray {
    item: TrayItem,
    wake: Receiver<()>,
}

impl Tray {
    /// `unlock` asks for passwords on screen; `wake` is the receiving end of
    /// the [`Changed`] registered with `databases`.
    pub fn new(
        databases: Arc<Databases>,
        display: DisplayHandle,
        unlock: Arc<Prompt<Zeroizing<String>>>,
        wake: Receiver<()>,
    ) -> Tray {
        Tray {
            item: TrayItem::new(databases, display, unlock),
            wake,
        }
    }

    /// Runs the tray for the daemon's life, on the calling thread.
    pub fn run(self) {
        let Tray { item, wake } = self;
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

        // `spawn` succeeds both when the item registered with the watcher and
        // when there was no watcher yet, which `watcher_offline` has already
        // said: this line without a "no tray host" one before it means it
        // registered, and `watcher_online` says when a host comes back.
        log::info(format_args!("tray started"));

        // Give the item its own handle, so a finished background unlock
        // (`TrayItem::start_unlock`) can tell `ksni` to refresh.
        let for_item = handle.clone();
        handle.update(move |item| item.handle = Some(for_item));

        // `None` means the service shut down (watcher gone, or "Quit").
        refresh_when_told(&wake, || handle.update(|_| {}).is_some());
    }
}

#[cfg(test)]
impl Tray {
    /// What a click on "Unlock" comes to, on the calling thread.
    pub(crate) fn unlock(&self, name: &str) -> Result<(), &'static str> {
        let item = &self.item;
        unlock(&item.databases, &item.display, &item.unlock, name)
    }
}

/// Calls `refresh` once for each run of wakes, until it says the service is
/// gone or every sender is.
fn refresh_when_told(wake: &Receiver<()>, mut refresh: impl FnMut() -> bool) {
    while wake.recv().is_ok() {
        // `lock_all` tells once per database; one refresh covers them all.
        while wake.try_recv().is_ok() {}
        if !refresh() {
            return;
        }
    }
}

/// The `ksni::Tray` implementor. No internal locking: `ksni` already
/// serializes every call and `Handle::update` closure on this value.
struct TrayItem {
    databases: Arc<Databases>,
    display: DisplayHandle,
    /// How an unlock asks for the password.
    unlock: Arc<Prompt<Zeroizing<String>>>,
    /// Set once, right after `spawn`.
    handle: Option<Handle<TrayItem>>,
    /// The database and label of the most recent failed `unlock`, cleared by
    /// the next `lock`/`unlock`. Never a prompt's own error text, and never
    /// set by a prompt the user dismissed.
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
        fallback_icon(&self.databases.snapshot(), self.last_error.is_some())
    }

    fn status(&self) -> ksni::Status {
        item_status(&self.databases.snapshot(), self.last_error.is_some())
    }

    fn tool_tip(&self) -> ToolTip {
        tool_tip(&self.databases.snapshot(), self.last_error.as_ref())
    }

    fn menu(&self) -> Vec<MenuItem<Self>> {
        build_menu(&self.databases.snapshot(), self.last_error.as_ref())
    }

    // A watcher coming and going (no tray host at all, or a panel
    // restarting) is a normal lifecycle event, not a failure: `Tray::run`'s
    // loop keeps the service alive either way, and `ksni` re-registers the
    // item on its own once a watcher reappears. Only a real "Quit"
    // (`build_menu`'s `std::process::exit`) ends the daemon.
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
    fn new(
        databases: Arc<Databases>,
        display: DisplayHandle,
        unlock: Arc<Prompt<Zeroizing<String>>>,
    ) -> TrayItem {
        TrayItem {
            databases,
            display,
            unlock,
            handle: None,
            last_error: None,
        }
    }

    /// "Lock all" and "Lock". Runs inline: it only takes the core's lock
    /// for a moment, so `ksni` can refresh right after.
    fn trigger_lock(&mut self, db: Option<&str>) {
        match db {
            Some(name) => match self.databases.lock(name) {
                Ok(()) => log::info(format_args!("locked {name:?}")),
                Err(UnknownDb) => log::warn(format_args!("lock failed: no database {name:?}")),
            },
            None => {
                self.databases.lock_all();
                log::info(format_args!("locked every database"));
            }
        }
        self.last_error = None;
    }

    /// "Unlock". Runs on its own thread, since it waits on a human and a
    /// KDF; the cloned handle lets that thread refresh `ksni` once done.
    fn start_unlock(&mut self, name: &str) {
        let databases = Arc::clone(&self.databases);
        let display = self.display.clone();
        let prompt = Arc::clone(&self.unlock);
        let handle = self.handle.clone();
        let name = name.to_string();
        let _ = thread::Builder::new().spawn(move || {
            let result = unlock(&databases, &display, &prompt, &name);
            if let Err(label) = result {
                log::warn(format_args!("unlock of {name:?} failed: {label}"));
            }
            let Some(handle) = handle else { return };
            handle.update(move |item| {
                item.last_error = result.err().map(|label| (name, label));
            });
        });
    }
}

/// Unlocks `name`: begin, gate, ask, finish. The token comes before the
/// display session is read: a screen lock either shows in that read and
/// refuses, or cancels the token and ends the prompt, so no prompt is raised
/// behind a locker.
///
/// `Err` is the label the tray shows for the failure, one of the names the
/// wire uses for the same failure. A prompt the user dismissed, or left
/// unanswered, is not a failure.
fn unlock(
    databases: &Databases,
    display: &DisplayHandle,
    prompt: &Prompt<Zeroizing<String>>,
    name: &str,
) -> Result<(), &'static str> {
    let unlocking = match databases.begin_unlock(name) {
        Err(BeginError::UnknownDb) => return Err("unknown_db"),
        Err(BeginError::InProgress) => return Err("unlock_in_progress"),
        Ok(Begin::AlreadyUnlocked) => return Ok(()),
        Ok(Begin::Started(unlocking)) => unlocking,
    };
    if !display_allows_prompt(&display.get()) {
        return Err("no_prompt");
    }
    log::debug(format_args!("prompting for {name:?}"));
    let question = Question::new(format!("Unlock {name}")).with("database", name);
    let password = match prompt.ask(&question, unlocking.unlock_token()) {
        Ok(PromptOutcome::Answer(password)) => password,
        Ok(PromptOutcome::Cancelled) => return Ok(()),
        Ok(PromptOutcome::TimedOut) => {
            log::info(format_args!("prompt for {name:?} unanswered"));
            return Ok(());
        }
        // A lock ended the prompt.
        Ok(PromptOutcome::Interrupted) => return Err("locked"),
        Err(err) => {
            log::warn(format_args!("prompt for {name:?} failed: {err}"));
            return Err("io");
        }
    };
    // An empty answer means "no password", the way to a keyfile-only
    // database from a prompt that always asks.
    unlocking
        .finish(Some(&password).filter(|password| !password.is_empty()))
        .map_err(failure_label)
}

/// A stable label for a failed unlock — never `Debug`, which can carry text
/// out of the database file.
fn failure_label(failure: UnlockFailure) -> &'static str {
    match failure {
        UnlockFailure::Vault(VaultError::NotFound(_) | VaultError::KeyfileNotFound(_)) => {
            "not_found"
        }
        UnlockFailure::Vault(VaultError::WrongCredentials) => "wrong_credentials",
        UnlockFailure::Vault(
            VaultError::Corrupt(_)
            | VaultError::UnsupportedFormat
            | VaultError::NotRegular(_)
            | VaultError::TooLarge(_),
        ) => "corrupt",
        UnlockFailure::Vault(VaultError::Io(_)) => "io",
        UnlockFailure::Vault(VaultError::Changed) => "stale",
        UnlockFailure::LockedMeanwhile => "locked",
    }
}

fn any_unlocked(databases: &[Snapshot]) -> bool {
    databases.iter().any(|db| !db.is_locked())
}

/// Error → `NeedsAttention`; otherwise always `Active`, never `Passive`
/// (which real hosts hide or dim — see this module's doc).
fn item_status(_databases: &[Snapshot], has_error: bool) -> ksni::Status {
    if has_error {
        ksni::Status::NeedsAttention
    } else {
        ksni::Status::Active
    }
}

/// One line per database, plus a trailing line for the last failed unlock.
fn tool_tip(databases: &[Snapshot], last_error: Option<&(String, &'static str)>) -> ToolTip {
    let mut lines: Vec<String> = databases
        .iter()
        .map(|db| match db.entries {
            Some(n) => format!("{}: unlocked ({n} entries)", db.name),
            None => format!("{}: locked", db.name),
        })
        .collect();
    if let Some((name, label)) = last_error {
        lines.push(format!("{name}: unlock failed ({label})"));
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

fn lock_shape(databases: &[Snapshot], has_error: bool) -> LockShape {
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
    include_bytes!("../../assets/tray/locked-22.png"),
    include_bytes!("../../assets/tray/locked-32.png"),
    include_bytes!("../../assets/tray/locked-44.png"),
];
const UNLOCKED_PNGS: [&[u8]; 3] = [
    include_bytes!("../../assets/tray/unlocked-22.png"),
    include_bytes!("../../assets/tray/unlocked-32.png"),
    include_bytes!("../../assets/tray/unlocked-44.png"),
];
const ERROR_PNGS: [&[u8]; 3] = [
    include_bytes!("../../assets/tray/error-22.png"),
    include_bytes!("../../assets/tray/error-32.png"),
    include_bytes!("../../assets/tray/error-44.png"),
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
fn fallback_icon(databases: &[Snapshot], has_error: bool) -> Vec<ksni::Icon> {
    let pngs = match lock_shape(databases, has_error) {
        LockShape::Locked => &LOCKED_PNGS,
        LockShape::Unlocked => &UNLOCKED_PNGS,
        LockShape::Error => &ERROR_PNGS,
    };
    pngs.iter().map(|png| decode_icon(png)).collect()
}

/// `docs/design.md` § Front ends (the tray): one submenu per database (Lock, Unlock —
/// only the applicable one enabled), then Lock all, then Quit. A free
/// function so it's testable against a plain `&[Snapshot]`.
fn build_menu(
    databases: &[Snapshot],
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
                        enabled: !db.is_locked(),
                        activate: Box::new(move |item: &mut TrayItem| {
                            item.trigger_lock(Some(&lock_name))
                        }),
                        ..Default::default()
                    }),
                    MenuItem::Standard(StandardItem {
                        label: "Unlock".to_string(),
                        enabled: db.is_locked(),
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
    use std::sync::mpsc;
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use super::*;
    use crate::clock::Moment;
    use crate::config::{Config, DatabaseConfig};
    use crate::databases::testing::{PASSWORD, TestEntry};
    use crate::display_session::{self, DisplaySession, DisplayWriter};
    use crate::prompt::{PromptQueue, Scripted, Step};

    /// The display session the tests' display sessions name.
    const SESSION: &str = "1";

    fn locked(name: &str) -> Snapshot {
        Snapshot {
            name: name.to_string(),
            entries: None,
        }
    }

    fn unlocked(name: &str, entries: usize) -> Snapshot {
        Snapshot {
            name: name.to_string(),
            entries: Some(entries),
        }
    }

    fn configs(names: &[&str]) -> Vec<DatabaseConfig> {
        let text: String = names
            .iter()
            .map(|name| format!("[[database]]\nname = \"{name}\"\npath = \"{name}.kdbx\"\n"))
            .collect();
        Config::parse(&text).expect("valid config").databases
    }

    fn display_session(locked: bool) -> DisplaySession {
        DisplaySession::new(SESSION, locked, true)
    }

    /// A real `Databases` with `names` configured and [`Changed`]
    /// registered, behind an unlocked display session and scripted prompts.
    struct Fixture {
        item: TrayItem,
        databases: Arc<Databases>,
        display: Arc<DisplayWriter>,
        prompts: Scripted<Zeroizing<String>>,
        /// What [`Changed`] sends on.
        wake: Receiver<()>,
    }

    fn fixture(names: &[&str]) -> Fixture {
        let (sender, wake) = mpsc::channel();
        let mut core = Databases::for_test(configs(names), Duration::from_secs(3600));
        core.observe(Arc::new(Changed::new(sender)));
        let databases = Arc::new(core);
        let (display, handle) = display_session::channel();
        display.set(display_session(false));
        let prompts = Scripted::new();
        let unlock = Arc::new(Prompt::new(
            Arc::new(PromptQueue::new()),
            prompts.clone(),
            Duration::from_secs(60),
        ));
        Fixture {
            item: TrayItem::new(Arc::clone(&databases), handle, unlock),
            databases,
            display: Arc::new(display),
            prompts,
            wake,
        }
    }

    impl Fixture {
        /// What the tray's unlock click comes to.
        fn unlock(&self, name: &str) -> Result<(), &'static str> {
            unlock(&self.databases, &self.item.display, &self.item.unlock, name)
        }

        /// Whether `personal`'s one unlock is taken.
        fn claimed(&self) -> bool {
            matches!(
                self.databases.begin_unlock("personal"),
                Err(BeginError::InProgress)
            )
        }
    }

    /// A prompt answered with `password`.
    fn typed(password: &str) -> Step<Zeroizing<String>> {
        Step::new(PromptOutcome::Answer(Zeroizing::new(password.to_string())))
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
        let fx = fixture(&[]);
        assert_eq!(ksni::Tray::icon_name(&fx.item), "");
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
    fn the_tooltip_names_a_failed_unlock_by_its_label_alone() {
        let databases = [locked("personal")];
        let error = ("personal".to_string(), "wrong_credentials");
        let tip = tool_tip(&databases, Some(&error));
        assert!(
            tip.description
                .ends_with("personal: unlock failed (wrong_credentials)")
        );
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

    /// The "Lock" (`0`) or "Unlock" (`1`) entry of the `database`th submenu.
    fn submenu_entry(
        menu: &[MenuItem<TrayItem>],
        database: usize,
        entry: usize,
    ) -> &StandardItem<TrayItem> {
        let MenuItem::SubMenu(submenu) = &menu[database] else {
            panic!("expected a submenu");
        };
        let MenuItem::Standard(item) = &submenu.submenu[entry] else {
            panic!("expected a standard item");
        };
        item
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
        assert!(
            !submenu_entry(&menu, 0, 0).enabled,
            "personal is already locked"
        );
        assert!(
            submenu_entry(&menu, 0, 1).enabled,
            "personal is locked, so it's unlockable"
        );
        assert!(
            submenu_entry(&menu, 1, 0).enabled,
            "work is unlocked, so Lock has something to do"
        );
        assert!(
            !submenu_entry(&menu, 1, 1).enabled,
            "work is already unlocked"
        );

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
    fn tray_item_reflects_what_the_core_holds() {
        let fx = fixture(&["personal", "work"]);

        assert_eq!(ksni::Tray::icon_pixmap(&fx.item)[0].width, 22);
        assert_eq!(
            ksni::Tray::tool_tip(&fx.item).description,
            "personal: locked\nwork: locked"
        );
        assert_eq!(
            labels(&ksni::Tray::menu(&fx.item)),
            vec!["personal", "work", "---", "Lock all", "---", "Quit"]
        );
        assert_eq!(
            ksni::Tray::icon_pixmap(&fx.item)[0].data,
            fallback_icon(&[locked("personal")], false)[0].data
        );

        fx.databases
            .install_for_test("work", vec![TestEntry::new("site")]);

        assert_eq!(
            ksni::Tray::tool_tip(&fx.item).description,
            "personal: locked\nwork: unlocked (1 entries)"
        );
        assert_eq!(
            ksni::Tray::icon_pixmap(&fx.item)[0].data,
            fallback_icon(&[unlocked("work", 1)], false)[0].data
        );
        assert!(submenu_entry(&ksni::Tray::menu(&fx.item), 1, 0).enabled);
    }

    #[test]
    fn a_stored_error_reaches_tray_item_s_icon() {
        let mut fx = fixture(&[]);
        fx.item.last_error = Some(("personal".to_string(), "wrong_credentials"));

        assert_eq!(
            ksni::Tray::icon_pixmap(&fx.item)[0].data,
            fallback_icon(&[], true)[0].data
        );
    }

    /// No session bus, a missing watcher, and any future `OfflineReason`
    /// `ksni` might add must all keep the daemon alive — only a real
    /// "Quit" from the menu may end it.
    #[test]
    fn a_missing_tray_host_never_shuts_the_service_down() {
        let fx = fixture(&[]);

        assert!(ksni::Tray::watcher_offline(&fx.item, OfflineReason::No));
        assert!(ksni::Tray::watcher_offline(
            &fx.item,
            OfflineReason::Error(ksni::Error::WontShow)
        ));
        assert!(ksni::Tray::watcher_offline(
            &fx.item,
            OfflineReason::Error(ksni::Error::Watcher(zbus::fdo::Error::ServiceUnknown(
                "The name org.kde.StatusNotifierWatcher was not provided by any .service files"
                    .to_string()
            )))
        ));
    }

    #[test]
    fn the_menu_locks_one_database_or_all_and_clears_the_error() {
        let mut fx = fixture(&["personal", "work"]);
        for name in ["personal", "work"] {
            fx.databases.install_for_test(name, vec![]);
        }
        fx.item.last_error = Some(("work".to_string(), "wrong_credentials"));

        let menu = ksni::Tray::menu(&fx.item);
        (submenu_entry(&menu, 0, 0).activate)(&mut fx.item);

        let state: Vec<bool> = fx
            .databases
            .snapshot()
            .iter()
            .map(Snapshot::is_locked)
            .collect();
        assert_eq!(state, [true, false]);
        assert_eq!(fx.item.last_error, None);

        fx.item.last_error = Some(("work".to_string(), "wrong_credentials"));
        let menu = ksni::Tray::menu(&fx.item);
        let MenuItem::Standard(lock_all) = &menu[3] else {
            panic!("expected a standard item");
        };
        (lock_all.activate)(&mut fx.item);

        assert!(fx.databases.snapshot().iter().all(Snapshot::is_locked));
        assert_eq!(fx.item.last_error, None);
    }

    #[test]
    fn the_loop_is_told_of_every_unlock_and_lock() {
        let (sender, wake) = mpsc::channel();
        let mut databases = Databases::for_test(configs(&["personal", "work"]), Duration::ZERO);
        databases.observe(Arc::new(Changed::new(sender)));
        let told = || wake.try_iter().count();

        databases.install_for_test("personal", vec![]);
        assert_eq!(told(), 1, "an unlock");

        databases.lock("personal").expect("configured");
        assert_eq!(told(), 1, "a lock of one database");

        databases.install_for_test("personal", vec![]);
        databases.install_for_test("work", vec![]);
        told();
        databases.lock_all();
        assert_eq!(told(), 2, "a lock of everything tells once per database");

        databases.install_for_test("personal", vec![]);
        told();
        databases.expire_idle(Moment::now());
        assert_eq!(told(), 1, "an idle lock");

        databases.install_for_test("work", vec![]);
        told();
        databases.change_file_for_test("work");
        databases.drop_stale(["work"]);
        assert_eq!(told(), 1, "a lock for a changed file");
    }

    /// A tray that is gone has nobody to tell, and the core carries on.
    #[test]
    fn a_core_with_no_tray_left_to_tell_still_locks() {
        let (sender, wake) = mpsc::channel();
        let mut databases = Databases::for_test(configs(&["personal"]), Duration::from_secs(60));
        databases.observe(Arc::new(Changed::new(sender)));
        drop(wake);

        databases.install_for_test("personal", vec![]);
        databases.lock_all();

        assert!(databases.snapshot()[0].is_locked());
    }

    /// `ksni` runs a menu callback holding the item's lock, and
    /// `Handle::update` waits for that same lock. This is the item behind
    /// such a lock, the real core with the observer registered, and the
    /// loop's refresh taking the lock as `update` does: the menu's "Lock"
    /// returns, and only then is the refresh able to run.
    #[test]
    fn a_menu_lock_with_the_observer_registered_does_not_deadlock() {
        let fx = fixture(&["personal"]);
        fx.databases
            .install_for_test("personal", vec![TestEntry::new("site")]);
        while fx.wake.try_recv().is_ok() {}
        let Fixture {
            item,
            databases,
            wake,
            ..
        } = fx;
        let service = Arc::new(Mutex::new(item));
        let events = Arc::new(Mutex::new(Vec::new()));

        let (done, finished) = mpsc::channel();
        let menu_thread = {
            let (service, events, databases) = (
                Arc::clone(&service),
                Arc::clone(&events),
                Arc::clone(&databases),
            );
            thread::spawn(move || {
                let mut item = service.lock().unwrap();
                let menu = build_menu(&databases.snapshot(), None);
                (submenu_entry(&menu, 0, 0).activate)(&mut item);
                events.lock().unwrap().push("lock returned");
            })
        };
        let loop_thread = {
            let (service, events) = (Arc::clone(&service), Arc::clone(&events));
            thread::spawn(move || {
                refresh_when_told(&wake, || {
                    drop(service.lock().unwrap());
                    events.lock().unwrap().push("refreshed");
                    false
                });
                done.send(()).expect("the test is waiting");
            })
        };

        finished
            .recv_timeout(Duration::from_secs(10))
            .expect("the menu's Lock and the refresh both finish");
        menu_thread.join().expect("menu thread");
        loop_thread.join().expect("loop thread");
        assert_eq!(*events.lock().unwrap(), ["lock returned", "refreshed"]);
        assert!(databases.snapshot()[0].is_locked());
    }

    #[test]
    fn the_loop_refreshes_once_for_a_run_of_wakes() {
        let (sender, wake) = mpsc::channel();
        for _ in 0..3 {
            sender.send(()).unwrap();
        }
        drop(sender);
        let mut refreshes = 0;

        refresh_when_told(&wake, || {
            refreshes += 1;
            true
        });

        assert_eq!(refreshes, 1);
    }

    #[test]
    fn the_loop_ends_when_the_service_is_gone() {
        let (sender, wake) = mpsc::channel();
        sender.send(()).unwrap();
        let mut refreshes = 0;

        refresh_when_told(&wake, || {
            refreshes += 1;
            false
        });

        assert_eq!(refreshes, 1, "it returns with a sender still alive");
    }

    #[test]
    fn an_unknown_database_and_an_unlocked_one_are_answered_before_any_prompt() {
        let fx = fixture(&["personal"]);
        assert_eq!(fx.unlock("nope"), Err("unknown_db"));
        fx.databases.install_for_test("personal", vec![]);
        assert_eq!(fx.unlock("personal"), Ok(()));
        assert!(fx.prompts.shown().is_empty());
    }

    #[test]
    fn no_prompt_is_raised_without_a_display_session_or_behind_a_locker() {
        let fx = fixture(&["personal"]);
        fx.prompts.push(Step::new(PromptOutcome::Cancelled));

        fx.display.set(display_session(true));
        assert_eq!(fx.unlock("personal"), Err("no_prompt"));
        fx.display.set(DisplaySession::None);
        assert_eq!(fx.unlock("personal"), Err("no_prompt"));
        assert!(
            fx.prompts.shown().is_empty(),
            "a prompt ran behind a locker"
        );
        assert!(!fx.claimed(), "the refusal gave the claim back");

        fx.display.set(display_session(false));
        assert_eq!(fx.unlock("personal"), Ok(()));
        assert_eq!(
            fx.prompts.shown(),
            ["Unlock personal"],
            "the prompt runs once the display session is unlocked"
        );
    }

    /// An inactive display session (a VT switch) still shows a prompt.
    #[test]
    fn an_inactive_display_session_still_shows_the_prompt() {
        let fx = fixture(&["personal"]);
        fx.prompts.push(Step::new(PromptOutcome::Cancelled));
        fx.display.set(DisplaySession::new(SESSION, false, false));

        assert_eq!(fx.unlock("personal"), Ok(()));
        assert_eq!(fx.prompts.shown(), ["Unlock personal"]);
        assert_eq!(
            serde_json::Value::Object(fx.prompts.shown_questions()[0].data.clone()),
            serde_json::json!({"database": "personal"})
        );
    }

    /// The claim is taken before the display session is read, so a second
    /// click on a database whose unlock is under way is `unlock_in_progress`
    /// even where it would have been `no_prompt`.
    #[test]
    fn unlock_in_progress_comes_before_no_prompt() {
        let fx = fixture(&["personal"]);
        fx.display.set(DisplaySession::None);
        let Ok(Begin::Started(unlocking)) = fx.databases.begin_unlock("personal") else {
            panic!("expected an unlock to start");
        };

        assert_eq!(fx.unlock("personal"), Err("unlock_in_progress"));
        drop(unlocking);
    }

    #[test]
    fn a_dismissed_or_unanswered_prompt_is_no_failure() {
        let fx = fixture(&["personal"]);
        fx.prompts.push(Step::new(PromptOutcome::Cancelled));
        fx.prompts.push(Step::new(PromptOutcome::TimedOut));

        assert_eq!(fx.unlock("personal"), Ok(()));
        assert_eq!(fx.unlock("personal"), Ok(()));
        assert!(!fx.claimed());
        assert!(fx.databases.snapshot()[0].is_locked());
    }

    #[test]
    fn a_prompt_that_fails_to_show_is_an_io_failure() {
        let fx = fixture(&["personal"]);
        fx.prompts.push(Step::fails());

        assert_eq!(fx.unlock("personal"), Err("io"));
        assert!(!fx.claimed());
    }

    /// The vault is where an answered prompt ends up in these tests, and the
    /// file the core is configured with is no database.
    #[test]
    fn an_answered_prompt_goes_on_to_read_the_database() {
        let fx = fixture(&["personal"]);
        fx.prompts.push(typed(PASSWORD));

        assert_eq!(fx.unlock("personal"), Err("corrupt"));
        assert!(!fx.claimed());
    }

    #[test]
    fn an_answered_prompt_unlocks_the_database_and_tells_the_loop() {
        let fx = fixture(&["personal"]);
        fx.databases
            .write_for_test("personal", vec![TestEntry::new("site")]);
        fx.prompts.push(typed(PASSWORD));

        assert_eq!(fx.unlock("personal"), Ok(()));

        assert_eq!(fx.databases.snapshot()[0].entries, Some(1));
        assert_eq!(fx.wake.try_iter().count(), 1);
        assert_eq!(fx.prompts.shown(), ["Unlock personal"]);
    }

    #[test]
    fn an_answer_that_does_not_open_the_file_is_wrong_credentials() {
        let fx = fixture(&["personal"]);
        fx.databases
            .write_for_test("personal", vec![TestEntry::new("site")]);
        fx.prompts.push(typed("not the password"));

        assert_eq!(fx.unlock("personal"), Err("wrong_credentials"));

        assert!(fx.databases.snapshot()[0].is_locked());
        assert!(!fx.claimed());
    }

    #[test]
    fn a_screen_lock_while_the_prompt_is_up_ends_it() {
        let fx = fixture(&["personal"]);
        let (databases, display) = (Arc::clone(&fx.databases), Arc::clone(&fx.display));
        fx.prompts.push(typed(PASSWORD).while_up(move || {
            display.set(display_session(true));
            databases.lock_all();
        }));

        assert_eq!(fx.unlock("personal"), Err("locked"));
        assert!(!fx.claimed());
    }

    #[test]
    fn locking_the_database_ends_its_prompt_and_locking_another_does_not() {
        let fx = fixture(&["personal", "work"]);
        let databases = Arc::clone(&fx.databases);
        fx.prompts
            .push(Step::new(PromptOutcome::Cancelled).while_up({
                let databases = Arc::clone(&databases);
                move || databases.lock("work").expect("configured")
            }));
        fx.prompts.push(typed(PASSWORD).while_up(move || {
            databases.lock("personal").expect("configured");
        }));

        assert_eq!(fx.unlock("personal"), Ok(()), "work's lock left it alone");
        assert_eq!(fx.unlock("personal"), Err("locked"));
    }

    #[test]
    fn every_failure_has_a_short_label_and_never_its_text() {
        use crate::databases::VaultFile;

        let path = || std::path::PathBuf::from("/secret/path");
        let cases: [(UnlockFailure, &str); 10] = [
            (
                UnlockFailure::Vault(VaultError::NotFound(path())),
                "not_found",
            ),
            (
                UnlockFailure::Vault(VaultError::KeyfileNotFound(path())),
                "not_found",
            ),
            (
                UnlockFailure::Vault(VaultError::WrongCredentials),
                "wrong_credentials",
            ),
            (
                UnlockFailure::Vault(VaultError::Corrupt("secret stuff".to_string())),
                "corrupt",
            ),
            (
                UnlockFailure::Vault(VaultError::UnsupportedFormat),
                "corrupt",
            ),
            (
                UnlockFailure::Vault(VaultError::NotRegular(VaultFile::Database)),
                "corrupt",
            ),
            (
                UnlockFailure::Vault(VaultError::TooLarge(VaultFile::Keyfile)),
                "corrupt",
            ),
            (
                UnlockFailure::Vault(VaultError::Io(std::io::Error::other("secret stuff"))),
                "io",
            ),
            (UnlockFailure::Vault(VaultError::Changed), "stale"),
            (UnlockFailure::LockedMeanwhile, "locked"),
        ];
        for (failure, label) in cases {
            assert_eq!(failure_label(failure), label);
        }
    }
}
