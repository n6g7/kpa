//! The clipboard (`docs/plan.md` step 3, `docs/design.md` § Clipboard).
//!
//! Two layers, mirroring `policy.rs`'s split between [`policy::Policy`]
//! (what to decide) and `watch_forever` (the real D-Bus backend):
//!
//! - [`Backend`] is the primitive a real clipboard gives us: the ability to
//!   start serving a secret as an [`Offer`]. [`WaylandBackend`] implements
//!   it on kpa's own Wayland client (`crate::wayland`). Nothing here
//!   decides *when* to stop serving.
//! - [`Clipboard`] is the part that decides: "a second `copy` replaces the
//!   first" and "drop the offer after the timeout, but only if nothing else
//!   already took the clipboard" are both decided against the [`Backend`]
//!   trait alone, so they're tested with a fake backend whose offers have
//!   no Wayland connection at all (see the tests below).
//!
//! **Why `clipboard_timeout` isn't enforced inside this module.** Driving a
//! timeout needs a sleep somewhere, and [`Clipboard::expire`] is written so
//! that sleep can be real (`server.rs` spawns a thread that sleeps then
//! calls it, the same shape as `server.rs`'s own `watch_idle`) or absent
//! entirely (tests call `expire` immediately). Baking `thread::sleep` into
//! `Clipboard` itself would make every test either wait out a real timeout
//! or inject a fake clock; not needing a clock at all is simpler than
//! either.
//!
//! **Ending an offer never touches anyone else's clipboard.** Once
//! something else takes the clipboard, the compositor cancels kpa's data
//! source and [`Offer::is_live`] turns false on its own, so `expire` does
//! nothing. And when kpa does end a live offer, it destroys only its own
//! data source: the compositor clears the selection only if that source
//! still holds it. So a copy landing between `is_live` and `end` survives.

use std::sync::{Arc, Mutex, MutexGuard};

use zeroize::Zeroizing;

use crate::wayland;
pub use crate::wayland::Offer;

/// What went wrong handing a secret to the clipboard backend. `Display`
/// text only, and never the secret itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClipboardError(pub String);

impl std::fmt::Display for ClipboardError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ClipboardError {}

/// A clipboard able to start serving one offer at a time.
pub trait Backend: Send + Sync {
    /// Starts serving `secret` as the clipboard content of the display
    /// session `session` (its logind id), with the password-manager hint
    /// alongside it. Blocks only long enough to know whether the backend
    /// accepted the offer — the actual serving runs on a thread of the
    /// backend's own.
    fn start(&self, secret: Zeroizing<String>, session: &str)
    -> Result<Arc<Offer>, ClipboardError>;
}

/// Tracks the most recently started offer, so a later timeout can tell
/// whether it's still the one to drop. Backend-agnostic: everything here is
/// decided against [`Backend`] alone, which is what makes it
/// testable with a fake backend (see `tests` below) the same way
/// `policy::Policy` is tested against `Locks`/`SleepInhibitor` with no real
/// D-Bus connection.
pub struct Clipboard {
    backend: Box<dyn Backend>,
    current: Mutex<Option<Arc<Offer>>>,
}

impl Clipboard {
    pub fn new(backend: impl Backend + 'static) -> Clipboard {
        Clipboard {
            backend: Box::new(backend),
            current: Mutex::new(None),
        }
    }

    /// Starts serving `secret`. "A second `copy` call replaces the first"
    /// falls out of the backend itself (a new offer supersedes the old one
    /// at the protocol level) plus this call remembering the new offer as
    /// current, so a stale timeout for the old one no longer matches it.
    pub fn offer(
        &self,
        secret: Zeroizing<String>,
        session: &str,
    ) -> Result<Arc<Offer>, ClipboardError> {
        let offer = self.backend.start(secret, session)?;
        *lock(&self.current) = Some(Arc::clone(&offer));
        Ok(offer)
    }

    /// Drops `offer` if it is still both the most recently started offer
    /// and live. Either condition failing means there is nothing to do:
    /// a newer `copy` already replaced it (and, in doing so, already
    /// caused the backend to supersede it — see `offer`'s doc), or
    /// something else already took the clipboard, in which case `is_live`
    /// is already false and no action is taken at all.
    ///
    /// Called after `clipboard_timeout` elapses for `offer` — `server.rs`
    /// spawns a thread that sleeps and then calls this; nothing in this
    /// method itself waits.
    pub fn expire(&self, offer: &Arc<Offer>) {
        let mut current = lock(&self.current);
        let is_current = matches!(&*current, Some(c) if Arc::ptr_eq(c, offer));
        if is_current && offer.is_live() {
            offer.end();
            *current = None;
        }
    }

    /// Ends whatever offer is current right now, unconditionally — unlike
    /// [`expire`](Self::expire), this isn't told which offer it means, so
    /// it ends the current one regardless of which `copy` started it.
    /// Called on `lock` (`server.rs`'s `Lock`/`policy::Locks::lock_all`
    /// impls and the idle timer): a database locking is exactly the
    /// moment `docs/threat-model.md` G-6 ("lock clears what kpa owns")
    /// says a copied secret kpa still owns should stop being served. A
    /// `current` that is `None`, or already not live (already superseded
    /// by something else taking the clipboard), is a no-op — the same
    /// "nothing to do" cases `expire` already handles.
    pub fn end_now(&self) {
        let mut current = lock(&self.current);
        // `current.take()` always runs, live or not — only `end()` is
        // conditional on `is_live()`.
        if let Some(offer) = current.take()
            && offer.is_live()
        {
            offer.end();
        }
    }
}

fn lock(mutex: &Mutex<Option<Arc<Offer>>>) -> MutexGuard<'_, Option<Arc<Offer>>> {
    mutex.lock().unwrap_or_else(|e| e.into_inner())
}

/// The real backend: kpa's own Wayland client, in-process, per
/// `docs/design.md` § Clipboard — never `wl-copy` the binary. It speaks
/// `ext-data-control`/`wlr-data-control`, so it can own a clipboard offer
/// without ever holding keyboard focus, which a daemon never has.
pub struct WaylandBackend;

impl Backend for WaylandBackend {
    fn start(
        &self,
        secret: Zeroizing<String>,
        session: &str,
    ) -> Result<Arc<Offer>, ClipboardError> {
        let failed = |err: wayland::Error| ClipboardError(err.0);
        let stream = wayland::connect(session).map_err(failed)?;
        let offer = wayland::offer(stream, secret).map_err(failed)?;
        Ok(Arc::new(offer))
    }
}

/// A backend with no Wayland connection, for tests elsewhere in the crate
/// that need a `Server` with a working `Clipboard` but have nothing to do
/// with this module's own state-machine tests (`tests::FakeBackend`,
/// below, is the richer fake those use). Every offer is a detached
/// [`Offer`], live until `end` — enough for `server.rs`'s tests to check
/// both that `copy` reaches the clipboard with the right secret,
/// and that a `lock` actually ends an outstanding offer rather than
/// leaving it served.
///
/// `new` hands back a second, shared handle to what was offered — the
/// backend itself ends up owned by a `Clipboard`, so a test needs that
/// handle to see what it recorded, the same shape as `tests::FakeBackend`.
#[cfg(test)]
type OfferHandles = Arc<Mutex<Vec<Arc<Offer>>>>;

#[cfg(test)]
pub(crate) struct RecordingBackend {
    offered: Arc<Mutex<Vec<String>>>,
    offers: OfferHandles,
}

#[cfg(test)]
impl RecordingBackend {
    pub(crate) fn new() -> (RecordingBackend, Arc<Mutex<Vec<String>>>) {
        let (backend, offered, _offers) = RecordingBackend::new_tracking();
        (backend, offered)
    }

    /// Like `new`, but also hands back a handle to every offer this
    /// backend has started (oldest first), so a test can check `is_live`
    /// on a specific one after some later action (e.g. a `lock`) that
    /// should have ended it.
    pub(crate) fn new_tracking() -> (RecordingBackend, Arc<Mutex<Vec<String>>>, OfferHandles) {
        let offered = Arc::new(Mutex::new(Vec::new()));
        let offers = Arc::new(Mutex::new(Vec::new()));
        (
            RecordingBackend {
                offered: Arc::clone(&offered),
                offers: Arc::clone(&offers),
            },
            offered,
            offers,
        )
    }
}

#[cfg(test)]
impl Backend for RecordingBackend {
    fn start(
        &self,
        secret: Zeroizing<String>,
        _session: &str,
    ) -> Result<Arc<Offer>, ClipboardError> {
        self.offered
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(secret.to_string());
        let offer = Arc::new(Offer::detached());
        self.offers
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(Arc::clone(&offer));
        Ok(offer)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    use zeroize::Zeroizing;

    use super::{Backend, Clipboard, ClipboardError, Offer};

    /// A backend whose offers have no Wayland connection at all.
    struct FakeBackend {
        fail_next: AtomicBool,
    }

    impl FakeBackend {
        fn new() -> FakeBackend {
            FakeBackend {
                fail_next: AtomicBool::new(false),
            }
        }

        fn fail_next_start(&self) {
            self.fail_next.store(true, Ordering::SeqCst);
        }
    }

    impl Backend for FakeBackend {
        fn start(
            &self,
            _secret: Zeroizing<String>,
            _session: &str,
        ) -> Result<Arc<Offer>, ClipboardError> {
            if self.fail_next.swap(false, Ordering::SeqCst) {
                return Err(ClipboardError("fake backend refused".to_string()));
            }
            Ok(Arc::new(Offer::detached()))
        }
    }

    const SESSION: &str = "2";

    fn secret(s: &str) -> Zeroizing<String> {
        Zeroizing::new(s.to_string())
    }

    /// The timeout firing on an offer nothing has touched since: it's both
    /// current and live, so `expire` ends it.
    #[test]
    fn expire_drops_a_still_live_current_offer() {
        let backend = FakeBackend::new();
        let clip = Clipboard::new(backend);
        let offer = clip
            .offer(secret("hunter2"), SESSION)
            .expect("fake backend accepts");

        clip.expire(&offer);

        assert!(!offer.is_live(), "expire should have ended it");
    }

    /// A second `copy` before the first's timeout: the first offer is
    /// still live (nothing superseded it), but it is no longer current, so
    /// its own eventual `expire` must leave it alone — ending the
    /// *second* offer's timer is what's supposed to drop the clipboard.
    #[test]
    fn a_second_copy_makes_the_first_offers_timeout_a_no_op() {
        let backend = FakeBackend::new();
        let clip = Clipboard::new(backend);
        let first = clip
            .offer(secret("first"), SESSION)
            .expect("fake backend accepts");
        let second = clip
            .offer(secret("second"), SESSION)
            .expect("fake backend accepts");

        clip.expire(&first);
        assert!(
            first.is_live(),
            "the superseded offer's own timeout must not act"
        );

        clip.expire(&second);
        assert!(
            !second.is_live(),
            "the current offer's timeout must still drop it"
        );
    }

    /// A backend that refuses the offer (standing in for "no reachable
    /// Wayland compositor") surfaces as an error, not a silently-dropped
    /// secret.
    #[test]
    fn a_refusing_backend_reports_an_error() {
        let backend = FakeBackend::new();
        backend.fail_next_start();
        let clip = Clipboard::new(backend);

        assert!(clip.offer(secret("hunter2"), SESSION).is_err());
    }

    /// `end_now` is `lock`'s hook (`docs/threat-model.md` G-6): it ends
    /// the current offer without being told which one it is, unlike
    /// `expire`.
    #[test]
    fn end_now_drops_a_live_current_offer() {
        let backend = FakeBackend::new();
        let clip = Clipboard::new(backend);
        let offer = clip
            .offer(secret("hunter2"), SESSION)
            .expect("fake backend accepts");

        clip.end_now();

        assert!(!offer.is_live(), "end_now should have ended it");
    }

    /// Nothing offered yet: `end_now` has nothing to do and must not panic.
    #[test]
    fn end_now_on_an_empty_clipboard_does_nothing() {
        let backend = FakeBackend::new();
        let clip = Clipboard::new(backend);

        clip.end_now();
    }
}
