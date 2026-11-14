//! The clipboard (`docs/plan.md` step 3, `docs/design.md` § Clipboard).
//!
//! Two layers, mirroring `policy.rs`'s split between [`policy::Policy`]
//! (what to decide) and `watch_forever` (the real D-Bus backend):
//!
//! - [`Backend`]/[`Offer`] are the primitive a real clipboard gives us: the
//!   ability to start serving a secret, and to ask whether a given offer is
//!   still the live one. [`WaylandBackend`] implements these on kpa's own
//!   Wayland client (`crate::wayland`). Nothing here decides *when* to stop
//!   serving.
//! - [`Clipboard`] is the part that decides: "a second `copy` replaces the
//!   first" and "drop the offer after the timeout, but only if nothing else
//!   already took the clipboard" are both decided against the [`Backend`]/
//!   [`Offer`] traits alone, so they're tested with a fake backend and no
//!   Wayland connection at all (see the tests below).
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

#[cfg(test)]
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use zeroize::Zeroizing;

use crate::wayland;

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

/// One still-tracked clipboard offer.
pub trait Offer: Send + Sync {
    /// Whether this is still the thing being served — false once anything
    /// has superseded it, including another `copy` or a successful `end`.
    fn is_live(&self) -> bool;

    /// Ends this offer. Only ever called once `is_live` said it's still
    /// the one holding the clipboard.
    fn end(&self);
}

/// A clipboard able to start serving one offer at a time.
pub trait Backend: Send + Sync {
    /// Starts serving `secret` as the clipboard content of the display
    /// session `session` (its logind id), with the password-manager hint
    /// alongside it. Blocks only long enough to know whether the backend
    /// accepted the offer — the actual serving runs on a thread of the
    /// backend's own.
    fn start(
        &self,
        secret: Zeroizing<String>,
        session: &str,
    ) -> Result<Arc<dyn Offer>, ClipboardError>;
}

/// Tracks the most recently started offer, so a later timeout can tell
/// whether it's still the one to drop. Backend-agnostic: everything here is
/// decided against [`Backend`]/[`Offer`] alone, which is what makes it
/// testable with a fake backend (see `tests` below) the same way
/// `policy::Policy` is tested against `Locks`/`SleepInhibitor` with no real
/// D-Bus connection.
pub struct Clipboard {
    backend: Box<dyn Backend>,
    current: Mutex<Option<Arc<dyn Offer>>>,
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
    ) -> Result<Arc<dyn Offer>, ClipboardError> {
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
    pub fn expire(&self, offer: &Arc<dyn Offer>) {
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

fn lock(mutex: &Mutex<Option<Arc<dyn Offer>>>) -> MutexGuard<'_, Option<Arc<dyn Offer>>> {
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
    ) -> Result<Arc<dyn Offer>, ClipboardError> {
        let failed = |err: wayland::Error| ClipboardError(err.0);
        let stream = wayland::connect(session).map_err(failed)?;
        let offer = wayland::offer(stream, secret).map_err(failed)?;
        Ok(Arc::new(offer))
    }
}

impl Offer for wayland::Offer {
    fn is_live(&self) -> bool {
        wayland::Offer::is_live(self)
    }

    fn end(&self) {
        wayland::Offer::end(self);
    }
}

/// A backend with no Wayland connection, for tests elsewhere in the crate
/// that need a `Server` with a working `Clipboard` but have nothing to do
/// with this module's own state-machine tests (`tests::FakeBackend`,
/// below, is the richer fake those use). Every offer starts "live"; `end`
/// clears it, same as a real offer — enough for `server.rs`'s tests to
/// check both that `copy` reaches the clipboard with the right secret,
/// and that a `lock` actually ends an outstanding offer rather than
/// leaving it served.
///
/// `new` hands back a second, shared handle to what was offered — the
/// backend itself ends up owned by a `Clipboard`, so a test needs that
/// handle to see what it recorded, the same shape as `tests::FakeBackend`.
#[cfg(test)]
type OfferHandles = Arc<Mutex<Vec<Arc<RecordedOffer>>>>;

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
    ) -> Result<Arc<dyn Offer>, ClipboardError> {
        self.offered
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(secret.to_string());
        let offer = Arc::new(RecordedOffer::new());
        self.offers
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(Arc::clone(&offer));
        Ok(offer)
    }
}

/// An offer that actually tracks liveness, unlike a plain no-op stand-in —
/// so a test can assert that a `lock` (via `Clipboard::end_now`) really
/// ended a `RecordingBackend` offer, not just that nothing panicked.
#[cfg(test)]
pub(crate) struct RecordedOffer {
    live: AtomicBool,
}

#[cfg(test)]
impl RecordedOffer {
    fn new() -> RecordedOffer {
        RecordedOffer {
            live: AtomicBool::new(true),
        }
    }
}

#[cfg(test)]
impl Offer for RecordedOffer {
    fn is_live(&self) -> bool {
        self.live.load(Ordering::SeqCst)
    }

    fn end(&self) {
        self.live.store(false, Ordering::SeqCst);
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    use zeroize::Zeroizing;

    use super::{Backend, Clipboard, ClipboardError, Offer};

    struct FakeOffer {
        live: AtomicBool,
        ended: AtomicUsize,
    }

    impl FakeOffer {
        fn new() -> Arc<FakeOffer> {
            Arc::new(FakeOffer {
                live: AtomicBool::new(true),
                ended: AtomicUsize::new(0),
            })
        }

        fn supersede(&self) {
            // Stands in for the compositor cancelling kpa's data source
            // because something else took the clipboard — not a call to
            // `end`, since nothing *asked* this offer to end.
            self.live.store(false, Ordering::SeqCst);
        }

        fn end_count(&self) -> usize {
            self.ended.load(Ordering::SeqCst)
        }
    }

    impl Offer for FakeOffer {
        fn is_live(&self) -> bool {
            self.live.load(Ordering::SeqCst)
        }

        fn end(&self) {
            self.ended.fetch_add(1, Ordering::SeqCst);
            self.live.store(false, Ordering::SeqCst);
        }
    }

    /// A backend with no Wayland connection at all. `offers` is a handle
    /// the test keeps *outside* the backend, shared with it, so the test
    /// can still reach each call's concrete `FakeOffer` — with its
    /// `supersede`/`end_count` beyond what the `Offer` trait exposes —
    /// after the backend itself has been moved into a `Clipboard`.
    struct FakeBackend {
        offers: Arc<Mutex<Vec<Arc<FakeOffer>>>>,
        fail_next: AtomicBool,
    }

    impl FakeBackend {
        fn new() -> (FakeBackend, Arc<Mutex<Vec<Arc<FakeOffer>>>>) {
            let offers = Arc::new(Mutex::new(Vec::new()));
            let backend = FakeBackend {
                offers: Arc::clone(&offers),
                fail_next: AtomicBool::new(false),
            };
            (backend, offers)
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
        ) -> Result<Arc<dyn Offer>, ClipboardError> {
            if self.fail_next.swap(false, Ordering::SeqCst) {
                return Err(ClipboardError("fake backend refused".to_string()));
            }
            let offer = FakeOffer::new();
            self.offers.lock().unwrap().push(Arc::clone(&offer));
            Ok(offer)
        }
    }

    const SESSION: &str = "2";

    fn secret(s: &str) -> Zeroizing<String> {
        Zeroizing::new(s.to_string())
    }

    /// The `n`th offer a `FakeBackend` started, oldest first — reached
    /// through the shared handle `FakeBackend::new` hands back, since the
    /// backend itself is, by this point, owned by a `Clipboard`.
    fn nth_offer(offers: &Mutex<Vec<Arc<FakeOffer>>>, n: usize) -> Arc<FakeOffer> {
        Arc::clone(&offers.lock().unwrap()[n])
    }

    /// The timeout firing on an offer nothing has touched since: it's both
    /// current and live, so `expire` ends it.
    #[test]
    fn expire_drops_a_still_live_current_offer() {
        let (backend, offers) = FakeBackend::new();
        let clip = Clipboard::new(backend);
        let offer = clip
            .offer(secret("hunter2"), SESSION)
            .expect("fake backend accepts");

        clip.expire(&offer);

        assert!(!offer.is_live(), "expire should have ended it");
        assert_eq!(nth_offer(&offers, 0).end_count(), 1);
    }

    /// The ownership test from `docs/plan.md` step 3, at the state-machine
    /// level: something else takes the clipboard (`supersede`, standing in
    /// for the compositor cancelling kpa's data source — deliberately
    /// *not* `end`, since nothing asked this offer to end), and the later
    /// timeout must take no action at all, not even a call to `end`.
    #[test]
    fn expire_does_nothing_once_superseded() {
        let (backend, offers) = FakeBackend::new();
        let clip = Clipboard::new(backend);
        let offer = clip
            .offer(secret("hunter2"), SESSION)
            .expect("fake backend accepts");

        nth_offer(&offers, 0).supersede();
        assert!(
            !offer.is_live(),
            "supersede should be visible through `offer` too"
        );

        clip.expire(&offer);

        assert_eq!(
            nth_offer(&offers, 0).end_count(),
            0,
            "expire must not call end() once already superseded"
        );
    }

    /// A second `copy` before the first's timeout: the first offer is
    /// still live (nothing superseded it), but it is no longer current, so
    /// its own eventual `expire` must leave it alone — ending the
    /// *second* offer's timer is what's supposed to drop the clipboard.
    #[test]
    fn a_second_copy_makes_the_first_offers_timeout_a_no_op() {
        let (backend, offers) = FakeBackend::new();
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
        assert_eq!(nth_offer(&offers, 0).end_count(), 0);

        clip.expire(&second);
        assert!(
            !second.is_live(),
            "the current offer's timeout must still drop it"
        );
        assert_eq!(nth_offer(&offers, 1).end_count(), 1);
    }

    /// A backend that refuses the offer (standing in for "no reachable
    /// Wayland compositor") surfaces as an error, not a silently-dropped
    /// secret.
    #[test]
    fn a_refusing_backend_reports_an_error() {
        let (backend, _offers) = FakeBackend::new();
        backend.fail_next_start();
        let clip = Clipboard::new(backend);

        assert!(clip.offer(secret("hunter2"), SESSION).is_err());
    }

    /// `end_now` is `lock`'s hook (`docs/threat-model.md` G-6): it ends
    /// the current offer without being told which one it is, unlike
    /// `expire`.
    #[test]
    fn end_now_drops_a_live_current_offer() {
        let (backend, offers) = FakeBackend::new();
        let clip = Clipboard::new(backend);
        let offer = clip
            .offer(secret("hunter2"), SESSION)
            .expect("fake backend accepts");

        clip.end_now();

        assert!(!offer.is_live(), "end_now should have ended it");
        assert_eq!(nth_offer(&offers, 0).end_count(), 1);
    }

    /// Nothing offered yet: `end_now` has nothing to do and must not panic.
    #[test]
    fn end_now_on_an_empty_clipboard_does_nothing() {
        let (backend, _offers) = FakeBackend::new();
        let clip = Clipboard::new(backend);

        clip.end_now();
    }

    /// Already superseded by something else: `end_now` must not call
    /// `end` on an offer it no longer owns, same rule `expire` follows.
    #[test]
    fn end_now_does_nothing_once_superseded() {
        let (backend, offers) = FakeBackend::new();
        let clip = Clipboard::new(backend);
        let _offer = clip
            .offer(secret("hunter2"), SESSION)
            .expect("fake backend accepts");

        nth_offer(&offers, 0).supersede();
        clip.end_now();

        assert_eq!(
            nth_offer(&offers, 0).end_count(),
            0,
            "end_now must not call end() once already superseded"
        );
    }
}
