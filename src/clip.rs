//! The clipboard (`docs/plan.md` step 3, `docs/design.md` § Clipboard).
//!
//! Two layers, mirroring `policy.rs`'s split between [`policy::Policy`]
//! (what to decide) and `watch_forever` (the real D-Bus backend):
//!
//! - [`Backend`]/[`Offer`] are the primitive a real clipboard gives us: the
//!   ability to start serving a secret, and to ask whether a given offer is
//!   still the live one. [`WaylandBackend`] implements these on
//!   `wl-clipboard-rs`. Nothing here decides *when* to stop serving.
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
//! ## The one gap `wl-clipboard-rs` 0.9.5 doesn't close
//!
//! `docs/design.md` claims dropping an expired offer is a no-op if
//! something else already took the clipboard, "no content comparison
//! needed, no risk of clobbering." That claim holds in full for the case
//! the ownership test in `tests/clipboard.rs` exercises: once something
//! else takes the clipboard, the compositor cancels kpa's own data source,
//! [`WaylandOffer::is_live`] turns false on its own, and `expire` then does
//! nothing — genuinely zero action taken, not a check-then-skip.
//!
//! The gap is the *other* direction. `wl-clipboard-rs`'s `copy` module
//! keeps the live `Source`/`Device` objects behind a private `PreparedCopy`
//! with no handle to destroy just one still-live offer from another
//! thread — the only way to end one is `wl_clipboard_rs::copy::clear`,
//! which unconditionally resets the seat's selection regardless of who
//! currently holds it. `WaylandOffer::end` only calls `clear` when
//! `Clipboard::expire` has just confirmed (via `is_live`) that kpa is still
//! the owner, but that confirmation and the `clear` call are two separate
//! round trips to the compositor — a vanishingly narrow window remains
//! where something else sets the clipboard in between, and `clear` would
//! wipe it. Closing this fully would need either a cancel hook this crate
//! version doesn't expose, or reimplementing `ext-data-control`/
//! `wlr-data-control` by hand instead of using `wl-clipboard-rs`. Recorded
//! here rather than overclaimed, matching this repo's "verified vs.
//! reasoned" discipline (see e.g. `vault.rs`'s `Fingerprint` doc).

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::sync_channel;
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread;

use wl_clipboard_rs::copy::{self, MimeSource, MimeType, Options, Source};
use zeroize::Zeroizing;

/// The one MIME type offered for the secret itself. `Options::sensitive`
/// (set below) adds the second one, `x-kde-passwordManagerHint`
/// (`docs/design.md` § Clipboard), on its own.
const TEXT_MIME_TYPE: &str = "text/plain;charset=utf-8";

/// What went wrong handing a secret to the clipboard backend. `Display`
/// text only — it comes from `wl-clipboard-rs`'s own `Error`, which never
/// carries the secret itself (the secret isn't in scope by the time a
/// `wl_clipboard_rs::copy::Error` can occur: only connection/protocol
/// failures are).
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

    /// Ends this offer. Only ever called by [`Clipboard::expire`] after it
    /// has confirmed, via `is_live`, that this offer is both the most
    /// recent one and still live — see this module's doc for the narrow
    /// race that confirmation can't fully close.
    fn end(&self);
}

/// A clipboard able to start serving one offer at a time.
pub trait Backend: Send + Sync {
    /// Starts serving `secret` as the clipboard content, with the
    /// password-manager hint alongside it. Blocks only long enough to know
    /// whether the backend accepted the offer — the actual serving runs on
    /// a thread of the backend's own.
    fn start(&self, secret: Zeroizing<String>) -> Result<Arc<dyn Offer>, ClipboardError>;
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
    pub fn offer(&self, secret: Zeroizing<String>) -> Result<Arc<dyn Offer>, ClipboardError> {
        let offer = self.backend.start(secret)?;
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

/// The real backend: `wl-clipboard-rs`, in-process, per `docs/design.md`
/// § Clipboard — never `wl-copy` the binary. The crate speaks
/// `ext-data-control`/`wlr-data-control`, so it can own a clipboard offer
/// without ever holding keyboard focus, which a daemon never has.
pub struct WaylandBackend;

impl Backend for WaylandBackend {
    fn start(&self, secret: Zeroizing<String>) -> Result<Arc<dyn Offer>, ClipboardError> {
        // Moved into the serving thread below; `secret` itself (the
        // `Zeroizing<String>`) is dropped at the end of this scope, which
        // zeroizes *this* copy. The `Box<[u8]>` made from it is a second
        // copy that `wl-clipboard-rs` holds unzeroized for as long as it
        // serves the offer — upstream, not reachable from here, the same
        // shape as the gaps `docs/design.md` § Security already documents
        // for `keepass`'s own key-derivation intermediates.
        let bytes: Box<[u8]> = secret.as_bytes().to_vec().into_boxed_slice();

        let live = Arc::new(AtomicBool::new(true));
        let live_in_thread = Arc::clone(&live);
        let (ready_tx, ready_rx) = sync_channel(1);

        let spawned = thread::Builder::new()
            .name("kpa-clip".to_string())
            .spawn(move || {
                let mut options = Options::new();
                options
                    .foreground(true)
                    .sensitive(true)
                    .omit_additional_text_mime_types(true);
                let source = MimeSource {
                    source: Source::Bytes(bytes),
                    mime_type: MimeType::Specific(TEXT_MIME_TYPE.to_string()),
                };
                match options.prepare_copy_multi(vec![source]) {
                    Ok(prepared) => {
                        let _ = ready_tx.send(Ok(()));
                        // Blocks until superseded (by anything, including
                        // `WaylandOffer::end`'s own `clear`) or an error.
                        // Either way there is nobody left to report to;
                        // `live` is what the rest of this module reads.
                        let _ = prepared.serve();
                    }
                    Err(err) => {
                        let _ = ready_tx.send(Err(err.to_string()));
                    }
                }
                live_in_thread.store(false, Ordering::SeqCst);
            })
            .map_err(|err| ClipboardError(err.to_string()))?;

        match ready_rx.recv() {
            Ok(Ok(())) => Ok(Arc::new(WaylandOffer { live }) as Arc<dyn Offer>),
            Ok(Err(detail)) => Err(ClipboardError(detail)),
            // The thread panicked (or was otherwise killed) before
            // replying. `spawned` is dropped here, which just detaches it.
            Err(_) => {
                drop(spawned);
                Err(ClipboardError(
                    "the clipboard thread exited before confirming the offer".to_string(),
                ))
            }
        }
    }
}

struct WaylandOffer {
    live: Arc<AtomicBool>,
}

impl Offer for WaylandOffer {
    fn is_live(&self) -> bool {
        self.live.load(Ordering::SeqCst)
    }

    fn end(&self) {
        // See this module's doc comment for why this is "clear the
        // clipboard," not "destroy only our own offer" — `wl-clipboard-rs`
        // 0.9.5 has no handle for the latter. Best-effort: a failure here
        // just leaves the offer being served a little past its nominal
        // expiry, which `Clipboard::expire` already decided was safe to
        // risk (it only reaches this call once `is_live` said we're still
        // the one holding it).
        let _ = copy::clear(copy::ClipboardType::Regular, copy::Seat::All);
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
    fn start(&self, secret: Zeroizing<String>) -> Result<Arc<dyn Offer>, ClipboardError> {
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
        fn start(&self, _secret: Zeroizing<String>) -> Result<Arc<dyn Offer>, ClipboardError> {
            if self.fail_next.swap(false, Ordering::SeqCst) {
                return Err(ClipboardError("fake backend refused".to_string()));
            }
            let offer = FakeOffer::new();
            self.offers.lock().unwrap().push(Arc::clone(&offer));
            Ok(offer)
        }
    }

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
        let offer = clip.offer(secret("hunter2")).expect("fake backend accepts");

        clip.expire(&offer);

        assert!(!offer.is_live(), "expire should have ended it");
        assert_eq!(nth_offer(&offers, 0).end_count(), 1);
    }

    /// The ownership test from `docs/plan.md` step 3, at the state-machine
    /// level: something else takes the clipboard (`supersede`, standing in
    /// for the compositor cancelling kpa's data source — deliberately
    /// *not* `end`, since nothing asked this offer to end), and the later
    /// timeout must take no action at all — not even a call to `end` that
    /// happens to be idempotent, since the real backend's `end` is a
    /// `clear()` that is not conditional on anything.
    #[test]
    fn expire_does_nothing_once_superseded() {
        let (backend, offers) = FakeBackend::new();
        let clip = Clipboard::new(backend);
        let offer = clip.offer(secret("hunter2")).expect("fake backend accepts");

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
        let first = clip.offer(secret("first")).expect("fake backend accepts");
        let second = clip.offer(secret("second")).expect("fake backend accepts");

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

        assert!(clip.offer(secret("hunter2")).is_err());
    }

    /// `end_now` is `lock`'s hook (`docs/threat-model.md` G-6): it ends
    /// the current offer without being told which one it is, unlike
    /// `expire`.
    #[test]
    fn end_now_drops_a_live_current_offer() {
        let (backend, offers) = FakeBackend::new();
        let clip = Clipboard::new(backend);
        let offer = clip.offer(secret("hunter2")).expect("fake backend accepts");

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
        let _offer = clip.offer(secret("hunter2")).expect("fake backend accepts");

        nth_offer(&offers, 0).supersede();
        clip.end_now();

        assert_eq!(
            nth_offer(&offers, 0).end_count(),
            0,
            "end_now must not call end() once already superseded"
        );
    }
}
