//! The clipboard (`docs/plan.md` step 3, `docs/design.md` § Clipboard).
//!
//! Two layers, a real backend and the part that decides:
//!
//! - [`Backend`] is the primitive a real clipboard gives us: the ability to
//!   start serving a secret as an [`Offer`]. [`WaylandBackend`] implements
//!   it on kpa's own Wayland client (`wayland`). Nothing here
//!   decides *when* to stop serving.
//! - [`Clipboard`] is the part that decides: "drop the offer after the
//!   timeout, but only if nothing else already took the clipboard" is
//!   decided against the [`Backend`] trait alone, so it's tested with a fake
//!   backend whose offers have no Wayland connection at all (see the tests
//!   below).
//!
//! **Why `clipboard_timeout` isn't enforced inside this module.** Driving a
//! timeout needs a sleep somewhere, and [`Clipboard::expire`] is written so
//! that sleep can be real (`control::CopyState` spawns a thread that sleeps then
//! calls it, the same shape as `auto_lock`'s idle tick) or absent
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

mod wayland;

use std::sync::Arc;
#[cfg(test)]
use std::sync::Mutex;

use zeroize::Zeroizing;

use crate::display_session::DisplaySession;

pub use wayland::Offer;

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
    /// session `display_session`, with the password-manager hint
    /// alongside it. Blocks only long enough to know whether the backend
    /// accepted the offer — the actual serving runs on a thread of the
    /// backend's own.
    fn start(
        &self,
        secret: Zeroizing<String>,
        display_session: &DisplaySession,
    ) -> Result<Arc<Offer>, ClipboardError>;
}

/// Starts offers on a [`Backend`] and drops them. Keeps no state of its own:
/// a new offer supersedes the one before at the protocol level, so which
/// offers are still live is the offers' own to say ([`Offer::is_live`]), and
/// it is decided against [`Backend`] alone, which is what makes it testable
/// with a fake backend (see `tests` below), with no Wayland connection.
pub struct Clipboard {
    backend: Box<dyn Backend>,
}

impl Clipboard {
    pub fn new(backend: impl Backend + 'static) -> Clipboard {
        Clipboard {
            backend: Box::new(backend),
        }
    }

    /// Starts serving `secret`. "A second `copy` call replaces the first"
    /// falls out of the backend itself: a new offer supersedes the old one
    /// at the protocol level, which turns the old one's `is_live` false.
    pub fn offer(
        &self,
        secret: Zeroizing<String>,
        display_session: &DisplaySession,
    ) -> Result<Arc<Offer>, ClipboardError> {
        self.backend.start(secret, display_session)
    }

    /// Drops `offer` if it is still live. Nothing to do if something else
    /// already took the clipboard (a newer `copy` included), since that
    /// turned `is_live` false, and ending an offer destroys only its own data
    /// source, so a dropped offer never clears anyone else's clipboard.
    ///
    /// Called when `clipboard_timeout` elapses for `offer`, and when a lock
    /// ends the unlock it came from: `control::CopyState` does both, and
    /// nothing in this method itself waits.
    pub fn expire(&self, offer: &Arc<Offer>) {
        if offer.is_live() {
            offer.end();
        }
    }
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
        display_session: &DisplaySession,
    ) -> Result<Arc<Offer>, ClipboardError> {
        let failed = |err: wayland::Error| ClipboardError(err.0);
        let stream = wayland::connect(display_session).map_err(failed)?;
        let offer = wayland::offer(stream, secret).map_err(failed)?;
        Ok(Arc::new(offer))
    }
}

/// A backend with no Wayland connection, for tests elsewhere in the crate
/// that need a working `Clipboard` but have nothing to do
/// with this module's own state-machine tests (`tests::FakeBackend`,
/// below, is the richer fake those use). Every offer is a detached
/// [`Offer`], live until `end` — enough for `control`'s tests to check
/// both that `copy` reaches the clipboard with the right secret,
/// and that a `lock` actually ends an outstanding offer rather than
/// leaving it served.
///
/// `new_tracking` hands back a second, shared handle to what was offered — the
/// backend itself ends up owned by a `Clipboard`, so a test needs that
/// handle to see what it recorded, the same shape as `tests::FakeBackend`.
#[cfg(test)]
pub(crate) type OfferHandles = Arc<Mutex<Vec<Arc<Offer>>>>;

#[cfg(test)]
pub(crate) struct RecordingBackend {
    offered: Arc<Mutex<Vec<String>>>,
    offers: OfferHandles,
}

#[cfg(test)]
impl RecordingBackend {
    /// A backend, with a handle to what it was offered and to every offer this
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
        _display_session: &DisplaySession,
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
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};

    use zeroize::Zeroizing;

    use super::{Backend, Clipboard, ClipboardError, Offer};
    use crate::display_session::DisplaySession;

    /// A backend whose offers have no Wayland connection at all. Like a
    /// compositor, it ends the previous offer when a new one starts.
    struct FakeBackend {
        fail_next: AtomicBool,
        last: Mutex<Option<Arc<Offer>>>,
    }

    impl FakeBackend {
        fn new() -> FakeBackend {
            FakeBackend {
                fail_next: AtomicBool::new(false),
                last: Mutex::new(None),
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
            _display_session: &DisplaySession,
        ) -> Result<Arc<Offer>, ClipboardError> {
            if self.fail_next.swap(false, Ordering::SeqCst) {
                return Err(ClipboardError("fake backend refused".to_string()));
            }
            let offer = Arc::new(Offer::detached());
            if let Some(previous) = self.last.lock().unwrap().replace(Arc::clone(&offer)) {
                previous.end();
            }
            Ok(offer)
        }
    }

    fn session() -> DisplaySession {
        DisplaySession::Unlocked {
            id: "2".to_string(),
            active: true,
        }
    }

    fn secret(s: &str) -> Zeroizing<String> {
        Zeroizing::new(s.to_string())
    }

    /// The timeout firing on an offer nothing has touched since: it's live,
    /// so `expire` ends it.
    #[test]
    fn expire_drops_a_still_live_offer() {
        let backend = FakeBackend::new();
        let clip = Clipboard::new(backend);
        let offer = clip
            .offer(secret("hunter2"), &session())
            .expect("fake backend accepts");

        clip.expire(&offer);

        assert!(!offer.is_live(), "expire should have ended it");
    }

    /// A second `copy` before the first's timeout supersedes the first, so
    /// the first's own eventual `expire` has nothing to do, and the second
    /// stays until its own timeout.
    #[test]
    fn a_second_copy_makes_the_first_offers_timeout_a_no_op() {
        let backend = FakeBackend::new();
        let clip = Clipboard::new(backend);
        let first = clip
            .offer(secret("first"), &session())
            .expect("fake backend accepts");
        let second = clip
            .offer(secret("second"), &session())
            .expect("fake backend accepts");
        assert!(!first.is_live(), "sanity: the second copy superseded it");

        clip.expire(&first);
        assert!(
            second.is_live(),
            "the superseded offer's own timeout must not act on the new one"
        );

        clip.expire(&second);
        assert!(
            !second.is_live(),
            "the newer offer's timeout must still drop it"
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

        assert!(clip.offer(secret("hunter2"), &session()).is_err());
    }
}
