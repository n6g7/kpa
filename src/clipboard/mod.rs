//! The clipboard (`docs/plan.md` step 3, `docs/design.md` § Clipboard).
//!
//! - [`Backend`] is the primitive a real clipboard gives us: the ability to
//!   start serving a secret as an [`Offer`]. [`WaylandBackend`] implements
//!   it on kpa's own Wayland client (`wayland`); `RecordingBackend` is the
//!   test one, whose offers have no Wayland connection at all. Nothing here
//!   decides *when* to stop serving.
//! - [`Offer`] is one secret being served: live until [`Offer::end`] or
//!   until something else takes the clipboard.
//!
//! **Why `clipboard_timeout` isn't enforced inside this module.** Driving a
//! timeout needs a sleep somewhere, and a backend that slept would make
//! every test either wait out a real timeout or inject a fake clock.
//! `control::CopyState` spawns a thread that sleeps and then ends the offer
//! (the same shape as `auto_lock`'s idle tick), and tests end an offer at
//! once; not needing a clock at all is simpler than either.
//!
//! **Ending an offer never touches anyone else's clipboard.** Once
//! something else takes the clipboard, the compositor cancels kpa's data
//! source and [`Offer::is_live`] turns false on its own, so ending it does
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

/// A clipboard able to start serving one offer at a time. A new offer
/// supersedes the one before it, which turns that one's
/// [`Offer::is_live`] false.
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

/// Every offer a test backend has started, oldest first.
#[cfg(test)]
pub(crate) type OfferHandles = Arc<Mutex<Vec<Arc<Offer>>>>;

/// A backend with no Wayland connection, for tests elsewhere in the crate.
/// Every offer is a detached [`Offer`], live until `end` — enough for
/// `control`'s tests to check both that `copy` reaches the clipboard with the
/// right secret, and that a `lock` actually ends an outstanding offer rather
/// than leaving it served.
///
/// `new_tracking` hands back second, shared handles to what was offered: the
/// backend itself ends up owned by whoever it is given to, so a test needs
/// them to see what it recorded.
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
