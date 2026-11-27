//! Offering one secret on the clipboard and serving pastes of it.
//!
//! Each offer has its own Wayland connection and its own thread, which
//! answers pastes until the compositor cancels the offer (something else
//! took the clipboard) or [`Offer::end`] asks it to stop. Stopping destroys
//! kpa's own data sources and nothing else: the compositor clears the
//! selection only if one of them still holds it, so ending an offer can't
//! wipe what another client copied since.

use std::io;
use std::net::Shutdown;
use std::os::fd::OwnedFd;
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, sync_channel};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use rustix::event::{PollFd, PollFlags, Timespec, poll};
use rustix::fs::{OFlags, fcntl_getfl, fcntl_setfl};
use rustix::io::Errno;
use wayland_client::globals::{GlobalListContents, registry_queue_init};
use wayland_client::protocol::wl_registry::WlRegistry;
use wayland_client::protocol::wl_seat::WlSeat;
use wayland_client::{Connection, Dispatch, EventQueue, Proxy, QueueHandle};
use zeroize::Zeroizing;

use super::Error;
use super::data_control::{Device, Manager, Source};
use crate::cancel::CancelToken;

/// The MIME type the secret itself is offered as.
const TEXT_MIME_TYPE: &str = "text/plain;charset=utf-8";
/// Offered alongside, with the value `secret`: what clipboard-history
/// managers check to skip passwords (`docs/design.md` § Clipboard).
const HINT_MIME_TYPE: &str = "x-kde-passwordManagerHint";

/// How long one paste may take to accept the secret. A reader that stalls
/// past this gets a truncated paste, so it can't hold up `end`.
const WRITE_DEADLINE: Duration = Duration::from_secs(1);
/// How long `end` waits for the serving thread to confirm.
const END_TIMEOUT: Duration = Duration::from_secs(2);

/// The serving thread's state: the secret and kpa's own protocol objects.
pub struct State {
    secret: Zeroizing<Vec<u8>>,
    /// The unlock the secret came from. A paste is answered with nothing
    /// once it is cancelled.
    unlock: CancelToken,
    devices: Vec<Device>,
    sources: Vec<Source>,
}

impl State {
    fn any_live(&self) -> bool {
        self.sources.iter().any(Source::is_alive)
    }

    /// Answers one paste. Only the two offered MIME types get an answer,
    /// and none does once the unlock is locked: the reader gets end of file,
    /// whatever else is still in flight.
    pub(super) fn send(&mut self, mime_type: &str, fd: OwnedFd) {
        if self.unlock.is_cancelled() {
            return;
        }
        let data: &[u8] = match mime_type {
            TEXT_MIME_TYPE => &self.secret,
            HINT_MIME_TYPE => b"secret",
            _ => return,
        };
        if let Err(err) = write_all_by(&fd, data, Instant::now() + WRITE_DEADLINE) {
            crate::log::debug(format_args!("a paste didn't complete: {err}"));
        }
    }

    fn destroy_all(&self) {
        for source in self.sources.iter().filter(|s| s.is_alive()) {
            source.destroy();
        }
        for device in &self.devices {
            device.destroy();
        }
    }
}

impl Dispatch<WlRegistry, GlobalListContents> for State {
    fn event(
        _: &mut State,
        _: &WlRegistry,
        _: <WlRegistry as Proxy>::Event,
        _: &GlobalListContents,
        _: &Connection,
        _: &QueueHandle<State>,
    ) {
    }
}

impl Dispatch<WlSeat, ()> for State {
    fn event(
        _: &mut State,
        _: &WlSeat,
        _: <WlSeat as Proxy>::Event,
        _: &(),
        _: &Connection,
        _: &QueueHandle<State>,
    ) {
    }
}

/// A secret being served. Dropping every handle stops it, like [`end`].
///
/// [`end`]: Offer::end
pub struct Offer {
    live: Arc<AtomicBool>,
    stop: UnixStream,
    done: Mutex<Receiver<()>>,
}

impl Offer {
    /// Whether this offer still holds the clipboard on some seat.
    pub fn is_live(&self) -> bool {
        self.live.load(Ordering::SeqCst)
    }

    /// Stops serving and waits, up to [`END_TIMEOUT`], until the compositor
    /// has processed it. Does nothing to an offer that isn't live: it ended
    /// already, or something else took the clipboard and the compositor
    /// cancelled it. Ending an offer destroys only its own data source, so
    /// it never clears a clipboard someone else now holds.
    pub fn end(&self) {
        if !self.is_live() {
            return;
        }
        let _ = self.stop.shutdown(Shutdown::Both);
        let done = self.done.lock().unwrap_or_else(|e| e.into_inner());
        let _ = done.recv_timeout(END_TIMEOUT);
    }
}

/// Offers `secret` on every seat of the compositor at `stream`, and serves
/// it on a thread of its own until `unlock` is cancelled, after which no
/// paste gets it. Returns once the compositor has the offer.
pub fn offer(
    stream: UnixStream,
    secret: Zeroizing<String>,
    unlock: CancelToken,
) -> Result<Offer, Error> {
    let secret = Zeroizing::new(secret.as_bytes().to_vec());
    let (queue, state) = start(stream, secret, unlock)?;
    spawn(move |stop| serve(queue, state, stop))
}

/// Runs `serve` on a thread of its own, which ends the offer when it
/// returns. `serve` gets the end of the stop pipe that `end` closes.
fn spawn(serve: impl FnOnce(&UnixStream) + Send + 'static) -> Result<Offer, Error> {
    let live = Arc::new(AtomicBool::new(true));
    let (stop, stop_rx) =
        UnixStream::pair().map_err(|err| Error(format!("couldn't create a pipe: {err}")))?;
    let (done_tx, done_rx) = sync_channel(1);
    let live_in_thread = Arc::clone(&live);
    thread::Builder::new()
        .name("kpa-clip".to_string())
        .spawn(move || {
            serve(&stop_rx);
            live_in_thread.store(false, Ordering::SeqCst);
            let _ = done_tx.send(());
        })
        .map_err(|err| Error(format!("couldn't start the clipboard thread: {err}")))?;

    Ok(Offer {
        live,
        stop,
        done: Mutex::new(done_rx),
    })
}

#[cfg(test)]
impl Offer {
    /// An offer with no compositor behind it, for tests: live until `end`
    /// or until it's dropped.
    pub fn detached() -> Offer {
        spawn(|stop| {
            let _ = io::Read::read(&mut &*stop, &mut [0]);
        })
        .expect("a detached offer needs only a pipe and a thread")
    }
}

/// Connects, binds the data-control manager and every seat, and sets one
/// source per seat as its selection.
fn start(
    stream: UnixStream,
    secret: Zeroizing<Vec<u8>>,
    unlock: CancelToken,
) -> Result<(EventQueue<State>, State), Error> {
    let conn = Connection::from_socket(stream)
        .map_err(|err| Error(format!("couldn't connect to the compositor: {err}")))?;
    let (globals, mut queue) = registry_queue_init::<State>(&conn)
        .map_err(|err| Error(format!("couldn't list the compositor's globals: {err}")))?;
    let qh = queue.handle();

    let manager = Manager::bind(&globals, &qh).ok_or_else(|| {
        Error("the compositor supports neither ext-data-control nor wlr-data-control".to_string())
    })?;
    let registry = globals.registry();
    let seats: Vec<WlSeat> = globals.contents().with_list(|list| {
        list.iter()
            .filter(|global| global.interface == WlSeat::interface().name)
            .map(|global| registry.bind(global.name, 1, &qh, ()))
            .collect()
    });
    if seats.is_empty() {
        return Err(Error("the compositor has no seat".to_string()));
    }

    let mut state = State {
        secret,
        unlock,
        devices: Vec::new(),
        sources: Vec::new(),
    };
    for seat in &seats {
        let device = manager.get_data_device(seat, &qh);
        let source = manager.create_data_source(&qh);
        // The secret first: some readers take the first type offered.
        source.offer(TEXT_MIME_TYPE);
        source.offer(HINT_MIME_TYPE);
        device.set_selection(&source);
        state.devices.push(device);
        state.sources.push(source);
    }
    queue
        .roundtrip(&mut state)
        .map_err(|err| Error(format!("the compositor refused the offer: {err}")))?;
    if !state.any_live() {
        return Err(Error(
            "the compositor cancelled the offer at once".to_string(),
        ));
    }
    Ok((queue, state))
}

/// Dispatches events until every source is gone, the connection fails, or
/// `stop` is closed. On `stop`, destroys kpa's sources and waits for the
/// compositor to process that.
fn serve(mut queue: EventQueue<State>, mut state: State, stop: &UnixStream) {
    let mut stopped = false;
    while state.any_live() {
        if queue.flush().is_err() {
            return;
        }
        let Some(guard) = queue.prepare_read() else {
            if queue.dispatch_pending(&mut state).is_err() {
                return;
            }
            continue;
        };
        let (wayland_ready, stop_ready) = {
            let wayland_fd = guard.connection_fd();
            let mut fds = [
                PollFd::new(&wayland_fd, PollFlags::IN),
                PollFd::new(stop, PollFlags::IN),
            ];
            match poll(&mut fds, None) {
                Ok(_) => {}
                Err(Errno::INTR) => continue,
                Err(_) => return,
            }
            (!fds[0].revents().is_empty(), !fds[1].revents().is_empty())
        };
        if stop_ready {
            drop(guard);
            stopped = true;
            break;
        }
        if wayland_ready {
            match guard.read() {
                Ok(_) => {}
                Err(wayland_client::backend::WaylandError::Io(err))
                    if err.kind() == io::ErrorKind::WouldBlock => {}
                Err(_) => return,
            }
        } else {
            drop(guard);
        }
        if queue.dispatch_pending(&mut state).is_err() {
            return;
        }
    }
    if stopped {
        state.destroy_all();
        let _ = queue.roundtrip(&mut state);
    }
}

/// Writes all of `data` to the pipe `fd` before `deadline`.
fn write_all_by(fd: &OwnedFd, mut data: &[u8], deadline: Instant) -> io::Result<()> {
    let flags = fcntl_getfl(fd)?;
    fcntl_setfl(fd, flags | OFlags::NONBLOCK)?;
    while !data.is_empty() {
        match rustix::io::write(fd, data) {
            Ok(written) => data = &data[written..],
            Err(Errno::INTR) => {}
            Err(Errno::AGAIN) => {
                let left = deadline.saturating_duration_since(Instant::now());
                if left.is_zero() {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "the reader stalled",
                    ));
                }
                let timeout = Timespec {
                    tv_sec: left.as_secs() as _,
                    tv_nsec: left.subsec_nanos() as _,
                };
                let mut fds = [PollFd::new(fd, PollFlags::OUT)];
                match poll(&mut fds, Some(&timeout)) {
                    Ok(_) | Err(Errno::INTR) => {}
                    Err(err) => return Err(err.into()),
                }
            }
            Err(err) => return Err(err.into()),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::io::Read;
    use std::os::fd::OwnedFd;
    use std::os::unix::net::UnixStream;
    use std::sync::mpsc::channel;
    use std::time::{Duration, Instant};

    use zeroize::Zeroizing;

    use super::super::fake::Fake;
    use super::{END_TIMEOUT, HINT_MIME_TYPE, Offer, TEXT_MIME_TYPE, offer, write_all_by};
    use crate::cancel::CancelSource;

    /// What the owner of the selection answered a paste with: everything it
    /// wrote before it closed its end.
    fn answer(mut reader: UnixStream) -> String {
        reader
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let mut answer = String::new();
        reader
            .read_to_string(&mut answer)
            .expect("the owner closes its end");
        answer
    }

    /// Offers `hunter2` to the compositor at `client` as the secret of `source`'s unlock.
    fn offer_to(client: UnixStream, source: &CancelSource) -> Offer {
        offer(
            client,
            Zeroizing::new("hunter2".to_string()),
            source.token(),
        )
        .expect("the compositor takes the offer")
    }

    /// Without a lock the compositor's paste is answered, so the tests
    /// below show a refusal and not a compositor that never asked.
    #[test]
    fn a_paste_of_an_unlocked_secret_gets_it_and_the_hint() {
        let (compositor, client) = Fake::start();
        let source = CancelSource::new();
        let offer = offer_to(client, &source);

        assert_eq!(answer(compositor.paste(TEXT_MIME_TYPE)), "hunter2");
        assert_eq!(answer(compositor.paste(HINT_MIME_TYPE)), "secret");
        offer.end();
    }

    /// A lock that lands after the compositor has the selection and before
    /// the offer is handed back, with a paste already asked: the answer is
    /// nothing. A recording backend can't show this, it has no compositor
    /// to ask.
    #[test]
    fn a_lock_between_set_selection_and_the_roundtrip_leaves_a_paste_unanswered() {
        let (compositor, client) = Fake::start();
        let source = CancelSource::new();
        let token = source.token();
        let (asked, pastes) = channel();
        let mut source = Some(source);
        compositor.on_set_selection(move |selection| {
            // The lock lands as the compositor processes `set_selection`.
            drop(source.take());
            for mime in [TEXT_MIME_TYPE, HINT_MIME_TYPE] {
                asked.send(selection.paste(mime)).unwrap();
            }
        });

        let offer = offer(client, Zeroizing::new("hunter2".to_string()), token)
            .expect("the compositor took the offer before it was locked");

        let pastes: Vec<_> = pastes.try_iter().collect();
        assert_eq!(pastes.len(), 2, "the compositor asked");
        for paste in pastes {
            assert_eq!(answer(paste), "");
        }
        offer.end();
    }

    /// A paste asked after the offer is being served is answered until the
    /// lock, and not after.
    #[test]
    fn a_paste_asked_after_a_lock_gets_nothing() {
        let (compositor, client) = Fake::start();
        let source = CancelSource::new();
        let offer = offer_to(client, &source);
        assert_eq!(answer(compositor.paste(TEXT_MIME_TYPE)), "hunter2");

        drop(source);

        assert_eq!(answer(compositor.paste(TEXT_MIME_TYPE)), "");
        assert_eq!(answer(compositor.paste(HINT_MIME_TYPE)), "");
        offer.end();
    }

    #[test]
    fn ending_an_offer_ends_it_and_ending_it_again_does_nothing() {
        let offer = Offer::detached();
        assert!(offer.is_live());

        offer.end();
        assert!(!offer.is_live());

        let started = Instant::now();
        offer.end();
        assert!(started.elapsed() < END_TIMEOUT / 2, "the second end waited");
    }

    #[test]
    fn a_reader_gets_everything() {
        let (reader, writer) = UnixStream::pair().unwrap();
        let fd = OwnedFd::from(writer);
        write_all_by(&fd, b"hunter2", Instant::now() + Duration::from_secs(1)).unwrap();
        drop(fd);
        let mut got = String::new();
        (&reader).read_to_string(&mut got).unwrap();
        assert_eq!(got, "hunter2");
    }

    #[test]
    fn a_stalled_reader_times_out() {
        let (_reader, writer) = UnixStream::pair().unwrap();
        let fd = OwnedFd::from(writer);
        let big = vec![0u8; 16 * 1024 * 1024];
        let started = Instant::now();
        let err = write_all_by(&fd, &big, Instant::now() + Duration::from_millis(100)).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::TimedOut);
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    #[test]
    fn a_closed_reader_is_an_error_not_a_hang() {
        let (reader, writer) = UnixStream::pair().unwrap();
        drop(reader);
        let fd = OwnedFd::from(writer);
        assert!(write_all_by(&fd, b"hunter2", Instant::now() + Duration::from_secs(1)).is_err());
    }
}
