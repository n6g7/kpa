//! A compositor for tests: the server end of `ext-data-control-v1` on one
//! socket of a pair, with one seat, for kpa's real client code to talk to.
//!
//! It makes a clipboard manager that asks for a paste at once reproducible:
//! [`Fake::on_set_selection`] runs a hook the moment the client's
//! `set_selection` is processed, and [`Fake::paste`] asks the current
//! selection's owner for a paste whenever a test says. Either hands back
//! the read end of the pipe the owner is told to write to. It reaches end of
//! file once the owner drops its end, with whatever the owner wrote before.

use std::ffi::CString;
use std::io::Write;
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread::{self, JoinHandle};

use rustix::event::{PollFd, PollFlags, Timespec, poll};
use wayland_backend::protocol::{Argument, Message};
use wayland_backend::server::{
    Backend, ClientId, GlobalHandler, GlobalId, Handle, ObjectData, ObjectId,
};
use wayland_client::Proxy;
use wayland_client::protocol::wl_seat::WlSeat;
use wayland_protocols::ext::data_control::v1::client::{
    ext_data_control_manager_v1::{self as manager, ExtDataControlManagerV1},
    ext_data_control_source_v1 as source,
};

/// The opcode of `ext_data_control_device_v1.set_selection`.
const SET_SELECTION: u16 = 0;

/// What a hook is given when a client sets the selection.
pub struct Selection<'a> {
    shared: &'a Shared,
    handle: &'a Handle,
    owner: &'a ObjectId,
}

impl Selection<'_> {
    /// Asks the selection's owner for `mime_type`, as a paste would.
    pub fn paste(&self, mime_type: &str) -> UnixStream {
        let (reader, writer) = UnixStream::pair().expect("a pipe");
        self.shared
            .ask(self.handle, self.owner, mime_type, writer.into());
        reader
    }
}

type Hook = Box<dyn FnMut(&Selection<'_>) + Send>;

struct Shared {
    /// Run when a client sets the selection.
    hook: Mutex<Option<Hook>>,
    /// The source that holds the selection now.
    owner: Mutex<Option<ObjectId>>,
    /// Pastes a test thread asked for, which the compositor's thread sends.
    asked: Mutex<Vec<(String, OwnedFd)>>,
    /// The write ends of the pastes asked, held until the events carrying
    /// them have been flushed.
    in_flight: Mutex<Vec<OwnedFd>>,
}

fn locked<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|e| e.into_inner())
}

impl Shared {
    /// Queues the event that makes `owner` write `mime_type` to `fd`.
    fn ask(&self, handle: &Handle, owner: &ObjectId, mime_type: &str, fd: OwnedFd) {
        let args = [
            Argument::Str(Some(Box::new(
                CString::new(mime_type).expect("a MIME type has no NUL"),
            ))),
            Argument::Fd(fd.as_raw_fd()),
        ];
        let sent = handle.send_event(Message {
            sender_id: owner.clone(),
            opcode: source::EVT_SEND_OPCODE,
            args: args.into_iter().collect(),
        });
        // An owner that is gone is asked nothing, and the reader sees end
        // of file when `fd` drops.
        if sent.is_ok() {
            locked(&self.in_flight).push(fd);
        }
    }
}

/// Which protocol object a request arrives on.
#[derive(Clone, Copy)]
enum Kind {
    Seat,
    Manager,
    Device,
    Source,
}

struct Object {
    kind: Kind,
    shared: Arc<Shared>,
}

impl Object {
    fn new(kind: Kind, shared: &Arc<Shared>) -> Arc<Object> {
        Arc::new(Object {
            kind,
            shared: Arc::clone(shared),
        })
    }
}

impl ObjectData<()> for Object {
    fn request(
        self: Arc<Self>,
        handle: &Handle,
        _: &mut (),
        _: ClientId,
        msg: Message<ObjectId, OwnedFd>,
    ) -> Option<Arc<dyn ObjectData<()>>> {
        match (self.kind, msg.opcode) {
            (Kind::Manager, manager::REQ_CREATE_DATA_SOURCE_OPCODE) => {
                Some(Object::new(Kind::Source, &self.shared))
            }
            (Kind::Manager, manager::REQ_GET_DATA_DEVICE_OPCODE) => {
                Some(Object::new(Kind::Device, &self.shared))
            }
            (Kind::Device, SET_SELECTION) => {
                if let Some(Argument::Object(owner)) = msg.args.first() {
                    *locked(&self.shared.owner) = Some(owner.clone());
                    if let Some(hook) = locked(&self.shared.hook).as_mut() {
                        hook(&Selection {
                            shared: &self.shared,
                            handle,
                            owner,
                        });
                    }
                }
                None
            }
            _ => None,
        }
    }

    fn destroyed(self: Arc<Self>, _: &Handle, _: &mut (), _: ClientId, _: ObjectId) {}
}

/// What binding a global gives the client.
struct Global {
    kind: Kind,
    shared: Arc<Shared>,
}

impl GlobalHandler<()> for Global {
    fn bind(
        self: Arc<Self>,
        _: &Handle,
        _: &mut (),
        _: ClientId,
        _: GlobalId,
        _: ObjectId,
    ) -> Arc<dyn ObjectData<()>> {
        Object::new(self.kind, &self.shared)
    }
}

/// The compositor, serving until dropped.
pub struct Fake {
    shared: Arc<Shared>,
    wake: UnixStream,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl Fake {
    /// A compositor with one seat and `ext-data-control-v1`, and the
    /// client's end of its socket.
    pub fn start() -> (Fake, UnixStream) {
        let (client, server) = UnixStream::pair().expect("a socket pair");
        (Fake::serve(server), client)
    }

    /// A compositor like [`Fake::start`]'s, serving the client at the other
    /// end of `server`.
    pub fn serve(server: UnixStream) -> Fake {
        let (wake, woken) = UnixStream::pair().expect("a socket pair");
        woken.set_nonblocking(true).expect("a non-blocking socket");
        let shared = Arc::new(Shared {
            hook: Mutex::new(None),
            owner: Mutex::new(None),
            asked: Mutex::new(Vec::new()),
            in_flight: Mutex::new(Vec::new()),
        });
        let mut backend = Backend::<()>::new().expect("a server backend");
        let mut handle = backend.handle();
        for (interface, kind) in [
            (WlSeat::interface(), Kind::Seat),
            (ExtDataControlManagerV1::interface(), Kind::Manager),
        ] {
            let global = Global {
                kind,
                shared: Arc::clone(&shared),
            };
            handle.create_global::<()>(interface, 1, Arc::new(global));
        }
        handle
            .insert_client(server, Arc::new(()))
            .expect("the client connects");
        let stop = Arc::new(AtomicBool::new(false));
        let thread = {
            let (shared, stop) = (Arc::clone(&shared), Arc::clone(&stop));
            thread::spawn(move || run(&mut backend, &handle, &shared, &woken, &stop))
        };
        Fake {
            shared,
            wake,
            stop,
            thread: Some(thread),
        }
    }

    /// Runs `hook` each time a client sets the selection, before the
    /// compositor reads another request from it.
    pub fn on_set_selection(&self, hook: impl FnMut(&Selection<'_>) + Send + 'static) {
        *locked(&self.shared.hook) = Some(Box::new(hook));
    }

    /// Asks the owner of the selection for `mime_type`, as a paste would.
    pub fn paste(&self, mime_type: &str) -> UnixStream {
        let (reader, writer) = UnixStream::pair().expect("a pipe");
        locked(&self.shared.asked).push((mime_type.to_string(), writer.into()));
        let _ = (&self.wake).write_all(&[0]);
        reader
    }
}

impl Drop for Fake {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = (&self.wake).write_all(&[0]);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// The compositor's loop: reads requests, sends the pastes a test asked
/// for, and flushes, until told to stop.
fn run(
    backend: &mut Backend<()>,
    handle: &Handle,
    shared: &Shared,
    woken: &UnixStream,
    stop: &AtomicBool,
) {
    let timeout = Timespec {
        tv_sec: 5,
        tv_nsec: 0,
    };
    while !stop.load(Ordering::SeqCst) {
        {
            let requests = backend.poll_fd();
            let mut fds = [
                PollFd::new(&requests, PollFlags::IN),
                PollFd::new(woken, PollFlags::IN),
            ];
            let _ = poll(&mut fds, Some(&timeout));
        }
        let _ = rustix::io::read(woken, &mut [0u8; 64]);
        let _ = backend.dispatch_all_clients(&mut ());
        let mut clients = 0;
        handle.with_all_clients(|_| clients += 1);
        if clients == 0 {
            // The client is gone.
            break;
        }
        let asked: Vec<_> = locked(&shared.asked).drain(..).collect();
        let owner = locked(&shared.owner).clone();
        if let Some(owner) = owner {
            for (mime_type, fd) in asked {
                shared.ask(handle, &owner, &mime_type, fd);
            }
        }
        let _ = backend.flush(None);
        locked(&shared.in_flight).clear();
    }
}
