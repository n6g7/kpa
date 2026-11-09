//! A password sent in an `unlock` request leaves no unwiped copy behind in
//! the daemon's heap: not of the request line, which holds it as base64,
//! and not of the password itself once decoded.
//!
//! Checked with a global allocator that, while armed, looks through every
//! block as it is freed (reallocations included) for either form. It has
//! to be its own test binary, since the allocator is process-wide, and it
//! runs `server::serve` in-process so the daemon's frees go through it.
//!
//! The request names a database that isn't configured, so the password is
//! decoded and then dropped unused: what `keepass` does with a password it
//! is given is upstream's (`docs/design.md` § Memory).

use std::alloc::{GlobalAlloc, Layout, System};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use kpa::config::Config;
use kpa::server::{self, Server};

const PLAINTEXT: &[u8] = b"kpa-zeroize-canary-7c1e9a4f";

static ENCODED: OnceLock<Vec<u8>> = OnceLock::new();
static ARMED: AtomicBool = AtomicBool::new(false);
static FOUND: AtomicBool = AtomicBool::new(false);

/// `System`, except that every block starts zeroed, so that scanning it
/// on free only ever reads bytes that were written, and that while
/// `ARMED` a freed block holding a canary sets `FOUND`.
struct Scanning;

unsafe impl GlobalAlloc for Scanning {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if ARMED.load(Ordering::SeqCst) {
            let block = unsafe { std::slice::from_raw_parts(ptr, layout.size()) };
            let encoded = ENCODED.get().map_or(&[][..], Vec::as_slice);
            if contains(block, PLAINTEXT) || contains(block, encoded) {
                FOUND.store(true, Ordering::SeqCst);
            }
        }
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static ALLOCATOR: Scanning = Scanning;

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

fn exchange(socket: &std::path::Path, line: &str) -> String {
    let mut stream = UnixStream::connect(socket).expect("connect");
    stream.write_all(line.as_bytes()).expect("write request");
    let mut reply = String::new();
    BufReader::new(stream)
        .read_line(&mut reply)
        .expect("read reply");
    reply
}

#[test]
fn a_password_in_a_request_leaves_no_copy_in_freed_memory() {
    let encoded = ENCODED.get_or_init(|| STANDARD.encode(PLAINTEXT).into_bytes());
    let encoded = std::str::from_utf8(encoded).expect("base64 is ASCII");
    let backslash = '\u{5c}';

    // Built before arming, and kept until after: this side's copies are
    // the test's, not the daemon's.
    let lines = [
        format!(r#"{{"v":1,"op":"unlock","db":"absent","password":"{encoded}"}}"#),
        // Refused for its escape, which must not cost a copy either.
        format!(r#"{{"v":1,"op":"unlock","db":"absent","password":"{encoded}{backslash}/"}}"#),
    ]
    .map(|line| line + "\n");

    let dir = tempfile::tempdir().expect("tempdir");
    let socket = dir.path().join("sock");
    let listener = UnixListener::bind(&socket).expect("bind");
    let daemon = Arc::new(Server::new(Config::parse("").expect("empty config")));
    std::thread::spawn(move || server::serve(daemon, listener));

    // `serve` answers only once its own startup allocations are done.
    let deadline = Instant::now() + Duration::from_secs(5);
    while !exchange(&socket, "{\"v\":1,\"op\":\"status\"}\n").contains("\"ok\":true") {
        assert!(Instant::now() < deadline, "the daemon never answered");
        std::thread::sleep(Duration::from_millis(20));
    }

    ARMED.store(true, Ordering::SeqCst);
    // The daemon wipes the request before it writes the reply, so once a
    // reply is in, every free that could hold the password has happened.
    let replies = lines.each_ref().map(|line| exchange(&socket, line));
    ARMED.store(false, Ordering::SeqCst);

    assert!(replies[0].contains("unknown_db"), "{}", replies[0]);
    assert!(replies[1].contains("malformed_request"), "{}", replies[1]);
    assert!(
        !FOUND.load(Ordering::SeqCst),
        "a freed block still held the password"
    );
}
