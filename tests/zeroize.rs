//! A password sent in an `unlock` request leaves no unwiped copy behind in
//! the daemon's heap: not of the request line, which holds it as base64,
//! and not of the password itself once decoded. Nor in the CLI's own heap,
//! on the way out: not in the line `proto::encode_request` builds for
//! `send_request` to write.
//!
//! Checked with a global allocator that, while armed, looks through every
//! block as it is freed (reallocations included) for either form. It has
//! to be its own test binary, since the allocator is process-wide, and the
//! daemon-side test runs `server::serve` in-process so its frees go
//! through it too.
//!
//! The two tests below share `ARMED`/`FOUND` and must not run at the same
//! time — `ARM_LOCK` serializes them against the test harness's own
//! threads.
//!
//! The daemon-side request names a database that isn't configured, so the
//! password is decoded and then dropped unused: what `keepass` does with a
//! password it is given is upstream's (`docs/design.md` § Memory).

use std::alloc::{GlobalAlloc, Layout, System};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use kpa::config::Config;
use kpa::proto::{self, Op, Password, Request, UnlockRequest};
use kpa::server::{self, Server};
use zeroize::Zeroizing;

const PLAINTEXT: &[u8] = b"kpa-zeroize-canary-7c1e9a4f";

static ENCODED: OnceLock<Vec<u8>> = OnceLock::new();
static ARMED: AtomicBool = AtomicBool::new(false);
static FOUND: AtomicBool = AtomicBool::new(false);

/// This binary's second canary, for the CLI-side test below: longer than
/// `serde_json::to_string`'s 128-byte initial buffer (even after base64 and
/// the request's JSON wrapper stay under it, the naive encoding this
/// replaces would never reallocate, and the bug would still go undetected
/// for a short-enough password), so the growing-`Vec` case the fix avoids
/// is actually exercised. Built once at runtime rather than a `const`, so
/// it can be assembled by repeating a short, recognizable pattern.
static REQUEST_PLAINTEXT: OnceLock<Vec<u8>> = OnceLock::new();
static REQUEST_ENCODED: OnceLock<Vec<u8>> = OnceLock::new();

/// Held for the body of every test that arms [`Scanning`], so the two
/// below never run concurrently on the test harness's own threads.
static ARM_LOCK: Mutex<()> = Mutex::new(());

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
            let request_plaintext = REQUEST_PLAINTEXT.get().map_or(&[][..], Vec::as_slice);
            let request_encoded = REQUEST_ENCODED.get().map_or(&[][..], Vec::as_slice);
            if contains(block, PLAINTEXT)
                || contains(block, encoded)
                || contains(block, request_plaintext)
                || contains(block, request_encoded)
            {
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
    let _guard = ARM_LOCK.lock().unwrap_or_else(|e| e.into_inner());
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

/// `proto::encode_request` (F-02): an `unlock` carrying the master
/// password, encoded for `send_request` to write, leaves no unwiped copy
/// behind — neither the password's base64 nor its plaintext.
///
/// Includes the control the finding was filed with: `serde_json::to_string`
/// (what `send_request` used before the fix) copies the base64 into a
/// plain `String` that is freed unwiped. If `encode_request` ever went back
/// to that, this test would fail on its second half the same way the
/// control fails on its first.
#[test]
fn encoding_an_unlock_request_leaves_no_copy_in_freed_memory() {
    let _guard = ARM_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let plaintext = REQUEST_PLAINTEXT.get_or_init(|| b"kpa-zeroize-canary-f02-9d4a1b-".repeat(8));
    let plaintext = String::from_utf8(plaintext.clone()).expect("canary is UTF-8");
    REQUEST_ENCODED.get_or_init(|| STANDARD.encode(&plaintext).into_bytes());

    let request = || Request {
        v: proto::VERSION,
        op: Op::Unlock(UnlockRequest {
            db: "personal".to_string(),
            password: Some(Password::new(Zeroizing::new(plaintext.clone()))),
        }),
    };

    // Control: the behaviour `encode_request` replaces. `serde_json::to_string`
    // builds an ordinary `String` around the password's base64 that is
    // freed without being wiped (F-02 as filed).
    FOUND.store(false, Ordering::SeqCst);
    ARMED.store(true, Ordering::SeqCst);
    let text = serde_json::to_string(&request()).expect("request serializes");
    drop(text);
    drop(request());
    drop(vec![0u8; 4096]);
    ARMED.store(false, Ordering::SeqCst);
    assert!(
        FOUND.load(Ordering::SeqCst),
        "control: serde_json::to_string should leave an unwiped copy behind"
    );

    // The fix: `encode_request` measures, then fills a `Zeroizing` buffer
    // allocated at exactly that size, so nothing is freed unwiped.
    FOUND.store(false, Ordering::SeqCst);
    ARMED.store(true, Ordering::SeqCst);
    let line = proto::encode_request(&request()).expect("request encodes");
    drop(line);
    drop(request());
    drop(vec![0u8; 4096]);
    ARMED.store(false, Ordering::SeqCst);
    assert!(
        !FOUND.load(Ordering::SeqCst),
        "a freed block still held the request's password"
    );
}
