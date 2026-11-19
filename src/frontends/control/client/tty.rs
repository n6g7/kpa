//! The CLI's terminal: the controlling terminal `kpa unlock` passes to the
//! daemon to ask for the master password on, and what an interrupt does
//! while the daemon is asking (`docs/headless.md` § 4). The CLI never reads
//! the password itself. No socket or protocol code — `client/mod.rs` calls these
//! and handles the request.

use std::fs::{File, OpenOptions};
use std::io;
use std::net::Shutdown;
use std::os::unix::net::UnixStream;
use std::thread;
use std::time::Duration;

/// The signals a terminal sends to the job in its foreground, or on hanging
/// up: `^C`, `^Z` and the hang-up of the terminal's own session.
const INTERRUPTS: [libc::c_int; 3] = [libc::SIGINT, libc::SIGTSTP, libc::SIGHUP];

/// How long an interrupted CLI waits for the daemon to put the terminal back
/// and close the connection before it exits anyway. The daemon does so within
/// the next wake-up of its prompt, a few milliseconds; this is an estimate of
/// how long to wait for one that is busy, not a measured bound. Where the
/// daemon is asking on screen it takes no notice of the interrupt, and the
/// CLI lingers this long after `^C`.
const DAEMON_CLOSE_WAIT: Duration = Duration::from_secs(2);

/// This process's controlling terminal, opened for reading and writing, or
/// `None` where it has none (a cron job) or can't open it. Redirecting stdin
/// or stdout doesn't change which terminal this is.
pub(super) fn controlling_terminal() -> Option<File> {
    OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .ok()
}

/// From now on `^C`, `^Z` and a terminal hang-up don't end this process at
/// once: they shut the write side of `connection` and wait for the daemon to
/// close it. A daemon asking for the password on the terminal this process
/// passed it sees the shutdown, stops reading and puts the terminal's modes
/// back. Exiting first would hand the terminal to the shell while the daemon
/// still reads from it, and then restores modes the shell has changed since.
///
/// The signals stay blocked for the rest of the process. A thread waits for
/// one and exits the process with its signal's usual status
/// ([`DAEMON_CLOSE_WAIT`] later at the latest), unless the response has come
/// and the process has ended by then.
pub(super) fn end_on_interrupt(connection: &UnixStream) -> io::Result<()> {
    let connection = connection.try_clone()?;
    // SAFETY: an all-zero `sigset_t` is a valid argument for `sigemptyset`,
    // which initializes it.
    let mut signals: libc::sigset_t = unsafe { std::mem::zeroed() };
    // SAFETY: `signals` is a live `sigset_t`, and `pthread_sigmask` only
    // reads it. It blocks the signals in this thread before the one spawned
    // below exists, so that thread starts with them blocked too, which
    // `sigwait` needs.
    let blocked = unsafe {
        libc::sigemptyset(&mut signals);
        for signal in INTERRUPTS {
            libc::sigaddset(&mut signals, signal);
        }
        libc::pthread_sigmask(libc::SIG_BLOCK, &signals, std::ptr::null_mut())
    };
    if blocked != 0 {
        return Err(io::Error::from_raw_os_error(blocked));
    }
    thread::Builder::new()
        .name("interrupts".to_string())
        .spawn(move || {
            let mut received: libc::c_int = 0;
            // SAFETY: `signals` is the live set blocked above, and `received`
            // a live `c_int` that `sigwait` writes.
            if unsafe { libc::sigwait(&signals, &mut received) } != 0 {
                return;
            }
            let _ = connection.shutdown(Shutdown::Write);
            thread::sleep(DAEMON_CLOSE_WAIT);
            std::process::exit(128 + received);
        })?;
    Ok(())
}
