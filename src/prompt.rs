//! Runs a dmenu-style prompt program and reads its answer: `unlock`'s
//! password prompt today (`docs/design.md` decision #9, `Config::prompt`),
//! and, once it exists, the SSH agent's approval prompt
//! (`ssh_agent.confirm_prompt`, same contract — `docs/ssh-agent.md` § 6.7).
//! Both callers go through `run_prompt`, queued through a shared
//! `PromptQueue` so only one prompt is ever on screen at a time.
//!
//! The prompt program's argv runs exactly as configured; what the prompt is
//! about reaches it through the `KPA_PROMPT_MESSAGE` environment variable
//! instead (`docs/ssh-agent.md` § 6.6).

use std::collections::VecDeque;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use zeroize::Zeroizing;

use crate::proto::MAX_PASSWORD_LEN;

/// How a prompt ended. `T` is what an answered prompt yields: a
/// [`Zeroizing`] password from [`run_prompt`], the chosen line from
/// [`run_choice_prompt`].
pub(crate) enum PromptOutcome<T> {
    /// The command exited unsuccessfully — e.g. the user dismissed a
    /// dmenu-style prompt — rather than printing an answer.
    Cancelled,
    /// Nothing was entered within `prompt_timeout`; the prompt was killed.
    TimedOut,
    /// A lock ended the prompt (`Slot::prompt_cancel`); it was killed, or —
    /// if it was still queued, never shown at all (`PromptQueue::enter`).
    Interrupted,
    Answer(T),
}

pub(crate) type PasswordOutcome = PromptOutcome<Zeroizing<String>>;

impl<T> PromptOutcome<T> {
    fn map<U>(self, f: impl FnOnce(T) -> U) -> PromptOutcome<U> {
        match self {
            PromptOutcome::Cancelled => PromptOutcome::Cancelled,
            PromptOutcome::TimedOut => PromptOutcome::TimedOut,
            PromptOutcome::Interrupted => PromptOutcome::Interrupted,
            PromptOutcome::Answer(answer) => PromptOutcome::Answer(f(answer)),
        }
    }
}

/// Redacts the answer, same reasoning as `UnlockRequest`'s own `Debug`
/// (`docs/headless.md` § 9): this is cheap insurance against it ending up
/// in a test failure message or a future `{:?}` log line.
impl<T> std::fmt::Debug for PromptOutcome<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PromptOutcome::Cancelled => write!(f, "Cancelled"),
            PromptOutcome::TimedOut => write!(f, "TimedOut"),
            PromptOutcome::Interrupted => write!(f, "Interrupted"),
            PromptOutcome::Answer(_) => write!(f, "Answer(_)"),
        }
    }
}

/// Longest prompt message kept (`docs/ssh-agent.md` § 6.6, § 6.7):
/// generous for "Unlock personal" and for the key names and destinations a
/// later approval prompt adds, short enough that a hostile database or
/// entry name can't hand the prompt program an unbounded argv element.
const MAX_PROMPT_MESSAGE_LEN: usize = 256;

/// Turns `text` into what a prompt program may safely be asked to render:
/// the same escaping the CLI applies to its own terminal output
/// (`output::escape_for_terminal`, since a prompt can show the same
/// hostile characters a terminal would act on — bidi overrides and the
/// like), capped at `MAX_PROMPT_MESSAGE_LEN` bytes on a character
/// boundary. Every message `unlock` and, later, an approval prompt builds
/// goes through here before it reaches `run_prompt`.
pub(crate) fn prompt_message(text: &str) -> String {
    let escaped = crate::output::escape_for_terminal(text);
    let mut end = escaped.len().min(MAX_PROMPT_MESSAGE_LEN);
    while !escaped.is_char_boundary(end) {
        end -= 1;
    }
    escaped[..end].to_string()
}

/// The environment variable `run_prompt` sets to what the prompt is about
/// (`docs/design.md` § Configuration, `docs/ssh-agent.md` § 6.6). A prompt
/// program that wants it reads the variable directly; one that only takes
/// its prompt text as an argument needs a wrapper script that reads the
/// variable and passes it on, e.g.
/// `["sh", "-c", "exec fuzzel --dmenu --prompt \"$KPA_PROMPT_MESSAGE\""]`.
/// Either way the argv itself runs exactly as configured — kpa never
/// rewrites it.
const PROMPT_MESSAGE_ENV: &str = "KPA_PROMPT_MESSAGE";

#[derive(Default)]
struct PromptQueueState {
    /// Something is running, or has just been released to run next.
    /// `false` means the next `enter` runs immediately.
    busy: bool,
    /// Ticket numbers handed out by `enter`, used only so a cancelling
    /// waiter can find and remove its own entry below.
    next_ticket: u64,
    /// FIFO of waiters behind whoever is running, each with the write end
    /// `release` closes to wake it: its `enter` poll sees the read end
    /// hang up.
    waiting: VecDeque<(u64, UnixStream)>,
}

/// Serializes every prompt across every database, so only one is ever on
/// screen (`docs/ssh-agent.md` § 6.7's "only one prompt is on screen at a
/// time"). `unlock`'s password prompt is the only caller today; the
/// approval prompt `ssh_agent.confirm_prompt` raises will share this same
/// queue once it exists.
pub(crate) struct PromptQueue {
    state: Mutex<PromptQueueState>,
}

impl PromptQueue {
    pub(crate) fn new() -> PromptQueue {
        PromptQueue {
            state: Mutex::new(PromptQueueState::default()),
        }
    }

    /// Blocks until either this call's turn comes up (`Ok(Some(turn))`,
    /// released by dropping it) or `cancel_watch` hangs up first — a lock
    /// ending a prompt that was still queued, never shown (`Ok(None)`).
    ///
    /// A ticket that wins the queue-empty race in `release` (it already
    /// popped this entry just as `cancel_watch` also hung up) still comes
    /// back `Some`: once `release` has committed to treating a ticket as
    /// the next to run, something must eventually call `release` again on
    /// its behalf, which only a `PromptTurn` does. Resolving that only
    /// under `state`'s lock — the same lock `release` pops under — is what
    /// keeps the two from disagreeing about which ticket is still queued.
    fn enter(&self, cancel_watch: &UnixStream) -> std::io::Result<Option<PromptTurn<'_>>> {
        // The busy check and, if it's already taken, joining the queue
        // happen under one lock hold: splitting them would let a release
        // between the two find the queue empty and clear `busy` before
        // this ticket ever gets into it, stranding it forever.
        let (ticket, watch) = {
            let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
            if !state.busy {
                state.busy = true;
                return Ok(Some(PromptTurn { queue: self }));
            }
            let (writer, watch) = UnixStream::pair()?;
            let ticket = state.next_ticket;
            state.next_ticket = state.next_ticket.wrapping_add(1);
            state.waiting.push_back((ticket, writer));
            (ticket, watch)
        };
        match wait_for_wake(&watch, cancel_watch)? {
            Wake::Turn => Ok(Some(PromptTurn { queue: self })),
            Wake::Cancel => {
                let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
                if let Some(pos) = state.waiting.iter().position(|(t, _)| *t == ticket) {
                    state.waiting.remove(pos);
                    return Ok(None);
                }
                // `release` already popped this ticket — see the doc
                // comment above.
                Ok(Some(PromptTurn { queue: self }))
            }
        }
    }

    /// Wakes the next waiter, or marks the queue idle once none are left.
    fn release(&self) {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        match state.waiting.pop_front() {
            None => state.busy = false,
            Some((_ticket, notify)) => drop(notify), // closing it wakes the waiter; `busy` stays set
        }
    }
}

/// Holds `PromptQueue`'s one running slot; releases it on drop, so every
/// return from `run_prompt` — success, timeout, interruption, or an I/O
/// error — lets the next queued prompt proceed.
struct PromptTurn<'a> {
    queue: &'a PromptQueue,
}

impl Drop for PromptTurn<'_> {
    fn drop(&mut self) {
        self.queue.release();
    }
}

enum Wake {
    /// `watch`'s write end closed: `release` has handed this ticket the
    /// turn.
    Turn,
    /// `cancel_watch` hung up before `watch` did.
    Cancel,
}

/// Blocks until `watch` or `cancel_watch` hangs up, whichever comes first.
fn wait_for_wake(watch: &UnixStream, cancel_watch: &UnixStream) -> std::io::Result<Wake> {
    use rustix::event::{PollFd, PollFlags, poll};

    loop {
        let mut fds = [
            PollFd::new(watch, PollFlags::IN),
            PollFd::new(cancel_watch, PollFlags::IN),
        ];
        match poll(&mut fds, None) {
            Ok(_) => {}
            Err(rustix::io::Errno::INTR) => continue,
            Err(err) => return Err(err.into()),
        }
        if !fds[0].revents().is_empty() {
            return Ok(Wake::Turn);
        }
        if !fds[1].revents().is_empty() {
            return Ok(Wake::Cancel);
        }
    }
}

/// Runs `argv` as a prompt (`docs/design.md` decision #9), queued through
/// `queue` so only one is ever on screen, and reads its answer from
/// stdout. The argv runs exactly as configured; `message` (already escaped
/// and length-capped by `prompt_message`) reaches the program through the
/// `PROMPT_MESSAGE_ENV` environment variable instead. `stdin`, when given,
/// is written before anything is read — the approval prompt
/// `ssh_agent.confirm_prompt` raises writes its `Allow`/`Deny` choices this
/// way; `unlock`'s password prompt passes `None`.
///
/// The prompt runs in its own process group. It is killed, with everything
/// it started, once `timeout` passes without it finishing, or as soon as
/// the other end of `cancel_watch` is dropped. A prompt still queued when
/// that happens is never spawned at all.
///
/// The output is read into a zeroizing buffer of fixed size that never
/// grows. That's the point: `Command::output()` collects into a `Vec` that
/// reallocates as it fills, and every reallocation frees an unwiped copy of
/// what it held so far — for a long passphrase, most of it survived both
/// unlock and lock (`docs/review-2026-09-secrets.md` finding 1). Output
/// longer than `MAX_PASSWORD_LEN` is refused rather than accommodated.
///
/// Trailing `\n`/`\r` are stripped, since dmenu-style prompts
/// newline-terminate their output. The copies kpa can't reach are the ones
/// inside the prompt program itself.
pub(crate) fn run_prompt(
    queue: &PromptQueue,
    argv: &[String],
    message: &str,
    timeout: Duration,
    cancel_watch: &UnixStream,
) -> std::io::Result<PasswordOutcome> {
    run(queue, argv, message, timeout, cancel_watch, None)
}

/// Same contract as [`run_prompt`] for a prompt that picks one of
/// `choices`: they're written to the program's stdin, one per line, and the
/// line it prints is the answer. The answer is whatever the program printed;
/// callers compare it against the choices they offered.
pub(crate) fn run_choice_prompt(
    queue: &PromptQueue,
    argv: &[String],
    message: &str,
    timeout: Duration,
    cancel_watch: &UnixStream,
    choices: &[&str],
) -> std::io::Result<PromptOutcome<String>> {
    let stdin: String = choices.iter().map(|choice| format!("{choice}\n")).collect();
    let outcome = run(
        queue,
        argv,
        message,
        timeout,
        cancel_watch,
        Some(stdin.as_bytes()),
    )?;
    Ok(outcome.map(|answer| answer.as_str().to_owned()))
}

fn run(
    queue: &PromptQueue,
    argv: &[String],
    message: &str,
    timeout: Duration,
    cancel_watch: &UnixStream,
    stdin: Option<&[u8]>,
) -> std::io::Result<PasswordOutcome> {
    use std::io::{Error, ErrorKind};

    let Some((program, args)) = argv.split_first() else {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            "prompt command is empty",
        ));
    };

    let Some(turn) = queue.enter(cancel_watch)? else {
        return Ok(PromptOutcome::Interrupted);
    };
    let result = spawn_and_read(
        program.as_str(),
        args,
        message,
        timeout,
        cancel_watch,
        stdin,
    );
    drop(turn); // release the screen as soon as this prompt is done with it
    result
}

/// The actual spawn-and-read behind `run_prompt`, split out so `run_prompt`
/// can drop its `PromptTurn` on every path through here without repeating
/// itself at each return.
fn spawn_and_read(
    program: &str,
    args: &[String],
    message: &str,
    timeout: Duration,
    cancel_watch: &UnixStream,
    stdin: Option<&[u8]>,
) -> std::io::Result<PasswordOutcome> {
    use std::io::{Error, ErrorKind};
    use std::os::unix::process::CommandExt;

    // `None` for a timeout too large to add: a deadline that never arrives.
    let deadline = Instant::now().checked_add(timeout);
    let mut child = Command::new(program)
        .args(args)
        .env(PROMPT_MESSAGE_ENV, message)
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        // Its own process group, so `kill_prompt` can kill everything it
        // started too, such as a wrapper script's real prompt window.
        .process_group(0)
        .spawn()?;

    if let Some(bytes) = stdin {
        // A choice prompt's whole input is a few short lines — small enough that this never blocks waiting
        // for the child to start reading.
        if let Some(mut child_stdin) = child.stdin.take() {
            let _ = child_stdin.write_all(bytes);
        }
    }

    let mut buf = Zeroizing::new(vec![0u8; MAX_PASSWORD_LEN]);
    let len = match read_prompt(&mut child, &mut buf, deadline, cancel_watch) {
        Ok(Ok(len)) => len,
        Ok(Err(ended)) => {
            kill_prompt(&mut child);
            return Ok(ended);
        }
        Err(err) => {
            kill_prompt(&mut child);
            return Err(err);
        }
    };

    if !child.wait()?.success() {
        return Ok(PromptOutcome::Cancelled);
    }

    let mut end = len;
    while end > 0 && matches!(buf[end - 1], b'\n' | b'\r') {
        end -= 1;
    }
    let text = std::str::from_utf8(&buf[..end])
        .map_err(|_| Error::new(ErrorKind::InvalidData, "prompt output is not valid UTF-8"))?;

    // Sized exactly, so `push_str` doesn't reallocate either.
    let mut password = Zeroizing::new(String::with_capacity(text.len()));
    password.push_str(text);
    Ok(PromptOutcome::Answer(password))
}

/// Read the child's stdout into `buf` until EOF, returning how much was
/// read. Errors rather than growing when `buf` fills up. Stops early with
/// `TimedOut` at `deadline`, or `Interrupted` once `cancel_watch` is readable or
/// hung up: either beats the output, so a lock wins over a prompt that
/// answers at the same moment.
fn read_prompt(
    child: &mut Child,
    buf: &mut [u8],
    deadline: Option<Instant>,
    cancel_watch: &UnixStream,
) -> std::io::Result<Result<usize, PasswordOutcome>> {
    use rustix::event::{PollFd, PollFlags, Timespec, poll};
    use std::io::{Error, ErrorKind};

    let mut stdout = child
        .stdout
        .take()
        .ok_or_else(|| Error::other("prompt stdout was not captured"))?;
    let mut len = 0;
    loop {
        if len == buf.len() {
            return Err(Error::new(
                ErrorKind::InvalidData,
                format!("prompt output exceeds {MAX_PASSWORD_LEN} bytes"),
            ));
        }
        let left = match deadline {
            Some(deadline) => {
                let left = deadline.saturating_duration_since(Instant::now());
                if left.is_zero() {
                    return Ok(Err(PromptOutcome::TimedOut));
                }
                Some(Timespec {
                    tv_sec: left.as_secs().try_into().unwrap_or(i64::MAX),
                    tv_nsec: left.subsec_nanos().into(),
                })
            }
            None => None,
        };
        let (output, cancelled) = {
            let mut fds = [
                PollFd::new(&stdout, PollFlags::IN),
                PollFd::new(cancel_watch, PollFlags::IN),
            ];
            match poll(&mut fds, left.as_ref()) {
                Ok(_) => {}
                // A signal interrupted the wait: wait again, for the time
                // left until the same `deadline`.
                Err(rustix::io::Errno::INTR) => continue,
                Err(err) => return Err(err.into()),
            }
            (!fds[0].revents().is_empty(), !fds[1].revents().is_empty())
        };
        if cancelled {
            return Ok(Err(PromptOutcome::Interrupted));
        }
        if !output {
            continue;
        }
        match stdout.read(&mut buf[len..]) {
            Ok(0) => return Ok(Ok(len)),
            Ok(n) => len += n,
            Err(err) if err.kind() == ErrorKind::Interrupted => {}
            Err(err) => return Err(err),
        }
    }
}

/// Kill the prompt's whole process group, so a wrapper's own prompt window
/// goes too, then reap the prompt. The group is signalled before the reap:
/// until then the prompt holds the group's id, so the signal can't reach a
/// recycled one.
fn kill_prompt(child: &mut Child) {
    use rustix::process::{Pid, Signal, kill_process_group};

    if let Some(pid) = i32::try_from(child.id()).ok().and_then(Pid::from_raw) {
        let _ = kill_process_group(pid, Signal::KILL);
    }
    let _ = child.wait();
}

/// Held by every test that spawns a process — here, and in `server`'s own
/// tests that unlock through a scripted prompt — and by the one that needs
/// a socket to be genuinely dead. Spawning a child briefly duplicates
/// every open file descriptor into it until it execs; if a prompt test
/// forks at the wrong moment, a "stale" socket elsewhere is still held
/// open by that child, and `socket::bind_socket` rightly refuses to delete
/// a socket that's still live.
#[cfg(test)]
static SPAWN_LOCK: Mutex<()> = Mutex::new(());

#[cfg(test)]
pub(crate) fn spawn_lock() -> std::sync::MutexGuard<'static, ()> {
    SPAWN_LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sh(script: &str) -> Vec<String> {
        vec!["/bin/sh".into(), "-c".into(), script.into()]
    }

    /// Runs `script` as the prompt, with a timeout long enough never to
    /// fire, nobody to cancel it, a queue of its own, and an arbitrary
    /// message — these tests don't care what it is.
    fn prompt(script: &str) -> std::io::Result<PasswordOutcome> {
        let (_prompt_cancel, cancel_watch) = UnixStream::pair().expect("socket pair");
        run_prompt(
            &PromptQueue::new(),
            &sh(script),
            "test message",
            Duration::from_secs(60),
            &cancel_watch,
        )
    }

    #[test]
    fn a_choice_prompt_gets_the_choices_on_stdin_and_returns_the_chosen_line() {
        let _spawning = spawn_lock();
        let (_prompt_cancel, cancel_watch) = UnixStream::pair().expect("socket pair");
        let outcome = run_choice_prompt(
            &PromptQueue::new(),
            &sh("sed -n 2p"),
            "test message",
            Duration::from_secs(60),
            &cancel_watch,
            &["Allow", "Deny"],
        );
        assert!(matches!(outcome, Ok(PromptOutcome::Answer(choice)) if choice == "Deny"));
    }

    #[test]
    fn prompt_output_has_its_line_ending_stripped() {
        let _spawning = spawn_lock();
        let Ok(PromptOutcome::Answer(password)) = prompt("printf 'hunter2\\r\\n'") else {
            panic!("expected a password");
        };
        assert_eq!(password.as_str(), "hunter2");
    }

    #[test]
    fn a_failing_prompt_is_a_cancellation() {
        let _spawning = spawn_lock();
        assert!(matches!(prompt("exit 1"), Ok(PromptOutcome::Cancelled)));
    }

    /// The buffer never grows, so over-long output is an error rather than
    /// a reallocation that would strand an unwiped copy.
    #[test]
    fn over_long_prompt_output_is_refused() {
        let _spawning = spawn_lock();
        let script = format!("head -c {} /dev/zero | tr '\\0' a", MAX_PASSWORD_LEN + 1);
        assert!(prompt(&script).is_err());
    }

    #[test]
    fn an_unanswered_prompt_times_out() {
        let _spawning = spawn_lock();
        let (_prompt_cancel, cancel_watch) = UnixStream::pair().expect("socket pair");
        let started = Instant::now();
        let outcome = run_prompt(
            &PromptQueue::new(),
            &sh("sleep 30; printf hunter2"),
            "test message",
            Duration::from_millis(200),
            &cancel_watch,
        );
        assert!(matches!(outcome, Ok(PromptOutcome::TimedOut)));
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    #[test]
    fn dropping_the_cancel_end_interrupts_the_prompt() {
        let _spawning = spawn_lock();
        let (prompt_cancel, cancel_watch) = UnixStream::pair().expect("socket pair");
        let started = Instant::now();
        let outcome = std::thread::scope(|scope| {
            scope.spawn(move || {
                std::thread::sleep(Duration::from_millis(200));
                drop(prompt_cancel);
            });
            run_prompt(
                &PromptQueue::new(),
                &sh("sleep 30; printf hunter2"),
                "test message",
                Duration::from_secs(60),
                &cancel_watch,
            )
        });
        assert!(matches!(outcome, Ok(PromptOutcome::Interrupted)));
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    /// A prompt can be a wrapper that starts the real prompt window. Ending
    /// the prompt ends what it started too, so no window stays on screen.
    #[test]
    fn ending_a_prompt_kills_what_it_started() {
        let _spawning = spawn_lock();
        let dir = tempfile::tempdir().expect("tempdir");
        let marker = dir.path().join("survived");
        let script = format!("(sleep 1; touch '{}') & sleep 30", marker.display());
        let (_prompt_cancel, cancel_watch) = UnixStream::pair().expect("socket pair");
        let outcome = run_prompt(
            &PromptQueue::new(),
            &sh(&script),
            "test message",
            Duration::from_millis(200),
            &cancel_watch,
        );
        assert!(matches!(outcome, Ok(PromptOutcome::TimedOut)));
        std::thread::sleep(Duration::from_millis(1500));
        assert!(!marker.exists(), "the prompt's child outlived it");
    }

    /// `run_prompt` passes the message through the environment rather than
    /// touching the argv: a prompt that reads `KPA_PROMPT_MESSAGE` sees it
    /// verbatim, escaped and capped exactly as `prompt_message` left it.
    #[test]
    fn the_message_reaches_the_prompt_as_an_environment_variable() {
        let _spawning = spawn_lock();
        let (_prompt_cancel, cancel_watch) = UnixStream::pair().expect("socket pair");
        let outcome = run_prompt(
            &PromptQueue::new(),
            &sh(&format!("printf %s \"${PROMPT_MESSAGE_ENV}\"")),
            "Unlock personal",
            Duration::from_secs(60),
            &cancel_watch,
        );
        let Ok(PromptOutcome::Answer(seen)) = outcome else {
            panic!("expected the message back, got {outcome:?}");
        };
        assert_eq!(seen.as_str(), "Unlock personal");
    }

    /// The argv runs exactly as configured: nothing in it is rewritten,
    /// even text that looks like it could have been a placeholder.
    #[test]
    fn the_prompt_argv_is_never_rewritten() {
        let _spawning = spawn_lock();
        let (_prompt_cancel, cancel_watch) = UnixStream::pair().expect("socket pair");
        let outcome = run_prompt(
            &PromptQueue::new(),
            &sh("printf %s '{message} literally'"),
            "Unlock personal",
            Duration::from_secs(60),
            &cancel_watch,
        );
        let Ok(PromptOutcome::Answer(seen)) = outcome else {
            panic!("expected a password, got {outcome:?}");
        };
        assert_eq!(seen.as_str(), "{message} literally");
    }

    #[test]
    fn prompt_message_escapes_hostile_characters() {
        let message = prompt_message("Unlock personal\u{202e}evil");
        assert!(!message.contains('\u{202e}'), "{message:?}");
        assert!(message.contains("\\u202e"), "{message:?}");
    }

    #[test]
    fn prompt_message_caps_its_length_on_a_char_boundary() {
        // "é" is two bytes, so the cap lands mid-character unless
        // `prompt_message` backs off to the nearest boundary.
        let long = "é".repeat(MAX_PROMPT_MESSAGE_LEN);
        let message = prompt_message(&long);
        assert!(message.len() <= MAX_PROMPT_MESSAGE_LEN);
        assert!(std::str::from_utf8(message.as_bytes()).is_ok());
    }

    /// Two unlocks of different databases never show their prompts at
    /// once: the second's `run_prompt` waits for the first's to finish.
    #[test]
    fn only_one_prompt_at_a_time_across_a_shared_queue() {
        let _spawning = spawn_lock();
        let dir = tempfile::tempdir().expect("tempdir");
        let marker = dir.path().join("marker");
        let overlap = dir.path().join("overlap");
        // Fails (and records an overlap) if another run is already
        // holding `marker` when this one starts.
        let script = format!(
            "if [ -e '{marker}' ]; then touch '{overlap}'; exit 1; fi; \
             touch '{marker}'; sleep 0.3; rm -f '{marker}'; printf ok",
            marker = marker.display(),
            overlap = overlap.display(),
        );
        let queue = PromptQueue::new();
        let (_cancel_a, watch_a) = UnixStream::pair().expect("socket pair");
        let (_cancel_b, watch_b) = UnixStream::pair().expect("socket pair");

        let (first, second) = std::thread::scope(|scope| {
            let first = scope
                .spawn(|| run_prompt(&queue, &sh(&script), "a", Duration::from_secs(10), &watch_a));
            std::thread::sleep(Duration::from_millis(50));
            let second = scope
                .spawn(|| run_prompt(&queue, &sh(&script), "b", Duration::from_secs(10), &watch_b));
            (
                first.join().expect("first prompt thread panicked"),
                second.join().expect("second prompt thread panicked"),
            )
        });

        assert!(matches!(first, Ok(PromptOutcome::Answer(_))), "{first:?}");
        assert!(matches!(second, Ok(PromptOutcome::Answer(_))), "{second:?}");
        assert!(!overlap.exists(), "both prompts were on screen at once");
    }

    /// A prompt that never got the screen — still waiting its turn behind
    /// another one — is cancelled the instant its own `cancel_watch` hangs
    /// up, without waiting for its turn to come up.
    #[test]
    fn a_queued_prompt_is_cancelled_without_ever_being_shown() {
        let _spawning = spawn_lock();
        let dir = tempfile::tempdir().expect("tempdir");
        let marker = dir.path().join("second-ran");
        let second_script = sh(&format!("touch '{}'; printf ok", marker.display()));
        let queue = PromptQueue::new();
        let (_cancel_first, watch_first) = UnixStream::pair().expect("socket pair");
        let (cancel_second, watch_second) = UnixStream::pair().expect("socket pair");

        let (first, second) = std::thread::scope(|scope| {
            // Holds the queue's one slot for long enough that the second
            // call below is still waiting when it gets cancelled.
            let first = scope.spawn(|| {
                run_prompt(
                    &queue,
                    &sh("sleep 1; printf ok"),
                    "first",
                    Duration::from_secs(10),
                    &watch_first,
                )
            });
            std::thread::sleep(Duration::from_millis(100));
            let second = scope.spawn(|| {
                run_prompt(
                    &queue,
                    &second_script,
                    "second",
                    Duration::from_secs(10),
                    &watch_second,
                )
            });
            std::thread::sleep(Duration::from_millis(100));
            let cancelled_at = Instant::now();
            drop(cancel_second);
            let second = second.join().expect("second prompt thread panicked");
            assert!(
                cancelled_at.elapsed() < Duration::from_millis(900),
                "the queued prompt waited for its turn instead of being cancelled"
            );
            (first.join().expect("first prompt thread panicked"), second)
        });

        assert!(matches!(first, Ok(PromptOutcome::Answer(_))), "{first:?}");
        assert!(
            matches!(second, Ok(PromptOutcome::Interrupted)),
            "{second:?}"
        );
        assert!(!marker.exists(), "a cancelled, still-queued prompt ran");
    }
}
