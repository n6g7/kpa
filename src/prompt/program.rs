//! The external-program backend: runs a dmenu-style prompt program and
//! reads its answer. [`run_prompt`] returns what it printed;
//! [`run_approval_prompt`] offers it `Allow` and `Deny` and reads which it
//! chose.
//!
//! The prompt program's argv runs exactly as configured; what the prompt is
//! about reaches it through the `KPA_PROMPT_MESSAGE` environment variable
//! instead (`docs/ssh-agent.md` § 6.6).

use std::io::{Read, Write};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use zeroize::Zeroizing;

use super::message::prompt_message;
use super::{Approval, CancelWatch, PromptOutcome, PromptQueue};
use crate::proto::MAX_PASSWORD_LEN;

/// The longest answer read; one more byte is an error. An answer can be a
/// secret, so this is the secrets' length cap.
const MAX_ANSWER_LEN: usize = MAX_PASSWORD_LEN;

/// The environment variable a prompt program finds its message in
/// (`docs/design.md` § Configuration, `docs/ssh-agent.md` § 6.6). A prompt
/// program that wants it reads the variable directly; one that only takes
/// its prompt text as an argument needs a wrapper script that reads the
/// variable and passes it on, e.g.
/// `["sh", "-c", "exec fuzzel --dmenu --prompt \"$KPA_PROMPT_MESSAGE\""]`.
/// Either way the argv itself runs exactly as configured — kpa never
/// rewrites it.
const PROMPT_MESSAGE_ENV: &str = "KPA_PROMPT_MESSAGE";

/// What an approval prompt is offered, one choice per line.
const APPROVAL_CHOICES: &[u8] = b"Allow\nDeny\n";

/// Runs `argv` as a prompt (`docs/design.md` decision #9), queued through
/// `queue` so only one is ever on screen, and returns what it printed.
/// `message` is plain text: it is escaped and length-capped here, then
/// reaches the program through the `KPA_PROMPT_MESSAGE` environment
/// variable.
///
/// The prompt runs in its own process group. It is killed, with everything
/// it started, once `timeout` passes without it finishing, or as soon as
/// `cancel`'s `PromptCancel` is dropped. A prompt still queued when that
/// happens is never spawned at all.
///
/// The output is read into a zeroizing buffer of fixed size that never
/// grows. That's the point: `Command::output()` collects into a `Vec` that
/// reallocates as it fills, and every reallocation frees an unwiped copy of
/// what it held so far — for a long passphrase, most of it survived both
/// unlock and lock (`docs/review-2026-09-secrets.md` finding 1). Output
/// longer than `MAX_ANSWER_LEN` is refused rather than accommodated.
///
/// Trailing `\n`/`\r` are stripped, since dmenu-style prompts
/// newline-terminate their output. The copies kpa can't reach are the ones
/// inside the prompt program itself.
pub fn run_prompt(
    queue: &PromptQueue,
    argv: &[String],
    message: &str,
    timeout: Duration,
    cancel: &CancelWatch,
) -> std::io::Result<PromptOutcome> {
    run(queue, argv, message, timeout, cancel, None)
}

/// Runs `argv` as an approval prompt: `Allow` and `Deny` go to its stdin
/// one per line, and exactly `Allow` on stdout is [`Approval::Allow`];
/// anything else it prints is [`Approval::Deny`]. Otherwise as
/// [`run_prompt`].
pub fn run_approval_prompt(
    queue: &PromptQueue,
    argv: &[String],
    message: &str,
    timeout: Duration,
    cancel: &CancelWatch,
) -> std::io::Result<PromptOutcome<Approval>> {
    let outcome = run(
        queue,
        argv,
        message,
        timeout,
        cancel,
        Some(APPROVAL_CHOICES),
    )?;
    Ok(outcome.map(|answer| {
        if answer.as_str() == "Allow" {
            Approval::Allow
        } else {
            Approval::Deny
        }
    }))
}

/// Both prompts' shared body. `stdin`, when given, is written before
/// anything is read — a prompt that picks among choices gets them this
/// way, one per line.
fn run(
    queue: &PromptQueue,
    argv: &[String],
    message: &str,
    timeout: Duration,
    cancel: &CancelWatch,
    stdin: Option<&[u8]>,
) -> std::io::Result<PromptOutcome> {
    use std::io::{Error, ErrorKind};

    let Some((program, args)) = argv.split_first() else {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            "prompt command is empty",
        ));
    };
    let message = prompt_message(message);

    let Some(turn) = queue.enter(cancel)? else {
        return Ok(PromptOutcome::Interrupted);
    };
    let result = spawn_and_read(program.as_str(), args, &message, timeout, cancel, stdin);
    drop(turn); // release the screen as soon as this prompt is done with it
    result
}

/// The actual spawn-and-read behind `run`, split out so `run` can drop its
/// `PromptTurn` on every path through here without repeating itself at
/// each return.
fn spawn_and_read(
    program: &str,
    args: &[String],
    message: &str,
    timeout: Duration,
    cancel: &CancelWatch,
    stdin: Option<&[u8]>,
) -> std::io::Result<PromptOutcome> {
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
        // Choices are a few short lines — small enough that this never
        // blocks waiting for the child to start reading.
        if let Some(mut child_stdin) = child.stdin.take() {
            let _ = child_stdin.write_all(bytes);
        }
    }

    let mut buf = Zeroizing::new(vec![0u8; MAX_ANSWER_LEN]);
    let len = match read_prompt(&mut child, &mut buf, deadline, cancel) {
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
    let mut answer = Zeroizing::new(String::with_capacity(text.len()));
    answer.push_str(text);
    Ok(PromptOutcome::Answer(answer))
}

/// Read the child's stdout into `buf` until EOF, returning how much was
/// read. Errors rather than growing when `buf` fills up. Stops early with
/// `TimedOut` at `deadline`, or `Interrupted` once `cancel` is readable or
/// hung up: either beats the output, so a lock wins over a prompt that
/// answers at the same moment.
fn read_prompt(
    child: &mut Child,
    buf: &mut [u8],
    deadline: Option<Instant>,
    cancel: &CancelWatch,
) -> std::io::Result<Result<usize, PromptOutcome>> {
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
                format!("prompt output exceeds {MAX_ANSWER_LEN} bytes"),
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
                PollFd::from_borrowed_fd(cancel.fd(), PollFlags::IN),
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
static SPAWN_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(test)]
pub(crate) fn spawn_lock() -> std::sync::MutexGuard<'static, ()> {
    SPAWN_LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

#[cfg(test)]
mod tests {
    use super::super::cancel_pair;
    use super::*;

    fn sh(script: &str) -> Vec<String> {
        vec!["/bin/sh".into(), "-c".into(), script.into()]
    }

    /// Runs `script` as the prompt, with a timeout long enough never to
    /// fire, nobody to cancel it, a queue of its own, and an arbitrary
    /// message — these tests don't care what it is.
    fn prompt(script: &str) -> std::io::Result<PromptOutcome> {
        let (_cancel, watch) = cancel_pair().expect("cancel pair");
        run_prompt(
            &PromptQueue::new(),
            &sh(script),
            "test message",
            Duration::from_secs(60),
            &watch,
        )
    }

    fn approval(script: &str) -> std::io::Result<PromptOutcome<Approval>> {
        let (_cancel, watch) = cancel_pair().expect("cancel pair");
        run_approval_prompt(
            &PromptQueue::new(),
            &sh(script),
            "test message",
            Duration::from_secs(60),
            &watch,
        )
    }

    #[test]
    fn an_approval_prompt_allows_only_an_exact_allow() {
        let _spawning = spawn_lock();
        for (script, expected) in [
            ("sed -n 1p", Approval::Allow),
            ("sed -n 2p", Approval::Deny),
            ("echo allow", Approval::Deny),
            ("echo 'Allow now'", Approval::Deny),
        ] {
            assert!(
                matches!(approval(script), Ok(PromptOutcome::Answer(a)) if a == expected),
                "{script}"
            );
        }
        assert!(matches!(approval("exit 1"), Ok(PromptOutcome::Cancelled)));
    }

    #[test]
    fn a_prompt_gets_stdin_and_returns_the_line_it_prints() {
        let _spawning = spawn_lock();
        let (_cancel, watch) = cancel_pair().expect("cancel pair");
        let outcome = run(
            &PromptQueue::new(),
            &sh("sed -n 2p"),
            "test message",
            Duration::from_secs(60),
            &watch,
            Some(b"Allow\nDeny\n"),
        );
        assert!(matches!(outcome, Ok(PromptOutcome::Answer(answer)) if answer.as_str() == "Deny"));
    }

    #[test]
    fn prompt_output_has_its_line_ending_stripped() {
        let _spawning = spawn_lock();
        let Ok(PromptOutcome::Answer(answer)) = prompt("printf 'hunter2\\r\\n'") else {
            panic!("expected an answer");
        };
        assert_eq!(answer.as_str(), "hunter2");
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
        let script = format!("head -c {} /dev/zero | tr '\\0' a", MAX_ANSWER_LEN + 1);
        assert!(prompt(&script).is_err());
    }

    #[test]
    fn an_empty_command_is_an_error() {
        let (_cancel, watch) = cancel_pair().expect("cancel pair");
        let outcome = run_prompt(
            &PromptQueue::new(),
            &[],
            "test message",
            Duration::from_secs(60),
            &watch,
        );
        assert!(outcome.is_err());
    }

    #[test]
    fn an_unanswered_prompt_times_out() {
        let _spawning = spawn_lock();
        let (_cancel, watch) = cancel_pair().expect("cancel pair");
        let started = Instant::now();
        let outcome = run_prompt(
            &PromptQueue::new(),
            &sh("sleep 30; printf hunter2"),
            "test message",
            Duration::from_millis(200),
            &watch,
        );
        assert!(matches!(outcome, Ok(PromptOutcome::TimedOut)));
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    #[test]
    fn dropping_the_cancel_end_interrupts_the_prompt() {
        let _spawning = spawn_lock();
        let (cancel, watch) = cancel_pair().expect("cancel pair");
        let started = Instant::now();
        let outcome = std::thread::scope(|scope| {
            scope.spawn(move || {
                std::thread::sleep(Duration::from_millis(200));
                drop(cancel);
            });
            run_prompt(
                &PromptQueue::new(),
                &sh("sleep 30; printf hunter2"),
                "test message",
                Duration::from_secs(60),
                &watch,
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
        let (_cancel, watch) = cancel_pair().expect("cancel pair");
        let outcome = run_prompt(
            &PromptQueue::new(),
            &sh(&script),
            "test message",
            Duration::from_millis(200),
            &watch,
        );
        assert!(matches!(outcome, Ok(PromptOutcome::TimedOut)));
        std::thread::sleep(Duration::from_millis(1500));
        assert!(!marker.exists(), "the prompt's child outlived it");
    }

    /// The message reaches the prompt through the environment rather than
    /// the argv: a prompt that reads `KPA_PROMPT_MESSAGE` sees it verbatim.
    #[test]
    fn the_message_reaches_the_prompt_as_an_environment_variable() {
        let _spawning = spawn_lock();
        let (_cancel, watch) = cancel_pair().expect("cancel pair");
        let outcome = run_prompt(
            &PromptQueue::new(),
            &sh(&format!("printf %s \"${PROMPT_MESSAGE_ENV}\"")),
            "Unlock personal",
            Duration::from_secs(60),
            &watch,
        );
        let Ok(PromptOutcome::Answer(seen)) = outcome else {
            panic!("expected the message back, got {outcome:?}");
        };
        assert_eq!(seen.as_str(), "Unlock personal");
    }

    /// Callers pass plain text: the prompt program only ever sees it
    /// escaped.
    #[test]
    fn the_message_is_escaped_before_the_prompt_sees_it() {
        let _spawning = spawn_lock();
        let (_cancel, watch) = cancel_pair().expect("cancel pair");
        let outcome = run_prompt(
            &PromptQueue::new(),
            &sh(&format!("printf %s \"${PROMPT_MESSAGE_ENV}\"")),
            "Unlock personal\u{202e}evil",
            Duration::from_secs(60),
            &watch,
        );
        let Ok(PromptOutcome::Answer(seen)) = outcome else {
            panic!("expected the message back, got {outcome:?}");
        };
        assert!(!seen.contains('\u{202e}'), "{:?}", seen.as_str());
        assert!(seen.contains("\\u202e"), "{:?}", seen.as_str());
    }

    /// The argv runs exactly as configured: nothing in it is rewritten,
    /// even text that looks like it could have been a placeholder.
    #[test]
    fn the_prompt_argv_is_never_rewritten() {
        let _spawning = spawn_lock();
        let (_cancel, watch) = cancel_pair().expect("cancel pair");
        let outcome = run_prompt(
            &PromptQueue::new(),
            &sh("printf %s '{message} literally'"),
            "Unlock personal",
            Duration::from_secs(60),
            &watch,
        );
        let Ok(PromptOutcome::Answer(seen)) = outcome else {
            panic!("expected an answer, got {outcome:?}");
        };
        assert_eq!(seen.as_str(), "{message} literally");
    }

    /// Two prompts for different databases never show at once: the
    /// second's `run_prompt` waits for the first's to finish.
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
        let (_cancel_a, watch_a) = cancel_pair().expect("cancel pair");
        let (_cancel_b, watch_b) = cancel_pair().expect("cancel pair");

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
    /// another one — is cancelled the instant its own `PromptCancel` is
    /// dropped, without waiting for its turn to come up.
    #[test]
    fn a_queued_prompt_is_cancelled_without_ever_being_shown() {
        let _spawning = spawn_lock();
        let dir = tempfile::tempdir().expect("tempdir");
        let marker = dir.path().join("second-ran");
        let second_script = sh(&format!("touch '{}'; printf ok", marker.display()));
        let queue = PromptQueue::new();
        let (_cancel_first, watch_first) = cancel_pair().expect("cancel pair");
        let (cancel_second, watch_second) = cancel_pair().expect("cancel pair");

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
