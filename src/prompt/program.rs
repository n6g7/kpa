//! The external-program backends: [`SecretProgram`] runs a dmenu-style
//! prompt program and reads what it prints; [`ConfirmProgram`] offers one
//! `Allow` and `Deny` and reads which it chose.
//!
//! The prompt program's argv runs exactly as configured; what the prompt is
//! about reaches it through the `KPA_PROMPT_MESSAGE` environment variable
//! instead (`docs/ssh-agent.md` § 6.6).

use std::io::{Error, ErrorKind, Read, Write};
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, Stdio};
use std::time::Instant;

use zeroize::Zeroizing;

use super::{Backend, ConfirmAnswer, MAX_ANSWER_LEN, PromptOutcome, Question, poll_timeout};
use crate::cancel::CancelToken;

/// The environment variable a prompt program finds its message in
/// (`config.example.toml`, `docs/ssh-agent.md` § 6.6). A prompt
/// program that wants it reads the variable directly; one that only takes
/// its prompt text as an argument needs a wrapper script that reads the
/// variable and passes it on, e.g.
/// `["sh", "-c", "exec fuzzel --dmenu --prompt \"$KPA_PROMPT_MESSAGE\""]`.
/// Either way the argv itself runs exactly as configured — kpa never
/// rewrites it.
const PROMPT_MESSAGE_ENV: &str = "KPA_PROMPT_MESSAGE";

/// Where the JSON of a prompt's data reaches it, next to the message.
const PROMPT_DATA_ENV: &str = "KPA_PROMPT_DATA";

/// The version of the data a prompt program gets: a change a consumer can't
/// ignore bumps it, a new field doesn't.
const DATA_VERSION: u32 = 1;

/// What a confirm prompt is offered, one choice per line.
const APPROVAL_CHOICES: &[u8] = b"Allow\nDeny\n";

/// Asks for a secret by running a dmenu-style program (`docs/design.md`
/// decision #9), such as the unlock prompt's argv (`Config::prompt`). The
/// program runs in its own process group. It is killed, with everything it
/// started, at its deadline, or as soon as its token is cancelled.
pub struct SecretProgram {
    argv: Vec<String>,
}

impl SecretProgram {
    pub fn new(argv: Vec<String>) -> SecretProgram {
        SecretProgram { argv }
    }
}

impl Backend<Zeroizing<String>> for SecretProgram {
    fn is_queued(&self) -> bool {
        true
    }

    /// Returns what the program printed, with its trailing `\n`/`\r`
    /// stripped, since dmenu-style prompts newline-terminate their output.
    ///
    /// The output is read into a zeroizing buffer of fixed size that never
    /// grows. That's the point: `Command::output()` collects into a `Vec`
    /// that reallocates as it fills, and every reallocation frees an unwiped
    /// copy of what it held so far — for a long passphrase, most of it
    /// survived both unlock and lock. Output longer than `MAX_ANSWER_LEN` is
    /// refused rather than accommodated. The copies kpa can't reach are the
    /// ones inside the prompt program itself.
    fn show(
        &self,
        question: &Question,
        deadline: Option<Instant>,
        cancel: &CancelToken,
    ) -> std::io::Result<PromptOutcome> {
        run(&self.argv, question, "enter", deadline, cancel, None)
    }
}

/// Asks for an approval by running a dmenu-style program, such as the SSH
/// agent's confirm prompt (`ssh_agent.confirm_prompt`): `Allow` and
/// `Deny` go to its stdin one per line, and exactly `Allow` on stdout is
/// [`ConfirmAnswer::Allow`]; anything else it prints is [`ConfirmAnswer::Deny`].
/// Otherwise run as [`SecretProgram`] runs its own.
pub struct ConfirmProgram {
    argv: Vec<String>,
}

impl ConfirmProgram {
    pub fn new(argv: Vec<String>) -> ConfirmProgram {
        ConfirmProgram { argv }
    }
}

impl Backend<ConfirmAnswer> for ConfirmProgram {
    fn is_queued(&self) -> bool {
        true
    }

    fn show(
        &self,
        question: &Question,
        deadline: Option<Instant>,
        cancel: &CancelToken,
    ) -> std::io::Result<PromptOutcome<ConfirmAnswer>> {
        let outcome = run(
            &self.argv,
            question,
            "select",
            deadline,
            cancel,
            Some(APPROVAL_CHOICES),
        )?;
        Ok(outcome.map(|answer| {
            if answer.as_str() == "Allow" {
                ConfirmAnswer::Allow
            } else {
                ConfirmAnswer::Deny
            }
        }))
    }
}

/// Runs `argv` with `question`'s message and data in its environment, and
/// reads what it prints. The data is the question's with `v`, the version of
/// this contract, and `kind` added: how the program is asked, `enter` for a
/// value it prints, `select` for one of the lines on its stdin. `stdin`, when
/// given, is written before anything is read — a prompt that picks among
/// choices gets them this way, one per line.
fn run(
    argv: &[String],
    question: &Question,
    kind: &str,
    deadline: Option<Instant>,
    cancel: &CancelToken,
    stdin: Option<&[u8]>,
) -> std::io::Result<PromptOutcome> {
    let Some((program, args)) = argv.split_first() else {
        return Err(Error::new(
            ErrorKind::InvalidInput,
            "prompt command is empty",
        ));
    };
    let Some(cancel) = cancel.watch()? else {
        return Ok(PromptOutcome::Interrupted);
    };
    let mut data = question.data.clone();
    data.insert("v".to_string(), DATA_VERSION.into());
    data.insert("kind".to_string(), kind.into());
    let data = serde_json::Value::Object(data).to_string();
    let mut child = Command::new(program)
        .args(args)
        .env(PROMPT_MESSAGE_ENV, &question.message)
        .env(PROMPT_DATA_ENV, data)
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
    let len = match read_prompt(&mut child, &mut buf, deadline, &cancel) {
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

    PromptOutcome::from_output(&buf[..len])
}

/// Read the child's stdout into `buf` until EOF, returning how much was
/// read. Errors rather than growing when `buf` fills up. Stops early with
/// `TimedOut` at `deadline`, or `Interrupted` once `cancel`, the token's
/// watch, wakes: either beats the output, so a lock wins over a prompt
/// that answers at the same moment.
fn read_prompt(
    child: &mut Child,
    buf: &mut [u8],
    deadline: Option<Instant>,
    cancel: &UnixStream,
) -> std::io::Result<Result<usize, PromptOutcome>> {
    use rustix::event::{PollFd, PollFlags, poll};

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
                Some(poll_timeout(left))
            }
            None => None,
        };
        let (output, cancelled) = {
            let mut fds = [
                PollFd::new(&stdout, PollFlags::IN),
                PollFd::new(cancel, PollFlags::IN),
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

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use std::sync::Arc;

    use super::super::{Prompt, PromptQueue};
    use super::*;
    use crate::cancel::CancelSource;
    use crate::prompt::testing::question;

    /// Held by every test here: each spawns a prompt, and spawning a child
    /// briefly duplicates every open file descriptor into it until it
    /// execs, which would hold up the wake-ups of the queue and cancel
    /// sockets another test is timing.
    static SPAWN_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn spawn_lock() -> std::sync::MutexGuard<'static, ()> {
        SPAWN_LOCK.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn sh(script: &str) -> Vec<String> {
        vec!["/bin/sh".into(), "-c".into(), script.into()]
    }

    /// `script` as a prompt with a queue of its own, timing out after
    /// `timeout` seconds.
    fn queued(script: &str, timeout: u64) -> Prompt<Zeroizing<String>> {
        Prompt::new(
            Arc::new(PromptQueue::new()),
            SecretProgram::new(sh(script)),
            Duration::from_secs(timeout),
        )
    }

    /// Runs `script` as the prompt with `message`, ending by `deadline`
    /// and with nobody to cancel it.
    fn shown(script: &str, message: &str, deadline: Duration) -> std::io::Result<PromptOutcome> {
        let source = CancelSource::new();
        SecretProgram::new(sh(script)).show(
            &question(message),
            Some(Instant::now() + deadline),
            &source.token(),
        )
    }

    /// Runs `script` as the prompt, with a deadline far enough off never to
    /// arrive and an arbitrary message — these tests don't care what it
    /// is.
    fn prompt(script: &str) -> std::io::Result<PromptOutcome> {
        shown(script, "test message", Duration::from_secs(60))
    }

    /// Runs `script` as the confirm prompt.
    fn approval(script: &str) -> std::io::Result<PromptOutcome<ConfirmAnswer>> {
        let source = CancelSource::new();
        ConfirmProgram::new(sh(script)).show(&question("test message"), None, &source.token())
    }

    #[test]
    fn an_approval_prompt_allows_only_an_exact_allow() {
        let _spawning = spawn_lock();
        for (script, expected) in [
            ("sed -n 1p", ConfirmAnswer::Allow),
            ("sed -n 2p", ConfirmAnswer::Deny),
            ("echo allow", ConfirmAnswer::Deny),
            ("echo 'Allow now'", ConfirmAnswer::Deny),
        ] {
            assert!(
                matches!(approval(script), Ok(PromptOutcome::Answer(a)) if a == expected),
                "{script}"
            );
        }
        assert!(matches!(approval("exit 1"), Ok(PromptOutcome::Cancelled)));
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
        let source = CancelSource::new();
        let outcome =
            SecretProgram::new(Vec::new()).show(&question("test message"), None, &source.token());
        assert!(outcome.is_err());
    }

    #[test]
    fn an_unanswered_prompt_times_out() {
        let _spawning = spawn_lock();
        let started = Instant::now();
        let outcome = shown(
            "sleep 30; printf hunter2",
            "test message",
            Duration::from_millis(200),
        );
        assert!(matches!(outcome, Ok(PromptOutcome::TimedOut)));
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    #[test]
    fn cancelling_the_token_interrupts_the_prompt() {
        let _spawning = spawn_lock();
        let source = CancelSource::new();
        let token = source.token();
        let started = Instant::now();
        let outcome = std::thread::scope(|scope| {
            scope.spawn(move || {
                std::thread::sleep(Duration::from_millis(200));
                drop(source);
            });
            SecretProgram::new(sh("sleep 30; printf hunter2")).show(
                &question("test message"),
                None,
                &token,
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
        let outcome = shown(&script, "test message", Duration::from_millis(200));
        assert!(matches!(outcome, Ok(PromptOutcome::TimedOut)));
        std::thread::sleep(Duration::from_millis(1500));
        assert!(!marker.exists(), "the prompt's child outlived it");
    }

    /// The message reaches the prompt through the environment rather than
    /// the argv: a prompt that reads `KPA_PROMPT_MESSAGE` sees it verbatim.
    #[test]
    fn the_message_reaches_the_prompt_as_an_environment_variable() {
        let _spawning = spawn_lock();
        let outcome = shown(
            &format!("printf %s \"${PROMPT_MESSAGE_ENV}\""),
            "Unlock personal",
            Duration::from_secs(60),
        );
        let Ok(PromptOutcome::Answer(seen)) = outcome else {
            panic!("expected the message back, got {outcome:?}");
        };
        assert_eq!(seen.as_str(), "Unlock personal");
    }

    /// The data reaches the prompt in `KPA_PROMPT_DATA`, as the JSON of what
    /// it was asked, next to the message, for both kinds of prompt.
    #[test]
    fn the_data_reaches_the_prompt_as_json_in_its_environment() {
        let _spawning = spawn_lock();
        let question = Question::new("Unlock personal").with("database", "personal");
        let source = CancelSource::new();

        let Ok(PromptOutcome::Answer(seen)) = SecretProgram::new(sh(&format!(
            "printf %s \"${PROMPT_DATA_ENV}\""
        )))
        .show(&question, None, &source.token()) else {
            panic!("expected the data back");
        };
        let seen: serde_json::Value = serde_json::from_str(seen.as_str()).expect("JSON");
        assert_eq!(
            seen,
            serde_json::json!({"v": 1, "kind": "enter", "database": "personal"})
        );

        // A program that selects is asked as one: its kind says so.
        let Ok(PromptOutcome::Answer(ConfirmAnswer::Allow)) = ConfirmProgram::new(sh(&format!(
            "cat >/dev/null; case \"${PROMPT_DATA_ENV}\" in *'\"kind\":\"select\"'*) echo Allow;; esac"
        )))
        .show(&question, None, &source.token()) else {
            panic!("expected the confirm program to see its kind");
        };
    }

    /// The argv runs exactly as configured: nothing in it is rewritten,
    /// even text that looks like it could have been a placeholder.
    #[test]
    fn the_prompt_argv_is_never_rewritten() {
        let _spawning = spawn_lock();
        let outcome = shown(
            "printf %s '{message} literally'",
            "Unlock personal",
            Duration::from_secs(60),
        );
        let Ok(PromptOutcome::Answer(seen)) = outcome else {
            panic!("expected an answer, got {outcome:?}");
        };
        assert_eq!(seen.as_str(), "{message} literally");
    }

    /// Callers of a prompt pass plain text: the prompt program only ever
    /// sees it escaped.
    #[test]
    fn the_message_is_escaped_before_the_prompt_sees_it() {
        let _spawning = spawn_lock();
        let unlock = queued(&format!("printf %s \"${PROMPT_MESSAGE_ENV}\""), 60);
        let source = CancelSource::new();
        let outcome = unlock.ask(&question("Unlock personal\u{202e}evil"), &source.token());
        let Ok(PromptOutcome::Answer(seen)) = outcome else {
            panic!("expected the message back, got {outcome:?}");
        };
        assert!(!seen.contains('\u{202e}'), "{:?}", seen.as_str());
        assert!(seen.contains("\\u202e"), "{:?}", seen.as_str());
    }

    /// Two prompts for different databases never show at once: the
    /// second waits for the first to finish.
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
        let unlock = queued(&script, 10);
        let (a, b) = (CancelSource::new(), CancelSource::new());

        let (first, second) = std::thread::scope(|scope| {
            let first = scope.spawn(|| unlock.ask(&question("a"), &a.token()));
            std::thread::sleep(Duration::from_millis(50));
            let second = scope.spawn(|| unlock.ask(&question("b"), &b.token()));
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
    /// another one — is cancelled the instant its token is, without
    /// waiting for its turn to come up.
    #[test]
    fn a_queued_prompt_is_cancelled_without_ever_being_shown() {
        let _spawning = spawn_lock();
        let dir = tempfile::tempdir().expect("tempdir");
        let marker = dir.path().join("second-ran");
        // The first prompt holds the screen for long enough that the
        // second is still waiting when it gets cancelled; the second, if
        // it ever ran, would leave `marker` behind.
        let script = format!(
            "if [ \"${PROMPT_MESSAGE_ENV}\" = second ]; then touch '{}'; fi; sleep 1; printf ok",
            marker.display()
        );
        let unlock = queued(&script, 10);
        let (first_source, second_source) = (CancelSource::new(), CancelSource::new());
        let second_token = second_source.token();

        let (first, second) = std::thread::scope(|scope| {
            let first = scope.spawn(|| unlock.ask(&question("first"), &first_source.token()));
            std::thread::sleep(Duration::from_millis(100));
            let second = scope.spawn(|| unlock.ask(&question("second"), &second_token));
            std::thread::sleep(Duration::from_millis(100));
            let cancelled_at = Instant::now();
            drop(second_source);
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
