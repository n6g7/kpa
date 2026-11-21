//! Asking on a terminal a requester passed with its request: [`Terminal`] is
//! that terminal, and [`SecretTerminal`] asks for a secret on it, with echo
//! off, as `ssh` and `sudo` do on their own (`docs/headless.md` § 4).
//!
//! The daemon is not the terminal's owner and the requester may be
//! misbehaving, so the prompt never waits on it unbounded. Every wait ends
//! at the deadline, on a lock, when the requester closes its connection and
//! when the terminal hangs up, and the terminal's modes are put back on every
//! one of those paths.

use std::io::{self, ErrorKind};
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::sync::Arc;
use std::time::Instant;

use rustix::event::{PollFd, PollFlags, poll};
use rustix::fs::{OFlags, fcntl_getfl, fcntl_setfl};
use rustix::io::Errno;
use rustix::termios::{LocalModes, OptionalActions, Termios, tcgetattr, tcsetattr};
use zeroize::Zeroizing;

use super::{Backend, MAX_ANSWER_LEN, PromptOutcome, Question, poll_timeout};
use crate::cancel::CancelToken;

/// A terminal the peer passed along with its request, and the connection it
/// came on: the daemon asks on the terminal, and stops asking once the peer
/// closes the connection.
///
/// Cloned freely: a clone is the same terminal.
#[derive(Debug, Clone)]
pub struct Terminal {
    fd: Arc<OwnedFd>,
    connection: Arc<UnixStream>,
}

impl Terminal {
    /// `fd`, as passed on `connection`. Refused unless it is a terminal: the
    /// daemon writes a prompt to it and switches its echo off, which it must
    /// not do to a file or a socket the peer picked.
    pub fn new(fd: OwnedFd, connection: &UnixStream) -> io::Result<Terminal> {
        if !rustix::termios::isatty(&fd) {
            return Err(io::Error::new(
                ErrorKind::InvalidInput,
                "the descriptor passed is not a terminal",
            ));
        }
        Ok(Terminal {
            fd: Arc::new(fd),
            connection: Arc::new(connection.try_clone()?),
        })
    }

    pub fn fd(&self) -> &OwnedFd {
        &self.fd
    }

    /// The connection the terminal came on, for noticing that the peer left.
    pub fn connection(&self) -> &UnixStream {
        &self.connection
    }
}

/// Two terminals are equal when one is a clone of the other, so a
/// [`Requester`](crate::authn::Requester) can be compared.
impl PartialEq for Terminal {
    fn eq(&self, other: &Terminal) -> bool {
        Arc::ptr_eq(&self.fd, &other.fd)
    }
}

impl Eq for Terminal {}

/// Asks for a secret on a terminal a requester passed
/// ([`Requester::terminal`](crate::authn::Requester::terminal)). It shows the
/// message, reads one line and returns it. It doesn't take the screen, so it
/// doesn't wait for its turn in the queue.
pub struct SecretTerminal {
    terminal: Terminal,
}

impl SecretTerminal {
    pub fn new(terminal: Terminal) -> SecretTerminal {
        SecretTerminal { terminal }
    }
}

impl Backend<Zeroizing<String>> for SecretTerminal {
    fn is_queued(&self) -> bool {
        false
    }

    fn show(
        &self,
        question: &Question,
        deadline: Option<Instant>,
        cancel: &CancelToken,
    ) -> io::Result<PromptOutcome> {
        let Some(cancel) = cancel.watch()? else {
            return Ok(PromptOutcome::Interrupted);
        };
        let tty = self.terminal.fd().as_fd();
        let asking = Asking {
            tty,
            connection: self.terminal.connection(),
            cancel: &cancel,
            deadline,
        };
        let _mode = TerminalMode::set(tty)?;
        let answer = asking.ask(&question.message);
        // With echo off the user's Enter was never shown, so the line the
        // prompt is on is still open.
        let _ = rustix::io::write(tty, b"\n");
        answer
    }
}

/// A terminal with its echo off, and reads and writes that never block, for
/// as long as this lives. Dropping it puts back what the terminal had, on
/// every way out of a prompt.
///
/// Non-blocking so that a terminal the requester has stopped (`^S`) or never
/// reads from can't hold a write forever, and with it the unlock that is
/// waiting on this prompt.
struct TerminalMode<'a> {
    tty: BorrowedFd<'a>,
    modes: Termios,
    flags: OFlags,
}

impl<'a> TerminalMode<'a> {
    fn set(tty: BorrowedFd<'a>) -> io::Result<TerminalMode<'a>> {
        let modes = tcgetattr(tty)?;
        let flags = fcntl_getfl(tty)?;
        let mut quiet = modes.clone();
        quiet.local_modes.remove(LocalModes::ECHO);
        tcsetattr(tty, OptionalActions::Now, &quiet)?;
        // From here the guard puts the modes back, including when this fails.
        let mode = TerminalMode { tty, modes, flags };
        fcntl_setfl(tty, flags | OFlags::NONBLOCK)?;
        Ok(mode)
    }
}

impl Drop for TerminalMode<'_> {
    fn drop(&mut self) {
        let _ = fcntl_setfl(self.tty, self.flags);
        let _ = tcsetattr(self.tty, OptionalActions::Now, &self.modes);
    }
}

/// One prompt on a terminal: what it waits on, and until when.
struct Asking<'a> {
    tty: BorrowedFd<'a>,
    /// The connection the requester passed the terminal on. A connection
    /// carries one request, which was read whole before this prompt began, so
    /// anything arriving on it now is the requester leaving, or misbehaving:
    /// either way the prompt ends.
    connection: &'a UnixStream,
    /// Reaches end of file once a lock has ended the prompt.
    cancel: &'a UnixStream,
    deadline: Option<Instant>,
}

impl Asking<'_> {
    /// Writes `message`, then reads the line typed in answer.
    fn ask(&self, message: &str) -> io::Result<PromptOutcome> {
        match self.write_prompt(message)? {
            Ok(()) => self.read_line(),
            Err(ended) => Ok(ended),
        }
    }

    fn write_prompt(&self, message: &str) -> io::Result<Result<(), PromptOutcome>> {
        let prompt = format!("{message}: ");
        let mut rest = prompt.as_bytes();
        while !rest.is_empty() {
            let ready = match self.wait(PollFlags::OUT)? {
                Ok(ready) => ready,
                Err(ended) => return Ok(Err(ended)),
            };
            if hung_up(ready) {
                return Ok(Err(PromptOutcome::Cancelled));
            }
            match rustix::io::write(self.tty, rest) {
                Ok(written) => rest = &rest[written..],
                Err(Errno::AGAIN | Errno::INTR) => {}
                Err(err) => return Err(err.into()),
            }
        }
        Ok(Ok(()))
    }

    /// Reads up to the first newline, or to end of file (`^D`) if none comes.
    /// The line goes into a zeroizing buffer of fixed size that never grows,
    /// and one longer than `MAX_ANSWER_LEN` is refused rather than read in
    /// parts.
    fn read_line(&self) -> io::Result<PromptOutcome> {
        // One byte more than the longest answer: a line of exactly
        // `MAX_ANSWER_LEN` still has room for the newline that ends it.
        let mut buf = Zeroizing::new(vec![0u8; MAX_ANSWER_LEN + 1]);
        let mut len = 0;
        let end = loop {
            if len == buf.len() {
                return Err(too_long());
            }
            let ready = match self.wait(PollFlags::IN)? {
                Ok(ready) => ready,
                Err(ended) => return Ok(ended),
            };
            if hung_up(ready) {
                return Ok(PromptOutcome::Cancelled);
            }
            match rustix::io::read(self.tty, &mut buf[len..]) {
                Ok(0) => break len,
                Ok(read) => {
                    len += read;
                    if let Some(newline) = buf[..len].iter().position(|&byte| byte == b'\n') {
                        break newline;
                    }
                }
                Err(Errno::AGAIN | Errno::INTR) => {}
                Err(err) => return Err(err.into()),
            }
        };
        if end > MAX_ANSWER_LEN {
            return Err(too_long());
        }
        PromptOutcome::from_output(&buf[..end])
    }

    /// Waits until the terminal is ready for `events` and returns what it is
    /// ready for. `Err` is the way the prompt ended instead. A lock wins over
    /// everything else, so it beats an answer typed at the same moment.
    fn wait(&self, events: PollFlags) -> io::Result<Result<PollFlags, PromptOutcome>> {
        loop {
            let timeout = match self.deadline {
                Some(deadline) => {
                    let left = deadline.saturating_duration_since(Instant::now());
                    if left.is_zero() {
                        return Ok(Err(PromptOutcome::TimedOut));
                    }
                    Some(poll_timeout(left))
                }
                None => None,
            };
            let mut fds = [
                PollFd::new(&self.tty, events),
                PollFd::new(self.connection, PollFlags::IN),
                PollFd::new(self.cancel, PollFlags::IN),
            ];
            match poll(&mut fds, timeout.as_ref()) {
                Ok(_) => {}
                // A signal interrupted the wait: wait again, for the time
                // left until the same deadline.
                Err(Errno::INTR) => continue,
                Err(err) => return Err(err.into()),
            }
            if !fds[2].revents().is_empty() {
                return Ok(Err(PromptOutcome::Interrupted));
            }
            if !fds[1].revents().is_empty() {
                return Ok(Err(PromptOutcome::Cancelled));
            }
            if !fds[0].revents().is_empty() {
                return Ok(Ok(fds[0].revents()));
            }
        }
    }
}

/// Whether the terminal went away: its other end closed, or it is no longer
/// open. Nobody can answer then.
fn hung_up(ready: PollFlags) -> bool {
    ready.intersects(PollFlags::HUP | PollFlags::ERR | PollFlags::NVAL)
}

fn too_long() -> io::Error {
    io::Error::new(
        ErrorKind::InvalidData,
        format!("answer exceeds {MAX_ANSWER_LEN} bytes"),
    )
}

#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::io::Write;
    use std::net::Shutdown;
    use std::sync::Arc;
    use std::time::Duration;

    use super::super::{Prompt, PromptQueue};
    use super::*;
    use crate::cancel::CancelSource;
    use crate::prompt::testing::{echoing, pty, question, read_until};

    const MESSAGE: &str = "Unlock personal";

    /// What a requester passes: a terminal and the connection it passed it
    /// on. The test is the user at `master`, the terminal's other end, and
    /// `client` is the requester's end of the connection.
    struct Rig {
        master: File,
        client: UnixStream,
        backend: SecretTerminal,
    }

    fn rig() -> Rig {
        let (master, slave) = pty();
        let (client, daemon) = UnixStream::pair().expect("connection");
        let terminal = Terminal::new(slave, &daemon).expect("a terminal");
        Rig {
            master,
            client,
            backend: SecretTerminal::new(terminal),
        }
    }

    fn type_line(master: &mut File, line: &str) {
        master.write_all(line.as_bytes()).expect("type");
    }

    fn answer(outcome: io::Result<PromptOutcome>) -> String {
        match outcome {
            Ok(PromptOutcome::Answer(answer)) => answer.as_str().to_string(),
            other => panic!("expected an answer, got {other:?}"),
        }
    }

    #[test]
    fn the_prompt_reads_the_typed_line_with_echo_off_and_restores_echo() {
        let Rig {
            mut master,
            client: _client,
            backend,
        } = rig();
        let source = CancelSource::new();
        let token = source.token();
        assert!(echoing(&master));

        let outcome = std::thread::scope(|scope| {
            let asking = scope.spawn(|| backend.show(&question(MESSAGE), None, &token));
            let screen = read_until(&mut master, "Unlock personal: ");
            assert!(!echoing(&master), "echo is off while the prompt is up");
            type_line(&mut master, "hunter2\n");
            let outcome = asking.join().expect("prompt thread");
            let after = read_until(&mut master, "\n");
            assert!(!screen.contains("hunter2") && !after.contains("hunter2"));
            outcome
        });

        assert_eq!(answer(outcome), "hunter2");
        assert!(echoing(&master), "echo is back");
    }

    #[test]
    fn an_empty_line_is_an_empty_answer() {
        let Rig {
            mut master,
            client: _client,
            backend,
        } = rig();
        let source = CancelSource::new();
        let token = source.token();

        let outcome = std::thread::scope(|scope| {
            let asking = scope.spawn(|| backend.show(&question(MESSAGE), None, &token));
            read_until(&mut master, "Unlock personal: ");
            type_line(&mut master, "\n");
            asking.join().expect("prompt thread")
        });

        assert_eq!(answer(outcome), "");
    }

    #[test]
    fn an_unanswered_prompt_times_out_and_restores_echo() {
        let rig = rig();
        let source = CancelSource::new();
        let started = Instant::now();

        let outcome = rig.backend.show(
            &question(MESSAGE),
            Some(Instant::now() + Duration::from_millis(200)),
            &source.token(),
        );

        assert!(
            matches!(outcome, Ok(PromptOutcome::TimedOut)),
            "{outcome:?}"
        );
        assert!(started.elapsed() < Duration::from_secs(5));
        assert!(echoing(&rig.master));
    }

    #[test]
    fn a_lock_ends_the_prompt_and_restores_echo() {
        let rig = rig();
        let source = CancelSource::new();
        let token = source.token();
        let started = Instant::now();

        let outcome = std::thread::scope(|scope| {
            let asking = scope.spawn(|| rig.backend.show(&question(MESSAGE), None, &token));
            std::thread::sleep(Duration::from_millis(200));
            drop(source);
            asking.join().expect("prompt thread")
        });

        assert!(
            matches!(outcome, Ok(PromptOutcome::Interrupted)),
            "{outcome:?}"
        );
        assert!(started.elapsed() < Duration::from_secs(5));
        assert!(echoing(&rig.master));
    }

    /// A prompt whose token is cancelled already never touches the terminal.
    #[test]
    fn a_prompt_cancelled_before_it_starts_leaves_the_terminal_alone() {
        let mut rig = rig();
        let source = CancelSource::new();
        let token = source.token();
        drop(source);

        let outcome = rig.backend.show(&question(MESSAGE), None, &token);

        assert!(
            matches!(outcome, Ok(PromptOutcome::Interrupted)),
            "{outcome:?}"
        );
        // Typed now, with echo still on: the screen shows the typing and
        // nothing from the prompt.
        type_line(&mut rig.master, "x\n");
        assert_eq!(read_until(&mut rig.master, "x\r\n"), "x\r\n");
    }

    #[test]
    fn the_requester_closing_its_connection_ends_the_prompt_and_restores_echo() {
        let rig = rig();
        let source = CancelSource::new();
        let token = source.token();
        let started = Instant::now();

        let outcome = std::thread::scope(|scope| {
            let asking = scope.spawn(|| rig.backend.show(&question(MESSAGE), None, &token));
            std::thread::sleep(Duration::from_millis(200));
            // What a client that caught `^C` does: shut its end and wait.
            rig.client.shutdown(Shutdown::Write).expect("shutdown");
            asking.join().expect("prompt thread")
        });

        assert!(
            matches!(outcome, Ok(PromptOutcome::Cancelled)),
            "{outcome:?}"
        );
        assert!(started.elapsed() < Duration::from_secs(5));
        assert!(echoing(&rig.master));
    }

    #[test]
    fn the_terminal_hanging_up_cancels_the_prompt() {
        let Rig {
            master,
            client: _client,
            backend,
        } = rig();
        let source = CancelSource::new();
        let token = source.token();

        let outcome = std::thread::scope(|scope| {
            let asking = scope.spawn(|| backend.show(&question(MESSAGE), None, &token));
            std::thread::sleep(Duration::from_millis(200));
            drop(master);
            asking.join().expect("prompt thread")
        });

        assert!(
            matches!(outcome, Ok(PromptOutcome::Cancelled)),
            "{outcome:?}"
        );
    }

    /// A terminal that never takes the prompt can't hold the unlock forever:
    /// the write waits only until the deadline.
    #[test]
    fn a_terminal_that_takes_no_output_still_times_out() {
        let rig = rig();
        let tty = rig.backend.terminal.fd().as_fd();
        let flags = fcntl_getfl(tty).expect("flags");
        fcntl_setfl(tty, flags | OFlags::NONBLOCK).expect("non-blocking");
        let filler = [b'.'; 4096];
        let mut filled = 0;
        while rustix::io::write(tty, &filler).is_ok() {
            filled += filler.len();
            assert!(filled < 16 * 1024 * 1024, "the pty never filled up");
        }
        fcntl_setfl(tty, flags).expect("blocking again");
        let source = CancelSource::new();
        let started = Instant::now();

        let outcome = rig.backend.show(
            &question(MESSAGE),
            Some(Instant::now() + Duration::from_millis(300)),
            &source.token(),
        );

        assert!(
            matches!(outcome, Ok(PromptOutcome::TimedOut)),
            "{outcome:?}"
        );
        assert!(started.elapsed() < Duration::from_secs(5));
        assert!(echoing(&rig.master));
    }

    /// The buffer never grows: a line over the limit is refused. Over a
    /// socket pair, since a real terminal's own line limit is close to this
    /// one but not the same.
    #[test]
    fn a_line_over_the_limit_is_refused_and_one_at_the_limit_is_not() {
        let read = |line: &[u8]| {
            let (mut typing, tty) = UnixStream::pair().expect("tty stand-in");
            let (_client, connection) = UnixStream::pair().expect("connection");
            let (_lock, cancel) = UnixStream::pair().expect("cancel");
            typing.write_all(line).expect("type");
            Asking {
                tty: tty.as_fd(),
                connection: &connection,
                cancel: &cancel,
                deadline: None,
            }
            .read_line()
        };

        let longest = "a".repeat(MAX_ANSWER_LEN);
        assert_eq!(answer(read(format!("{longest}\n").as_bytes())), longest);
        assert!(read("a".repeat(MAX_ANSWER_LEN + 1).as_bytes()).is_err());
        assert!(read(format!("{}\n", "a".repeat(MAX_ANSWER_LEN + 1)).as_bytes()).is_err());
    }

    #[test]
    fn an_answer_that_is_not_utf8_is_refused() {
        let (mut typing, tty) = UnixStream::pair().expect("tty stand-in");
        let (_client, connection) = UnixStream::pair().expect("connection");
        let (_lock, cancel) = UnixStream::pair().expect("cancel");
        typing.write_all(b"\xff\xfe\n").expect("type");

        let outcome = Asking {
            tty: tty.as_fd(),
            connection: &connection,
            cancel: &cancel,
            deadline: None,
        }
        .read_line();

        assert!(outcome.is_err());
    }

    /// A terminal prompt asks without taking the screen, so a prompt on
    /// screen that holds the queue doesn't hold it up.
    #[test]
    fn a_terminal_prompt_does_not_wait_for_the_queue() {
        let Rig {
            mut master,
            client: _client,
            backend,
        } = rig();
        let queue = Arc::new(PromptQueue::new());
        let source = CancelSource::new();
        let token = source.token();
        let _on_screen = queue.enter(&token).expect("enter").expect("a turn");
        let prompt = Prompt::new(Arc::clone(&queue), backend, Duration::from_secs(60));

        let outcome = std::thread::scope(|scope| {
            let asking = scope.spawn(|| prompt.ask(&question(MESSAGE), &token));
            read_until(&mut master, "Unlock personal: ");
            type_line(&mut master, "hunter2\n");
            asking.join().expect("prompt thread")
        });

        assert_eq!(answer(outcome), "hunter2");
    }

    /// The message reaches the terminal sanitized, like any prompt's.
    #[test]
    fn the_message_is_escaped_before_it_reaches_the_terminal() {
        let Rig {
            mut master,
            client: _client,
            backend,
        } = rig();
        let source = CancelSource::new();
        let token = source.token();
        let prompt = Prompt::new(
            Arc::new(PromptQueue::new()),
            backend,
            Duration::from_secs(60),
        );

        std::thread::scope(|scope| {
            let asking = scope.spawn(|| prompt.ask(&question("Unlock\u{1b}[2Jevil"), &token));
            let screen = read_until(&mut master, "evil: ");
            assert!(!screen.contains('\u{1b}'), "{screen:?}");
            assert!(screen.contains("\\u001b"), "{screen:?}");
            type_line(&mut master, "\n");
            let _ = asking.join().expect("prompt thread");
        });
    }
}
