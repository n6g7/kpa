//! `unlock`: begin, choose where to ask, ask, finish.

use std::sync::Arc;

use zeroize::Zeroizing;

use super::proto::{UnlockError, UnlockRequest};
use super::{Api, authz};
use crate::authn::Requester;
use crate::databases::{Begin, BeginError, UnlockFailure, VaultError};
use crate::log;
use crate::prompt::{self, Prompt, PromptOn, PromptOutcome, Question, SecretTerminal};

impl Api {
    /// The unlock `kpa unlock` runs for `requester`. The token comes before
    /// the display session is read: a screen lock either shows in that read
    /// and refuses, or cancels the token and ends the prompt, so no prompt
    /// is raised behind a locker.
    pub(super) fn unlock(
        &self,
        request: &UnlockRequest,
        requester: &Requester,
    ) -> Result<String, UnlockError> {
        let name = request.db.as_str();
        let db = || name.to_string();

        let unlocking = match self.databases.begin_unlock(name) {
            Err(BeginError::UnknownDb) => return Err(UnlockError::UnknownDb { db: db() }),
            Err(BeginError::InProgress) => return Err(UnlockError::InProgress { db: db() }),
            Ok(Begin::AlreadyUnlocked) => return Ok(db()),
            Ok(Begin::Started(unlocking)) => unlocking,
        };

        let backend: Arc<dyn prompt::Backend<Zeroizing<String>>> =
            match authz::choose_unlock_prompt(requester, &self.display.get())? {
                PromptOn::Screen => Arc::clone(&self.screen_unlock),
                PromptOn::Terminal => Arc::new(SecretTerminal::new(
                    requester.terminal.clone().ok_or(UnlockError::NoPrompt)?,
                )),
            };
        log::debug(format_args!("prompting for {name:?}"));
        let question = Question::new(format!("Unlock {name}")).with("database", name);
        let outcome = Prompt::new(Arc::clone(&self.prompts), backend, self.prompt_timeout)
            .ask(&question, unlocking.unlock_token());
        let password = match outcome {
            Ok(PromptOutcome::Answer(password)) => password,
            Ok(PromptOutcome::Cancelled) => return Err(UnlockError::PromptCancelled { db: db() }),
            Ok(PromptOutcome::TimedOut) => {
                log::info(format_args!(
                    "prompt for {name:?} unanswered after {:?}",
                    self.prompt_timeout
                ));
                return Err(UnlockError::PromptCancelled { db: db() });
            }
            // A lock ended the prompt, and has told its own client already.
            Ok(PromptOutcome::Interrupted) => {
                return Err(UnlockError::LockedDuringUnlock { db: db() });
            }
            Err(err) => {
                return Err(UnlockError::PromptFailed {
                    db: db(),
                    detail: err.to_string(),
                });
            }
        };

        // An empty answer means "no password", the only way to reach a
        // keyfile-only database from a prompt that always asks. A wrong one
        // fails with no backoff: any same-uid process can read the `.kdbx`
        // and guess offline.
        unlocking
            .finish(Some(&password).filter(|password| !password.is_empty()))
            .map_err(|failure| match failure {
                UnlockFailure::Vault(err) => unlock_error(name, err),
                UnlockFailure::LockedMeanwhile => UnlockError::LockedDuringUnlock { db: db() },
            })?;
        Ok(db())
    }
}

/// Maps a `VaultError` to the `unlock`-specific error type: `unlock` is the
/// only op that opens a file, so this is the only place vault errors enter
/// the protocol.
///
/// Deliberately drops `VaultError::Corrupt`'s inner message rather than
/// carrying it as `detail`: that string can embed raw bytes out of the
/// decrypted database (see the doc comment on `VaultError::Corrupt`), and a
/// socket client is exactly the sink that comment warns is now reachable.
fn unlock_error(name: &str, err: VaultError) -> UnlockError {
    let db = name.to_string();
    match err {
        VaultError::NotFound(_) | VaultError::KeyfileNotFound(_) => UnlockError::NotFound { db },
        VaultError::WrongCredentials => UnlockError::WrongCredentials { db },
        VaultError::Corrupt(_) => UnlockError::Corrupt { db },
        VaultError::UnsupportedFormat => UnlockError::UnsupportedFormat { db },
        // The text names which file and the ceiling, never anything from
        // inside it.
        refused @ (VaultError::NotRegular(_) | VaultError::TooLarge(_)) => {
            UnlockError::FileRefused {
                db,
                detail: refused.to_string(),
            }
        }
        VaultError::Io(_) => UnlockError::Io { db },
        VaultError::Changed => UnlockError::Stale { db },
    }
}

#[cfg(test)]
mod tests {
    use std::fs::File;
    use std::io::Write;
    use std::os::unix::net::UnixStream;
    use std::thread;

    use super::*;
    use crate::databases::{Begin, BeginError, FileKind};
    use crate::display_session::DisplaySession;
    use crate::frontends::control::testing::{
        Fixture, SESSION, desktop, fixture, outside, requester_in,
    };
    use crate::prompt::testing::{echoing, pty, read_until, shows_anything};
    use crate::prompt::{Scripted, Step, Terminal};

    fn prompt_fixture() -> (Fixture, Scripted<Zeroizing<String>>) {
        let fx = fixture();
        let prompts = fx.prompts.clone();
        (fx, prompts)
    }

    fn fixture_timing_out_after(timeout: &str) -> Fixture {
        crate::frontends::control::testing::fixture_with(
            &["personal", "work"],
            &format!("prompt_timeout = \"{timeout}\""),
        )
    }

    fn unlock(fx: &Fixture, name: &str) -> Result<String, UnlockError> {
        unlock_from(fx, name, &desktop())
    }

    fn unlock_from(fx: &Fixture, name: &str, requester: &Requester) -> Result<String, UnlockError> {
        fx.api.unlock(
            &UnlockRequest {
                db: name.to_string(),
            },
            requester,
        )
    }

    /// The vault is where an answered prompt ends up in these tests, and the
    /// file the core is configured with is no database.
    fn corrupt() -> Result<String, UnlockError> {
        Err(UnlockError::Corrupt {
            db: "personal".to_string(),
        })
    }

    #[test]
    fn a_format_kpa_does_not_read_is_reported_as_such() {
        assert!(matches!(
            unlock_error("personal", VaultError::UnsupportedFormat),
            UnlockError::UnsupportedFormat { db } if db == "personal"
        ));
    }

    #[test]
    fn a_file_kpa_refuses_to_read_says_which_and_why() {
        for (err, detail) in [
            (
                VaultError::NotRegular(FileKind::Database),
                "database file is not a regular file",
            ),
            (
                VaultError::TooLarge(FileKind::Keyfile),
                "keyfile is larger than 16 MiB",
            ),
        ] {
            assert_eq!(
                unlock_error("personal", err),
                UnlockError::FileRefused {
                    db: "personal".to_string(),
                    detail: detail.to_string()
                }
            );
        }
    }

    fn cancelled() -> Result<String, UnlockError> {
        Err(UnlockError::PromptCancelled {
            db: "personal".to_string(),
        })
    }

    fn locked_during() -> Result<String, UnlockError> {
        Err(UnlockError::LockedDuringUnlock {
            db: "personal".to_string(),
        })
    }

    /// A requester that passed a terminal with its request, on the desktop
    /// or not: the requester, the user's end of the terminal, and the
    /// requester's end of its connection.
    fn passing_a_terminal(on_desktop: bool) -> (Requester, File, UnixStream) {
        let (master, slave) = pty();
        let (client, connection) = UnixStream::pair().expect("connection");
        let requester = Requester {
            terminal: Some(Terminal::new(slave, &connection).expect("a terminal")),
            ..requester_in(on_desktop)
        };
        (requester, master, client)
    }

    /// Whether `personal`'s one unlock is taken.
    fn claimed(fx: &Fixture) -> bool {
        matches!(
            fx.databases.begin_unlock("personal"),
            Err(BeginError::InProgress)
        )
    }

    /// A prompt that types a password, unless something ends it first.
    fn typed() -> Step<Zeroizing<String>> {
        Step::new(PromptOutcome::Answer(Zeroizing::new("hunter2".to_string())))
    }

    #[test]
    fn an_unknown_database_and_an_unlocked_one_are_answered_before_any_prompt() {
        let (fx, prompts) = prompt_fixture();
        assert_eq!(
            unlock(&fx, "nope"),
            Err(UnlockError::UnknownDb {
                db: "nope".to_string()
            })
        );
        fx.databases.install_for_test("work", vec![]);
        assert_eq!(unlock(&fx, "work"), Ok("work".to_string()));
        assert!(prompts.shown().is_empty());
    }

    #[test]
    fn no_prompt_is_raised_while_the_display_session_is_locked() {
        let (fx, prompts) = prompt_fixture();
        prompts.push(Step::new(PromptOutcome::Cancelled));

        fx.display.set(DisplaySession::Locked {
            id: SESSION.to_string(),
            active: true,
        });
        assert_eq!(unlock(&fx, "personal"), Err(UnlockError::NoPrompt));
        assert!(prompts.shown().is_empty(), "a prompt ran behind the locker");
        assert!(!claimed(&fx), "the refusal gave the claim back");

        fx.display.set(DisplaySession::Unlocked {
            id: SESSION.to_string(),
            active: true,
        });
        assert_eq!(unlock(&fx, "personal"), cancelled());
        assert_eq!(
            prompts.shown(),
            ["Unlock personal"],
            "the prompt runs again once the display session is unlocked"
        );
    }

    #[test]
    fn no_prompt_is_raised_for_a_requester_outside_the_desktop() {
        let (fx, prompts) = prompt_fixture();
        prompts.push(Step::new(PromptOutcome::Cancelled));

        assert_eq!(
            unlock_from(&fx, "personal", &outside()),
            Err(UnlockError::NoPrompt)
        );
        assert!(
            prompts.shown().is_empty(),
            "a prompt ran for a requester outside"
        );

        assert_eq!(unlock_from(&fx, "personal", &desktop()), cancelled());
        assert_eq!(prompts.shown(), ["Unlock personal"]);
        // The data says which database it is for, whatever the message says.
        assert_eq!(
            serde_json::Value::Object(prompts.shown_questions()[0].data.clone()),
            serde_json::json!({"database": "personal"})
        );
    }

    /// The three places a screen lock can fall relative to an unlock's
    /// token. The display session is marked before everything is locked.
    #[test]
    fn a_screen_lock_before_the_token_refuses() {
        let (fx, prompts) = prompt_fixture();
        fx.display.set(DisplaySession::Locked {
            id: SESSION.to_string(),
            active: true,
        });
        fx.databases.lock_all();

        assert_eq!(unlock(&fx, "personal"), Err(UnlockError::NoPrompt));
        assert!(prompts.shown().is_empty());
    }

    #[test]
    fn a_screen_lock_between_the_token_and_the_read_refuses() {
        let (fx, prompts) = prompt_fixture();
        let unlocking = match fx.databases.begin_unlock("personal") {
            Ok(Begin::Started(unlocking)) => unlocking,
            _ => panic!("expected an unlock to start"),
        };
        // The mark precedes the lock, so a read after the token sees it, and
        // the token is cancelled as well.
        fx.display.set(DisplaySession::Locked {
            id: SESSION.to_string(),
            active: true,
        });
        fx.databases.lock_all();
        assert!(unlocking.unlock_token().is_cancelled());
        drop(unlocking);

        assert_eq!(unlock(&fx, "personal"), Err(UnlockError::NoPrompt));
        assert!(prompts.shown().is_empty());
    }

    #[test]
    fn a_screen_lock_after_the_read_cancels_the_prompt_it_raised() {
        let (fx, prompts) = prompt_fixture();
        let locker = Arc::clone(&fx.databases);
        let display = Arc::clone(&fx.display);
        prompts.push(typed().while_up(move || {
            display.set(DisplaySession::Locked {
                id: SESSION.to_string(),
                active: true,
            });
            locker.lock_all();
        }));

        assert_eq!(unlock(&fx, "personal"), locked_during());
        assert!(!claimed(&fx));
    }

    /// A second request for a database whose unlock is under way is refused
    /// as in progress, even from where it would be refused as `no_display`:
    /// the claim is taken first.
    #[test]
    fn unlock_in_progress_comes_before_no_prompt() {
        let (fx, _prompts) = prompt_fixture();
        let unlocking = match fx.databases.begin_unlock("personal") {
            Ok(Begin::Started(unlocking)) => unlocking,
            _ => panic!("expected an unlock to start"),
        };
        assert_eq!(
            unlock_from(&fx, "personal", &outside()),
            Err(UnlockError::InProgress {
                db: "personal".to_string()
            })
        );
        drop(unlocking);
    }

    /// Types `line` at `master` once the prompt on it is up, and returns
    /// what the unlock answers.
    fn answer_on_terminal(
        fx: &Fixture,
        requester: &Requester,
        preferred: Option<PromptOn>,
        master: &mut File,
        line: &str,
    ) -> Result<String, UnlockError> {
        thread::scope(|scope| {
            let unlocking = scope.spawn(|| {
                unlock_from(
                    fx,
                    "personal",
                    &Requester {
                        preferred,
                        ..requester.clone()
                    },
                )
            });
            read_until(master, "Unlock personal: ");
            assert!(!echoing(master), "echo is off while the prompt is up");
            master.write_all(line.as_bytes()).expect("type");
            unlocking.join().expect("unlock thread")
        })
    }

    #[test]
    fn an_unlock_from_outside_the_desktop_asks_on_the_terminal_the_requester_passed() {
        let (fx, prompts) = prompt_fixture();
        let (requester, mut master, _client) = passing_a_terminal(false);

        assert_eq!(
            answer_on_terminal(&fx, &requester, None, &mut master, "hunter2\n"),
            corrupt()
        );
        assert!(prompts.shown().is_empty(), "the screen prompt ran");
        assert!(echoing(&master), "echo is back");
        assert!(!claimed(&fx));
    }

    /// Where a prompt may appear on screen it does, and the terminal the
    /// requester passed is left alone.
    #[test]
    fn the_terminal_is_ignored_where_a_prompt_may_appear_on_screen() {
        let (fx, prompts) = prompt_fixture();
        prompts.push(typed());
        let (requester, master, _client) = passing_a_terminal(true);

        assert_eq!(unlock_from(&fx, "personal", &requester), corrupt());
        assert_eq!(prompts.shown(), ["Unlock personal"]);
        assert!(!shows_anything(&master), "something was written to it");
        assert!(echoing(&master));
    }

    #[test]
    fn a_request_preferring_the_terminal_is_asked_there_on_the_desktop_too() {
        let (fx, prompts) = prompt_fixture();
        let (requester, mut master, _client) = passing_a_terminal(true);

        assert_eq!(
            answer_on_terminal(
                &fx,
                &requester,
                Some(PromptOn::Terminal),
                &mut master,
                "hunter2\n"
            ),
            corrupt()
        );
        assert!(prompts.shown().is_empty(), "the screen prompt ran");
    }

    #[test]
    fn a_request_preferring_a_terminal_it_did_not_pass_is_no_prompt() {
        let (fx, prompts) = prompt_fixture();

        assert_eq!(
            unlock_from(
                &fx,
                "personal",
                &Requester {
                    preferred: Some(PromptOn::Terminal),
                    ..desktop()
                },
            ),
            Err(UnlockError::NoPrompt)
        );
        assert!(prompts.shown().is_empty(), "the screen prompt ran");
        assert!(!claimed(&fx));
    }

    #[test]
    fn a_request_preferring_the_screen_is_never_asked_on_the_terminal() {
        let (fx, prompts) = prompt_fixture();
        let (requester, master, _client) = passing_a_terminal(false);

        assert_eq!(
            unlock_from(
                &fx,
                "personal",
                &Requester {
                    preferred: Some(PromptOn::Screen),
                    ..requester.clone()
                },
            ),
            Err(UnlockError::NoPrompt)
        );
        assert!(prompts.shown().is_empty());
        assert!(!shows_anything(&master), "something was written to it");
        assert!(echoing(&master));
    }

    /// A requester on the desktop behind a locker has no screen to answer
    /// on, but its terminal still is one.
    #[test]
    fn a_requester_on_the_desktop_behind_a_locker_is_asked_on_its_terminal() {
        let (fx, prompts) = prompt_fixture();
        fx.display.set(DisplaySession::Locked {
            id: SESSION.to_string(),
            active: true,
        });
        let (requester, mut master, _client) = passing_a_terminal(true);

        assert_eq!(
            answer_on_terminal(&fx, &requester, None, &mut master, "hunter2\n"),
            corrupt()
        );
        assert!(prompts.shown().is_empty());
    }

    #[test]
    fn a_lock_ends_a_prompt_on_the_terminal() {
        let (fx, _prompts) = prompt_fixture();
        let (requester, mut master, _client) = passing_a_terminal(false);

        let outcome = thread::scope(|scope| {
            let unlocking = scope.spawn(|| unlock_from(&fx, "personal", &requester));
            read_until(&mut master, "Unlock personal: ");
            fx.databases.lock_all();
            unlocking.join().expect("unlock thread")
        });

        assert_eq!(outcome, locked_during());
        assert!(echoing(&master));
        assert!(!claimed(&fx));
    }

    #[test]
    fn a_prompt_on_the_terminal_times_out() {
        let fx = fixture_timing_out_after("300ms");
        let (requester, mut master, _client) = passing_a_terminal(false);

        let outcome = thread::scope(|scope| {
            let unlocking = scope.spawn(|| unlock_from(&fx, "personal", &requester));
            read_until(&mut master, "Unlock personal: ");
            unlocking.join().expect("unlock thread")
        });

        assert_eq!(outcome, cancelled());
        assert!(echoing(&master));
        assert!(!claimed(&fx));
    }

    #[test]
    fn the_requester_leaving_ends_a_prompt_on_the_terminal() {
        let (fx, _prompts) = prompt_fixture();
        let (requester, mut master, client) = passing_a_terminal(false);

        let outcome = thread::scope(|scope| {
            let unlocking = scope.spawn(|| unlock_from(&fx, "personal", &requester));
            read_until(&mut master, "Unlock personal: ");
            client.shutdown(std::net::Shutdown::Write).expect("leave");
            unlocking.join().expect("unlock thread")
        });

        assert_eq!(outcome, cancelled());
        assert!(echoing(&master));
        assert!(!claimed(&fx));
    }

    /// A prompt on a terminal is still the database's one unlock: a second
    /// request for it is refused, not given a second prompt.
    #[test]
    fn a_second_unlock_is_refused_while_the_terminal_prompt_is_up() {
        let (fx, _prompts) = prompt_fixture();
        let (requester, mut master, client) = passing_a_terminal(false);

        thread::scope(|scope| {
            let unlocking = scope.spawn(|| unlock_from(&fx, "personal", &requester));
            read_until(&mut master, "Unlock personal: ");

            assert_eq!(
                unlock(&fx, "personal"),
                Err(UnlockError::InProgress {
                    db: "personal".to_string()
                })
            );

            client.shutdown(std::net::Shutdown::Write).expect("leave");
            let _ = unlocking.join().expect("unlock thread");
        });
    }

    #[test]
    fn lock_all_ends_a_prompt_in_flight() {
        let (fx, prompts) = prompt_fixture();
        let locker = Arc::clone(&fx.databases);
        prompts.push(typed().while_up(move || locker.lock_all()));

        assert_eq!(unlock(&fx, "personal"), locked_during());
        assert!(!claimed(&fx));
    }

    #[test]
    fn locking_the_database_ends_its_prompt() {
        let (fx, prompts) = prompt_fixture();
        let locker = Arc::clone(&fx.databases);
        prompts.push(typed().while_up(move || {
            let _ = locker.lock("personal");
        }));

        assert_eq!(unlock(&fx, "personal"), locked_during());
    }

    /// Locking another database leaves this one's prompt open; it ends on
    /// its own, dismissed here.
    #[test]
    fn locking_another_database_leaves_the_prompt_alone() {
        let (fx, prompts) = prompt_fixture();
        let locker = Arc::clone(&fx.databases);
        prompts.push(Step::new(PromptOutcome::Cancelled).while_up(move || {
            let _ = locker.lock("work");
        }));

        assert_eq!(unlock(&fx, "personal"), cancelled());
    }
}
