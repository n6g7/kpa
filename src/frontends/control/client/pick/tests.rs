//! `pick_with` against a real `Api` on a socket, a recording clipboard, and a
//! shell script standing in for fzf: it keeps what it was given and answers
//! as the test scripts it.

use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::thread;

use tempfile::TempDir;

use super::*;
use crate::databases::testing::TestEntry;
use crate::frontends::control::testing::{Fixture, fixture, serve};

/// A fake fzf, and the directory it keeps what it saw in: its `n`th run
/// leaves its stdin in `stdin.n` and its arguments, one per line, in
/// `args.n`, then runs `scripts[n - 1]`, which prints what fzf would.
struct FakeFzf {
    dir: TempDir,
}

impl FakeFzf {
    fn new(scripts: &[&str]) -> FakeFzf {
        let dir = tempfile::tempdir().expect("temp dir");
        let cases: String = scripts
            .iter()
            .enumerate()
            .map(|(i, script)| format!("{}) {script};;\n", i + 1))
            .collect();
        let program = format!(
            "#!/bin/sh\nd='{}'\n\
             n=$(cat \"$d/n\" 2>/dev/null || echo 0); n=$((n + 1)); echo $n > \"$d/n\"\n\
             cat > \"$d/stdin.$n\"\nprintf '%s\\n' \"$@\" > \"$d/args.$n\"\n\
             case $n in\n{cases}esac\n",
            dir.path().display()
        );
        let path = dir.path().join("fzf");
        fs::write(&path, program).expect("write the script");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).expect("chmod");
        FakeFzf { dir }
    }

    fn program(&self) -> PathBuf {
        self.dir.path().join("fzf")
    }

    fn runs(&self) -> usize {
        fs::read_to_string(self.dir.path().join("n"))
            .map(|n| n.trim().parse().expect("a count"))
            .unwrap_or(0)
    }

    /// What run `n` (from 1) was given on stdin, as lines.
    fn stdin(&self, n: usize) -> Vec<String> {
        self.read(&format!("stdin.{n}"))
    }

    /// What run `n` (from 1) was given as arguments.
    fn args(&self, n: usize) -> Vec<String> {
        self.read(&format!("args.{n}"))
    }

    fn read(&self, name: &str) -> Vec<String> {
        fs::read_to_string(self.dir.path().join(name))
            .expect("the fake fzf ran")
            .lines()
            .map(str::to_string)
            .collect()
    }
}

/// A script that ends on `key` (empty for Enter) with the first line given
/// that contains `text`.
fn choosing(key: &str, text: &str) -> String {
    format!("printf '%s\\n' '{key}'; grep -m1 -F '{text}' \"$d/stdin.$n\"")
}

/// A script that chooses `text` in a second fzf, which has no key to report.
fn choosing_field(text: &str) -> String {
    format!("grep -m1 -F '{text}' \"$d/stdin.$n\"")
}

fn pick(socket: &Path, fzf: &FakeFzf, query: &[&str]) -> Result<String, PickError> {
    let query: Vec<String> = query.iter().map(|word| word.to_string()).collect();
    pick_with(socket, fzf.program().as_os_str(), &query)
}

/// `personal` unlocked with entries, `work` locked.
fn with_entries() -> (Fixture, TempDir, PathBuf) {
    let fx = fixture();
    fx.databases.install_for_test(
        "personal",
        vec![
            TestEntry::new("GitHub")
                .field("UserName", "alice")
                .field("Password", "pw-github")
                .field("URL", "https://github.example")
                .field("api-key", "key-github")
                .field(
                    "otp",
                    "otpauth://totp/Example:alice?secret=JBSWY3DPEHPK3PXP&issuer=Example",
                ),
            TestEntry::new("Bank").field("Password", "pw-bank"),
        ],
    );
    let (dir, socket) = serve(&fx, true);
    (fx, dir, socket)
}

fn offered(fx: &Fixture) -> Vec<String> {
    fx.offered.lock().unwrap().clone()
}

#[test]
fn each_key_copies_its_field_of_the_entry_chosen() {
    let (fx, _dir, socket) = with_entries();
    for (key, expected) in [
        ("", "pw-github"),
        ("ctrl-u", "alice"),
        ("ctrl-l", "https://github.example"),
    ] {
        let fzf = FakeFzf::new(&[&choosing(key, "GitHub")]);
        let said = pick(&socket, &fzf, &[]).expect("picked");
        assert_eq!(offered(&fx).last().map(String::as_str), Some(expected));
        assert!(said.starts_with("copied "), "{said}");
    }

    let fzf = FakeFzf::new(&[&choosing("ctrl-t", "GitHub")]);
    pick(&socket, &fzf, &[]).expect("picked");
    let code = offered(&fx).pop().expect("a code");
    assert!(
        code.len() >= 6 && code.chars().all(|c| c.is_ascii_digit()),
        "{code}"
    );

    // Another entry, so what is copied follows what was chosen.
    let fzf = FakeFzf::new(&[&choosing("", "Bank")]);
    pick(&socket, &fzf, &[]).expect("picked");
    assert_eq!(offered(&fx).pop().as_deref(), Some("pw-bank"));
}

#[test]
fn ctrl_o_chooses_among_the_entrys_own_fields_custom_ones_included() {
    let (fx, _dir, socket) = with_entries();
    let fzf = FakeFzf::new(&[&choosing("ctrl-o", "GitHub"), &choosing_field("api-key")]);

    pick(&socket, &fzf, &[]).expect("picked");

    assert_eq!(offered(&fx), ["key-github"]);
    let fields = fzf.stdin(2);
    for name in ["UserName", "Password", "URL", "totp", "api-key"] {
        assert!(
            fields.iter().any(|line| line.ends_with(name)),
            "{name} in {fields:?}"
        );
    }
    // The second fzf is headed by the entry's title, the first line of its
    // list, which it can't choose, and keeps no history or preview either.
    assert_eq!(fields[0], "\tGitHub");
    let args = fzf.args(2);
    let at = args
        .iter()
        .position(|arg| arg == "--prompt")
        .expect("--prompt");
    assert_eq!(args[at + 1], "field> ");
    assert!(args.contains(&"--header-lines=1".to_string()), "{args:?}");
    assert!(!args.contains(&"--header".to_string()), "{args:?}");
    for flag in [
        "--no-history",
        "--no-preview",
        "--height=60%",
        "--layout=reverse",
    ] {
        assert!(args.contains(&flag.to_string()), "{flag} in {args:?}");
    }
}

/// No vault text is on either fzf's command line, which another uid can read
/// while the chooser is open: not an entry's title, of whatever length, nor
/// its username, nor the name of a field. The entry's title reaches the field
/// chooser on its list, cut to its budget, with the fields after it.
#[test]
fn no_entry_text_is_on_either_fzfs_command_line() {
    let long = format!("TITLEMARK{}", "x".repeat(200_000));
    for title in ["TITLEMARK", long.as_str()] {
        let fx = fixture();
        fx.databases.install_for_test(
            "personal",
            vec![
                TestEntry::new(title)
                    .field("UserName", "USERMARK")
                    .field("Password", "pw-mark")
                    .field("FIELDMARK", "value-mark"),
            ],
        );
        let (_dir, socket) = serve(&fx, true);
        let fzf = FakeFzf::new(&[
            &choosing("ctrl-o", "TITLEMARK"),
            &choosing_field("FIELDMARK"),
        ]);

        pick(&socket, &fzf, &[]).expect("picked");

        assert_eq!(offered(&fx), ["value-mark"]);
        for run in [1, 2] {
            for arg in fzf.args(run) {
                assert!(arg.len() < 1000, "run {run}: {} bytes", arg.len());
                for text in ["TITLEMARK", "USERMARK", "FIELDMARK", "mark"] {
                    assert!(!arg.contains(text), "run {run}: {text} in {arg}");
                }
            }
        }
        let list = fzf.stdin(2);
        assert_eq!(list.len(), 1 + 3, "{list:?}");
        assert!(
            list[0].starts_with("\tTITLEMARK") && list[0].len() <= 1 + 64,
            "{}",
            list[0]
        );
        assert!(list[1..].iter().any(|line| line.ends_with("FIELDMARK")));
    }
}

#[test]
fn fzf_gets_the_query_and_a_line_per_entry_with_no_secret_in_it() {
    let (_fx, _dir, socket) = with_entries();
    let fzf = FakeFzf::new(&[&choosing("", "Bank")]);

    pick(&socket, &fzf, &["git", "hub"]).expect("picked");

    let args = fzf.args(1);
    let at = args
        .iter()
        .position(|arg| arg == "--query")
        .expect("--query");
    assert_eq!(args[at + 1], "git hub");
    // Whatever the environment's fzf options say, no history is kept and no
    // preview runs.
    for flag in ["--no-history", "--no-preview"] {
        assert!(args.contains(&flag.to_string()), "{flag} in {args:?}");
    }
    assert!(!args.iter().any(|arg| arg.starts_with("--history")));
    let lines = fzf.stdin(1);
    assert_eq!(lines.len(), 2);
    let all = lines.join("\n");
    assert!(all.contains("GitHub") && all.contains("alice") && all.contains("personal"));
    for secret in ["pw-github", "pw-bank", "key-github", "github.example"] {
        assert!(!all.contains(secret), "{secret}");
    }
}

/// An entry's title and username are vault text: nothing in them can add a
/// line or a field, or reach the terminal raw, and the line chosen is still
/// the entry it came from.
#[test]
fn hostile_entry_text_is_escaped_and_the_choice_still_names_its_entry() {
    let fx = fixture();
    fx.databases.install_for_test(
        "personal",
        vec![
            TestEntry::new("decoy").field("Password", "pw-decoy"),
            TestEntry::new("evil\u{1b}[2J\t0\tx\nsecond line\u{202e}")
                .field("UserName", "u\r\u{7}")
                .field("Password", "pw-evil"),
        ],
    );
    let (_dir, socket) = serve(&fx, true);
    let fzf = FakeFzf::new(&[&choosing("", "evil")]);

    pick(&socket, &fzf, &[]).expect("picked");

    let lines = fzf.stdin(1);
    assert_eq!(lines.len(), 2, "{lines:?}");
    for line in &lines {
        assert_eq!(line.matches('\t').count(), 1, "{line:?}");
        assert!(
            !line.contains(['\u{1b}', '\u{7}', '\r', '\u{202e}']),
            "{line:?}"
        );
    }
    assert_eq!(offered(&fx), ["pw-evil"]);
}

/// A field's name is the entry author's text, and the sentence that says what
/// was copied is one line whatever it holds: a newline in a name can't start a
/// second line, nor a quote end the name and carry on the sentence.
#[test]
fn the_sentence_for_a_field_with_a_hostile_name_is_one_line() {
    let forged = "x\ncopied password of \"Bank\" from \"work\"; the clipboard clears in 60s";
    let fx = fixture();
    fx.databases.install_for_test(
        "personal",
        vec![
            TestEntry::new("GitHub")
                .field("Password", "pw-github")
                .field("a\nb\tc", "value-ab")
                .field(forged, "value-forged"),
        ],
    );
    let (_dir, socket) = serve(&fx, true);

    for (marker, value) in [
        ("a\\u000ab", "value-ab"),
        ("x\\u000acopied", "value-forged"),
    ] {
        let fzf = FakeFzf::new(&[&choosing("ctrl-o", "GitHub"), &choosing_field(marker)]);

        let said = pick(&socket, &fzf, &[]).expect("picked");

        assert_eq!(offered(&fx).pop().as_deref(), Some(value));
        assert!(!said.contains(['\n', '\t', '\r']), "{said:?}");
        assert!(
            said.starts_with("copied \"")
                && said.ends_with(" from \"personal\"; the clipboard clears in 30s"),
            "{said:?}"
        );
        // The title and the database are quoted the same way.
        assert!(
            said.contains("\" of \"GitHub\" from \"personal\"; the clipboard"),
            "{said:?}"
        );
    }
}

#[test]
fn without_fzf_the_error_names_it_and_nothing_is_copied() {
    let (fx, _dir, socket) = with_entries();
    let missing = Path::new("/nonexistent/fzf");

    let err = pick_with(&socket, missing.as_os_str(), &[]).expect_err("no fzf");

    assert!(matches!(err, PickError::NoFzf), "{err:?}");
    assert!(err.to_string().contains("fzf"), "{err}");
    assert!(offered(&fx).is_empty());
}

/// A requester that can't copy is stopped on `status`, though there are
/// entries to pick: fzf is never started and no prompt is asked.
#[test]
fn a_requester_that_cannot_copy_is_refused_before_anything_is_listed() {
    let fx = fixture();
    fx.databases
        .install_for_test("personal", vec![TestEntry::new("GitHub")]);
    let (_dir, socket) = serve(&fx, false);
    let fzf = FakeFzf::new(&[&choosing("", "x")]);

    let err = pick(&socket, &fzf, &[]).expect_err("refused");

    assert!(matches!(err, PickError::CannotCopy), "{err:?}");
    assert!(err.to_string().contains("no_display"), "{err}");
    assert_eq!(fzf.runs(), 0);
    assert!(fx.offered.lock().unwrap().is_empty());
    assert!(fx.prompts.shown().is_empty());
}

/// Every database locked: `pick` says so and names one to unlock, and
/// neither unlocks nor asks anything.
#[test]
fn with_every_database_locked_it_fails_naming_one_to_unlock() {
    let fx = fixture();
    let (_dir, socket) = serve(&fx, true);
    let fzf = FakeFzf::new(&[&choosing("", "x")]);

    let err = pick(&socket, &fzf, &[]).expect_err("all locked");

    assert!(matches!(err, PickError::AllLocked(_)), "{err:?}");
    assert!(err.to_string().contains("kpa unlock personal"), "{err}");
    assert_eq!(fzf.runs(), 0);
    assert!(!fx.databases.any_unlocked());
    assert!(fx.prompts.shown().is_empty());
}

/// Some database unlocked: the locked ones are named in fzf's header, and
/// nothing is unlocked.
#[test]
fn with_some_database_unlocked_the_locked_ones_are_named_in_the_header_only() {
    let (fx, _dir, socket) = with_entries();
    let fzf = FakeFzf::new(&[&choosing("", "Bank")]);

    pick(&socket, &fzf, &[]).expect("picked");

    let args = fzf.args(1);
    let at = args
        .iter()
        .position(|arg| arg == "--header")
        .expect("--header");
    // The header is the keys, then the locked databases, a line each.
    assert_eq!(args[at + 1], keys::HELP);
    assert_eq!(args[at + 2], "locked: work");
    assert!(fx.prompts.shown().is_empty());
    assert!(
        fx.databases
            .snapshot()
            .iter()
            .any(|database| database.name == "work" && database.is_locked())
    );
}

#[test]
fn leaving_fzf_without_choosing_copies_nothing() {
    let (fx, _dir, socket) = with_entries();
    let fzf = FakeFzf::new(&["exit 130"]);

    let err = pick(&socket, &fzf, &[]).expect_err("cancelled");

    assert!(matches!(err, PickError::Cancelled), "{err:?}");
    assert!(offered(&fx).is_empty());
}

#[test]
fn a_field_the_entry_lacks_is_the_daemons_refusal() {
    let (fx, _dir, socket) = with_entries();
    let fzf = FakeFzf::new(&[&choosing("ctrl-u", "Bank")]);

    let err = pick(&socket, &fzf, &[]).expect_err("no username");

    assert!(err.to_string().contains("field_empty"), "{err}");
    assert!(offered(&fx).is_empty());
}

/// Answers each connection with the next of `replies`, and hands back the
/// request lines it read.
fn canned_daemon(replies: Vec<String>) -> (TempDir, PathBuf, thread::JoinHandle<Vec<String>>) {
    let dir = tempfile::tempdir().expect("temp dir");
    let socket = dir.path().join("sock");
    let listener = UnixListener::bind(&socket).expect("bind");
    let server = thread::spawn(move || {
        let mut requests = Vec::new();
        for reply in replies {
            let (mut stream, _) = listener.accept().expect("accept");
            let mut line = String::new();
            BufReader::new(&stream)
                .read_line(&mut line)
                .expect("read the request");
            requests.push(line);
            writeln!(stream, "{reply}").expect("answer");
        }
        requests
    });
    (dir, socket, server)
}

/// A daemon that predates `can_copy` doesn't send it. The field is advisory,
/// so the pick goes on and `copy` decides.
#[test]
fn a_status_without_can_copy_is_not_a_refusal() {
    let (_dir, socket, server) = canned_daemon(vec![
        r#"{"v":3,"ok":true,"databases":[{"name":"personal","locked":false,"entries":1}],"version":"0.2.0"}"#.to_string(),
        r#"{"v":3,"ok":true,"entries":[{"db":"personal","uuid":"00000000-0000-0000-0000-000000000000","title":"GitHub","group":"Dev","fields":["Password"]}]}"#.to_string(),
        r#"{"v":3,"ok":true,"copied":"Password","expires_in":30}"#.to_string(),
    ]);
    let fzf = FakeFzf::new(&[&choosing("", "GitHub")]);

    let said = pick(&socket, &fzf, &[]).expect("picked");

    let requests = server.join().expect("daemon thread");
    assert_eq!(requests.len(), 3);
    assert!(requests[2].contains(r#""op":"copy""#), "{}", requests[2]);
    assert!(
        requests[2].contains(r#""field":"Password""#),
        "{}",
        requests[2]
    );
    assert!(said.contains("Password") && said.contains("30s"), "{said}");
}

#[test]
fn a_status_saying_no_stops_after_that_one_request() {
    let (_dir, socket, server) = canned_daemon(vec![
        r#"{"v":3,"ok":true,"databases":[{"name":"personal","locked":false,"entries":1}],"version":"1","can_copy":false}"#.to_string(),
    ]);
    let fzf = FakeFzf::new(&[&choosing("", "x")]);

    let err = pick(&socket, &fzf, &[]).expect_err("refused");

    assert!(matches!(err, PickError::CannotCopy), "{err:?}");
    assert_eq!(server.join().expect("daemon thread").len(), 1);
    assert_eq!(fzf.runs(), 0);
}
