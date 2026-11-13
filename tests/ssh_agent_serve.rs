//! Integration tests for the local SSH agent (`docs/ssh-agent.md` § 6),
//! driving `kpa`'s agent socket with the real OpenSSH tools against the
//! `fixture-ssh.kdbx` fixture.

mod common;

use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::process::Command;

use common::InProcessDaemon;

/// A config with one database, `personal`, pointed at `db_path`, serving
/// SSH keys. `prompt` always answers with `common::PASSWORD` — these tests
/// aren't about the unlock prompt itself — and the approval prompt always
/// answers `Allow`.
fn config(db_path: &Path) -> String {
    format!(
        "prompt = [\"/bin/sh\", \"-c\", \"printf {password}\"]\n\n\
         [ssh_agent]\n\
         confirm_prompt = [\"/bin/sh\", \"-c\", \"head -n1\"]\n\n\
         [[database]]\n\
         name = \"personal\"\n\
         path = \"{path}\"\n\
         serve_ssh_keys = true\n",
        password = common::PASSWORD,
        path = db_path.display(),
    )
}

/// The running SSH agent socket for a `daemon`'s `Server`, in its own
/// tempdir, with its own SSH key cache — isolated from this process's
/// real `$XDG_CACHE_HOME`, the same reasoning `Config::expand_home`
/// taking `home` as a parameter is for `$HOME`.
struct SshAgent {
    socket: PathBuf,
    _socket_dir: tempfile::TempDir,
    _cache_dir: tempfile::TempDir,
}

fn start_ssh_agent(daemon: &InProcessDaemon) -> SshAgent {
    let socket_dir = tempfile::tempdir().expect("tempdir");
    let socket = socket_dir.path().join("agent.sock");
    let cache_dir = tempfile::tempdir().expect("tempdir");
    daemon
        .server
        .assume_ssh_cache_dir(cache_dir.path().to_path_buf());
    let listener = UnixListener::bind(&socket).expect("bind ssh agent socket");
    let server = daemon.server.clone();
    std::thread::spawn(move || kpa::ssh_agent::serve::serve(server, listener));
    SshAgent {
        socket,
        _socket_dir: socket_dir,
        _cache_dir: cache_dir,
    }
}

fn ssh_add<'a>(agent: &SshAgent, args: impl IntoIterator<Item = &'a str>) -> std::process::Output {
    Command::new("ssh-add")
        .args(args)
        .env("SSH_AUTH_SOCK", &agent.socket)
        .output()
        .expect("failed to spawn ssh-add")
}

fn stdout(output: &std::process::Output) -> String {
    String::from_utf8_lossy(&output.stdout).to_string()
}

#[test]
fn ssh_add_lists_nothing_without_a_cache_and_refuses_to_add_or_remove() {
    let daemon = InProcessDaemon::start(&config(&common::ssh_db()));
    let agent = start_ssh_agent(&daemon);

    let listed = ssh_add(&agent, ["-L"]);
    assert!(
        !listed.status.success(),
        "a fresh cache should list nothing: {}",
        stdout(&listed)
    );

    // The agent never accepts a key or a secret (docs/ssh-agent.md § 6.1).
    assert!(!ssh_add(&agent, ["-D"]).status.success());
    assert!(!ssh_add(&agent, ["-x"]).status.success());
}

/// `ssh-add -L`'s comment column is each key's name — the entry title
/// while unlocked, per `docs/ssh-agent.md` § 6.4 "Names".
fn public_key_line(listed: &str, title: &str) -> String {
    listed
        .lines()
        .find(|line| line.ends_with(title))
        .unwrap_or_else(|| panic!("no identity named {title:?} in: {listed:?}"))
        .to_string()
}

#[test]
fn identities_list_from_the_cache_while_locked_and_live_once_unlocked() {
    let daemon = InProcessDaemon::start(&config(&common::ssh_db()));
    let agent = start_ssh_agent(&daemon);

    assert_eq!(daemon.run(&["unlock", "personal"])["ok"], true);
    let unlocked = stdout(&ssh_add(&agent, ["-L"]));
    for title in ["Ed25519", "Ecdsa", "Rsa"] {
        public_key_line(&unlocked, title);
    }
    assert!(
        !unlocked.contains("Pem"),
        "the skipped PEM attachment must never be listed"
    );

    assert_eq!(daemon.run(&["lock", "personal"])["ok"], true);
    let locked = stdout(&ssh_add(&agent, ["-L"]));
    // The cache holds no titles, so a locked listing falls back to
    // "<database> <fingerprint>" instead.
    for title in ["Ed25519", "Ecdsa", "Rsa"] {
        assert!(
            !locked.contains(title),
            "a locked listing must not show titles: {locked:?}"
        );
    }
    assert!(locked.contains("personal SHA256:"));
}

/// Writes `line` (one `ssh-add -L` line) to its own file, for
/// `ssh-keygen -Y sign`'s `-f`.
fn write_pubkey(dir: &Path, name: &str, line: &str) -> PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, format!("{line}\n")).expect("write pubkey");
    path
}

#[test]
fn signing_and_verifying_works_after_unlock_and_approval() {
    let daemon = InProcessDaemon::start(&config(&common::ssh_db()));
    let agent = start_ssh_agent(&daemon);
    let dir = tempfile::tempdir().expect("tempdir");

    assert_eq!(daemon.run(&["unlock", "personal"])["ok"], true);
    let listed = stdout(&ssh_add(&agent, ["-L"]));
    let pubkey_line = public_key_line(&listed, "Ed25519");
    let pubkey_path = write_pubkey(dir.path(), "key.pub", &pubkey_line);

    let data_path = dir.path().join("data");
    std::fs::write(&data_path, b"hello ssh agent").expect("write data");

    let sign = Command::new("ssh-keygen")
        .args(["-Y", "sign", "-f"])
        .arg(&pubkey_path)
        .args(["-n", "test"])
        .arg(&data_path)
        .env("SSH_AUTH_SOCK", &agent.socket)
        .output()
        .expect("failed to spawn ssh-keygen -Y sign");
    assert!(
        sign.status.success(),
        "signing should succeed after the approval prompt answers Allow: {}",
        String::from_utf8_lossy(&sign.stderr)
    );

    let allowed_signers = dir.path().join("allowed_signers");
    std::fs::write(&allowed_signers, format!("tester {pubkey_line}\n")).expect("write");

    let verify = Command::new("ssh-keygen")
        .args(["-Y", "verify", "-f"])
        .arg(&allowed_signers)
        .args(["-I", "tester", "-n", "test", "-s"])
        .arg(data_path.with_extension("sig"))
        .stdin(std::process::Stdio::from(
            std::fs::File::open(&data_path).expect("open data"),
        ))
        .output()
        .expect("failed to spawn ssh-keygen -Y verify");
    assert!(
        verify.status.success(),
        "verification should accept kpa's signature: {}",
        String::from_utf8_lossy(&verify.stderr)
    );

    // A second signature with the same key doesn't need another approval.
    let sign_again = Command::new("ssh-keygen")
        .args(["-Y", "sign", "-f"])
        .arg(&pubkey_path)
        .args(["-n", "test"])
        .arg(&data_path)
        .env("SSH_AUTH_SOCK", &agent.socket)
        .env("SSH_ASKPASS", "")
        .output()
        .expect("failed to spawn ssh-keygen -Y sign");
    assert!(sign_again.status.success());
}

#[test]
fn locking_makes_signing_fail_again() {
    let daemon = InProcessDaemon::start(&config(&common::ssh_db()));
    let agent = start_ssh_agent(&daemon);
    let dir = tempfile::tempdir().expect("tempdir");

    assert_eq!(daemon.run(&["unlock", "personal"])["ok"], true);
    let listed = stdout(&ssh_add(&agent, ["-L"]));
    let pubkey_line = public_key_line(&listed, "Ed25519");
    let pubkey_path = write_pubkey(dir.path(), "key.pub", &pubkey_line);
    let data_path = dir.path().join("data");
    std::fs::write(&data_path, b"hello again").expect("write data");

    assert_eq!(daemon.run(&["lock", "personal"])["ok"], true);

    let sign = Command::new("ssh-keygen")
        .args(["-Y", "sign", "-f"])
        .arg(&pubkey_path)
        .args(["-n", "test"])
        .arg(&data_path)
        .env("SSH_AUTH_SOCK", &agent.socket)
        .output()
        .expect("failed to spawn ssh-keygen -Y sign");
    assert!(
        !sign.status.success(),
        "signing with a locked database must fail"
    );
}
