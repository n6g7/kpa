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
/// aren't about the unlock prompt itself — and the confirm prompt always
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
/// tempdir. The key cache is the daemon's own, under its tempdir
/// (`InProcessDaemon::paths`), never this process's real
/// `$XDG_CACHE_HOME`.
struct SshAgent {
    socket: PathBuf,
    _socket_dir: tempfile::TempDir,
}

fn start_ssh_agent(daemon: &InProcessDaemon) -> SshAgent {
    let socket_dir = tempfile::tempdir().expect("tempdir");
    let socket = socket_dir.path().join("agent.sock");
    let listener = UnixListener::bind(&socket).expect("bind ssh agent socket");
    kpa::authn::assume_cgroup(&socket, &daemon.cgroup);
    let server = daemon.server.clone();
    std::thread::spawn(move || kpa::server::serve_ssh_agent(server, listener));
    SshAgent {
        socket,
        _socket_dir: socket_dir,
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

/// With nothing cached and the database locked, `ssh-add -L` reaches the
/// agent and hears it has no identities (exit 1; 2 would mean it couldn't
/// connect). The agent never takes a key or a secret either
/// (`docs/ssh-agent.md` § 6.1): adding a key, removing every key and
/// locking the agent all fail.
#[test]
fn ssh_add_lists_nothing_without_a_cache_and_never_takes_a_key() {
    use std::os::unix::fs::OpenOptionsExt as _;

    let daemon = InProcessDaemon::start(&config(&common::ssh_db()));
    let agent = start_ssh_agent(&daemon);

    let listed = ssh_add(&agent, ["-L"]);
    assert_eq!(
        listed.status.code(),
        Some(1),
        "a fresh cache should list nothing: {}",
        stdout(&listed)
    );

    let dir = tempfile::tempdir().expect("tempdir");
    let keyfile = dir.path().join("id_ed25519");
    let pem = raw::throwaway_key(7)
        .to_openssh(ssh_key::LineEnding::LF)
        .expect("key encodes");
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&keyfile)
        .and_then(|mut file| std::io::Write::write_all(&mut file, pem.as_bytes()))
        .expect("write key file");
    let keyfile = keyfile.to_str().expect("utf-8 path");
    assert!(!ssh_add(&agent, [keyfile]).status.success());
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

/// `ssh-keygen -Y sign` of `data_path` with the public key at
/// `pubkey_path`, through `agent`: its signature lands next to the data.
fn sign(agent: &SshAgent, pubkey_path: &Path, data_path: &Path) -> std::process::Output {
    Command::new("ssh-keygen")
        .args(["-Y", "sign", "-f"])
        .arg(pubkey_path)
        .args(["-n", "test"])
        .arg(data_path)
        .env("SSH_AUTH_SOCK", &agent.socket)
        .output()
        .expect("failed to spawn ssh-keygen -Y sign")
}

/// Signs `data_path` with the identity named `title`, verifies it, and
/// signs the same data again: the first signature raises one approval
/// prompt (counted in `counter`), the second none.
fn sign_and_verify(agent: &SshAgent, dir: &Path, listed: &str, title: &str, counter: &Path) {
    let pubkey_line = public_key_line(listed, title);
    let pubkey_path = write_pubkey(dir, &format!("{title}.pub"), &pubkey_line);
    let data_path = dir.join(format!("{title}-data"));
    std::fs::write(&data_path, format!("hello from {title}")).expect("write data");
    let prompts = count_lines(counter);

    let signed = sign(agent, &pubkey_path, &data_path);
    assert!(
        signed.status.success(),
        "{title}: signing should succeed after the confirm prompt answers Allow: {}",
        String::from_utf8_lossy(&signed.stderr)
    );
    assert_eq!(count_lines(counter), prompts + 1, "{title}: one prompt");

    let allowed_signers = dir.join(format!("{title}-allowed_signers"));
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
        "{title}: verification should accept kpa's signature: {}",
        String::from_utf8_lossy(&verify.stderr)
    );

    let signed_again = sign(agent, &pubkey_path, &data_path);
    assert!(
        signed_again.status.success(),
        "{title}: a second signature with the same key should succeed"
    );
    assert_eq!(
        count_lines(counter),
        prompts + 1,
        "{title}: a second signature with the same key shouldn't need another approval"
    );
}

/// Every served key type (`docs/ssh-agent.md` § 6.5) can sign and the
/// result verifies, both through the real OpenSSH tools.
#[test]
fn signing_and_verifying_works_after_unlock_and_approval() {
    let dir = tempfile::tempdir().expect("tempdir");
    let counter = dir.path().join("prompts");
    let daemon = InProcessDaemon::start(&config_counting_prompts(&common::ssh_db(), &counter));
    let agent = start_ssh_agent(&daemon);

    assert_eq!(daemon.run(&["unlock", "personal"])["ok"], true);
    let listed = stdout(&ssh_add(&agent, ["-L"]));
    for title in ["Ed25519", "Ecdsa", "Rsa"] {
        sign_and_verify(&agent, dir.path(), &listed, title, &counter);
    }
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

    assert!(
        !sign(&agent, &pubkey_path, &data_path).status.success(),
        "signing with a locked database must fail"
    );
}

/// A config whose confirm prompt appends a line to `counter` on every
/// invocation (always answering `Allow`), with `[[database.ssh_key]]`
/// overriding `fingerprint`'s `confirm` setting.
fn config_with_override(
    db_path: &Path,
    counter: &Path,
    fingerprint: &str,
    confirm: &str,
) -> String {
    format!(
        "prompt = [\"/bin/sh\", \"-c\", \"printf {password}\"]\n\n\
         [ssh_agent]\n\
         confirm_prompt = [\"/bin/sh\", \"-c\", \"echo x >> '{counter}'; head -n1\"]\n\n\
         [[database]]\n\
         name = \"personal\"\n\
         path = \"{path}\"\n\
         serve_ssh_keys = true\n\n\
         [[database.ssh_key]]\n\
         fingerprint = \"{fingerprint}\"\n\
         confirm = \"{confirm}\"\n",
        password = common::PASSWORD,
        counter = counter.display(),
        path = db_path.display(),
    )
}

fn count_lines(path: &Path) -> usize {
    std::fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .count()
}

/// `confirm = "always"` asks on every signature, forwarded or not — here,
/// three signatures with the same key and destination each raise their own
/// prompt (`docs/ssh-agent.md` § 6.7).
#[test]
fn confirm_always_prompts_every_signature() {
    let fingerprint = common::ssh_fixture_fingerprint("Ed25519");
    let counter_dir = tempfile::tempdir().expect("tempdir");
    let counter = counter_dir.path().join("prompts");
    let daemon = InProcessDaemon::start(&config_with_override(
        &common::ssh_db(),
        &counter,
        &fingerprint,
        "always",
    ));
    let agent = start_ssh_agent(&daemon);
    let dir = tempfile::tempdir().expect("tempdir");

    assert_eq!(daemon.run(&["unlock", "personal"])["ok"], true);
    let listed = stdout(&ssh_add(&agent, ["-L"]));
    let pubkey_line = public_key_line(&listed, "Ed25519");
    let pubkey_path = write_pubkey(dir.path(), "key.pub", &pubkey_line);
    let data_path = dir.path().join("data");
    std::fs::write(&data_path, b"always").expect("write data");

    for i in 0..3 {
        assert!(
            sign(&agent, &pubkey_path, &data_path).status.success(),
            "sign {i} should succeed"
        );
    }
    assert_eq!(
        count_lines(&counter),
        3,
        "confirm = always should prompt on every signature"
    );
}

/// `confirm = "never"` never asks for local use — the confirm prompt here
/// would fail the test outright if it were ever invoked, so a successful
/// signature already proves it wasn't.
#[test]
fn confirm_never_never_prompts() {
    let fingerprint = common::ssh_fixture_fingerprint("Ed25519");
    let marker_dir = tempfile::tempdir().expect("tempdir");
    let marker = marker_dir.path().join("prompted");
    let daemon = InProcessDaemon::start(&format!(
        "prompt = [\"/bin/sh\", \"-c\", \"printf {password}\"]\n\n\
         [ssh_agent]\n\
         confirm_prompt = [\"/bin/sh\", \"-c\", \"touch '{marker}'; exit 1\"]\n\n\
         [[database]]\n\
         name = \"personal\"\n\
         path = \"{path}\"\n\
         serve_ssh_keys = true\n\n\
         [[database.ssh_key]]\n\
         fingerprint = \"{fingerprint}\"\n\
         confirm = \"never\"\n",
        password = common::PASSWORD,
        marker = marker.display(),
        path = common::ssh_db().display(),
    ));
    let agent = start_ssh_agent(&daemon);
    let dir = tempfile::tempdir().expect("tempdir");

    assert_eq!(daemon.run(&["unlock", "personal"])["ok"], true);
    let listed = stdout(&ssh_add(&agent, ["-L"]));
    let pubkey_line = public_key_line(&listed, "Ed25519");
    let pubkey_path = write_pubkey(dir.path(), "key.pub", &pubkey_line);
    let data_path = dir.path().join("data");
    std::fs::write(&data_path, b"never").expect("write data");

    let signed = sign(&agent, &pubkey_path, &data_path);
    assert!(
        signed.status.success(),
        "confirm = never should sign without a prompt: {}",
        String::from_utf8_lossy(&signed.stderr)
    );
    assert!(
        !marker.exists(),
        "confirm = never must never run the confirm prompt"
    );
}

/// A lock drops every approval along with the key cache
/// (`docs/ssh-agent.md` § 6.9): re-unlocking the same database asks again,
/// rather than remembering the approval across the lock.
#[test]
fn locking_clears_approvals() {
    let fingerprint = common::ssh_fixture_fingerprint("Ed25519");
    let counter_dir = tempfile::tempdir().expect("tempdir");
    let counter = counter_dir.path().join("prompts");
    let daemon = InProcessDaemon::start(&config_with_override(
        &common::ssh_db(),
        &counter,
        &fingerprint,
        "once",
    ));
    let agent = start_ssh_agent(&daemon);
    let dir = tempfile::tempdir().expect("tempdir");

    assert_eq!(daemon.run(&["unlock", "personal"])["ok"], true);
    let listed = stdout(&ssh_add(&agent, ["-L"]));
    let pubkey_line = public_key_line(&listed, "Ed25519");
    let pubkey_path = write_pubkey(dir.path(), "key.pub", &pubkey_line);
    let data_path = dir.path().join("data");
    std::fs::write(&data_path, b"before and after a lock").expect("write data");

    let sign_once = |label: &str| {
        assert!(
            sign(&agent, &pubkey_path, &data_path).status.success(),
            "{label} sign should succeed"
        );
    };

    sign_once("first");
    assert_eq!(count_lines(&counter), 1);

    assert_eq!(daemon.run(&["lock", "personal"])["ok"], true);
    assert_eq!(daemon.run(&["unlock", "personal"])["ok"], true);

    sign_once("after re-unlock");
    assert_eq!(
        count_lines(&counter),
        2,
        "a lock should have dropped the earlier approval"
    );
}

/// A lock in flight kills an SSH confirm prompt exactly like it kills
/// `unlock`'s own: once the prompt is up (it touches a marker first),
/// `ssh-keygen -Y sign` fails quickly rather than waiting out the whole
/// (deliberately long) prompt.
#[test]
fn locking_kills_an_open_approval_prompt() {
    let marker_dir = tempfile::tempdir().expect("tempdir");
    let marker = marker_dir.path().join("prompt-up");
    let daemon = InProcessDaemon::start(&format!(
        "prompt = [\"/bin/sh\", \"-c\", \"printf {password}\"]\n\n\
         [ssh_agent]\n\
         confirm_prompt = [\"/bin/sh\", \"-c\", \"touch '{marker}'; sleep 30; printf Allow\"]\n\n\
         [[database]]\n\
         name = \"personal\"\n\
         path = \"{path}\"\n\
         serve_ssh_keys = true\n",
        password = common::PASSWORD,
        marker = marker.display(),
        path = common::ssh_db().display(),
    ));
    let agent = start_ssh_agent(&daemon);
    let dir = tempfile::tempdir().expect("tempdir");

    assert_eq!(daemon.run(&["unlock", "personal"])["ok"], true);
    let listed = stdout(&ssh_add(&agent, ["-L"]));
    let pubkey_line = public_key_line(&listed, "Ed25519");
    let pubkey_path = write_pubkey(dir.path(), "key.pub", &pubkey_line);
    let data_path = dir.path().join("data");
    std::fs::write(&data_path, b"interrupted").expect("write data");

    let socket = agent.socket.clone();
    let sign_thread = std::thread::spawn(move || {
        Command::new("ssh-keygen")
            .args(["-Y", "sign", "-f"])
            .arg(&pubkey_path)
            .args(["-n", "test"])
            .arg(&data_path)
            .env("SSH_AUTH_SOCK", socket)
            .output()
            .expect("failed to spawn ssh-keygen -Y sign")
    });

    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    while !marker.exists() {
        assert!(
            std::time::Instant::now() < deadline,
            "the confirm prompt never came up"
        );
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    let started = std::time::Instant::now();
    assert_eq!(daemon.run(&["lock", "personal"])["ok"], true);

    let sign = sign_thread.join().expect("sign thread panicked");
    assert!(
        !sign.status.success(),
        "a signature whose confirm prompt got killed by a lock must not succeed"
    );
    assert!(
        started.elapsed() < std::time::Duration::from_secs(10),
        "the confirm prompt should have been killed by the lock, not run its full 30s"
    );
}

/// Raw agent-protocol driving, for cases the real OpenSSH tools can't
/// easily exercise: binding a connection to a specific (fake) destination
/// host key, and claiming `is_forwarding` — both without needing a real
/// `sshd`.
mod raw {
    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;
    use std::path::Path;

    use signature::Signer;
    use ssh_key::encoding::Encode;
    use ssh_key::{Algorithm, PrivateKey};

    /// A deterministic, non-cryptographic stand-in for `OsRng` — these
    /// tests only need *a* valid keypair. It duplicates
    /// `src/ssh_agent/testing.rs`'s, which is test-only code inside the
    /// library crate and so out of reach of an integration test.
    pub struct TestRng(pub u64);

    impl TestRng {
        fn next(&mut self) -> u64 {
            self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^ (z >> 31)
        }
    }

    impl ssh_key::rand_core::TryRng for TestRng {
        type Error = std::convert::Infallible;

        fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
            Ok(self.next() as u32)
        }

        fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
            Ok(self.next())
        }

        fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
            for chunk in dst.chunks_mut(8) {
                chunk.copy_from_slice(&self.next().to_le_bytes()[..chunk.len()]);
            }
            Ok(())
        }
    }

    impl ssh_key::rand_core::TryCryptoRng for TestRng {}

    pub fn throwaway_key(seed: u64) -> PrivateKey {
        PrivateKey::random(&mut TestRng(seed), Algorithm::Ed25519).expect("key generation")
    }

    fn string(bytes: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + bytes.len());
        out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
        out.extend_from_slice(bytes);
        out
    }

    /// `EXTENSION session-bind@openssh.com`, signed by `host`.
    pub fn session_bind(host: &PrivateKey, session_id: &[u8], is_forwarding: bool) -> Vec<u8> {
        let sig: ssh_key::Signature = host.try_sign(session_id).expect("sign session id");
        let mut message = vec![27u8];
        message.extend(string(b"session-bind@openssh.com"));
        message.extend(string(
            &host.public_key().to_bytes().expect("encode hostkey"),
        ));
        message.extend(string(session_id));
        message.extend(string(&sig.encode_vec().expect("encode signature")));
        message.push(u8::from(is_forwarding));
        message
    }

    /// `SIGN_REQUEST`, `data` already built (e.g. by [`login_data`]).
    pub fn sign_request(key_blob: &[u8], data: &[u8]) -> Vec<u8> {
        let mut message = vec![13u8];
        message.extend(string(key_blob));
        message.extend(string(data));
        message.extend_from_slice(&0u32.to_be_bytes());
        message
    }

    /// A well-formed SSH login signing request (`docs/ssh-agent.md` § 6.3),
    /// matching what OpenSSH's own `ssh` builds in `sign_and_send_pubkey`.
    pub fn login_data(session_id: &[u8], user: &str, pkalg: &str, key_blob: &[u8]) -> Vec<u8> {
        let mut data = string(session_id);
        data.push(50); // SSH2_MSG_USERAUTH_REQUEST
        data.extend(string(user.as_bytes()));
        data.extend(string(b"ssh-connection"));
        data.extend(string(b"publickey"));
        data.push(1); // sig-follows
        data.extend(string(pkalg.as_bytes()));
        data.extend(string(key_blob));
        data
    }

    /// A connection to the agent socket, for sending frames built above and
    /// reading back just the response's type byte — all these tests need.
    pub struct Connection(UnixStream);

    impl Connection {
        pub fn open(socket: &Path) -> Connection {
            Connection(UnixStream::connect(socket).expect("connect to ssh agent socket"))
        }

        /// Sends `message` framed, and returns the response's type byte
        /// (`6` = `SUCCESS`, `14` = `SIGN_RESPONSE`, `28` =
        /// `EXTENSION_FAILURE`, `5` = `FAILURE`).
        pub fn send(&mut self, message: &[u8]) -> u8 {
            self.0
                .write_all(&kpa::ssh_agent::wire::encode_frame(message))
                .expect("write request");
            let mut len_buf = [0u8; 4];
            self.0
                .read_exact(&mut len_buf)
                .expect("read response length");
            let len = u32::from_be_bytes(len_buf) as usize;
            let mut body = vec![0u8; len];
            self.0.read_exact(&mut body).expect("read response body");
            body[0]
        }
    }
}

/// A config whose confirm prompt counts its invocations, with no
/// per-key overrides — every served key keeps the default `confirm =
/// "once"`.
fn config_counting_prompts(db_path: &Path, counter: &Path) -> String {
    format!(
        "prompt = [\"/bin/sh\", \"-c\", \"printf {password}\"]\n\n\
         [ssh_agent]\n\
         confirm_prompt = [\"/bin/sh\", \"-c\", \"echo x >> '{counter}'; head -n1\"]\n\n\
         [[database]]\n\
         name = \"personal\"\n\
         path = \"{path}\"\n\
         serve_ssh_keys = true\n",
        password = common::PASSWORD,
        counter = counter.display(),
        path = db_path.display(),
    )
}

/// A local, bound connection's first signature for a destination prompts;
/// a second signature to that *same* destination, over the same
/// connection, doesn't; a *different* destination — a fresh connection
/// bound to a different host key — prompts again
/// (`docs/ssh-agent.md` § 6.7).
#[test]
fn a_different_destination_prompts_again_but_the_same_one_does_not() {
    use base64::Engine as _;

    let counter_dir = tempfile::tempdir().expect("tempdir");
    let counter = counter_dir.path().join("prompts");
    let daemon = InProcessDaemon::start(&config_counting_prompts(&common::ssh_db(), &counter));
    let agent = start_ssh_agent(&daemon);

    assert_eq!(daemon.run(&["unlock", "personal"])["ok"], true);
    let listed = stdout(&ssh_add(&agent, ["-L"]));
    let pubkey_line = public_key_line(&listed, "Ed25519");
    let key_blob = base64::engine::general_purpose::STANDARD
        .decode(
            pubkey_line
                .split_whitespace()
                .nth(1)
                .expect("ssh-add -L line has a base64 field"),
        )
        .expect("valid base64 key blob");

    let host_a = raw::throwaway_key(1);
    let host_b = raw::throwaway_key(2);

    // First destination: binds, then signs twice over the same connection.
    let mut conn_a = raw::Connection::open(&agent.socket);
    assert_eq!(
        conn_a.send(&raw::session_bind(&host_a, b"session-a", false)),
        6
    );
    let data_a = raw::login_data(b"session-a", "alice", "ssh-ed25519", &key_blob);
    assert_eq!(conn_a.send(&raw::sign_request(&key_blob, &data_a)), 14);
    assert_eq!(
        count_lines(&counter),
        1,
        "the first signature should prompt"
    );
    assert_eq!(conn_a.send(&raw::sign_request(&key_blob, &data_a)), 14);
    assert_eq!(
        count_lines(&counter),
        1,
        "a second signature to the same destination must not prompt again"
    );

    // A different destination: a new connection, bound to a different host
    // key, must prompt again even though the key itself is the same.
    let mut conn_b = raw::Connection::open(&agent.socket);
    assert_eq!(
        conn_b.send(&raw::session_bind(&host_b, b"session-b", false)),
        6
    );
    let data_b = raw::login_data(b"session-b", "alice", "ssh-ed25519", &key_blob);
    assert_eq!(conn_b.send(&raw::sign_request(&key_blob, &data_b)), 14);
    assert_eq!(
        count_lines(&counter),
        2,
        "a different destination must prompt again"
    );
}

/// Forwarded signatures are refused: every `SIGN_REQUEST` over a forwarded
/// connection gets `FAILURE` (`docs/ssh-agent.md` § 6.3), even a
/// well-formed, approvable login.
#[test]
fn forwarded_signatures_are_refused() {
    use base64::Engine as _;

    let daemon = InProcessDaemon::start(&config(&common::ssh_db()));
    let agent = start_ssh_agent(&daemon);

    assert_eq!(daemon.run(&["unlock", "personal"])["ok"], true);
    let listed = stdout(&ssh_add(&agent, ["-L"]));
    let pubkey_line = public_key_line(&listed, "Ed25519");
    let key_blob = base64::engine::general_purpose::STANDARD
        .decode(
            pubkey_line
                .split_whitespace()
                .nth(1)
                .expect("ssh-add -L line has a base64 field"),
        )
        .expect("valid base64 key blob");

    let forwarding_host = raw::throwaway_key(3);
    let mut conn = raw::Connection::open(&agent.socket);
    assert_eq!(
        conn.send(&raw::session_bind(&forwarding_host, b"fwd-session", true)),
        6
    );
    let data = raw::login_data(b"fwd-session", "alice", "ssh-ed25519", &key_blob);
    assert_eq!(
        conn.send(&raw::sign_request(&key_blob, &data)),
        5,
        "a forwarded signature must be refused (FAILURE), not signed"
    );
}
