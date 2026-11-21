//! End-to-end tests for forwarded SSH agent use (`docs/ssh-agent.md` § 6.2,
//! § 6.3, § 6.7, § 6.9): the real `ssh -A` forwards kpa's agent to a private,
//! unprivileged `sshd` on a loopback port with a throwaway host key, and a
//! second `ssh` run there signs in through the forwarded agent.
//!
//! Each test skips where `sshd` is not installed. It uses its own sockets,
//! ports and key files, and runs both `ssh` clients with `-F /dev/null`, so
//! nothing of the user's SSH setup is read.

mod common;

use std::collections::HashSet;
use std::net::{Ipv4Addr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

use common::{InProcessDaemon, SshAgent, start_ssh_agent};

/// The OpenSSH programs the tests run, found on `PATH` (`sshd` must be
/// started by its absolute path).
struct Tools {
    sshd: PathBuf,
    ssh: PathBuf,
    ssh_add: PathBuf,
    ssh_keygen: PathBuf,
}

impl Tools {
    /// `None` where `sshd` or a client is missing.
    fn find() -> Option<Tools> {
        let on_path = |name: &str| {
            std::env::split_paths(&std::env::var_os("PATH")?)
                .map(|dir| dir.join(name))
                .find(|candidate| candidate.is_file())
        };
        Some(Tools {
            sshd: on_path("sshd")?,
            ssh: on_path("ssh")?,
            ssh_add: on_path("ssh-add")?,
            ssh_keygen: on_path("ssh-keygen")?,
        })
    }
}

/// A running `sshd`, killed when dropped.
struct Sshd {
    child: Child,
    port: u16,
}

impl Drop for Sshd {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// A free loopback port.
fn free_port() -> u16 {
    TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .expect("bind a loopback port")
        .local_addr()
        .expect("local address")
        .port()
}

fn generate_key(tools: &Tools, path: &Path) {
    let status = Command::new(&tools.ssh_keygen)
        .args(["-q", "-t", "ed25519", "-N", "", "-f"])
        .arg(path)
        .status()
        .expect("spawn ssh-keygen");
    assert!(status.success(), "ssh-keygen failed");
}

/// Starts an `sshd` that accepts the keys in `authorized_keys` for the
/// current user, and waits until it takes connections.
fn start_sshd(tools: &Tools, dir: &Path, host_key: &Path, authorized_keys: &str) -> Sshd {
    let port = free_port();
    let authorized = dir.join("authorized_keys");
    std::fs::write(&authorized, authorized_keys).expect("write authorized_keys");
    let config = dir.join("sshd_config");
    std::fs::write(
        &config,
        format!(
            "Port {port}\n\
             ListenAddress 127.0.0.1\n\
             HostKey {host_key}\n\
             AuthorizedKeysFile {authorized}\n\
             PidFile {pid}\n\
             UsePAM no\n\
             StrictModes no\n\
             PasswordAuthentication no\n\
             KbdInteractiveAuthentication no\n\
             AllowAgentForwarding yes\n",
            host_key = host_key.display(),
            authorized = authorized.display(),
            pid = dir.join("sshd.pid").display(),
        ),
    )
    .expect("write sshd_config");
    let log = std::fs::File::create(dir.join("sshd.log")).expect("create sshd.log");
    let child = Command::new(&tools.sshd)
        .args(["-D", "-e", "-f"])
        .arg(&config)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(log)
        .spawn()
        .expect("spawn sshd");
    let mut sshd = Sshd { child, port };
    let deadline = Instant::now() + Duration::from_secs(10);
    while TcpStream::connect((Ipv4Addr::LOCALHOST, port)).is_err() {
        let log = || std::fs::read_to_string(dir.join("sshd.log")).unwrap_or_default();
        if let Some(status) = sshd.child.try_wait().expect("poll sshd") {
            panic!("sshd exited with {status}: {}", log());
        }
        assert!(Instant::now() < deadline, "sshd never listened: {}", log());
        std::thread::sleep(Duration::from_millis(50));
    }
    sshd
}

/// `text` as one shell word.
fn quoted(text: &str) -> String {
    format!("'{}'", text.replace('\'', "'\\''"))
}

/// The user the tests log in as: the one running them, the only one an
/// unprivileged `sshd` accepts.
fn current_user() -> String {
    let output = Command::new("id").arg("-un").output().expect("spawn id");
    String::from_utf8(output.stdout)
        .expect("utf-8 user name")
        .trim()
        .to_string()
}

/// kpa's agent, serving the SSH fixture, forwarded to a private `sshd`.
struct Rig {
    daemon: InProcessDaemon,
    agent: SshAgent,
    sshd: Sshd,
    tools: Tools,
    dir: tempfile::TempDir,
    user: String,
    /// The key `ssh -A` itself logs in with.
    client_key: PathBuf,
    /// What `ssh-add -L` listed from kpa's agent, as the desk sees it.
    listed: String,
    /// One line per confirm prompt kpa raised: the question it asked.
    confirmations: PathBuf,
}

impl Rig {
    /// Starts kpa on the SSH fixture, unlocked, with `idle_timeout` and
    /// `overrides` (TOML for `[[database.ssh_key]]` tables), and an `sshd`
    /// that accepts the fixture's `Ed25519`, `Ecdsa` and `Rsa` keys. The
    /// confirm prompt allows and records its question. `None` where the
    /// OpenSSH programs are missing.
    fn start(idle_timeout: &str, overrides: &str) -> Option<Rig> {
        let Some(tools) = Tools::find() else {
            eprintln!("skipping: sshd and the OpenSSH clients are not installed");
            return None;
        };
        let dir = tempfile::tempdir().expect("tempdir");
        let confirmations = dir.path().join("confirmations");
        let config = format!(
            "idle_timeout = \"{idle_timeout}\"\n\
             prompt = [\"/bin/sh\", \"-c\", \"printf {password}\"]\n\n\
             [ssh_agent]\n\
             confirm_prompt = [\"/bin/sh\", \"-c\", \"echo \\\"$KPA_PROMPT_MESSAGE\\\" >> '{log}'; head -n1\"]\n\n\
             [[database]]\n\
             name = \"personal\"\n\
             path = \"{db}\"\n\
             serve_ssh_keys = true\n\
             {overrides}",
            password = common::PASSWORD,
            log = confirmations.display(),
            db = common::ssh_db().display(),
        );
        let daemon = InProcessDaemon::start(&config);
        let agent = start_ssh_agent(&daemon);
        assert_eq!(daemon.run(&["unlock", "personal"])["ok"], true);
        let listed = Command::new(&tools.ssh_add)
            .arg("-L")
            .env("SSH_AUTH_SOCK", &agent.socket)
            .output()
            .expect("spawn ssh-add");
        let listed = String::from_utf8(listed.stdout).expect("utf-8 listing");

        let host_key = dir.path().join("host_key");
        let client_key = dir.path().join("client_key");
        generate_key(&tools, &host_key);
        generate_key(&tools, &client_key);
        let public = |path: &Path| {
            std::fs::read_to_string(path.with_extension("pub")).expect("read public key")
        };
        let mut authorized = public(&client_key);
        for title in ["Ed25519", "Ecdsa", "Rsa"] {
            authorized.push_str(&format!("{}\n", key_line(&listed, title)));
        }
        let sshd = start_sshd(&tools, dir.path(), &host_key, &authorized);
        let known_hosts = daemon
            .paths
            .known_hosts
            .clone()
            .expect("the daemon's known_hosts");
        std::fs::write(
            known_hosts,
            format!("[127.0.0.1]:{} {}", sshd.port, public(&host_key)),
        )
        .expect("write known_hosts");

        Some(Rig {
            daemon,
            agent,
            sshd,
            tools,
            user: current_user(),
            client_key,
            listed,
            confirmations,
            dir,
        })
    }

    /// The options both `ssh` clients run with: no configuration file, the
    /// private `sshd`, and the `known_hosts` kpa reads too.
    fn ssh_options(&self) -> Vec<String> {
        let known_hosts = self.daemon.paths.known_hosts.clone().expect("known_hosts");
        let mut options: Vec<String> = ["-F", "/dev/null", "-p"]
            .iter()
            .map(|option| option.to_string())
            .collect();
        options.push(self.sshd.port.to_string());
        for option in [
            "BatchMode=yes".to_string(),
            "StrictHostKeyChecking=yes".to_string(),
            "CheckHostIP=no".to_string(),
            "GlobalKnownHostsFile=/dev/null".to_string(),
            format!("UserKnownHostsFile={}", known_hosts.display()),
            "LogLevel=ERROR".to_string(),
            "ConnectTimeout=10".to_string(),
        ] {
            options.push("-o".to_string());
            options.push(option);
        }
        options.push("127.0.0.1".to_string());
        options
    }

    /// Runs `remote` on the `sshd` through `ssh -A`, which forwards kpa's
    /// agent into that session; the session logs in with its own key, not
    /// kpa's.
    fn forwarded(&self, remote: &str) -> Output {
        Command::new(&self.tools.ssh)
            .args(&self.ssh_options()[..self.ssh_options().len() - 1])
            .args(["-A", "-o", "IdentitiesOnly=yes", "-i"])
            .arg(&self.client_key)
            .arg("127.0.0.1")
            .env("SSH_AUTH_SOCK", &self.agent.socket)
            .arg(remote)
            .env("HOME", self.dir.path())
            .output()
            .expect("spawn ssh -A")
    }

    /// A file holding the public key of `title`, as `ssh -i` and `ssh-keygen
    /// -f` take it to pick an agent key.
    fn public_key_file(&self, title: &str) -> PathBuf {
        use std::os::unix::fs::PermissionsExt as _;

        let path = self.dir.path().join(format!("{title}.pub"));
        std::fs::write(&path, format!("{}\n", key_line(&self.listed, title)))
            .expect("write public key");
        // `ssh -i` ignores a key file others can read.
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
            .expect("chmod public key");
        path
    }

    /// The command that, run on the `sshd`, logs in to it again with
    /// `title`'s key through the forwarded agent, and runs `true`.
    fn second_hop(&self, title: &str) -> String {
        let public = self.public_key_file(title);
        let mut words = vec![quoted(self.tools.ssh.to_str().expect("utf-8 path"))];
        let options = self.ssh_options();
        let (host, options) = options.split_last().expect("options");
        words.extend(options.iter().map(|option| quoted(option)));
        words.extend([
            "-o".to_string(),
            "IdentitiesOnly=yes".to_string(),
            "-i".to_string(),
        ]);
        words.push(quoted(public.to_str().expect("utf-8 path")));
        words.extend([quoted(host), "true".to_string()]);
        words.join(" ")
    }

    /// What `kpa ssh grants` lists: each approval in force, as JSON.
    fn grants(&self) -> Vec<serde_json::Value> {
        let listed = self.daemon.run(&["--json", "ssh", "grants"]);
        assert_eq!(listed["ok"], true, "{listed}");
        listed["grants"].as_array().expect("grants").clone()
    }

    /// The questions kpa's confirm prompt has asked so far.
    fn confirmations(&self) -> Vec<String> {
        std::fs::read_to_string(&self.confirmations)
            .unwrap_or_default()
            .lines()
            .map(str::to_string)
            .collect()
    }

    /// The question for a forwarded login with `title`'s key: through the
    /// `sshd`'s host, to the same host, as the current user.
    fn question(&self, title: &str) -> String {
        let host = format!("[127.0.0.1]:{}", self.sshd.port);
        format!(
            "Approve use of key \"{title}\" on {host} to log in to {}@{host}?",
            self.user
        )
    }
}

/// The `ssh-add -L` line of the identity named `title`.
fn key_line<'a>(listed: &'a str, title: &str) -> &'a str {
    listed
        .lines()
        .find(|line| line.ends_with(title))
        .unwrap_or_else(|| panic!("no identity named {title:?} in: {listed:?}"))
}

/// The base64 key blobs of an `ssh-add -L` listing.
fn blobs(listed: &str) -> HashSet<&str> {
    listed
        .lines()
        .filter_map(|line| line.split_whitespace().nth(1))
        .collect()
}

fn output_text(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

/// An approval covers its own `ssh -A` session: the first login through the
/// forwarded agent asks, naming the forwarding host and the destination, a
/// second one in the same session doesn't, and a new session asks again.
#[test]
fn a_forwarded_login_asks_once_per_ssh_session() {
    let Some(rig) = Rig::start("30m", "") else {
        return;
    };
    let hop = rig.second_hop("Ed25519");

    let first = rig.forwarded(&format!("{hop} && {hop}"));
    assert!(first.status.success(), "{}", output_text(&first));
    assert_eq!(rig.confirmations(), [rig.question("Ed25519")]);
    // The approval is listed with the host the session was forwarded to, how
    // it was given, and the two logins it has covered.
    let grants = rig.grants();
    assert_eq!(grants.len(), 1);
    assert_eq!(grants[0]["by"], "on_screen");
    assert_eq!(grants[0]["uses"], 2);
    assert_eq!(grants[0]["remember"], true);
    let scope = &grants[0]["scope"];
    assert!(scope["forwarding_host"].is_string());
    assert_eq!(scope["forwarding_session"], 1);
    assert!(grants[0]["last_used_at"].is_u64());
    assert_eq!(scope["forwarding_host"], scope["destination"]);

    let second = rig.forwarded(&hop);
    assert!(second.status.success(), "{}", output_text(&second));
    assert_eq!(
        rig.confirmations(),
        [rig.question("Ed25519"), rig.question("Ed25519")]
    );
    let grants = rig.grants();
    assert_eq!(grants.len(), 2);
    assert_eq!(grants[1]["uses"], 1);
    assert_eq!(grants[1]["scope"]["forwarding_session"], 2);
    assert_eq!(grants[0]["scope"]["forwarding_session"], 1);
}

/// A key with `forwarded = false` is not listed to the forwarded agent and
/// no login with it succeeds; `SSHSIG` data is never signed over a
/// forwarded connection. Neither raises a prompt.
#[test]
fn a_forwarded_connection_signs_only_logins_with_keys_allowed_on_it() {
    let ecdsa = common::ssh_fixture_fingerprint("Ecdsa");
    let Some(rig) = Rig::start(
        "30m",
        &format!("\n[[database.ssh_key]]\nfingerprint = \"{ecdsa}\"\nforwarded = false\n"),
    ) else {
        return;
    };

    let listing = rig.forwarded(&format!(
        "SSH_AUTH_SOCK=\"$SSH_AUTH_SOCK\" {} -L",
        quoted(rig.tools.ssh_add.to_str().expect("utf-8 path"))
    ));
    assert!(listing.status.success(), "{}", output_text(&listing));
    let remote_listing = String::from_utf8_lossy(&listing.stdout).to_string();
    let remote = blobs(&remote_listing);
    let local = blobs(&rig.listed);
    let ecdsa_blob = key_line(&rig.listed, "Ecdsa")
        .split_whitespace()
        .nth(1)
        .expect("a key blob");
    assert!(local.contains(ecdsa_blob));
    assert!(!remote.contains(ecdsa_blob), "listed: {remote_listing}");
    for title in ["Ed25519", "Rsa"] {
        let blob = key_line(&rig.listed, title)
            .split_whitespace()
            .nth(1)
            .expect("a key blob");
        assert!(remote.contains(blob), "{title} missing: {remote_listing}");
    }

    let login = rig.forwarded(&rig.second_hop("Ecdsa"));
    assert!(!login.status.success(), "{}", output_text(&login));

    let data = rig.dir.path().join("data");
    std::fs::write(&data, "data").expect("write data");
    let public = rig.public_key_file("Ed25519");
    let sign = rig.forwarded(&format!(
        "{} -Y sign -f {} -n test {}",
        quoted(rig.tools.ssh_keygen.to_str().expect("utf-8 path")),
        quoted(public.to_str().expect("utf-8 path")),
        quoted(data.to_str().expect("utf-8 path")),
    ));
    assert!(!sign.status.success(), "{}", output_text(&sign));
    assert!(!data.with_extension("sig").exists());

    assert_eq!(rig.confirmations(), Vec::<String>::new());
}

/// A forwarded signature is a remote host's: it does not keep the database
/// unlocked, so the idle timeout still locks it.
#[test]
fn a_forwarded_signature_does_not_reset_the_idle_timer() {
    let Some(rig) = Rig::start("6s", "") else {
        return;
    };
    let started = Instant::now();
    std::thread::sleep(Duration::from_secs(3));

    let login = rig.forwarded(&rig.second_hop("Ed25519"));
    assert!(login.status.success(), "{}", output_text(&login));
    assert_eq!(rig.confirmations().len(), 1);
    assert!(
        started.elapsed() < Duration::from_secs(6),
        "the login came too late to prove anything"
    );

    // Idle for 6 s since the unlock: locked by 7.5 s. Had the signature
    // counted, the timer would run until about 9 s.
    std::thread::sleep(
        (started + Duration::from_millis(7500)).saturating_duration_since(Instant::now()),
    );
    assert!(
        !rig.daemon.databases.any_unlocked(),
        "the database is still unlocked"
    );
}
