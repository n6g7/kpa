//! `kpa ssh keys` (`docs/ssh-agent.md` § 6.4) against `fixture-ssh.kdbx`,
//! through the real CLI and an in-process daemon.
//!
//! The fixture holds an Ed25519, an ECDSA and an RSA key, each on its own
//! entry (titled `Ed25519`, `Ecdsa` and `Rsa`); a passphrase-protected key
//! (`Encrypted`) and a PEM-format RSA key (`Pem`) that must be skipped; and
//! two keys that are invisible, one only in an entry's history and one only
//! in the recycle bin.

mod common;

use std::process::{Command, Output};

use common::InProcessDaemon;
use kpa::config::Config;

fn daemon() -> InProcessDaemon {
    InProcessDaemon::start(&common::config_toml(
        &format!("printf {}", common::PASSWORD),
        &common::ssh_db().display().to_string(),
    ))
}

fn ssh_keys(daemon: &InProcessDaemon, database: &str) -> Output {
    Command::new(env!("CARGO_BIN_EXE_kpa"))
        .arg("--socket")
        .arg(&daemon.socket)
        .args(["ssh", "keys", database])
        .output()
        .expect("failed to spawn kpa")
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8(bytes.to_vec()).expect("output is UTF-8")
}

#[test]
fn prints_the_three_keys_and_the_skipped_attachments() {
    let daemon = daemon();
    assert_eq!(daemon.run(&["unlock", "personal"])["ok"], true);

    let output = ssh_keys(&daemon, "personal");
    let stdout = text(&output.stdout);
    assert!(output.status.success(), "{stdout}{}", text(&output.stderr));

    for (key_type, title, attachment) in [
        ("ssh-ed25519", "Ed25519", "id_ed25519"),
        ("ecdsa-sha2-nistp256", "Ecdsa", "id_ecdsa"),
        ("ssh-rsa", "Rsa", "id_rsa"),
    ] {
        let fingerprint = common::ssh_fixture_fingerprint(title);
        let line = format!("  {key_type}  {fingerprint}  {title} ({attachment})\n");
        assert!(stdout.contains(&line), "no line {line:?} in:\n{stdout}");
    }

    let skipped = stdout
        .split_once("Skipped attachments:\n")
        .expect("a skipped section")
        .1;
    let skipped: Vec<&str> = skipped
        .lines()
        .take_while(|line| line.starts_with("  "))
        .collect();
    assert_eq!(skipped.len(), 2, "{skipped:?}");
    assert!(
        skipped
            .iter()
            .any(|line| line.contains("Encrypted (id_encrypted)")
                && line.contains("protected by a passphrase")),
        "{skipped:?}"
    );
    assert!(
        skipped
            .iter()
            .any(|line| line.contains("Pem (id_rsa_pem)") && line.contains("PEM format")),
        "{skipped:?}"
    );

    // History and the recycle bin are not looked at.
    assert!(!stdout.contains("Historical") && !stdout.contains("Recycled"));
}

/// The blocks in the output are config: pasted under a database that
/// serves SSH keys, they parse and name exactly the printed fingerprints.
#[test]
fn the_pasted_blocks_parse_as_config_for_each_key() {
    let daemon = daemon();
    assert_eq!(daemon.run(&["unlock", "personal"])["ok"], true);
    let stdout = text(&ssh_keys(&daemon, "personal").stdout);

    let lines: Vec<&str> = stdout.lines().collect();
    let first = lines
        .iter()
        .position(|line| *line == "[[database.ssh_key]]")
        .expect("a block");
    // Each block starts one line above its table, with a `#` comment.
    let blocks = lines[first - 1..].join("\n");

    let config = Config::parse(&format!(
        "[ssh_agent]\nconfirm_prompt = [\"true\"]\n\n\
         [[database]]\nname = \"personal\"\npath = \"/vaults/personal.kdbx\"\n\
         serve_ssh_keys = true\n\n{blocks}\n"
    ))
    .expect("the pasted blocks should parse as config");

    let mut parsed: Vec<String> = config.databases[0]
        .ssh_keys
        .iter()
        .map(|key| key.fingerprint.to_string())
        .collect();
    parsed.sort();
    let mut expected: Vec<String> = ["Ed25519", "Ecdsa", "Rsa"]
        .into_iter()
        .map(common::ssh_fixture_fingerprint)
        .collect();
    expected.sort();
    assert_eq!(parsed, expected);
}

/// A locked database is an error the user can act on, not an empty list.
#[test]
fn a_locked_database_is_an_error_not_an_empty_list() {
    let daemon = daemon();

    let output = ssh_keys(&daemon, "personal");

    assert!(!output.status.success());
    assert!(output.stdout.is_empty(), "{}", text(&output.stdout));
    let stderr = text(&output.stderr);
    assert!(stderr.contains("is locked"), "{stderr}");
    assert!(stderr.contains("kpa unlock personal"), "{stderr}");
}

#[test]
fn an_unknown_database_is_named_in_the_error() {
    let daemon = daemon();

    let output = ssh_keys(&daemon, "nonesuch");

    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    let stderr = text(&output.stderr);
    assert!(
        stderr.contains("no database named \"nonesuch\""),
        "{stderr}"
    );
}

/// A database whose attachments hold no keys says so.
#[test]
fn a_vault_without_keys_says_so() {
    let daemon = InProcessDaemon::start(&common::config_toml(
        &format!("printf {}", common::PASSWORD),
        &common::password_db().display().to_string(),
    ));
    assert_eq!(daemon.run(&["unlock", "personal"])["ok"], true);

    let output = ssh_keys(&daemon, "personal");

    assert!(output.status.success());
    assert_eq!(text(&output.stdout), "No SSH keys found in personal.\n");
}
