//! `kpa ssh keys` (`docs/ssh-agent.md` § 6.4) against `fixture-ssh.kdbx`,
//! through the real CLI and an in-process daemon.
//!
//! The fixture holds an Ed25519, an ECDSA and an RSA key, each on its own
//! entry (titled `Ed25519`, `Ecdsa` and `Rsa`); a passphrase-protected key
//! (`Encrypted`) and a PEM-format RSA key (`Pem`) that must be skipped; and
//! two keys that are invisible, one only in an entry's history and one only
//! in the recycle bin. The daemon here configures it twice, as `personal`
//! and `work`, and a third database, `archive`, that stays locked.

mod common;

use std::process::{Command, Output};

use common::InProcessDaemon;
use kpa::config::Config;

fn daemon() -> InProcessDaemon {
    let ssh = common::ssh_db().display().to_string();
    let other = common::password_db().display().to_string();
    InProcessDaemon::start(&format!(
        "prompt = [\"/bin/sh\", \"-c\", \"printf {password}\"]\n\n\
         [[database]]\nname = \"personal\"\npath = \"{ssh}\"\n\n\
         [[database]]\nname = \"work\"\npath = \"{ssh}\"\n\n\
         [[database]]\nname = \"archive\"\npath = \"{other}\"\n",
        password = common::PASSWORD,
    ))
}

fn unlock(daemon: &InProcessDaemon, names: &[&str]) {
    for name in names {
        assert_eq!(daemon.run(&["unlock", name])["ok"], true);
    }
}

fn kpa(daemon: &InProcessDaemon, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_kpa"))
        .arg("--socket")
        .arg(&daemon.socket)
        .args(args)
        .output()
        .expect("failed to spawn kpa")
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8(bytes.to_vec()).expect("output is UTF-8")
}

/// The rows of the table whose header has the cells `header`, split into
/// cells, header first. Cells hold no spaces in this fixture.
fn rows<'a>(stdout: &'a str, header: &[&str]) -> Vec<Vec<&'a str>> {
    stdout
        .lines()
        .skip_while(|line| !line.split_whitespace().eq(header.iter().copied()))
        .take_while(|line| !line.is_empty())
        .map(|line| line.split_whitespace().collect())
        .collect()
}

#[test]
fn prints_every_unlocked_databases_keys_skipped_attachments_and_locked_names() {
    let daemon = daemon();
    unlock(&daemon, &["personal", "work"]);

    let output = kpa(&daemon, &["ssh", "keys"]);
    let stdout = text(&output.stdout);
    assert!(output.status.success(), "{stdout}{}", text(&output.stderr));

    // A key two databases hold shows once for each, in config order.
    let keys = rows(
        &stdout,
        &[
            "NAME",
            "DATABASE",
            "ENTRY",
            "ATTACHMENT",
            "TYPE",
            "FINGERPRINT",
        ],
    );
    assert!(!keys.is_empty(), "no keys table in:\n{stdout}");
    let expected: Vec<Vec<String>> = ["personal", "work"]
        .into_iter()
        .flat_map(|db| {
            [
                ("ssh-ed25519", "Ed25519", "id_ed25519"),
                ("ecdsa-sha2-nistp256", "Ecdsa", "id_ecdsa"),
                ("ssh-rsa", "Rsa", "id_rsa"),
            ]
            .map(|(key_type, title, attachment)| {
                vec![
                    // No override names these keys, so they are served under
                    // their entries' titles.
                    title.to_string(),
                    db.to_string(),
                    title.to_string(),
                    attachment.to_string(),
                    key_type.to_string(),
                    common::ssh_fixture_fingerprint(title),
                ]
            })
        })
        .collect();
    let mut shown: Vec<Vec<String>> = keys[1..]
        .iter()
        .map(|row| row.iter().map(|cell| cell.to_string()).collect())
        .collect();
    let mut expected_sorted = expected.clone();
    shown.sort();
    expected_sorted.sort();
    assert_eq!(shown, expected_sorted, "{stdout}");
    assert_eq!(keys[1][1], "personal", "config order: {stdout}");
    assert_eq!(keys[4][1], "work", "config order: {stdout}");

    // Fingerprints line up under their header.
    let header = stdout.lines().next().expect("a header");
    let column = header.find("FINGERPRINT").expect("a FINGERPRINT column");
    for line in stdout.lines().filter(|line| line.contains("SHA256:")) {
        assert_eq!(line.find("SHA256:"), Some(column), "{stdout}");
    }

    let skipped = rows(&stdout, &["DATABASE", "ENTRY", "ATTACHMENT", "REASON"]);
    assert!(!skipped.is_empty(), "no skipped table in:\n{stdout}");
    assert_eq!(skipped.len(), 5, "two skipped attachments in each of two");
    for db in ["personal", "work"] {
        for (title, attachment, reason) in [
            ("Encrypted", "id_encrypted", "protected"),
            ("Pem", "id_rsa_pem", "PEM"),
        ] {
            assert!(
                skipped[1..]
                    .iter()
                    .any(|row| row[..3] == [db, title, attachment]
                        && row[3..].join(" ").contains(reason)),
                "{db} {title}: {stdout}"
            );
        }
    }

    assert!(
        stdout.ends_with("Locked, not scanned: archive (`kpa unlock <database>` first)\n"),
        "{stdout}"
    );
    // History and the recycle bin are not looked at.
    assert!(!stdout.contains("Historical") && !stdout.contains("Recycled"));
}

#[test]
fn database_limits_it_to_one() {
    let daemon = daemon();
    unlock(&daemon, &["personal", "work"]);

    let stdout = text(&kpa(&daemon, &["ssh", "keys", "--database", "work"]).stdout);

    assert!(stdout.contains("work "), "{stdout}");
    assert!(!stdout.contains("personal"), "{stdout}");
    assert!(!stdout.contains("Locked"), "{stdout}");
}

/// What `--toml` prints is config: pasted under the database it names, the
/// blocks parse and name exactly the keys the table shows.
#[test]
fn toml_prints_blocks_that_parse_as_config() {
    let daemon = daemon();
    unlock(&daemon, &["personal"]);

    let output = kpa(&daemon, &["ssh", "keys", "--toml"]);
    let stdout = text(&output.stdout);

    assert!(output.status.success());
    assert!(stdout.starts_with("# Paste under [[database]] personal:\n"));
    assert!(!stdout.contains("DATABASE"), "{stdout}");
    let config = Config::parse(&format!(
        "[ssh_agent]\nconfirm_prompt = [\"true\"]\n\n\
         [[database]]\nname = \"personal\"\npath = \"/vaults/personal.kdbx\"\n\
         serve_ssh_keys = true\n\n{stdout}"
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

/// Naming a locked database is an error the user can act on; asking for
/// every database just says which were not scanned.
#[test]
fn a_locked_database_is_an_error_when_named_and_a_note_otherwise() {
    let daemon = daemon();

    let named = kpa(&daemon, &["ssh", "keys", "--database", "personal"]);
    assert!(!named.status.success());
    assert!(named.stdout.is_empty());
    let stderr = text(&named.stderr);
    assert!(stderr.contains("is locked"), "{stderr}");
    assert!(stderr.contains("kpa unlock personal"), "{stderr}");

    let all = kpa(&daemon, &["ssh", "keys"]);
    assert!(all.status.success());
    assert_eq!(
        text(&all.stdout),
        "No SSH keys found.\n\nLocked, not scanned: personal, work, archive \
         (`kpa unlock <database>` first)\n"
    );
}

#[test]
fn an_unknown_database_is_named_in_the_error() {
    let daemon = daemon();

    let output = kpa(&daemon, &["ssh", "keys", "--database", "nonesuch"]);

    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    let stderr = text(&output.stderr);
    assert!(
        stderr.contains("no database named \"nonesuch\""),
        "{stderr}"
    );
}

/// `--json` prints the daemon's response line, wherever the flag stands.
#[test]
fn json_prints_the_daemons_response_line() {
    let daemon = daemon();
    unlock(&daemon, &["personal"]);

    for args in [
        ["--json", "ssh", "keys", "--database", "personal"],
        ["ssh", "keys", "--database", "personal", "--json"],
    ] {
        let output = kpa(&daemon, &args);
        assert!(output.status.success());
        let line: serde_json::Value =
            serde_json::from_str(text(&output.stdout).trim()).expect("a JSON line");
        assert_eq!(line["keys"].as_array().expect("keys").len(), 3);
        assert_eq!(line["keys"][0]["db"], "personal");
        assert_eq!(line["skipped"].as_array().expect("skipped").len(), 2);
        assert!(line.get("locked").is_none());
    }

    let all = kpa(&daemon, &["ssh", "keys", "--json"]);
    let line: serde_json::Value =
        serde_json::from_str(text(&all.stdout).trim()).expect("a JSON line");
    assert_eq!(line["locked"], serde_json::json!(["work", "archive"]));
}

/// A refusal under `--json` is the daemon's error line, with the same exit
/// status as the sentence it would have been.
#[test]
fn json_prints_a_refusal_as_the_daemons_error_line() {
    let daemon = daemon();

    let output = kpa(
        &daemon,
        &["ssh", "keys", "--database", "personal", "--json"],
    );

    assert!(!output.status.success());
    let line: serde_json::Value =
        serde_json::from_str(text(&output.stdout).trim()).expect("a JSON line");
    assert_eq!(line["error"], "locked");
    assert!(output.stderr.is_empty());
}

#[test]
fn toml_and_json_are_refused_together() {
    let daemon = daemon();
    assert!(
        !kpa(&daemon, &["ssh", "keys", "--toml", "--json"])
            .status
            .success()
    );
}

/// `--json` is accepted by every client command, before or after it.
#[test]
fn json_is_accepted_by_other_commands_too() {
    let daemon = daemon();

    for args in [["--json", "status"], ["status", "--json"]] {
        let output = kpa(&daemon, &args);
        assert!(output.status.success());
        let line: serde_json::Value =
            serde_json::from_str(text(&output.stdout).trim()).expect("a JSON line");
        assert_eq!(line["ok"], true);
    }
}
