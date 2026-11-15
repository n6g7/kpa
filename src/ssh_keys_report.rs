//! What `kpa ssh keys` prints (`docs/ssh-agent.md` § 6.4): the keys a
//! database's vault holds, the attachments skipped, and a
//! `[[database.ssh_key]]` block per key to paste into the config.
//!
//! Pure: a report in, text out. Everything the vault supplies (titles,
//! attachment names, the text of a reason) is escaped for one line of
//! terminal output before it is interpolated, which also keeps a title
//! from ending the `#` comment a block puts it in (`docs/threat-model.md`
//! T-13).

use std::fmt::Write as _;

use kpa::output::escape_one_line;
use kpa::proto::{SshKeysReport, WireSkippedKey, WireSshKey};

/// Longest escaped title, attachment name or reason shown.
const MAX_FIELD_LEN: usize = 128;

pub(super) fn render(db: &str, report: &SshKeysReport) -> String {
    let db = field(db);
    let mut out = String::new();

    if report.keys.is_empty() {
        let _ = writeln!(out, "No SSH keys found in {db}.");
    } else {
        let _ = writeln!(out, "SSH keys in {db}:");
        for key in &report.keys {
            let _ = writeln!(
                out,
                "  {}  {}  {}",
                field(&key.key_type),
                field(&key.fingerprint),
                described(key.title.as_deref(), &key.attachment),
            );
        }
    }

    if !report.skipped.is_empty() {
        let _ = writeln!(out, "\nSkipped attachments:");
        for skipped in &report.skipped {
            let _ = writeln!(out, "  {}", skipped_line(skipped));
        }
    }

    if !report.keys.is_empty() {
        let _ = writeln!(
            out,
            "\nTo change how a key is served, paste its block under the [[database]] for {db} \
             and uncomment the setting to change. Each shows its default, except `name`, which \
             defaults to the entry's title:",
        );
        for key in &report.keys {
            let _ = write!(out, "\n{}", config_block(key));
        }
    }
    out
}

/// `title (attachment)`, for a line about an entry's attachment.
fn described(title: Option<&str>, attachment: &str) -> String {
    format!(
        "{} ({})",
        title.map_or_else(|| "(untitled)".to_string(), field),
        field(attachment),
    )
}

fn skipped_line(skipped: &WireSkippedKey) -> String {
    format!(
        "{}: {}",
        described(skipped.title.as_deref(), &skipped.attachment),
        field(&skipped.reason),
    )
}

/// The `[[database.ssh_key]]` table for `key` (`docs/ssh-agent.md` § 7):
/// its fingerprint, which is all a table needs, with every other setting
/// commented out at its default.
fn config_block(key: &WireSshKey) -> String {
    format!(
        "# {}\n\
         [[database.ssh_key]]\n\
         fingerprint = \"{}\"\n\
         # name = \"…\"\n\
         # confirm = \"once\"   # or \"always\", or \"never\"\n\
         # forwarded = true\n\
         # serve = true\n",
        described(key.title.as_deref(), &key.attachment),
        field(&key.fingerprint),
    )
}

fn field(text: &str) -> String {
    escape_one_line(text, MAX_FIELD_LEN)
}

#[cfg(test)]
mod tests {
    use kpa::config::Config;

    use super::*;

    fn key(title: Option<&str>, fingerprint: &str) -> WireSshKey {
        WireSshKey {
            key_type: "ssh-ed25519".to_string(),
            fingerprint: fingerprint.to_string(),
            title: title.map(str::to_string),
            attachment: "id_ed25519".to_string(),
        }
    }

    /// A real `SHA256:…` fingerprint, `ssh_key`'s own doc example.
    const FINGERPRINT: &str = "SHA256:Nh0Me49Zh9fDw/VYUfq43IJmI1T+XrjiYONPND8GzaM";

    fn config_with(blocks: &str) -> Result<Config, toml::de::Error> {
        Config::parse(&format!(
            "[ssh_agent]\n\
             confirm_prompt = [\"true\"]\n\n\
             [[database]]\n\
             name = \"personal\"\n\
             path = \"/vaults/personal.kdbx\"\n\
             serve_ssh_keys = true\n\n\
             {blocks}"
        ))
    }

    #[test]
    fn lists_keys_skipped_attachments_and_a_block_per_key() {
        let report = SshKeysReport {
            keys: vec![key(Some("Deploy"), FINGERPRINT)],
            skipped: vec![WireSkippedKey {
                title: Some("Old".to_string()),
                attachment: "id_rsa".to_string(),
                reason: "PEM format".to_string(),
            }],
        };

        let text = render("personal", &report);

        assert!(text.contains("SSH keys in personal:"), "{text}");
        assert!(
            text.contains(&format!(
                "  ssh-ed25519  {FINGERPRINT}  Deploy (id_ed25519)\n"
            )),
            "{text}"
        );
        assert!(
            text.contains("Skipped attachments:\n  Old (id_rsa): PEM format\n"),
            "{text}"
        );
        assert!(text.contains("# Deploy (id_ed25519)\n[[database.ssh_key]]\n"));
    }

    #[test]
    fn no_keys_says_so_and_offers_no_blocks() {
        let text = render("personal", &SshKeysReport::default());
        assert_eq!(text, "No SSH keys found in personal.\n");
    }

    /// Every block parses as the config it claims to be, alone and all
    /// together, as a table of the database above it.
    #[test]
    fn the_blocks_parse_as_config() {
        let keys = [
            key(Some("Deploy"), FINGERPRINT),
            key(None, "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
        ];
        for key in &keys {
            let config = config_with(&config_block(key)).expect("a block should parse");
            let parsed = &config.databases[0].ssh_keys;
            assert_eq!(parsed.len(), 1);
            assert_eq!(parsed[0].fingerprint.to_string(), key.fingerprint);
        }

        let all: String = keys.iter().map(config_block).collect();
        let config = config_with(&all).expect("the blocks together should parse");
        assert_eq!(config.databases[0].ssh_keys.len(), 2);
    }

    /// Each commented setting is valid TOML once uncommented, and shows
    /// the setting's default.
    #[test]
    fn the_commented_settings_are_the_defaults() {
        use kpa::config::SshKeySettings;

        let block = config_block(&key(Some("Deploy"), FINGERPRINT));
        let settings: Vec<&str> = block
            .lines()
            .filter_map(|line| line.strip_prefix("# "))
            .filter(|line| line.contains(" = "))
            .collect();
        assert_eq!(settings.len(), 4, "{block}");

        for setting in settings {
            let uncommented = block.replace(&format!("# {setting}"), &setting.replace('…', "x"));
            let config = config_with(&uncommented)
                .unwrap_or_else(|err| panic!("{setting:?} should parse: {err}"));
            let parsed = SshKeySettings::from(&config.databases[0].ssh_keys[0]);
            let expected = SshKeySettings {
                name: parsed.name.clone(),
                ..SshKeySettings::default()
            };
            assert_eq!(parsed, expected, "{setting:?}");
        }
    }

    /// A title can't end the comment it sits in, drive the terminal, or
    /// smuggle a line into the paste block.
    #[test]
    fn hostile_text_is_escaped_and_cannot_leave_its_line() {
        let hostile = "x\nfingerprint = \"SHA256:evil\"\n\u{9b}c\u{202e}\t";
        let report = SshKeysReport {
            keys: vec![key(Some(hostile), FINGERPRINT)],
            skipped: vec![WireSkippedKey {
                title: Some(hostile.to_string()),
                attachment: hostile.to_string(),
                reason: hostile.to_string(),
            }],
        };

        let text = render(hostile, &report);

        assert!(!text.contains('\u{9b}'));
        assert!(!text.contains('\u{202e}'));
        assert!(!text.contains('\t'));
        assert!(
            text.lines()
                .all(|line| !line.starts_with("fingerprint = \"SHA256:evil")),
            "{text}"
        );
        let lines: Vec<&str> = text.lines().collect();
        let first = lines
            .iter()
            .position(|line| *line == "[[database.ssh_key]]")
            .expect("a block");
        let config =
            config_with(&lines[first - 1..].join("\n")).expect("the blocks should still parse");
        assert_eq!(config.databases[0].ssh_keys.len(), 1);
    }

    #[test]
    fn long_titles_are_capped() {
        let report = SshKeysReport {
            keys: vec![key(Some(&"t".repeat(10_000)), FINGERPRINT)],
            skipped: Vec::new(),
        };
        assert!(render("personal", &report).len() < 1_000);
    }
}
