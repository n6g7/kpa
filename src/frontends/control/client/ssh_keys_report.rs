//! What `kpa ssh keys` prints (`docs/ssh-agent.md` § 6.4): the keys the
//! unlocked databases hold and the attachments skipped, or, on request, a
//! `[[database.ssh_key]]` block per key to paste into the config. A key is
//! listed by the name it is served under, the one `kpa ssh grants` and `kpa
//! ssh pending` show.
//!
//! Pure: a report in, text out. Cells go through `output::Table`, which
//! escapes them; the rest of a line is built from `escape_one_line`, which
//! also keeps a title from ending the `#` comment a block puts it in
//! (`docs/threat-model.md` T-13).

use std::fmt::Write as _;

use crate::frontends::control::proto::{SshKeysReport, WireSshKey};
use crate::output::{Table, escape_one_line};

/// Longest escaped title, attachment name or database name in a comment.
const MAX_TEXT_LEN: usize = 128;

/// An entry without a title.
const UNTITLED: &str = "(untitled)";

/// The keys table's columns, in order, and the ones shown without `--full`:
/// what a key is, by name, type and fingerprint. Where it comes from
/// (database, entry, attachment) is the rest.
const HEADER: [&str; 6] = [
    "NAME",
    "DATABASE",
    "ENTRY",
    "ATTACHMENT",
    "TYPE",
    "FINGERPRINT",
];
const BRIEF: [usize; 3] = [0, 4, 5];

/// `toml` shows only the blocks, for a file. Without `full` the keys table
/// keeps to name, type and fingerprint.
pub fn render(report: &SshKeysReport, toml: bool, full: bool) -> String {
    if toml {
        return blocks(report);
    }
    let mut sections = Vec::new();

    if report.keys.is_empty() {
        sections.push("No SSH keys found.\n".to_string());
    } else {
        let rows = report.keys.iter().map(|key| {
            [
                key.name.as_str(),
                key.db.as_str(),
                key.title.as_deref().unwrap_or(UNTITLED),
                key.attachment.as_str(),
                key.key_type.as_str(),
                key.fingerprint.as_str(),
            ]
        });
        sections.push(if full {
            let mut table = Table::new(HEADER);
            rows.for_each(|row| table.row(row));
            table.render()
        } else {
            let mut table = Table::new(BRIEF.map(|column| HEADER[column]));
            rows.for_each(|row| table.row(BRIEF.map(|column| row[column])));
            table.render()
        });
    }

    if !report.skipped.is_empty() {
        let mut table = Table::new(["DATABASE", "ENTRY", "ATTACHMENT", "REASON"]);
        for skipped in &report.skipped {
            table.row([
                &skipped.db,
                skipped.title.as_deref().unwrap_or(UNTITLED),
                &skipped.attachment,
                &skipped.reason,
            ]);
        }
        sections.push(format!("Skipped attachments:\n{}", table.render()));
    }

    if !report.locked.is_empty() {
        let names: Vec<String> = report.locked.iter().map(|db| one_line(db)).collect();
        sections.push(format!(
            "Locked, not scanned: {} (`kpa unlock <database>` first)\n",
            names.join(", ")
        ));
    }
    sections.join("\n")
}

/// One `[[database.ssh_key]]` block per key, under a comment naming the
/// database it belongs under: a table joins the last `[[database]]` above
/// it. With every other setting commented out at its default.
fn blocks(report: &SshKeysReport) -> String {
    let mut out = String::new();
    let mut current = None;
    for key in &report.keys {
        if current != Some(&key.db) {
            if current.is_some() {
                out.push('\n');
            }
            let _ = writeln!(out, "# Paste under [[database]] {}:", one_line(&key.db));
            current = Some(&key.db);
        }
        let _ = write!(out, "\n{}", block(key));
    }
    out
}

/// The table for `key` (`docs/ssh-agent.md` § 7): its fingerprint, which is
/// all a table needs, and the other settings commented out at their
/// defaults.
fn block(key: &WireSshKey) -> String {
    format!(
        "# entry: {}, attachment: {}\n\
         [[database.ssh_key]]\n\
         fingerprint = \"{}\"\n\
         # name = \"…\"\n\
         # confirm = \"once\"   # or \"always\", or \"never\"\n\
         # forwarded = true\n\
         # serve = true\n",
        one_line(key.title.as_deref().unwrap_or(UNTITLED)),
        one_line(&key.attachment),
        one_line(&key.fingerprint),
    )
}

fn one_line(text: &str) -> String {
    escape_one_line(text, MAX_TEXT_LEN)
}

#[cfg(test)]
mod tests {
    use crate::config::Config;
    use crate::frontends::control::proto::WireSkippedKey;

    use super::*;

    /// A real `SHA256:…` fingerprint, `ssh_key`'s own doc example.
    const FINGERPRINT: &str = "SHA256:Nh0Me49Zh9fDw/VYUfq43IJmI1T+XrjiYONPND8GzaM";

    fn key(db: &str, title: Option<&str>) -> WireSshKey {
        WireSshKey {
            db: db.to_string(),
            key_type: "ssh-ed25519".to_string(),
            fingerprint: FINGERPRINT.to_string(),
            // A key with no title is served under its database's fallback.
            name: title.map_or_else(|| format!("{db} {FINGERPRINT}"), str::to_string),
            entry: uuid::Uuid::from_u128(1),
            title: title.map(str::to_string),
            attachment: "id_ed25519".to_string(),
        }
    }

    fn report(keys: Vec<WireSshKey>) -> SshKeysReport {
        SshKeysReport {
            keys,
            ..SshKeysReport::default()
        }
    }

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
    fn lists_keys_skipped_attachments_and_locked_databases() {
        let report = SshKeysReport {
            keys: vec![
                // Named by its override, not by its entry's title.
                WireSshKey {
                    name: "deploy-prod".to_string(),
                    ..key("personal", Some("Deploy"))
                },
                WireSshKey {
                    key_type: "ecdsa-sha2-nistp256".to_string(),
                    attachment: "id_ecdsa".to_string(),
                    ..key("work", None)
                },
                // Named by its entry's title.
                key("work", Some("Staging")),
            ],
            skipped: vec![WireSkippedKey {
                db: "personal".to_string(),
                title: Some("Old".to_string()),
                attachment: "id_rsa".to_string(),
                reason: "PEM format".to_string(),
            }],
            locked: vec!["archive".to_string()],
        };

        // The NAME column is as wide as the longest name, the fallback.
        let name =
            |text: &str| format!("{text:<width$}", width = "work ".len() + FINGERPRINT.len());
        assert_eq!(
            render(&report, false, true),
            format!(
                "{}  DATABASE  ENTRY       ATTACHMENT  TYPE                 FINGERPRINT\n\
                 {}  personal  Deploy      id_ed25519  ssh-ed25519          {FINGERPRINT}\n\
                 work {FINGERPRINT}  work      (untitled)  id_ecdsa    ecdsa-sha2-nistp256  {FINGERPRINT}\n\
                 {}  work      Staging     id_ed25519  ssh-ed25519          {FINGERPRINT}\n\
                 \n\
                 Skipped attachments:\n\
                 DATABASE  ENTRY  ATTACHMENT  REASON\n\
                 personal  Old    id_rsa      PEM format\n\
                 \n\
                 Locked, not scanned: archive (`kpa unlock <database>` first)\n",
                name("NAME"),
                name("deploy-prod"),
                name("Staging"),
            )
        );
    }

    /// Without `--full` the keys table has the name, type and fingerprint
    /// and nothing of where the key comes from. The skipped attachments, which
    /// no name or fingerprint identifies, keep theirs.
    #[test]
    fn the_default_table_keeps_to_name_type_and_fingerprint() {
        let report = SshKeysReport {
            keys: vec![
                WireSshKey {
                    name: "deploy-prod".to_string(),
                    ..key("personal", Some("Deploy"))
                },
                key("work", Some("Staging")),
            ],
            skipped: vec![WireSkippedKey {
                db: "personal".to_string(),
                title: Some("Old".to_string()),
                attachment: "id_rsa".to_string(),
                reason: "PEM format".to_string(),
            }],
            locked: Vec::new(),
        };

        assert_eq!(
            render(&report, false, false),
            format!(
                "NAME         TYPE         FINGERPRINT\n\
                 deploy-prod  ssh-ed25519  {FINGERPRINT}\n\
                 Staging      ssh-ed25519  {FINGERPRINT}\n\
                 \n\
                 Skipped attachments:\n\
                 DATABASE  ENTRY  ATTACHMENT  REASON\n\
                 personal  Old    id_rsa      PEM format\n"
            )
        );
    }

    #[test]
    fn no_keys_says_so() {
        assert_eq!(
            render(&SshKeysReport::default(), false, false),
            "No SSH keys found.\n"
        );
        assert_eq!(render(&SshKeysReport::default(), true, false), "");
    }

    /// The blocks come grouped under the database they belong to, and parse
    /// as the config they claim to be, each under its own database.
    #[test]
    fn the_blocks_parse_as_config_under_their_database() {
        let text = render(
            &report(vec![
                key("personal", Some("Deploy")),
                key("personal", None),
                key("work", Some("Build")),
            ]),
            true,
            false,
        );

        assert_eq!(
            text.matches("# Paste under [[database]]").count(),
            2,
            "{text}"
        );
        let personal = text
            .split("# Paste under [[database]] work:")
            .next()
            .expect("the first group");
        let config = config_with(personal).expect("the blocks should parse");
        assert_eq!(config.databases[0].ssh_keys.len(), 2);
        assert_eq!(
            config.databases[0].ssh_keys[0].fingerprint.to_string(),
            FINGERPRINT
        );
    }

    /// Each commented setting is valid TOML once uncommented, and shows
    /// the setting's default.
    #[test]
    fn the_commented_settings_are_the_defaults() {
        use crate::config::SshKeySettings;

        let block = block(&key("personal", Some("Deploy")));
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

    /// A title can't end the comment it sits in or smuggle a line into the
    /// blocks, and can't drive the terminal from the table either.
    #[test]
    fn hostile_text_is_escaped_and_cannot_leave_its_line() {
        let hostile = "x\nfingerprint = \"SHA256:evil\"\n\u{9b}c\u{202e}\t";
        let report = report(vec![key(hostile, Some(hostile))]);

        for toml in [false, true] {
            let text = render(&report, toml, true);
            assert!(!text.contains('\u{9b}') && !text.contains('\u{202e}'));
            assert!(!text.contains('\t'));
            assert!(
                text.lines()
                    .all(|line| !line.starts_with("fingerprint = \"SHA256:evil")),
                "{text}"
            );
        }
        // Only the real fingerprint is in the blocks.
        let blocks = render(&report, true, false);
        let after_header = blocks.split_once('\n').expect("a header").1;
        let config = config_with(after_header).expect("the blocks should still parse");
        assert_eq!(config.databases[0].ssh_keys.len(), 1);
    }
}
