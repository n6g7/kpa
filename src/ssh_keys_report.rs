//! What `kpa ssh keys` prints (`docs/ssh-agent.md` § 6.4): the keys a
//! database's vault holds, the attachments skipped, and, on request, a
//! `[[database.ssh_key]]` block per key to paste into the config.
//!
//! Pure: a report in, text out. Everything the vault supplies (titles,
//! attachment names, the text of a reason) is escaped for one line of
//! terminal output before it is interpolated, which also keeps a title
//! from ending the `#` comment a block puts it in (`docs/threat-model.md`
//! T-13). Columns are padded to the widest escaped cell, so no cell can
//! push the next one out of line.

use std::fmt::Write as _;

use kpa::output::escape_one_line;
use kpa::proto::{SshKeysReport, WireSshKey};

/// Longest escaped title, attachment name or reason shown.
const MAX_FIELD_LEN: usize = 128;

/// An entry without a title.
const UNTITLED: &str = "(untitled)";

/// `blocks` adds the `[[database.ssh_key]]` block per key.
pub(super) fn render(db: &str, report: &SshKeysReport, blocks: bool) -> String {
    let db = field(db);
    let mut out = String::new();

    if report.keys.is_empty() {
        let _ = writeln!(out, "No SSH keys found in {db}.");
    } else {
        let _ = writeln!(out, "SSH keys in {db}:");
        let rows = report
            .keys
            .iter()
            .map(|key| {
                [
                    field(&key.key_type),
                    field(&key.fingerprint),
                    entry(key.title.as_deref()),
                    field(&key.attachment),
                ]
            })
            .collect();
        out.push_str(&table(["TYPE", "FINGERPRINT", "ENTRY", "ATTACHMENT"], rows));
    }

    if !report.skipped.is_empty() {
        let _ = writeln!(out, "\nSkipped attachments:");
        let rows = report
            .skipped
            .iter()
            .map(|skipped| {
                [
                    entry(skipped.title.as_deref()),
                    field(&skipped.attachment),
                    field(&skipped.reason),
                ]
            })
            .collect();
        out.push_str(&table(["ENTRY", "ATTACHMENT", "REASON"], rows));
    }

    if blocks && !report.keys.is_empty() {
        let _ = writeln!(
            out,
            "\nPaste a block under the [[database]] for {db} and uncomment a setting to change \
             it. Each shows its default, except `name`, which defaults to the entry's title:",
        );
        for key in &report.keys {
            let _ = write!(out, "\n{}", config_block(key));
        }
    }
    out
}

/// A header row and `rows`, each column padded to its widest cell and
/// separated by two spaces. The last column is not padded.
fn table<const N: usize>(header: [&str; N], rows: Vec<[String; N]>) -> String {
    let mut widths = header.map(|cell| cell.chars().count());
    for row in &rows {
        for (width, cell) in widths.iter_mut().zip(row) {
            *width = (*width).max(cell.chars().count());
        }
    }

    let mut out = String::new();
    let mut push_row = |cells: [&str; N]| {
        let last = N - 1;
        for (i, (cell, width)) in cells.iter().zip(widths).enumerate() {
            if i == last {
                out.push_str(cell);
            } else {
                let _ = write!(out, "{cell:<width$}  ");
            }
        }
        out.push('\n');
    };
    push_row(header);
    for row in &rows {
        push_row(row.each_ref().map(String::as_str));
    }
    out
}

/// An entry's title as one line of text.
fn entry(title: Option<&str>) -> String {
    title.map_or_else(|| UNTITLED.to_string(), field)
}

/// The `[[database.ssh_key]]` table for `key` (`docs/ssh-agent.md` § 7):
/// its fingerprint, which is all a table needs, with every other setting
/// commented out at its default.
fn config_block(key: &WireSshKey) -> String {
    format!(
        "# entry: {}, attachment: {}\n\
         [[database.ssh_key]]\n\
         fingerprint = \"{}\"\n\
         # name = \"…\"\n\
         # confirm = \"once\"   # or \"always\", or \"never\"\n\
         # forwarded = true\n\
         # serve = true\n",
        entry(key.title.as_deref()),
        field(&key.attachment),
        field(&key.fingerprint),
    )
}

fn field(text: &str) -> String {
    escape_one_line(text, MAX_FIELD_LEN)
}

#[cfg(test)]
mod tests {
    use kpa::config::Config;
    use kpa::proto::WireSkippedKey;

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

    /// The text of `rendered` from its first `[[database.ssh_key]]` line,
    /// one line above, to the end: the blocks.
    fn blocks_of(rendered: &str) -> String {
        let lines: Vec<&str> = rendered.lines().collect();
        let first = lines
            .iter()
            .position(|line| *line == "[[database.ssh_key]]")
            .expect("a block");
        lines[first - 1..].join("\n")
    }

    #[test]
    fn lists_keys_and_skipped_attachments_in_labelled_columns() {
        let report = SshKeysReport {
            keys: vec![
                key(Some("Deploy"), FINGERPRINT),
                WireSshKey {
                    key_type: "ecdsa-sha2-nistp256".to_string(),
                    title: None,
                    attachment: "id_ecdsa".to_string(),
                    ..key(None, FINGERPRINT)
                },
            ],
            skipped: vec![WireSkippedKey {
                title: Some("Old".to_string()),
                attachment: "id_rsa".to_string(),
                reason: "PEM format".to_string(),
            }],
        };

        let text = render("personal", &report, false);

        assert_eq!(
            text,
            format!(
                "SSH keys in personal:\n\
                 TYPE                 FINGERPRINT                                         \
                 ENTRY       ATTACHMENT\n\
                 ssh-ed25519          {FINGERPRINT}  Deploy      id_ed25519\n\
                 ecdsa-sha2-nistp256  {FINGERPRINT}  (untitled)  id_ecdsa\n\
                 \n\
                 Skipped attachments:\n\
                 ENTRY  ATTACHMENT  REASON\n\
                 Old    id_rsa      PEM format\n"
            )
        );
    }

    #[test]
    fn no_keys_says_so_and_offers_no_blocks() {
        let text = render("personal", &SshKeysReport::default(), true);
        assert_eq!(text, "No SSH keys found in personal.\n");
    }

    #[test]
    fn blocks_come_only_when_asked_for() {
        let report = SshKeysReport {
            keys: vec![key(Some("Deploy"), FINGERPRINT)],
            skipped: Vec::new(),
        };

        assert!(!render("personal", &report, false).contains("database.ssh_key"));

        let text = render("personal", &report, true);
        assert!(
            text.contains(
                "# entry: Deploy, attachment: id_ed25519\n[[database.ssh_key]]\n\
                 fingerprint = \"SHA256:Nh0Me49Zh9fDw/VYUfq43IJmI1T+XrjiYONPND8GzaM\"\n"
            ),
            "{text}"
        );
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

        let text = render(hostile, &report, true);

        assert!(!text.contains('\u{9b}'));
        assert!(!text.contains('\u{202e}'));
        assert!(!text.contains('\t'));
        assert!(
            text.lines()
                .all(|line| !line.starts_with("fingerprint = \"SHA256:evil")),
            "{text}"
        );
        let config = config_with(&blocks_of(&text)).expect("the blocks should still parse");
        assert_eq!(config.databases[0].ssh_keys.len(), 1);
    }

    /// Widths are measured on the escaped text, so a title full of
    /// newlines, tabs and control characters still leaves every row's
    /// attachment where the header put it.
    #[test]
    fn hostile_titles_do_not_break_the_alignment() {
        let titles = [
            Some("plain"),
            Some("two\nlines"),
            Some("tab\there"),
            Some("\u{9b}c\u{202e}\u{7f}"),
            None,
        ];
        let keys: Vec<WireSshKey> = titles
            .iter()
            .enumerate()
            .map(|(i, title)| WireSshKey {
                key_type: ["ssh-rsa", "ssh-ed25519", "ecdsa-sha2-nistp384"][i % 3].to_string(),
                attachment: format!("att-{i}"),
                ..key(*title, FINGERPRINT)
            })
            .collect();
        let report = SshKeysReport {
            keys,
            skipped: Vec::new(),
        };

        let text = render("personal", &report, false);

        let mut lines = text.lines().skip(1);
        let header = lines.next().expect("a header");
        let column = header.find("ATTACHMENT").expect("an ATTACHMENT column");
        let rows: Vec<&str> = lines.collect();
        assert_eq!(rows.len(), titles.len(), "a title added a line: {text}");
        for (i, row) in rows.iter().enumerate() {
            assert_eq!(
                row.get(column..),
                Some(format!("att-{i}").as_str()),
                "row {i} is out of line:\n{text}"
            );
        }
    }

    #[test]
    fn long_titles_are_capped() {
        let report = SshKeysReport {
            keys: vec![key(Some(&"t".repeat(10_000)), FINGERPRINT)],
            skipped: Vec::new(),
        };
        assert!(render("personal", &report, true).len() < 1_000);
    }
}
