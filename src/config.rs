//! TOML config parsing, matching the shape settled in `docs/design.md`
//! § Configuration. `main.rs`'s `serve` subcommand reads and parses this at
//! startup; `server::Server` owns the resulting `Config` for the lifetime
//! of the daemon.

use std::path::PathBuf;
use std::time::Duration;

use serde::Deserialize;

/// Top-level config, `$XDG_CONFIG_HOME/kpa/config.toml`.
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct Config {
    /// Lock all databases after this much time with no requests. Defaults
    /// match `docs/design.md`'s settled decision #7 (30 minutes) — logind's
    /// `Lock` signal already covers screen-lock, this only catches walking
    /// away without locking.
    #[serde(with = "humantime_serde", default = "default_idle_timeout")]
    pub idle_timeout: Duration,

    /// argv for the passphrase prompt, e.g.
    /// `["fuzzel", "--dmenu", "--password", "--prompt"]`. Swappable per
    /// decision #9 in the design doc — `pinentry-qt` is the long-term
    /// answer but fiddly, so this stays a plain argv rather than an enum.
    #[serde(default = "default_prompt")]
    pub prompt: Vec<String>,

    /// How long a copied secret stays on the clipboard before kpa drops
    /// its own clipboard offer (see § Clipboard).
    #[serde(with = "humantime_serde", default = "default_clipboard_timeout")]
    pub clipboard_timeout: Duration,

    /// One or more `.kdbx` files to manage. TOML array-of-tables, per
    /// decision #10 — each database unlocks and tracks tray state
    /// independently.
    #[serde(rename = "database", default)]
    pub databases: Vec<DatabaseConfig>,
}

/// One `[[database]]` entry.
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct DatabaseConfig {
    /// Stable id used in requests and the tray — not derived from the
    /// filename, so renaming the file on disk doesn't break references to
    /// it in flight.
    pub name: String,

    pub path: PathBuf,

    /// Optional keyfile alongside the password. `None` means
    /// password-only.
    #[serde(default)]
    pub keyfile: Option<PathBuf>,
}

fn default_idle_timeout() -> Duration {
    Duration::from_secs(30 * 60)
}

fn default_clipboard_timeout() -> Duration {
    Duration::from_secs(30)
}

fn default_prompt() -> Vec<String> {
    vec![
        "fuzzel".to_string(),
        "--dmenu".to_string(),
        "--password".to_string(),
        "--prompt".to_string(),
    ]
}

impl Config {
    /// Parse a config from a TOML string. Takes `&str` rather than a path —
    /// reading the file is main.rs's job, this is the pure parsing half.
    pub fn parse(input: &str) -> Result<Config, toml::de::Error> {
        toml::from_str(input)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_full_example_from_design_doc() {
        // Verbatim from docs/design.md § Configuration, so this test is
        // really "does the design doc's own example parse".
        let input = r#"
            idle_timeout = "30m"
            prompt = ["fuzzel", "--dmenu", "--password", "--prompt"]
            clipboard_timeout = "30s"

            [[database]]
            name    = "personal"
            path    = "~/vault/personal.kdbx"
            keyfile = "~/.keys/personal.key"

            [[database]]
            name = "work"
            path = "~/vault/work.kdbx"
        "#;

        let config = Config::parse(input).expect("valid config should parse");

        assert_eq!(config.idle_timeout, Duration::from_secs(30 * 60));
        assert_eq!(
            config.prompt,
            vec!["fuzzel", "--dmenu", "--password", "--prompt"]
        );
        assert_eq!(config.clipboard_timeout, Duration::from_secs(30));

        assert_eq!(config.databases.len(), 2);

        let personal = &config.databases[0];
        assert_eq!(personal.name, "personal");
        assert_eq!(personal.path, PathBuf::from("~/vault/personal.kdbx"));
        assert_eq!(
            personal.keyfile,
            Some(PathBuf::from("~/.keys/personal.key"))
        );

        let work = &config.databases[1];
        assert_eq!(work.name, "work");
        assert_eq!(work.path, PathBuf::from("~/vault/work.kdbx"));
        assert_eq!(work.keyfile, None);
    }

    #[test]
    fn parses_short_human_durations() {
        let input = r#"
            idle_timeout = "10s"
            clipboard_timeout = "5s"
        "#;

        let config = Config::parse(input).expect("valid config should parse");
        assert_eq!(config.idle_timeout, Duration::from_secs(10));
        assert_eq!(config.clipboard_timeout, Duration::from_secs(5));
        assert!(config.databases.is_empty());
    }

    #[test]
    fn defaults_apply_when_top_level_keys_are_omitted() {
        // An empty config is valid: every top-level key has a default, and
        // an empty database list is meaningful (nothing configured yet).
        let config = Config::parse("").expect("empty config should parse");

        assert_eq!(config.idle_timeout, Duration::from_secs(30 * 60));
        assert_eq!(config.clipboard_timeout, Duration::from_secs(30));
        assert_eq!(
            config.prompt,
            vec!["fuzzel", "--dmenu", "--password", "--prompt"]
        );
        assert!(config.databases.is_empty());
    }

    #[test]
    fn rejects_malformed_duration() {
        let input = r#"
            idle_timeout = "not-a-duration"
        "#;

        assert!(Config::parse(input).is_err());
    }
}
