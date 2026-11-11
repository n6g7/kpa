//! The config file, matching the shape settled in `docs/design.md`
//! § Configuration. `Config::load` does everything from finding the file to
//! expanding `~` in its paths; `main.rs`'s `serve` calls it once at startup,
//! and `server::Server` owns the result for the life of the daemon.

use std::path::{Component, Path, PathBuf};
use std::time::Duration;

use serde::Deserialize;

use crate::log::Level;

/// Top-level config, `$XDG_CONFIG_HOME/kpa/config.toml`.
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct Config {
    /// Lock each database after this much time with no successful `list`
    /// of it and no unlock that installed it (`list` of all databases counts
    /// for each one it reads). `status`, `lock` and refused requests don't
    /// count (`docs/threat-model.md` G-5). Each database has its own timer:
    /// using one does not keep another unlocked. Defaults to 30 minutes,
    /// matching `docs/design.md`'s settled decision #7 — logind's
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

    /// How long a prompt may stay open unanswered. Past this the prompt is
    /// killed and the unlock fails with `prompt_cancelled`, so a prompt
    /// raised where nobody is looking doesn't wait there indefinitely.
    #[serde(with = "humantime_serde", default = "default_prompt_timeout")]
    pub prompt_timeout: Duration,

    /// How long a copied secret stays on the clipboard before kpa drops
    /// its own clipboard offer (see § Clipboard).
    #[serde(with = "humantime_serde", default = "default_clipboard_timeout")]
    pub clipboard_timeout: Duration,

    /// How much `serve` logs; `--log-level` overrides it. See
    /// `docs/design.md` § Logging.
    #[serde(default)]
    pub log_level: Level,

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

fn default_prompt_timeout() -> Duration {
    Duration::from_secs(60)
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
    /// Find, read, parse and resolve the config: `path` if given (from
    /// `--config`), otherwise `$XDG_CONFIG_HOME/kpa/config.toml`, falling
    /// back to `~/.config/kpa/config.toml`.
    ///
    /// A leading `~/` in any database or keyfile path is expanded to
    /// `$HOME`. `~user/...` is an error rather than a literal directory
    /// name: nobody means a directory called `~user`, and silently looking
    /// for one is exactly the failure expansion exists to prevent. Other
    /// relative paths are left as written, and resolve against the
    /// daemon's working directory.
    pub fn load(path: Option<&Path>) -> Result<Config, ConfigError> {
        let path = match path {
            Some(path) => path.to_path_buf(),
            None => default_path()?,
        };
        let text = std::fs::read_to_string(&path).map_err(|source| ConfigError::Read {
            path: path.clone(),
            source,
        })?;
        let config = Config::parse(&text).map_err(|source| ConfigError::Parse {
            path: path.clone(),
            source,
        })?;
        let home = std::env::var_os("HOME").map(PathBuf::from);
        config.expand_home(home.as_deref(), &path)
    }

    /// Parse a config from a TOML string, paths exactly as written — the
    /// pure half of `load`, and what tests use to build a `Config`.
    pub fn parse(input: &str) -> Result<Config, toml::de::Error> {
        toml::from_str(input)
    }

    /// `home` is a parameter, not read here, so this can be tested without
    /// touching the process environment (`set_var` is `unsafe` in Rust
    /// 2024 for good reason, with tests on parallel threads). `load` passes
    /// the real `$HOME`; tests that build a daemon in-process pass their
    /// own. `config` is the config file's path, for error messages.
    pub fn expand_home(
        mut self,
        home: Option<&Path>,
        config: &Path,
    ) -> Result<Config, ConfigError> {
        let expand = |path: &Path| {
            expand(path, home).map_err(|kind| ConfigError::Path {
                config: config.to_path_buf(),
                path: path.to_path_buf(),
                kind,
            })
        };
        for db in &mut self.databases {
            db.path = expand(&db.path)?;
            if let Some(keyfile) = &db.keyfile {
                db.keyfile = Some(expand(keyfile)?);
            }
        }
        Ok(self)
    }
}

fn default_path() -> Result<PathBuf, ConfigError> {
    if let Some(dir) = std::env::var_os("XDG_CONFIG_HOME") {
        return Ok(PathBuf::from(dir).join("kpa/config.toml"));
    }
    std::env::var_os("HOME")
        .map(|home| PathBuf::from(home).join(".config/kpa/config.toml"))
        .ok_or(ConfigError::NoDefaultPath)
}

/// Everything `Config::load` can fail with. Each names the file involved.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("no config path given, and neither XDG_CONFIG_HOME nor HOME is set")]
    NoDefaultPath,
    #[error("reading {}: {source}", path.display())]
    Read {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("parsing {}: {source}", path.display())]
    Parse {
        path: PathBuf,
        source: toml::de::Error,
    },
    #[error("in {}: {}: {kind}", config.display(), path.display())]
    Path {
        config: PathBuf,
        path: PathBuf,
        kind: TildeError,
    },
}

/// Why a `~` path couldn't be expanded.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum TildeError {
    #[error("`~` needs $HOME, which is not set")]
    NoHome,
    #[error("`~user` paths are not supported; use an absolute path")]
    OtherUser,
}

fn expand(path: &Path, home: Option<&Path>) -> Result<PathBuf, TildeError> {
    let mut components = path.components();
    let Some(Component::Normal(first)) = components.next() else {
        return Ok(path.to_path_buf());
    };
    if first == "~" {
        Ok(home.ok_or(TildeError::NoHome)?.join(components.as_path()))
    } else if first.as_encoded_bytes().starts_with(b"~") {
        Err(TildeError::OtherUser)
    } else {
        Ok(path.to_path_buf())
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
            prompt_timeout = "60s"
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
        assert_eq!(config.prompt_timeout, Duration::from_secs(60));
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
            prompt_timeout = "2m"
            clipboard_timeout = "5s"
        "#;

        let config = Config::parse(input).expect("valid config should parse");
        assert_eq!(config.idle_timeout, Duration::from_secs(10));
        assert_eq!(config.prompt_timeout, Duration::from_secs(120));
        assert_eq!(config.clipboard_timeout, Duration::from_secs(5));
        assert!(config.databases.is_empty());
    }

    #[test]
    fn defaults_apply_when_top_level_keys_are_omitted() {
        // An empty config is valid: every top-level key has a default, and
        // an empty database list is meaningful (nothing configured yet).
        let config = Config::parse("").expect("empty config should parse");

        assert_eq!(config.idle_timeout, Duration::from_secs(30 * 60));
        assert_eq!(config.prompt_timeout, Duration::from_secs(60));
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

    fn one_database(path: &str, keyfile: Option<&str>) -> Config {
        let keyfile = keyfile
            .map(|k| format!("keyfile = \"{k}\"\n"))
            .unwrap_or_default();
        Config::parse(&format!(
            "[[database]]\nname = \"personal\"\npath = \"{path}\"\n{keyfile}"
        ))
        .expect("valid config should parse")
    }

    fn expanded(path: &str, home: Option<&str>) -> Result<PathBuf, TildeError> {
        expand(Path::new(path), home.map(Path::new))
    }

    #[test]
    fn a_leading_tilde_expands_to_home() {
        assert_eq!(
            expanded("~/vault/personal.kdbx", Some("/home/alice")),
            Ok(PathBuf::from("/home/alice/vault/personal.kdbx"))
        );
        assert_eq!(
            expanded("~", Some("/home/alice")),
            Ok(PathBuf::from("/home/alice"))
        );
    }

    #[test]
    fn paths_without_a_leading_tilde_are_untouched() {
        for path in [
            "/abs/vault.kdbx",
            "relative/vault.kdbx",
            "vault~.kdbx",
            "dir/~/vault.kdbx",
        ] {
            assert_eq!(expanded(path, Some("/home/alice")), Ok(PathBuf::from(path)));
        }
    }

    /// Without `$HOME`, only a path that actually needs it is an error.
    #[test]
    fn a_missing_home_only_matters_when_a_path_needs_it() {
        assert_eq!(
            expanded("/abs/vault.kdbx", None),
            Ok(PathBuf::from("/abs/vault.kdbx"))
        );
        assert_eq!(expanded("~/vault.kdbx", None), Err(TildeError::NoHome));
    }

    #[test]
    fn another_users_home_is_refused_not_taken_literally() {
        assert_eq!(
            expanded("~bob/vault.kdbx", Some("/home/alice")),
            Err(TildeError::OtherUser)
        );
    }

    #[test]
    fn keyfiles_expand_too() {
        let config = one_database("/vault.kdbx", Some("~/.keys/personal.key"))
            .expand_home(Some(Path::new("/home/alice")), Path::new("config.toml"))
            .expect("should expand");
        assert_eq!(
            config.databases[0].keyfile,
            Some(PathBuf::from("/home/alice/.keys/personal.key"))
        );
    }

    /// `load` end to end on a real file. Absolute paths only, so the
    /// result doesn't depend on this process's `$HOME`; `~` through `load`
    /// is covered by spawning the daemon with its own `HOME`, in
    /// `tests/server.rs`.
    #[test]
    fn load_reads_and_parses_a_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("config.toml");
        std::fs::write(
            &path,
            "idle_timeout = \"10s\"\n[[database]]\nname = \"p\"\npath = \"/v.kdbx\"\n",
        )
        .expect("write");

        let config = Config::load(Some(&path)).expect("should load");
        assert_eq!(config.idle_timeout, Duration::from_secs(10));
        assert_eq!(config.databases[0].path, PathBuf::from("/v.kdbx"));
    }

    /// Every failure names the file, so the daemon's startup error says
    /// where to look.
    #[test]
    fn load_errors_name_the_file() {
        let dir = tempfile::tempdir().expect("tempdir");

        let missing = dir.path().join("missing.toml");
        let err = Config::load(Some(&missing)).expect_err("a missing file should fail");
        assert!(matches!(err, ConfigError::Read { .. }));
        assert!(err.to_string().contains("missing.toml"), "{err}");

        let bad = dir.path().join("bad.toml");
        std::fs::write(&bad, "idle_timeout = [").expect("write");
        let err = Config::load(Some(&bad)).expect_err("bad TOML should fail");
        assert!(matches!(err, ConfigError::Parse { .. }));
        assert!(err.to_string().contains("bad.toml"), "{err}");

        let tilde = dir.path().join("tilde.toml");
        std::fs::write(
            &tilde,
            "[[database]]\nname = \"p\"\npath = \"~bob/v.kdbx\"\n",
        )
        .expect("write");
        let err = Config::load(Some(&tilde)).expect_err("~user should fail");
        assert!(matches!(
            err,
            ConfigError::Path {
                kind: TildeError::OtherUser,
                ..
            }
        ));
        assert!(err.to_string().contains("tilde.toml"), "{err}");
    }
}
