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

    /// argv for the passphrase prompt, by default
    /// `["sh", "-c", "exec fuzzel --dmenu --password --prompt \"$KPA_PROMPT_MESSAGE\""]`.
    /// Swappable per decision #9 in the design doc — `pinentry-qt` is the
    /// long-term answer but fiddly, so this stays a plain argv rather than
    /// an enum.
    /// Runs exactly as configured: `prompt::SecretProgram` passes what the
    /// prompt is about through the `KPA_PROMPT_MESSAGE` environment
    /// variable instead of touching the argv.
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

    /// `[ssh_agent]` — settings for the SSH agent socket
    /// (`docs/ssh-agent.md` § 7). Present (with its own field defaults)
    /// even when no database serves SSH keys.
    #[serde(default)]
    pub ssh_agent: SshAgentConfig,
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

    /// Serve this database's OpenSSH-formatted key attachments over the
    /// SSH agent socket (`docs/ssh-agent.md` § 6.4).
    #[serde(default)]
    pub serve_ssh_keys: bool,

    /// Per-key overrides, matched by fingerprint against the keys this
    /// database's entries hold. A config error unless `serve_ssh_keys` is
    /// also true (`Config::validate`).
    #[serde(rename = "ssh_key", default)]
    pub ssh_keys: Vec<SshKeyConfig>,
}

/// `[ssh_agent]` (`docs/ssh-agent.md` § 7). An unknown key is an error, so
/// a typo fails the load rather than leaving a setting at its default.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SshAgentConfig {
    /// The agent socket's path: absolute, or under `~/`, which `load`
    /// expands. `None` means the default, `$XDG_RUNTIME_DIR/kpa/ssh-agent`,
    /// resolved by [`SshAgentConfig::socket_path`] rather than at parse
    /// time, since the default depends on the environment.
    #[serde(default)]
    pub socket: Option<PathBuf>,

    /// argv for the confirm prompt, dmenu style (`docs/ssh-agent.md`
    /// § 6.7). Empty (the default) until set — required once any database
    /// has `serve_ssh_keys = true` (`Config::validate`).
    #[serde(default)]
    pub confirm_prompt: Vec<String>,

    /// How long the confirm prompt may stay open unanswered before it is
    /// killed and the signature refused. `None` (unset) means the
    /// top-level `prompt_timeout`, as [`Config::confirm_prompt_timeout`]
    /// resolves it.
    #[serde(with = "humantime_serde", default)]
    pub confirm_prompt_timeout: Option<Duration>,

    /// How long a cancelled unlock or confirm prompt holds back
    /// signatures from its database (`docs/ssh-agent.md` § 6.6).
    #[serde(with = "humantime_serde", default = "default_ssh_agent_backoff")]
    pub backoff: Duration,
}

impl Default for SshAgentConfig {
    fn default() -> Self {
        SshAgentConfig {
            socket: None,
            confirm_prompt: Vec::new(),
            confirm_prompt_timeout: None,
            backoff: default_ssh_agent_backoff(),
        }
    }
}

impl SshAgentConfig {
    /// The socket path: `socket` if set, else `runtime_dir.join("kpa/ssh-agent")`.
    /// `runtime_dir` is a parameter, not read from the environment here, so
    /// this can be tested without touching the process environment — the
    /// same reason [`Config::expand_home`] takes `home` as a parameter.
    /// `None` if `socket` is unset and no `runtime_dir` is given.
    pub fn socket_path(&self, runtime_dir: Option<&Path>) -> Option<PathBuf> {
        self.socket
            .clone()
            .or_else(|| runtime_dir.map(|dir| dir.join("kpa/ssh-agent")))
    }
}

/// `[[database.ssh_key]]`: an override for one key, matched by fingerprint
/// (`docs/ssh-agent.md` § 7). An unknown key is an error: a typo such as
/// `fowarded = false` must fail the load, not leave the key forwardable.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SshKeyConfig {
    /// `SHA256:…`, as `ssh-add -l` and `kpa ssh keys` print it. Parsed
    /// as the config loads, so one that doesn't parse, or isn't SHA-256,
    /// fails the load.
    #[serde(deserialize_with = "deserialize_fingerprint")]
    pub fingerprint: ssh_key::Fingerprint,

    /// Identity comment, shown in prompts and logs. Defaults to the
    /// entry's title while unlocked, or `<database> <fingerprint>` while
    /// locked.
    #[serde(default)]
    pub name: Option<String>,

    /// Local approval policy (`docs/ssh-agent.md` § 6.7).
    #[serde(default)]
    pub confirm: SshKeyConfirm,

    /// Usable through `ssh -A`, with its own approval. `false` keeps the
    /// key off every forwarded connection.
    #[serde(default = "SshKeySettings::default_forwarded")]
    pub forwarded: bool,

    /// `false` keeps this key out of the agent entirely.
    #[serde(default = "SshKeySettings::default_serve")]
    pub serve: bool,
}

/// Reads an `SshKeyConfig::fingerprint`. An invalid one is a parse error,
/// which TOML reports at the offending line. Only a SHA-256 fingerprint is
/// accepted: kpa matches keys by theirs, so any other kind would never
/// match and the override would silently do nothing.
fn deserialize_fingerprint<'de, D>(deserializer: D) -> Result<ssh_key::Fingerprint, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let text = String::deserialize(deserializer)?;
    let fingerprint: ssh_key::Fingerprint = text.parse().map_err(|err| {
        serde::de::Error::custom(format!("ssh_key fingerprint {text:?} is invalid: {err}"))
    })?;
    match fingerprint {
        ssh_key::Fingerprint::Sha256(_) => Ok(fingerprint),
        _ => Err(serde::de::Error::custom(format!(
            "ssh_key fingerprint {text:?} is not a SHA-256 one: write it as `SHA256:…`, \
             as `ssh-add -l` prints it"
        ))),
    }
}

/// A key's effective settings: its `[[database.ssh_key]]` override, or the
/// defaults when none matches (`DatabaseConfig::ssh_key_settings`). The
/// serde defaults of `SshKeyConfig` and the no-override case share these
/// values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshKeySettings {
    pub name: Option<String>,
    pub confirm: SshKeyConfirm,
    pub forwarded: bool,
    pub serve: bool,
}

impl SshKeySettings {
    fn default_forwarded() -> bool {
        true
    }

    fn default_serve() -> bool {
        true
    }
}

impl Default for SshKeySettings {
    fn default() -> Self {
        SshKeySettings {
            name: None,
            confirm: SshKeyConfirm::default(),
            forwarded: Self::default_forwarded(),
            serve: Self::default_serve(),
        }
    }
}

impl From<&SshKeyConfig> for SshKeySettings {
    fn from(key: &SshKeyConfig) -> Self {
        SshKeySettings {
            name: key.name.clone(),
            confirm: key.confirm,
            forwarded: key.forwarded,
            serve: key.serve,
        }
    }
}

impl DatabaseConfig {
    /// The settings for the key with `fingerprint` in this database: its
    /// `[[database.ssh_key]]` override, or the defaults if none matches.
    pub fn ssh_key_settings(&self, fingerprint: ssh_key::Fingerprint) -> SshKeySettings {
        self.ssh_keys
            .iter()
            .find(|key| key.fingerprint == fingerprint)
            .map(SshKeySettings::from)
            .unwrap_or_default()
    }
}

/// `[[database.ssh_key]]`'s `confirm` (`docs/ssh-agent.md` § 6.7).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SshKeyConfirm {
    /// The first local signature with the key after each unlock asks; the
    /// approval holds until the database locks.
    #[default]
    Once,
    /// Every signature asks, forwarded ones included.
    Always,
    /// Local signatures never ask. Forwarded use still needs its own
    /// per-session approval regardless.
    Never,
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
        "sh".to_string(),
        "-c".to_string(),
        "exec fuzzel --dmenu --password --prompt \"$KPA_PROMPT_MESSAGE\"".to_string(),
    ]
}

fn default_ssh_agent_backoff() -> Duration {
    Duration::from_secs(2 * 60)
}

impl Config {
    /// How long the SSH agent's confirm prompt may stay open:
    /// `ssh_agent.confirm_prompt_timeout` if set, `prompt_timeout`
    /// otherwise.
    pub fn confirm_prompt_timeout(&self) -> Duration {
        self.ssh_agent
            .confirm_prompt_timeout
            .unwrap_or(self.prompt_timeout)
    }

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
        let config = config.expand_home(home.as_deref(), &path)?;
        config.validate(&path)?;
        Ok(config)
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
        if let Some(socket) = &self.ssh_agent.socket {
            self.ssh_agent.socket = Some(expand(socket)?);
        }
        Ok(self)
    }

    /// Checks the rules TOML's own shape can't express
    /// (`docs/ssh-agent.md` § 7):
    ///
    /// - `ssh_agent.confirm_prompt` is required once any database opts in;
    /// - `ssh_agent.socket`, if set, is absolute, since a relative one
    ///   would bind against the daemon's working directory;
    /// - a `[[database.ssh_key]]` override needs its database's
    ///   `serve_ssh_keys = true`;
    /// - fingerprints are unique within one database. The same fingerprint
    ///   in two databases is not a conflict: config order decides which
    ///   one serves it.
    ///
    /// `load` runs this after `expand_home`; `config` is the file's path,
    /// for error messages.
    pub fn validate(&self, config: &Path) -> Result<(), ConfigError> {
        if let Some(socket) = &self.ssh_agent.socket
            && !socket.is_absolute()
        {
            return Err(ConfigError::RelativeSshAgentSocket {
                config: config.to_path_buf(),
                socket: socket.clone(),
            });
        }
        if self.databases.iter().any(|db| db.serve_ssh_keys)
            && self.ssh_agent.confirm_prompt.is_empty()
        {
            return Err(ConfigError::SshAgentConfirmRequired {
                config: config.to_path_buf(),
            });
        }
        for db in &self.databases {
            if !db.serve_ssh_keys && !db.ssh_keys.is_empty() {
                return Err(ConfigError::SshKeyOverrideWithoutAgent {
                    config: config.to_path_buf(),
                    database: db.name.clone(),
                });
            }
            let mut seen = std::collections::HashSet::new();
            for key in &db.ssh_keys {
                if !seen.insert(key.fingerprint) {
                    return Err(ConfigError::DuplicateSshKeyFingerprint {
                        config: config.to_path_buf(),
                        database: db.name.clone(),
                        fingerprint: key.fingerprint,
                    });
                }
            }
        }
        Ok(())
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
    #[error(
        "in {}: ssh_agent.confirm_prompt is required once a database has serve_ssh_keys = true",
        config.display()
    )]
    SshAgentConfirmRequired { config: PathBuf },
    #[error(
        "in {}: ssh_agent.socket {} is relative; give an absolute path or one under ~/",
        config.display(),
        socket.display()
    )]
    RelativeSshAgentSocket { config: PathBuf, socket: PathBuf },
    #[error(
        "in {}: database {database:?} has [[database.ssh_key]] overrides but serve_ssh_keys is not true",
        config.display()
    )]
    SshKeyOverrideWithoutAgent { config: PathBuf, database: String },
    #[error(
        "in {}: database {database:?} has a duplicate ssh_key fingerprint: {fingerprint}",
        config.display()
    )]
    DuplicateSshKeyFingerprint {
        config: PathBuf,
        database: String,
        fingerprint: ssh_key::Fingerprint,
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
            prompt = ["sh", "-c", "exec fuzzel --dmenu --password --prompt \"$KPA_PROMPT_MESSAGE\""]
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
            vec![
                "sh",
                "-c",
                "exec fuzzel --dmenu --password --prompt \"$KPA_PROMPT_MESSAGE\""
            ]
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

    /// Without its own timeout, the confirm prompt uses `prompt_timeout`.
    #[test]
    fn the_confirm_prompt_timeout_falls_back_to_prompt_timeout() {
        let config = Config::parse("prompt_timeout = \"2m\"\n").expect("valid config");
        assert_eq!(config.ssh_agent.confirm_prompt_timeout, None);
        assert_eq!(config.confirm_prompt_timeout(), Duration::from_secs(120));

        let default = Config::parse("").expect("valid config");
        assert_eq!(default.confirm_prompt_timeout(), default.prompt_timeout);
    }

    /// Set, it overrides `prompt_timeout` for the confirm prompt only, and
    /// parses as `prompt_timeout` does.
    #[test]
    fn the_confirm_prompt_timeout_overrides_prompt_timeout() {
        let config = Config::parse(
            "prompt_timeout = \"2m\"\n\n\
             [ssh_agent]\nconfirm_prompt_timeout = \"15s\"\n",
        )
        .expect("valid config");
        assert_eq!(config.confirm_prompt_timeout(), Duration::from_secs(15));
        assert_eq!(config.prompt_timeout, Duration::from_secs(120));

        let config = Config::parse("[ssh_agent]\nconfirm_prompt_timeout = \"1m 30s\"\n")
            .expect("valid config");
        assert_eq!(config.confirm_prompt_timeout(), Duration::from_secs(90));
        assert!(Config::parse("[ssh_agent]\nconfirm_prompt_timeout = \"soon\"\n").is_err());
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
            vec![
                "sh",
                "-c",
                "exec fuzzel --dmenu --password --prompt \"$KPA_PROMPT_MESSAGE\""
            ]
        );
        assert!(config.databases.is_empty());
        assert_eq!(config.ssh_agent.socket, None);
        assert!(config.ssh_agent.confirm_prompt.is_empty());
        assert_eq!(config.ssh_agent.backoff, Duration::from_secs(2 * 60));
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

    /// A real `SHA256:…` fingerprint — `ssh_key`'s own doc example
    /// (`fingerprint.rs`), reused here rather than computed fresh, so this
    /// test is independently checkable.
    const FINGERPRINT: &str = "SHA256:Nh0Me49Zh9fDw/VYUfq43IJmI1T+XrjiYONPND8GzaM";

    /// `docs/ssh-agent.md` § 7's example, with real fingerprints in place of
    /// its elided ones.
    #[test]
    fn parses_the_ssh_agent_example_from_the_design_doc() {
        let input = r#"
            idle_timeout = "30m"
            clipboard_timeout = "30s"
            prompt = ["sh", "-c", "exec fuzzel --dmenu --password --prompt \"$KPA_PROMPT_MESSAGE\""]
            prompt_timeout = "60s"

            [ssh_agent]
            confirm_prompt = ["sh", "-c", "exec fuzzel --dmenu --prompt \"$KPA_PROMPT_MESSAGE\""]

            [[database]]
            name = "personal"
            path = "~/vaults/personal.kdbx"
            serve_ssh_keys = true

              # A key that signs into production: ask on every use, and never forward it.
              [[database.ssh_key]]
              fingerprint = "SHA256:Nh0Me49Zh9fDw/VYUfq43IJmI1T+XrjiYONPND8GzaM"
              name = "prod-root"
              confirm = "always"
              forwarded = false

              # An old key that is kept in the vault but no longer used.
              [[database.ssh_key]]
              fingerprint = "SHA256:ZMuWmr4ohuhbbvJAsN3CAUIuKhHjpBgWMPyNuDsxZ3I"
              serve = false

            [[database]]
            name = "work"
            path = "~/vaults/work.kdbx"
            # No `serve_ssh_keys`: this database's keys are never served.
        "#;

        let config = Config::parse(input).expect("the design doc's own example should parse");

        assert_eq!(
            config.ssh_agent.confirm_prompt,
            vec![
                "sh",
                "-c",
                "exec fuzzel --dmenu --prompt \"$KPA_PROMPT_MESSAGE\""
            ]
        );
        assert_eq!(config.ssh_agent.socket, None);
        assert_eq!(config.ssh_agent.backoff, Duration::from_secs(2 * 60));

        let personal = &config.databases[0];
        assert!(personal.serve_ssh_keys);
        assert_eq!(personal.ssh_keys.len(), 2);
        assert_eq!(personal.ssh_keys[0].name.as_deref(), Some("prod-root"));
        assert_eq!(personal.ssh_keys[0].confirm, SshKeyConfirm::Always);
        assert!(!personal.ssh_keys[0].forwarded);
        assert!(personal.ssh_keys[0].serve);
        assert_eq!(personal.ssh_keys[1].name, None);
        assert_eq!(personal.ssh_keys[1].confirm, SshKeyConfirm::Once);
        assert!(personal.ssh_keys[1].forwarded);
        assert!(!personal.ssh_keys[1].serve);

        let work = &config.databases[1];
        assert!(!work.serve_ssh_keys);
        assert!(work.ssh_keys.is_empty());

        config
            .validate(Path::new("config.toml"))
            .expect("the design doc's own example should validate");
    }

    #[test]
    fn ssh_agent_socket_defaults_to_none_and_resolves_against_runtime_dir() {
        let config = Config::parse("").expect("empty config should parse");
        assert_eq!(config.ssh_agent.socket_path(None), None);
        assert_eq!(
            config
                .ssh_agent
                .socket_path(Some(Path::new("/run/user/1000"))),
            Some(PathBuf::from("/run/user/1000/kpa/ssh-agent"))
        );
    }

    #[test]
    fn ssh_agent_socket_override_wins_over_runtime_dir() {
        let config = Config::parse(
            r#"[ssh_agent]
socket = "/custom/sock"
"#,
        )
        .expect("valid config should parse");
        assert_eq!(
            config
                .ssh_agent
                .socket_path(Some(Path::new("/run/user/1000"))),
            Some(PathBuf::from("/custom/sock"))
        );
    }

    #[test]
    fn database_serve_ssh_keys_defaults_to_false_and_ssh_keys_to_empty() {
        let config = one_database("/vault.kdbx", None);
        assert!(!config.databases[0].serve_ssh_keys);
        assert!(config.databases[0].ssh_keys.is_empty());
    }

    #[test]
    fn ssh_key_override_defaults_confirm_once_and_forwarded_and_serve_true() {
        let input = format!(
            "[[database]]\nname = \"personal\"\npath = \"/v.kdbx\"\nserve_ssh_keys = true\n\n\
             [[database.ssh_key]]\nfingerprint = \"{FINGERPRINT}\"\n"
        );
        let config = Config::parse(&input).expect("valid config should parse");
        let key = &config.databases[0].ssh_keys[0];
        assert_eq!(key.fingerprint.to_string(), FINGERPRINT);
        assert_eq!(key.name, None);
        assert_eq!(key.confirm, SshKeyConfirm::Once);
        assert!(key.forwarded);
        assert!(key.serve);
    }

    #[test]
    fn ssh_key_settings_fall_back_to_the_defaults_without_a_matching_override() {
        let input = format!(
            "[[database]]\nname = \"personal\"\npath = \"/v.kdbx\"\nserve_ssh_keys = true\n\n\
             [[database.ssh_key]]\nfingerprint = \"{FINGERPRINT}\"\nforwarded = false\n"
        );
        let config = Config::parse(&input).expect("valid config should parse");
        let db = &config.databases[0];

        let matched = db.ssh_key_settings(FINGERPRINT.parse().expect("fingerprint"));
        assert!(!matched.forwarded);
        assert!(matched.serve);

        let other = "SHA256:ZMuWmr4ohuhbbvJAsN3CAUIuKhHjpBgWMPyNuDsxZ3I"
            .parse()
            .expect("fingerprint");
        assert_eq!(db.ssh_key_settings(other), SshKeySettings::default());
        assert_eq!(SshKeySettings::default().confirm, SshKeyConfirm::Once);
        assert!(SshKeySettings::default().forwarded);
        assert!(SshKeySettings::default().serve);
    }

    /// An override must name its key by SHA-256 fingerprint, the only kind
    /// kpa matches: a SHA-512 one would never match, so its settings
    /// (`forwarded = false`, say) would silently do nothing.
    #[test]
    fn ssh_key_override_with_a_sha512_fingerprint_fails_to_parse() {
        let sha512 = ssh_key::PublicKey::from_openssh(
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILM+rvN+ot98qgEN796jTiQfZfG1KaT0PtFDJ/XFSqti",
        )
        .expect("test key")
        .fingerprint(ssh_key::HashAlg::Sha512);
        let input = format!(
            "[[database]]\nname = \"personal\"\npath = \"/v.kdbx\"\nserve_ssh_keys = true\n\n\
             [[database.ssh_key]]\nfingerprint = \"{sha512}\"\nforwarded = false\n"
        );
        let err = Config::parse(&input).expect_err("only SHA-256 fingerprints are accepted");
        assert!(err.to_string().contains("SHA256:"), "{err}");
    }

    /// A typo in an override's or `[ssh_agent]`'s keys fails the load
    /// rather than leaving the setting at its default.
    #[test]
    fn unknown_ssh_keys_fail_to_parse() {
        let typo_in_override = format!(
            "[[database]]\nname = \"personal\"\npath = \"/v.kdbx\"\nserve_ssh_keys = true\n\n\
             [[database.ssh_key]]\nfingerprint = \"{FINGERPRINT}\"\nfowarded = false\n"
        );
        let err = Config::parse(&typo_in_override).expect_err("fowarded is not a key");
        assert!(err.to_string().contains("fowarded"), "{err}");

        let typo_in_agent = "[ssh_agent]\nconfirm_promt = [\"true\"]\n";
        let err = Config::parse(typo_in_agent).expect_err("confirm_promt is not a key");
        assert!(err.to_string().contains("confirm_promt"), "{err}");
    }

    #[test]
    fn the_ssh_agent_socket_expands_home_and_must_be_absolute() {
        let expanded = Config::parse("[ssh_agent]\nsocket = \"~/agent.sock\"\n")
            .expect("valid config should parse")
            .expand_home(Some(Path::new("/home/alice")), Path::new("config.toml"))
            .expect("expands");
        assert_eq!(
            expanded.ssh_agent.socket.as_deref(),
            Some(Path::new("/home/alice/agent.sock"))
        );
        expanded
            .validate(Path::new("config.toml"))
            .expect("an absolute socket is valid");

        let relative = Config::parse("[ssh_agent]\nsocket = \"agent.sock\"\n")
            .expect("valid config should parse");
        let err = relative
            .validate(Path::new("config.toml"))
            .expect_err("a relative socket is refused");
        assert!(matches!(err, ConfigError::RelativeSshAgentSocket { .. }));
    }

    #[test]
    fn ssh_key_override_without_a_fingerprint_fails_to_parse() {
        let input = "[[database]]\nname = \"personal\"\npath = \"/v.kdbx\"\nserve_ssh_keys = true\n\n\
             [[database.ssh_key]]\nname = \"no-fingerprint\"\n";
        assert!(Config::parse(input).is_err());
    }

    #[test]
    fn validate_requires_confirm_once_a_database_opts_in() {
        let input =
            "[[database]]\nname = \"personal\"\npath = \"/v.kdbx\"\nserve_ssh_keys = true\n";
        let config = Config::parse(input).expect("valid config should parse");
        let err = config
            .validate(Path::new("config.toml"))
            .expect_err("ssh_agent.confirm_prompt is required");
        assert!(matches!(err, ConfigError::SshAgentConfirmRequired { .. }));
        assert!(err.to_string().contains("config.toml"), "{err}");
    }

    #[test]
    fn validate_passes_once_confirm_is_set() {
        let input = "[ssh_agent]\nconfirm_prompt = [\"fuzzel\", \"--dmenu\"]\n\n\
             [[database]]\nname = \"personal\"\npath = \"/v.kdbx\"\nserve_ssh_keys = true\n";
        let config = Config::parse(input).expect("valid config should parse");
        config
            .validate(Path::new("config.toml"))
            .expect("confirm_prompt is set, so validate should pass");
    }

    #[test]
    fn validate_ignores_confirm_when_no_database_opts_in() {
        let config = Config::parse("").expect("empty config should parse");
        config
            .validate(Path::new("config.toml"))
            .expect("no database opts into serve_ssh_keys, so confirm_prompt isn't required");
    }

    #[test]
    fn validate_rejects_an_override_without_serve_ssh_keys() {
        let input = format!(
            "[[database]]\nname = \"personal\"\npath = \"/v.kdbx\"\n\n\
             [[database.ssh_key]]\nfingerprint = \"{FINGERPRINT}\"\n"
        );
        let config = Config::parse(&input).expect("valid config should parse");
        let err = config
            .validate(Path::new("config.toml"))
            .expect_err("an override needs serve_ssh_keys = true");
        assert!(matches!(
            err,
            ConfigError::SshKeyOverrideWithoutAgent { ref database, .. } if database == "personal"
        ));
    }

    #[test]
    fn validate_rejects_a_duplicate_fingerprint_within_one_database() {
        let input = format!(
            "[ssh_agent]\nconfirm_prompt = [\"fuzzel\"]\n\n\
             [[database]]\nname = \"personal\"\npath = \"/v.kdbx\"\nserve_ssh_keys = true\n\n\
             [[database.ssh_key]]\nfingerprint = \"{FINGERPRINT}\"\n\n\
             [[database.ssh_key]]\nfingerprint = \"{FINGERPRINT}\"\n"
        );
        let config = Config::parse(&input).expect("valid config should parse");
        let err = config
            .validate(Path::new("config.toml"))
            .expect_err("a duplicate fingerprint within one database is an error");
        assert!(matches!(
            err,
            ConfigError::DuplicateSshKeyFingerprint { ref database, .. } if database == "personal"
        ));
    }

    #[test]
    fn validate_allows_the_same_fingerprint_in_two_different_databases() {
        let input = format!(
            "[ssh_agent]\nconfirm_prompt = [\"fuzzel\"]\n\n\
             [[database]]\nname = \"personal\"\npath = \"/a.kdbx\"\nserve_ssh_keys = true\n\n\
             [[database.ssh_key]]\nfingerprint = \"{FINGERPRINT}\"\n\n\
             [[database]]\nname = \"work\"\npath = \"/b.kdbx\"\nserve_ssh_keys = true\n\n\
             [[database.ssh_key]]\nfingerprint = \"{FINGERPRINT}\"\n"
        );
        let config = Config::parse(&input).expect("valid config should parse");
        config
            .validate(Path::new("config.toml"))
            .expect("the same fingerprint in two different databases is not a conflict");
    }

    #[test]
    fn an_invalid_fingerprint_fails_to_parse() {
        let input = "[ssh_agent]\nconfirm_prompt = [\"fuzzel\"]\n\n\
             [[database]]\nname = \"personal\"\npath = \"/v.kdbx\"\nserve_ssh_keys = true\n\n\
             [[database.ssh_key]]\nfingerprint = \"not-a-fingerprint\"\n";
        let err = Config::parse(input).expect_err("a malformed fingerprint is an error");
        let message = err.to_string();
        assert!(
            message.contains("ssh_key fingerprint \"not-a-fingerprint\" is invalid"),
            "{message}"
        );
        assert!(message.contains("line 10"), "{message}");
    }

    #[test]
    fn load_runs_validate_too() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("config.toml");
        std::fs::write(
            &path,
            "[[database]]\nname = \"p\"\npath = \"/v.kdbx\"\nserve_ssh_keys = true\n",
        )
        .expect("write");

        let err =
            Config::load(Some(&path)).expect_err("missing ssh_agent.confirm_prompt should fail");
        assert!(matches!(err, ConfigError::SshAgentConfirmRequired { .. }));
    }
}
