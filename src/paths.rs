//! Where kpa's sockets, caches and OpenSSH's `known_hosts` live on this
//! machine. [`Paths::from_env`] reads them from the environment once, at
//! startup, and the code that needs one is handed the `Paths` it resolved;
//! a test builds its own `Paths` rather than depending on this process's
//! environment. Two locations are looked up by their own subsystems
//! instead: the config file (`config`) and the Wayland compositor's socket
//! (`wayland`).
//!
//! These are the per-user base directories, not kpa's own files: each
//! caller joins its own name under `kpa/` (the main socket in `main.rs`,
//! the SSH agent's socket in `config::SshAgentConfig::socket_path`, its key
//! cache in `ssh_agent::keys::cache_dir`).
//!
//! Depends on nothing else in kpa.

use std::ffi::OsString;
use std::path::PathBuf;

/// The per-user locations kpa uses. Each is `None` when the environment
/// doesn't say where it is; whoever needs one decides whether that's an
/// error. A variable that is empty or holds a relative path counts as
/// unset, as the XDG Base Directory specification says for its own.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Paths {
    /// The per-user runtime directory, for sockets: `$XDG_RUNTIME_DIR`.
    pub runtime_dir: Option<PathBuf>,
    /// The per-user cache directory: `$XDG_CACHE_HOME`, or `$HOME/.cache`
    /// if that's unset.
    pub cache_dir: Option<PathBuf>,
    /// OpenSSH's known-hosts file: `$HOME/.ssh/known_hosts`.
    pub known_hosts: Option<PathBuf>,
}

impl Paths {
    /// Every location, read from this process's environment.
    pub fn from_env() -> Paths {
        Paths::from_vars(|name| std::env::var_os(name))
    }

    /// [`Paths::from_env`] with the environment lookup passed in, so tests
    /// don't read or change the process's own.
    fn from_vars(var: impl Fn(&str) -> Option<OsString>) -> Paths {
        let dir = |name| absolute(var(name));
        let home = dir("HOME");
        Paths {
            runtime_dir: dir("XDG_RUNTIME_DIR"),
            cache_dir: dir("XDG_CACHE_HOME")
                .or_else(|| home.as_ref().map(|home| home.join(".cache"))),
            known_hosts: home.map(|home| home.join(".ssh/known_hosts")),
        }
    }
}

/// `value` as a path, if it is an absolute one. Empty and relative values
/// are `None`.
fn absolute(value: Option<OsString>) -> Option<PathBuf> {
    value.map(PathBuf::from).filter(|path| path.is_absolute())
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::ffi::OsString;
    use std::path::PathBuf;

    use super::Paths;

    fn paths(vars: &[(&str, &str)]) -> Paths {
        let vars: HashMap<&str, OsString> = vars
            .iter()
            .map(|(name, value)| (*name, OsString::from(value)))
            .collect();
        Paths::from_vars(|name| vars.get(name).cloned())
    }

    #[test]
    fn every_location_comes_from_its_variable() {
        let paths = paths(&[
            ("XDG_RUNTIME_DIR", "/run/user/1000"),
            ("XDG_CACHE_HOME", "/var/cache/me"),
            ("HOME", "/home/me"),
        ]);
        assert_eq!(paths.runtime_dir, Some(PathBuf::from("/run/user/1000")));
        assert_eq!(paths.cache_dir, Some(PathBuf::from("/var/cache/me")));
        assert_eq!(
            paths.known_hosts,
            Some(PathBuf::from("/home/me/.ssh/known_hosts"))
        );
    }

    #[test]
    fn the_cache_dir_falls_back_to_home() {
        let paths = paths(&[("HOME", "/home/me")]);
        assert_eq!(paths.cache_dir, Some(PathBuf::from("/home/me/.cache")));
        assert_eq!(paths.runtime_dir, None);
    }

    #[test]
    fn empty_and_relative_values_count_as_unset() {
        let resolved = paths(&[
            ("XDG_RUNTIME_DIR", ""),
            ("XDG_CACHE_HOME", "cache"),
            ("HOME", "/home/me"),
        ]);
        assert_eq!(resolved.runtime_dir, None);
        assert_eq!(resolved.cache_dir, Some(PathBuf::from("/home/me/.cache")));

        assert_eq!(paths(&[("HOME", "home/me")]), Paths::default());
        assert_eq!(paths(&[("HOME", "")]), Paths::default());
    }

    #[test]
    fn an_empty_environment_has_no_locations() {
        assert_eq!(paths(&[]), Paths::default());
    }
}
