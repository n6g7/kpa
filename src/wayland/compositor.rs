//! Finding the compositor to copy to, and checking it before it gets a
//! secret.
//!
//! The daemon usually starts before the compositor, so its own environment
//! has no `WAYLAND_DISPLAY`, and never will: a process's environment is
//! fixed when it starts. The service manager's environment is where the
//! compositor exports it once it's up, so that's read on every copy, over
//! the session bus.
//!
//! Whoever can set that variable is the same uid as the daemon (ASM-3's
//! trust), but the value can also be stale or name a socket that isn't a
//! compositor at all. So the name is only a hint: it must be a bare socket
//! name inside the daemon's own `$XDG_RUNTIME_DIR`, and the process
//! listening on it must be the daemon's uid and run on the desktop, judged
//! the same way a requester is (`origin`). The connection checked is the
//! one the copy then uses, so nothing can swap the socket in between.

use std::os::unix::net::UnixStream;
use std::path::PathBuf;

use zbus::blocking::Connection;
use zbus::zvariant::OwnedValue;

use super::Error;
use crate::authn::{self, Origin};

const SYSTEMD: &str = "org.freedesktop.systemd1";
const SYSTEMD_PATH: &str = "/org/freedesktop/systemd1";
const MANAGER_IFACE: &str = "org.freedesktop.systemd1.Manager";
const PROPERTIES_IFACE: &str = "org.freedesktop.DBus.Properties";

const DISPLAY_VAR: &str = "WAYLAND_DISPLAY=";

/// Connects to the compositor of the display session `session` (its logind
/// id), checked as this module's doc describes.
pub fn connect(session: &str) -> Result<UnixStream, Error> {
    let environment = manager_environment()?;
    let name = socket_name(&environment)?;
    let path = runtime_dir()?.join(name);
    let stream = UnixStream::connect(&path).map_err(|err| {
        Error(format!(
            "couldn't connect to the compositor at {name}: {err}"
        ))
    })?;
    check_listener(&stream, session)?;
    Ok(stream)
}

/// The service manager's `Environment` property, as `KEY=VALUE` strings.
fn manager_environment() -> Result<Vec<String>, Error> {
    let unavailable = |err: zbus::Error| {
        Error(format!(
            "couldn't read the service manager's environment: {err}"
        ))
    };
    let conn = Connection::session().map_err(unavailable)?;
    let reply = conn
        .call_method(
            Some(SYSTEMD),
            SYSTEMD_PATH,
            Some(PROPERTIES_IFACE),
            "Get",
            &(MANAGER_IFACE, "Environment"),
        )
        .map_err(unavailable)?;
    let value: OwnedValue = reply.body().deserialize().map_err(unavailable)?;
    Vec::<String>::try_from(value)
        .map_err(|err| Error(format!("unexpected service manager environment: {err}")))
}

/// `WAYLAND_DISPLAY` from `environment`, if it is a bare socket name. An
/// absolute path or anything with a `/` in it is refused rather than
/// resolved: only sockets in the daemon's own runtime directory count.
fn socket_name(environment: &[String]) -> Result<&str, Error> {
    let name = environment
        .iter()
        .find_map(|entry| entry.strip_prefix(DISPLAY_VAR))
        .ok_or_else(|| {
            Error("no WAYLAND_DISPLAY in the service manager's environment".to_string())
        })?;
    if name.is_empty() || name == "." || name == ".." || name.contains('/') {
        return Err(Error(format!(
            "WAYLAND_DISPLAY {name:?} is not a socket name in the runtime directory"
        )));
    }
    Ok(name)
}

fn runtime_dir() -> Result<PathBuf, Error> {
    std::env::var_os("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .filter(|dir| dir.is_absolute())
        .ok_or_else(|| Error("XDG_RUNTIME_DIR is not set to an absolute path".to_string()))
}

/// Refuses a socket whose listener isn't the daemon's uid, or isn't on the
/// desktop. Like `origin`, this tells the desktop from outside it, not an
/// honest process from a hostile one of the same uid (NG-1).
fn check_listener(stream: &UnixStream, session: &str) -> Result<(), Error> {
    let uid = crate::authn::process_uid();
    let listener = crate::socket::peer_uid(stream)
        .map_err(|err| Error(format!("couldn't identify the compositor: {err}")))?;
    if listener != uid {
        return Err(Error(
            "the compositor's socket belongs to another user".to_string(),
        ));
    }
    if authn::of_peer(stream, uid, Some(session)) != Origin::Desktop {
        return Err(Error(
            "the compositor's socket isn't served from the desktop".to_string(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{Error, socket_name};

    fn name_of(environment: &[&str]) -> Result<String, Error> {
        let owned: Vec<String> = environment.iter().map(|s| s.to_string()).collect();
        socket_name(&owned).map(str::to_owned)
    }

    #[test]
    fn the_name_comes_from_wayland_display() {
        let env = [
            "HOME=/home/u",
            "WAYLAND_DISPLAY=wayland-1",
            "XDG_RUNTIME_DIR=/run/user/1000",
        ];
        assert_eq!(name_of(&env).unwrap(), "wayland-1");
    }

    #[test]
    fn a_similarly_named_variable_does_not_count() {
        assert!(name_of(&["WAYLAND_DISPLAY_X=wayland-1"]).is_err());
        assert!(name_of(&["XWAYLAND_DISPLAY=wayland-1"]).is_err());
    }

    #[test]
    fn no_wayland_display_is_an_error() {
        assert!(name_of(&["HOME=/home/u"]).is_err());
        assert!(name_of(&[]).is_err());
    }

    #[test]
    fn only_a_bare_name_is_accepted() {
        for bad in [
            "WAYLAND_DISPLAY=",
            "WAYLAND_DISPLAY=.",
            "WAYLAND_DISPLAY=..",
            "WAYLAND_DISPLAY=/tmp/evil",
            "WAYLAND_DISPLAY=../1001/wayland-0",
            "WAYLAND_DISPLAY=sub/wayland-0",
        ] {
            assert!(name_of(&[bad]).is_err(), "{bad} should be refused");
        }
    }
}
