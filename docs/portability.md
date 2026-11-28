# kpa — portability

kpa runs on Linux. macOS support is planned (`ROADMAP.md`); Windows is out of
scope. Until macOS lands, kpa is written so that a macOS implementation can
slot in behind each OS-specific part without its callers changing.

## The rule

- **Every interface added or changed must be OS-neutral.** Shape it around
  what kpa needs ("who is the peer", "is the display session locked", "serve this
  secret on the clipboard"), not around the Linux mechanism behind it
  (`SO_PEERCRED`, logind's `LockedHint`, a Wayland data source).
- **Linux types stay inside the module that uses them.** No pidfds, cgroup
  paths, D-Bus object paths, `zbus` or `wayland-client` types, or `XDG_*`
  lookups in a signature another module calls.
- **The rule applies to code a task already touches.** Don't rewrite
  existing code only to make it portable; the [known leaks](#known-linux-shaped-interfaces)
  below get fixed when work next passes through them.
- **No macOS code yet**: no `#[cfg(target_os = "macos")]`, no macOS-only
  dependencies, no stub modules. Those come with the macOS work itself.

## Structuring OS-specific code

**The OS switch is a compile-time module choice, not a trait.** When macOS
work starts, each seam becomes one module with one OS-neutral API and an
implementation file per OS, picked with `#[cfg]`:

```rust
// src/peer/mod.rs — the API every caller uses
pub struct Peer { pub uid: u32, pub pid: Option<u32> }

pub fn peer(stream: &UnixStream) -> io::Result<Peer> {
    imp::peer(stream)
}

#[cfg(target_os = "linux")]
#[path = "linux.rs"]
mod imp;   // SO_PEERCRED, SO_PEERPIDFD
// a macOS build adds its own `imp` (getpeereid, LOCAL_PEERPID)
```

A trait isn't the right tool for the switch itself. A given build has
exactly one implementation, so a trait adds generics or dynamic dispatch
with nothing to choose between. It also can't check that the two
implementations agree: neither compiles on the other OS, so only building
for both targets does that. Until macOS work starts, a seam's Linux code
stays where it is, behind its module's API, so the split is a move rather
than a redesign. `frontends/auto_lock/` is shaped this way already: its
`mod.rs` is OS-neutral and `logind.rs` is the Linux side, so a macOS side
would be a `macos.rs` beside it.

**Traits are for more than one implementation in the same build.** That
covers:

- a choice between backends at runtime, such as an unlock or approval
  prompt run as an external program, or a native one where the OS has it
  (Touch ID answers allow or deny, with no string and no child process);
- a test double, such as `clipboard::Backend` (`RecordingBackend`) and
  `prompt::Backend` (`Scripted`).

These traits often sit on an OS boundary already. Keep their method
signatures OS-neutral, like any other interface.

**Answers and events are kpa's own types.** `auto_lock::Event` (screen locked, sleeping, the display
session's state) and `prompt::PromptOutcome<T>` (generic over the answer, so a prompt
needn't return a string) are the pattern to follow.

## Seams

Every place kpa depends on the OS, what it uses on Linux, and what a macOS
implementation would build on. The macOS column is there to check an
interface's shape against, not as a plan.

| Seam | Code | Linux | macOS counterpart | Keep the interface to |
|---|---|---|---|---|
| Socket peer identity | `authn.rs` | `SO_PEERCRED`, `SO_PEERPIDFD` | `getpeereid`, `LOCAL_PEERCRED`, `LOCAL_PEERPID` | a uid, and at most a pid. No pidfd. |
| Request origin | `authn.rs`, `authz.rs` | the peer's cgroup and command name (`comm`), from `/proc` | no cgroups or `/proc`; `proc_name` for the command name | `Requester`: the peer's uid, its cgroup text and its command name, read once at connect. `authz::on_desktop(&Requester, &DisplaySession)` is the one place the cgroup is judged, where every failure is outside the desktop. The command name is `None` on failure and only ever shown to the user. |
| File locations | `paths.rs` (sockets, caches, `known_hosts`), `config.rs` (the config file) | `$XDG_RUNTIME_DIR`, `$XDG_CONFIG_HOME`, `$XDG_CACHE_HOME`, `$HOME` | `~/Library/…`, the per-user `$TMPDIR` | paths resolved in one helper per location, handed to callers as `Path`s. Socket paths stay under 104 bytes, macOS's `sun_path` limit. |
| Lock triggers | `frontends/auto_lock/logind.rs` | logind over D-Bus: `Lock`, `LockedHint`, `PrepareForSleep`, a sleep inhibitor | screen-lock and sleep notifications | `auto_lock::Event` and `logind::Inhibitor`: the module sends events and holds the inhibitor when told, and knows nothing about databases. |
| Clipboard | `clipboard/mod.rs`, `clipboard/wayland/` | kpa's own Wayland client: data-control, serving each paste | `NSPasteboard` | "serve this secret, answer no paste asked after the unlock it came from is cancelled (a `CancelToken`), end it after the timeout, never clear anyone else's". |
| Idle clock | `clock.rs` | `CLOCK_BOOTTIME`, through `rustix` | `mach_continuous_time` (counts sleep; `mach_absolute_time` doesn't) | `clock::Moment`: a point on "time that counts sleep", with `now`, `+`, `-` a `Duration` and `saturating_duration_since`. The idle timer is its only user; an awake-time deadline stays an `Instant`. |
| Tray | `frontends/tray.rs` | StatusNotifierItem over D-Bus (`ksni`) | `NSStatusItem` | `databases::Snapshot`s in, lock and unlock out, told of every change by an observer that only sends on a channel; the unlock asks through the shared screen prompt, gated on `authz::display_allows_prompt`. |
| Prompts | `prompt/` | an external program per kind of prompt (`prompt/program.rs`), or the terminal a requester passed (`prompt/terminal.rs`: termios and `poll`, POSIX calls macOS has too), behind `prompt::Backend<T>`, ended through `cancel.rs`'s socket pair | another `Backend<T>` for a kind: the same program, or a native dialog, or Touch ID for an approval. The terminal backend needs nothing else | `Prompt<T>`, one per kind, sharing one `PromptQueue` that only a backend taking the screen (`Backend::is_queued`) waits in; `PromptOutcome<T>`; no assumption of a child process or a string answer; a `CancelToken` ends one. |
| Terminal passed with a request | `socket.rs` (`send_with_fd`, `recv_with_fd`), `authn.rs` (`Terminal`) | `SCM_RIGHTS`, received with `MSG_CMSG_CLOEXEC` | `SCM_RIGHTS`; no `MSG_CMSG_CLOEXEC`, so `FD_CLOEXEC` is set on the descriptor after it arrives | a request's bytes with at most one descriptor, close-on-exec once received; `Requester::terminal`, an `isatty` file descriptor and the connection it came on. |
| Process hardening | `main.rs` | `prctl(PR_SET_DUMPABLE)` | `setrlimit(RLIMIT_CORE)`, `ptrace(PT_DENY_ATTACH)` | one startup call. |
| Service manager | `nix/hm-module.nix` | a systemd user unit | a launchd agent | `kpa serve` as a plain foreground process: no socket activation or `sd_notify`. |

D-Bus itself is a Linux seam: macOS has no session or system bus by
default. Anything reached over it (logind, the tray, the compositor lookup
in `clipboard/wayland/compositor.rs`) stays inside its own module.

## Known Linux-shaped interfaces

These cross a module boundary with Linux details. Fix each one when work
next changes that code:

- `clipboard::Backend::start` takes a logind session id and returns
  `wayland::Offer`, which `clipboard/mod.rs` re-exports.
- `display_session::DisplaySession::{Locked, Unlocked}` carry the display session's logind id,
  which the clipboard uses to find the compositor. Callers other than the
  clipboard must treat it as opaque.
