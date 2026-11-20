# Background: why a custom agent, not Secret Service

The research behind [`design.md`](./design.md)'s decisions. If you just want
the settled design, you don't need this file.

## The ask

This research started from a broader wishlist — one KeePass vault reachable
from everything that needs a secret: autostart, browser autofill, SSH, a
launcher with custom hooks, all sharing one unlocked vault. Most of that is
already covered by any full-featured KeePass client. Two things weren't:

1. A CLI to look up passwords, reusing the already-unlocked session.
2. Password lookup from a launcher, via free-text search.

Hard constraint: **married to the KeePass `.kdbx` format**, but open to
whichever Linux client owns it day to day.

## Direction

**KeePassXC (or whichever full-featured KeePass client is already in use)
stays as the vault daemon. It does _not_ become the Secret Service
provider — `gnome-keyring` (or whatever secret-service daemon the desktop
uses) keeps that role.** Launcher and CLI access come from a small read-only agent
that reads the `.kdbx` directly — that's kpa.

Secret Service was considered and rejected: it can enumerate entries (the
one thing an existing browser-extension channel can't do), but item
*creation* is completely ungated once the collection is unlocked — any
libsecret-speaking app could silently write into the vault, with no way to
expose one group for reading while others stay writable. Not worth it for
a curated vault.

Cost: kpa is a second unlocked copy of the vault alongside the primary
client, so two unlocks per session. Avoiding that would mean reimplementing
the KeePassXC browser protocol end to end (see "full KeePassXC replacement"
below), which isn't worth it.

One constraint that matters for running both at once: **there is no
per-database lock file.** KeePassXC 2.7.12's only `QLockFile` is a
single-instance lock in `/tmp` (`gui/Application.cpp:79-84`), and saves go
through `QSaveFile` (`core/Database.cpp:361`) — write-to-temp plus atomic
rename; the non-atomic fallback for cloud-sync directories still ends in a
rename (`:409`). A concurrent reader never sees a torn file, so freshness (not
locking) is the only real problem to solve — see `design.md` § Files and
freshness. This was checked against KeePassXC 2.7.12's source; most modern
KeePass clients follow the same pattern (decrypt into memory, save through a
temp file and a rename), but it is worth re-verifying against another client.

## Verified constraints

Checked against source or a live machine, not documentation — several of
these came back wrong from a plain web search.

### 1. The KeePassXC browser protocol cannot enumerate entries

`src/browser/BrowserAction.cpp` (2.7.12) registers exactly: `associate`,
`change-public-keys`, `create-new-group`, `get-database-groups`,
`get-databasehash`, `get-logins`, `get-totp`, `lock-database`, `passkeys-get`,
`passkeys-register`, `request-autotype`, `set-login`, `test-associate`.

`get-logins` is **URL-matched**. `BrowserService::getDatabaseEntries()`
exists (`BrowserService.h:82`) but is wired to **no protocol action**.

So the well-authenticated socket a browser extension and
`git-credential-keepassxc` use cannot back a free-text launcher search. This
eliminates most tidy designs that would otherwise reuse that channel.

### 2. KeePassXC's global auto-type doesn't work on most Wayland compositors; typing via `wtype` does

KeePassXC's auto-type requires **both** the RemoteDesktop and
GlobalShortcuts XDG desktop portals, officially supported only on
KDE 6.6+ and GNOME 48+. `xdg-desktop-portal-wlr` (used by wlroots-based
compositors) provides ScreenCast only. Even where auto-type works, Wayland
gives no window-title matching or active-window tracking — the entire point
of global auto-type on X11.

**That's a KeePassXC implementation gap, not a Wayland limitation as such.**
Compositors that advertise `zwp_virtual_keyboard_manager_v1`,
`zwp_input_method_manager_v2`, and `zwlr_data_control_manager_v1` /
`ext_data_control_manager_v1` (niri and sway both do) support synthetic
typing (`wtype`) and headless clipboard access (`wl-clipboard`) fine — which
is what kpa's own clipboard integration relies on.

### 3. `keepassxc-cli` does not reuse an unlocked GUI session

It re-derives the key from the master password on every invocation
(upstream KeePassXC issue #12282, open at time of writing, no maintainer
response). This is exactly the gap kpa's daemon/client split closes.

### 4. `keepmenu`'s daemon has a weak-by-default IPC key in some packaged versions

Its daemon is reachable over loopback TCP with pickle-based RPC — a real
contrast with kpa's `0600` Unix socket, since a TCP port has no filesystem
permission barrier. Versions before 1.6.0 generate the auth key with a
non-cryptographic PRNG; 1.6.0 switched to a real CSPRNG.

**If you use `keepmenu`, use 1.6.0 or later** — some distro packages lag
behind.

### 5. `keepmenu` has no tray, no notifications, no per-read authorization

It's headless and pull-based: unlock is the only gate, and it doesn't tag
copied passwords as sensitive, so they can land in clipboard-history
managers that would otherwise skip them.

## Password lookup options

| | one unlocked vault | zero glue code | launcher search | vault stays clean |
|---|---|---|---|---|
| ~~Secret Service + a caching client~~ | yes | no | yes | **no — see Direction above** |
| `keepmenu` (1.6.0+) | no (2nd unlock) | **yes** | yes | yes |
| **a small read-only agent (kpa)** | no (2nd unlock) | no | yes | yes |

Secret Service is **rejected** for the reason in Direction above. That
leaves `keepmenu` or a purpose-built agent, and both cost a second unlock —
the unavoidable price of not exposing the vault to a channel other software
can write to.

**`keepmenu`** is the zero-glue answer: small, has a real daemon, has a CLI.
Costs: needs pinning to 1.6.0+ (#4), no tray, no notifications, no
per-read authorization, untagged clipboard (#5).

**A purpose-built agent** costs more code but is read-only by construction,
has a configurable locking policy, and uses a `0600` Unix socket instead of
loopback TCP with pickle-based RPC.

## Security boundary

**The boundary is the user account. Inside it, optimise for blast radius and
time, not caller identity.**

Anything running as the user can already read the `.kdbx` or log
keystrokes. So PID checks and exe-path allow-lists raise the bar against
*careless* software — a random app calling libsecret — and not at all
against anything actually targeting the user. An elaborate authorization
system inside that boundary is theater, and the expensive kind: it's the
part that's hard to get right.

Two Linux properties that improve the memory picture here — worth
confirming on the machine actually running kpa, rather than assumed:

- **`/proc/sys/kernel/yama/ptrace_scope` is `1`** on most distros by
  default — only a parent process can `ptrace` a child, so a random
  same-uid process can't attach to an unlocked vault daemon.
- **zram swap** (RAM-backed, compressed) reduces the chance that key
  material is paged to disk, but doesn't eliminate it — hibernation, a zram
  writeback device, or any secondary disk-backed swap all defeat it. This is
  a property of the machine's configuration, not one kpa's process can
  guarantee about itself.

**Neither of these helps a TCP-RPC design like `keepmenu`'s** (#4). Its
exposure is a pickle-based RPC reachable over a loopback socket — an
attacker connects to a port, they don't attach to a process. `ptrace`
restrictions are irrelevant to it, and the weak-authkey concern (in older
versions) stands on its own.

Worth defending, in rough order of value per effort:

1. **The vault at rest.** YubiKey HMAC-SHA1 challenge-response on the
   `.kdbx`. One checkbox in KeePassXC, and the only item here that helps if
   the file itself leaves the machine.
2. **Time.** Idle-lock and lock-on-screen-lock, both in the primary
   KeePass client and in kpa. An unlocked vault at 3am is the realistic
   exposure.
3. **Blast radius.** Don't expose the vault to a channel other software can
   enumerate or write to — this is the Secret Service decision above.
4. **Visibility.** Notifications on read, so unexpected access is
   noticeable.

Explicitly *not* on the list: per-caller authorization. That's what the
Secret Service route was buying, and it isn't worth the ungated writes.

Other standing notes:

- **The clipboard is not private on Wayland.** A compositor that advertises
  `wlr`/`ext` data-control lets any clipboard-history manager read a copied
  password. Prefer auto-type where it works, or keep clipboard history off
  for sensitive copies. Tag copies with `x-kde-passwordManagerHint: secret`
  so history managers that honor the hint skip them.

## Custom software: where the actual gap is

| Requirement | Covered by an existing full client | Gap |
|---|---|---|
| autostart + tray | yes, via config | — |
| Browser autofill | yes, via browser extension | — |
| SSH agent | yes, via built-in agent | — |
| Unlock prompt | yes | — |
| CLI reusing session | — | **gap** |
| Launcher free-text search | — | **gap** |
| Launcher with custom hooks | one of several launchers, or a custom-built one | choice |

Both real gaps are UI and plumbing, not cryptography. That should decide
what gets built.

### Candidate 1 — read-only agent + CLI client ← what kpa is

- **Shape:** KeePass library behind a **Unix socket** (`$XDG_RUNTIME_DIR`,
  `0600`) speaking line-delimited JSON: `list`, `search`, `get <uuid>
  <field>`-equivalent operations. **No write operations implemented at
  all** — that's what makes the ungated-writes problem structurally
  impossible. Unlock via a `--dmenu`-style prompt or `pinentry`. Locks on
  idle timeout and on the session-lock signal, so it locks with the screen.
- **Client:** a thin CLI that a launcher and a shell both call.
- **Complexity:** roughly 400-900 LoC for agent and client together.
- **Risk: medium.** Holds a decrypted vault for the session. Mitigated by
  being read-only, small, and aggressively locked.
- **Why not just `keepmenu`:** it's the zero-glue alternative and a
  legitimate choice on its own. A purpose-built agent differs by being
  read-only, using a Unix socket rather than loopback-TCP pickle RPC (#4),
  tagging the clipboard (#5), and locking on screen-lock. If the appetite
  for writing code is low, `keepmenu` 1.6.0+ is not a bad answer.

### Candidate 2 — agent-as-client-of-Secret-Service — rejected

Caching and policy in front of Secret Service, so the full client keeps
owning key material and the agent holds none. Attractive until it runs
into the reason in Direction above: it requires exposing the vault to
Secret Service, which means ungated writes from every other app. Rejected
for that reason alone.

### Candidate 3 — full replacement of the existing client — not worth it

To drop a full-featured client entirely, the agent would also need to speak
the browser-extension protocol directly (so the real browser extension talks
to it) plus implement an SSH agent.

- **Precedent:** at least one third-party project does exactly this for
  KeePass 2 — so it's possible. It also has a history of breaking on
  extension-protocol bumps and has to spoof a version string to stay
  compatible.
- **Work:** an authenticated-encryption handshake (X25519 +
  XSalsa20-Poly1305 or similar), nonce discipline, association-key storage,
  a dozen-plus message types, a stdio↔socket proxy, plus a few hundred LoC
  of ssh-agent. Realistically several thousand LoC.
- **Risk: high.** Security-critical, crypto-adjacent, parser-exposed code
  guarding everything — to replace a maintained, widely-audited application
  whose only real shortcoming is missing CLI/launcher integration.

The rule that falls out: **the gap in this ecosystem is the UI layer, not
the vault. Write UI, not crypto.**

## Open questions (as of this research)

These were open when this research was done; `design.md` reflects what was
actually decided.

- Build the agent (candidate 1), or just use `keepmenu` 1.6.0+ and accept
  its limitations? → **agent**, this project.
- Own launcher, or an existing one? → independent choice, not part of this
  design.
- Enable YubiKey challenge-response on the `.kdbx`? → deferred, see
  `design.md`'s "Deferred" section.
- What idle timeout? → 30 minutes by default, configurable — see
  `design.md`'s settled decision #7.
