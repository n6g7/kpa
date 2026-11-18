# kpa — design

A small, read-only KeePass agent: holds one or more `.kdbx` files unlocked
in memory and serves lookups to a launcher and a CLI over a Unix socket.

Background and the research this rests on is in [`background.md`](./background.md).
Staging is in [`plan.md`](./plan.md).

## Scope

**Is:** a read-only index and secret-copier for `.kdbx` files, plus a tray icon
showing lock state.

**Is not:** a vault editor, an SSH agent, a Secret Service provider, a browser
backend, or a replacement for a full-featured KeePass client. A client like
that already covers browser autofill, an SSH agent, and its own tray. kpa
adds the two things nothing in that ecosystem provides — free-text search
over all entries, and a CLI that reuses an already-unlocked session.

**Read-only is the defining property.** It is what makes this design safe to
run alongside any KeePass client that already has write access to the same
files (see `background.md` § Direction for why that guarantee matters). The
guarantee is structural: the protocol's op enum (`Op`, in
`src/proto/request.rs`) has no write variants, so there is no code path
that can modify a database. `keepass` is also built without its
`save_kdbx4` feature, which gives the claim a second leg.

## Settled decisions

| #   | Decision                                                                                                  | Rationale                                                                                                                                                                                                                     |
| --- | --------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1   | **Rust**                                                                                                  | `keepass` (the crate) covers KDBX3/4 + Argon2 + keyfile + (later) challenge-response; `zeroize`; single binary.                                                                                              |
| 2   | **JSON over a Unix socket**, serde                                                                        | Fewest moving parts; hand-debuggable with `socat`; self-describing. Protobuf was considered and is defensible, but costs `protoc`, a second type system, and ~150 LoC of conversion boilerplate for no benefit at this scale. |
| 3   | **Single binary, two roles** — `kpa serve` + client subcommands                                           | No client/daemon version skew within a release; one build artifact.                                                                                                                                                           |
| 4   | **No `get` in v1 — `copy` only**                                                                          | The daemon owns the clipboard, so the secret never enters the client's address space. `get` would print secrets to stdout, into shell history and scrollback. Deferred, and will be opt-in behind a flag if added.            |
| 5   | **v1 keys: master password + keyfile only**                                                               | Challenge-response deferred.                                                                                                                                                                                                  |
| 6   | **TOTP via `keepass`'s `totp` feature, read-only**                                                       | `copy` generates the current code from the `otp` field at copy time; the seed never leaves the process. HOTP is permanently out — counters need writes.                                                                     |
| 7   | **Idle timeout 30 min per database**, config-overridable                                                               | logind's `Lock` signal already covers screen-lock; this only catches walking away without locking.                                                                                                                            |
| 8   | **Daemon autostarts locked**                                                                              | A tray should show state from login onward, and nothing prompts until something actually asks.                                                                                                                                |
| 9   | **Unlock prompt: a `--dmenu`-style password prompt** (e.g. `fuzzel --password --dmenu`) in v1, config key; the client's own terminal otherwise | Trivial to wire up and fits most Wayland setups out of the box. `pinentry` is the better long-term answer for secure memory, but driving Assuan is fiddly — so the prompt is swappable from day one rather than hardcoded. A request from outside the desktop never raises it; `kpa unlock` reads the terminal instead (`docs/headless.md` § 4). |
| 10  | **Multiple databases**, TOML array of tables                                                              | Per-database unlock, per-database tray state.                                                                                                                                                                                 |
| 11  | **Linux only, with OS-neutral interfaces**                                                                | macOS support is planned, so each OS-specific part sits behind an interface a macOS implementation can share. Windows is out of scope. Rules and the list of OS seams: [`portability.md`](./portability.md).                     |
| 12  | **Subsystem dependencies form a DAG**                                                                     | Each top-level module exports a small API and depends on others in one direction, with decisions kept pure, so it reads and tests on its own. Rules: [`module-structure.md`](./module-structure.md).                          |

## Architecture

```mermaid
graph LR
    keybind["compositor keybind"] --> launcher["your launcher"]
    shell["shell"] --> subcmd
    launcher --> subcmd["kpa &lt;subcommand&gt;"]
    subcmd -->|unix socket| serve["kpa serve"]

    lock["loginctl lock-session"] --> signal["logind Lock signal"] --> serve

    serve --> keepass["keepass crate<br/>(kdbx, read-only)"]
    serve -->|ksni| tray["tray<br/>(any SNI host)"]
    serve --> clip["src/wayland<br/>(owns clipboard offer)"]
```

One long-lived daemon (`kpa serve`); short-lived clients (every other
`kpa <subcommand>`). "Your launcher" and "compositor keybind" are
deliberately generic — kpa doesn't ship or assume a particular launcher,
tray host, or keybinding scheme. Anything that can shell out to `kpa` or
speak the socket protocol directly works.

## Configuration

`$XDG_CONFIG_HOME/kpa/config.toml`.

```toml
idle_timeout = "30m"
prompt = ["sh", "-c", "exec fuzzel --dmenu --password --prompt \"$KPA_PROMPT_MESSAGE\""]
prompt_timeout = "60s"         # an unanswered prompt is killed after this
clipboard_timeout = "30s"
log_level = "info"             # error | warn | info | debug

[[database]]
name    = "personal"           # stable id used in requests and the tray
path    = "~/vault/personal.kdbx"
keyfile = "~/.keys/personal.key"   # optional

[[database]]
name = "work"
path = "~/vault/work.kdbx"
```

A leading `~/` in `path` or `keyfile` expands to `$HOME` when the daemon
starts; `~user/` is refused rather than taken literally, and other relative
paths resolve against the daemon's working directory.

**`prompt` runs exactly as configured.** What the unlock is about —
`"Unlock personal"`, for `personal` above — reaches the program through
`KPA_PROMPT_MESSAGE` in its environment instead of its argv, escaped the
way the CLI escapes its own terminal output, plus tab and newline so it
stays one line, and capped in length,
since a later request-derived message (an SSH key name, once the agent's
approval prompt exists) carries text this daemon didn't author. A program
that only takes its prompt text as an argument, as `fuzzel` does, needs a
wrapper that reads the variable and passes it on — the `sh -c` line above.
One thing the variable doesn't buy: a wrapper puts the message right back
into its own argv, so it's visible to other uids via `/proc/<pid>/cmdline`
either way. Only a program that reads the variable itself avoids that.

If you manage your system declaratively (Nix, Ansible, whatever), this shape
is meant to be generated rather than hand-edited — every setting is a plain
TOML value, nothing requires clicking through a GUI.

## Logging

`serve` writes one line per event to stderr, at one of four levels:
`error`, `warn`, `info` (the default) and `debug`. `log_level` in the config
sets it and `serve --log-level` overrides it. Under systemd, where stderr is
the journal, each line carries a `<N>` syslog priority prefix so
`journalctl -p warning` filters by level; the daemon decides that by
comparing `$JOURNAL_STREAM` against its own stderr. Elsewhere a line reads
`<local timestamp> <LEVEL> <message>` (RFC 3339 with the UTC offset), with the timestamp dimmed and the level
coloured when stderr is a terminal (not when `NO_COLOR` is set or `TERM` is
`dumb`). Under journald there is no timestamp of kpa's own: the journal
stamps its own.

| Level   | What it carries                                                           |
| ------- | ------------------------------------------------------------------------- |
| `info`  | Every unlock, lock (including idle, screen-lock and suspend), and copy (field, entry title, database); the tray registering, losing its host and re-registering |
| `warn`  | Failed or refused requests and connections, and logind failing, or a tray failure beyond a missing host (no session bus, or an unexpected D-Bus error) |
| `debug` | Why: prompt launches, logind subscription, sleep inhibitor, tray start    |

**What a line may contain.** The operation, the database name, the error
kind, and for a copy the field name and the entry's title (so the log says
which secret left, not just which field). Never passwords, protected fields
(a protected title is replaced by the entry's uuid), usernames, URLs or any
other vault content, at any level: a log outlives the unlocked session and
ends up somewhere far less guarded than the socket (threat model TB-7).
Reads (`status`, `list`) are not logged at all.
Control characters in a line are escaped, so a crafted name in a request
can't forge a second line. Every line goes through `log::log`, so that is
the one function to audit.

## Protocol

Line-delimited JSON over `$XDG_RUNTIME_DIR/kpa/sock`, mode `0600`.

**Exactly one request and one response per connection, then the connection
closes.** This is deliberate, not a limitation to work around later:
multiplexing multiple requests over one long-lived connection would need a
request-ID field so responses could be matched back to their requests, plus
ordering and partial-read handling. One-shot connections make that whole
class of problem not exist — "which response is this?" is answered by which
socket it arrived on. Unix-socket connects are cheap enough (no handshake,
no meaningful round-trip cost) that there's no performance reason to keep a
connection open across multiple requests either. A client that wants to
issue several ops just opens several connections.

Both requests and responses carry `"v": 1`. On the request side, a mismatch
is rejected rather than negotiated — the daemon's response still carries its
own `v`, which is how the client learns which version the daemon is
actually running without a separate pair of fields for it. This is
deliberate too: rather than engineer backward compatibility, we make skew
impossible to ignore. The daemon holds only a cache of decrypted data, so
restarting it costs one re-unlock.

### Requests

```json
{"v":1,"op":"status"}
{"v":1,"op":"unlock","db":"personal"}
{"v":1,"op":"unlock","db":"personal","password":"<base64>"}  // no prompt
{"v":1,"op":"lock","db":"personal"}          // db omitted = lock all
{"v":1,"op":"list"}                          // db omitted = all unlocked
{"v":1,"op":"copy","db":"personal","uuid":"…","field":"password"}
{"v":1,"op":"copy","db":"personal","uuid":"…","field":"custom:Password"}
{"v":1,"op":"ssh_keys"}                     // db omitted = all unlocked
{"v":1,"op":"ssh_keys","db":"personal"}     // the SSH keys the vault holds
```

An `unlock` that carries `password` unlocks with it and never runs the
prompt, so it goes ahead from outside the desktop and while the screen is
locked, where an `unlock` without one gets `no_display` (below). A wrong
one fails with `wrong_credentials`, with no backoff. The
password is base64 (standard alphabet, padded) so that its JSON string
never needs escaping: the daemon decodes it straight from the request line
into a zeroizing buffer, and refuses one longer than 4096 bytes, one that
isn't valid base64 or UTF-8, or one written with JSON escapes, as
`malformed_request`.

`field` accepts any name `list`'s `fields` array returns for that entry
(below): `username`, `password`, `url`, `notes`, `totp`, or a custom
(user-defined) field by its KeePass key. Decoding never rejects a `field`
value — any string is accepted, and one that doesn't resolve to anything on
the entry asked about fails with `field_empty`, the same as an empty or
absent field.

**Collision rule.** `username`, `password`, `url`, `notes`, `totp`, and
KeePass's own reserved `title` are matched case-insensitively and always
mean the built-in (`title` has no built-in `copy` serves, so a bare request
for it never resolves to anything). A custom field is legal in KeePass even
when its key collides with one of these only in case (e.g. a custom `Password`
field alongside the real one) — that field is still listed and copyable, but
only via the `custom:` prefix (`custom:Password`), never its bare key, so a
bare request always means the built-in. Any other custom field is addressed
by its bare key.

`ssh_keys` scans the unlocked databases' attachments for SSH keys
([`ssh-agent.md`](./ssh-agent.md) § 6.4), the scan behind `kpa ssh keys`.
Like `list`, a request with no `db` covers every unlocked database, and each
key and skipped attachment says which database it is in: a key two databases
hold is reported once for each. `locked` names the databases such a request
could not scan, and is left out when there are none. A request that names a
locked database fails with `locked` instead, as it does with `unknown_db` or
`stale`; it never answers from the key cache. Like `list`, it returns entry
titles to the caller and keeps them out of the daemon's log.

**CLI output.** The protocol is what the CLI speaks; what it prints is a
separate choice. A subcommand with a text output (`kpa ssh keys` so far)
renders the response for a person, with every string the vault supplied
escaped (T-13). `--json`, a flag every client subcommand takes, prints the
daemon's response line instead, so a script keeps a stable shape whatever
text a command grows. The subcommands without a text output yet print the
response line with or without it.

### Responses

```json
{"ok":true,"v":1,"databases":[{"name":"personal","locked":false,"entries":341},
                              {"name":"work","locked":true}],"version":"1.2.3"}

{"ok":true,"v":1,"entries":[{"db":"personal","uuid":"…","title":"GitHub",
                             "username":"alice","url":"https://github.com",
                             "group":"Dev",
                             "fields":["username","password","totp","custom:Password"]}]}

{"ok":true,"v":1,"copied":"password","expires_in":30}

{"ok":true,"v":1,"keys":[{"db":"personal","type":"ssh-ed25519",
                          "fingerprint":"SHA256:…","title":"Deploy",
                          "attachment":"id_ed25519"}],
                "skipped":[{"db":"personal","title":"Old","attachment":"id_rsa",
                            "reason":"PEM format; …"}],
                "locked":["work"]}

{"ok":false,"v":1,"error":"locked","db":"personal"}
{"ok":false,"v":1,"error":"unlock_in_progress","db":"personal"}
{"ok":false,"v":1,"error":"stale","db":"personal","detail":"database changed on disk"}
{"ok":false,"v":1,"error":"no_display","detail":"no display to prompt on"}

{"ok":false,"v":2,"error":"version_mismatch","detail":"client sent v1; restart the daemon or upgrade the client"}
```

The last one is the version-skew rejection: the client sent `"v":1`, the
daemon is actually on `2`, and its own `v` in the response is what makes
that visible — no extra `client_v`/`daemon_v` fields needed. `v` is the
*protocol* version, not the build: `status`'s `version` field is the
running daemon's build version (the same string `kpa version` prints for
the CLI itself), piggybacked on `status` rather than given its own op since
it's the one extra thing `kpa version` needs and `status` is already the
no-argument "what's the daemon's state" round trip. `kpa version` sends it
and prints both, labelled `client:`/`server:`, so an upgrade that replaces
the binary but leaves the old daemon running still shows up as a mismatch
rather than silently serving the previous build. No daemon reachable
(`server: not running`) and an older daemon that predates this field
(`server: unknown (daemon predates version reporting)`) are both reported
rather than treated as failures — `kpa version` always exits `0`.

Two `unlock` errors exist because unlocking is slow (it waits on a human
and a KDF) and happens outside the vault mutex:

- **`unlock_in_progress`** — an `unlock` for the same database is already
  prompting. The second request is refused rather than opening a second
  prompt; retry once the first resolves.
- **`locked`** from `unlock` — a `lock` arrived while this `unlock` was
  prompting or deriving. The lock wins: the database the unlock opened is
  discarded rather than silently reopening a vault the user just locked,
  and a prompt still open is killed.

An `unlock` without a password fails with `no_display`, without
prompting, when nobody could answer the prompt: the request comes from
outside the desktop (below), or the screen is known to be locked (§ Lock
policy). It names no database: the refusal is about where the request can
be answered, not about the database. `kpa unlock` answers `no_display` by
reading the password from its own controlling terminal, with echo off, and
sending it in a second request; `--tty` reads the terminal right away
instead of trying a plain request first, which is how a desktop terminal
asks for the terminal read instead of the graphical prompt
([`headless.md`](./headless.md) § 4). Without a controlling terminal,
`kpa unlock` reports `no_display` and exits non-zero. The tray's menu is
clicked at the desk, so its unlocks count as from the desktop.

A request line is capped at 64 KiB and must arrive within 5 seconds; a
line over the cap is answered `malformed_request`, and a connection that
sends nothing is dropped.

**Every connection is classified by where it comes from**
([`headless.md`](./headless.md) § 3). `authn.rs` identifies the caller as a
`Requester`: its uid, the peer's pidfd (`SO_PEERPIDFD`, or the
`SO_PEERCRED` pid on kernels without it) read for its
`/proc/<pid>/cgroup` once when the connection is accepted, and its command
name. `authz.rs` holds the decisions, pure functions of a
`Requester` and the display session: only the daemon's own uid may connect
(`authz::may_connect`), and the cgroup is classified against the display
session each time a decision asks, not once at connect, so a connection
that outlives a login session stops counting as the desktop with it. The peer is **on the
desktop** when the user has a
display session (`User.Display` is not `/`, § Lock policy) and the unified hierarchy's
path is under `/user.slice/user-<uid>.slice/`, in `user@<uid>.service` or
in the display session's `session-<id>.scope`. Everything else is
**outside**: another session's scope (an SSH login, or a terminal server
that registers each connection as a remote logind session), a system
service (a cron job, a terminal server's shells), no display session at
all, and any
peer whose cgroup can't be read or parsed, including one that exited
first. Whether the peer is on the desktop is logged at `debug` when the connection is accepted, and
decides whether `unlock` may prompt on screen (`authz::choose_unlock_prompt`) and
which session `copy` may put on the clipboard of (`authz::authorize_copy`, § Clipboard). It decides where to ask, not
who may ask: a same-uid process can start work in another cgroup.

**`list` never returns secrets** — it is an index. That holds for any field
the user marked protected in their KeePass client, not just `Password`: a
protected `Title`/`UserName`/`URL` is omitted, not de-protected — protection
is a property of the field, not of which field name it happens to be. A
field counts as protected when its XML carries `Protected="True"` or
`ProtectInMemory="True"`, matching KeePassXC. The pinned `keepass` crate
(0.15.0) reads only `Protected`, so until it reads `ProtectInMemory` too,
`list` can return a field that carries only that marker; the threat model
(A-2, G-3) records this as a known gap. The launcher does its own fuzzy
matching; kpa stays dumb and returns everything else.

**`fields` is the one exception, because it carries names, never values.**
Each entry's `fields` array names every field `copy` can be asked for on
it: the built-ins present and non-empty on the entry, in the order
`username`, `password`, `url`, `notes`, `totp`, then its custom fields by their
KeePass key (sorted — `keepass`'s own field storage is an unordered map, so
the database's own field order isn't recoverable), `custom:`-prefixed per
the collision rule above. Protectedness never hides a field's *name* here,
unlike `title`/`username`/`url` above: a protected `Password` still lists
`password`, and a custom field colliding with a protected built-in still
lists `custom:<key>`. `fields` is omitted from the wire when empty, like
the other optional fields.

## Concurrency and file freshness

A KeePass client and kpa can both have the file open at once. The
specifics below were checked against KeePassXC 2.7.12's source specifically
(it's what this design was developed against) — worth re-verifying against
a different client, though most modern KeePass clients follow the same
general pattern: open, decrypt into memory, and save through a temp-file-plus-
rename rather than an in-place write.

- **There is no per-database lock file** in KeePassXC. Its only `QLockFile` is
  a single-instance lock in `/tmp` (`gui/Application.cpp:79-84`), not next to
  the `.kdbx`. Nothing to contend with.
- **Saves are atomic.** KeePassXC writes through `QSaveFile`
  (`core/Database.cpp:361`); the non-atomic fallback for cloud-sync directories
  still ends in a rename (`:409`). A reader never sees a half-written file.

Rules:

1. **Never create a lock file. Never hold an fd.** Open, read whole file, close,
   parse. A few MB, once per unlock. One known exception, upstream: a file
   with pathological KDF parameters can make `keepass` hang mid-unlock, and
   that unlock holds its fd (and a core) for as long as it hangs.
2. **Never write.** Guaranteed by the `Op` enum in `src/proto/request.rs`.
3. **Freshness guard** (`docs/threat-model.md` T-12): record
   `(dev, ino, size, mtime, ctime)`, with nanoseconds on both times, by `fstat`
   on the fd that was read. Take it before the read and again after it; if the
   two differ, the unlock fails with `stale`. Before each use of an unlocked
   database, re-check by `stat` on the path. Any difference drops the in-memory
   database and returns `stale`, requiring re-unlock (`list` of all databases
   fails naming the stale one; `status` reports it as locked). Another client saving, or
   a sync tool landing a new copy, both cause this. Serving stale entries
   silently is the worse failure. Anyone syncing their vault across machines
   makes this a real case, not a theoretical one.

   ctime catches a restored mtime, since user space cannot set ctime. The
   `fstat` on the read fd, rather than a `stat` by path, closes the window
   between the read and the stat. ctime is only as reliable as the filesystem
   reports it. On coarse-timestamp, FUSE or network mounts the guard is best
   effort. A chmod, a link change, or a backup tool that hard-links the file
   also moves ctime and causes a spurious `stale`, which fails safe.

   **Not caught:**
   - A same-size write that leaves mtime and ctime equal to the recorded values.
     A tool that sets times cannot set ctime, and ctime moves on every write
     and every time change. So the tuple misses such a write only if the
     kernel's timestamp for that write equals the recorded one. That needs a
     filesystem with coarse timestamps, where the write lands in the same tick
     as the recorded one, or a writer that sets the system clock back, which
     requires root.
   - Substitution or rollback while the database is locked. The tuple is taken
     at unlock, so a file replaced with an older copy of the same vault, or
     with another vault sharing the password, before the next unlock is never
     compared against anything. This is T-17, and it is not addressed.
4. **Concurrency:** accept connections concurrently (bounded — a flood is
   refused rather than turned into unbounded threads, and a failed thread
   spawn drops that one connection instead of the daemon), serialize vault
   access behind a `Mutex`. Most requests are sub-millisecond. `unlock` is
   the exception — milliseconds to seconds, waiting on the prompt and the
   KDF — and it deliberately releases the mutex for that slow part so other
   requests keep being answered. That window is what the per-database lock
   epoch guards: every `lock` bumps it, and an `unlock` only installs its
   database if the epoch is unchanged since it started.

## Clipboard

kpa's own Wayland client (`src/wayland/`), in-process — **not** by
spawning `wl-copy`.

The Wayland clipboard is pull-based: the owning client must stay alive to serve
bytes on paste, which is why `wl-copy` forks. Since kpa is already long-lived it
should own the offer itself. The client speaks `ext-data-control`, falling
back to `wlr-data-control` (advertised by compositors like niri and sway), so
it can own the clipboard without ever holding keyboard focus — which a daemon
never has. Each offer has its own connection and serving thread.

**Which compositor.** The daemon usually starts before the compositor, and a
process's environment never changes after it starts, so its own
`WAYLAND_DISPLAY` is no use. Each `copy` reads `WAYLAND_DISPLAY` from the
service manager's environment instead (`org.freedesktop.systemd1.Manager`'s
`Environment`, on the session bus), where the compositor exports it. The
name is a hint, checked before any secret is sent:

- it must be a bare socket name, resolved in the daemon's own
  `$XDG_RUNTIME_DIR`; a path is refused;
- the process listening on that socket must be the daemon's uid, and on
  the desktop as § Protocol judges a requester: in `user@<uid>.service`
  or the display session's scope.

The copy then runs over the connection that was checked. A failure is an
`io` error naming what failed. A compositor that doesn't export
`WAYLAND_DISPLAY` to the service manager can't be copied to.

Two MIME types are offered: `text/plain;charset=utf-8` and
`x-kde-passwordManagerHint` with value `secret`. That's what clipboard-history
managers check to skip passwords. (`wl-copy --sensitive` offers exactly this —
`wl-clipboard/src/types/copy-action.c:76-80` — so the CLI is a viable stage-1
shortcut.)

**`copy` needs a desktop requester on an active, unlocked display
session** (`docs/headless.md` § 5): the requester is classified as on the
desktop the same way `unlock` is (§ Protocol), and the display session's state
(§ Lock policy) must be an active display session with `LockedHint`
false. Anything else — outside the desktop, no session, inactive, or
locked — fails with `no_display`, and the clipboard is never touched.
`active` is logind's `Active` session property, published alongside
`LockedHint` but never treated as a lock trigger: counting an inactive
session (a VT switch away from it) as locked would make kpa lock the
vault just for that.

**Expiry is correct by construction because we own the source.** After
`clipboard_timeout`, drop it. If the user copied something else meanwhile, the
compositor already replaced our source and the drop is a no-op — no content
comparison, no race, no risk of wiping someone else's clipboard. This is the
strongest argument for owning it natively rather than shelling out.

## Lock policy

Locking means: drop the `Database`, zeroize what can be zeroized, end any
clipboard offer that database's `copy` started, and update the tray icon.
A lock also cancels any `unlock` still in flight for that database (see §
Protocol), and kills its prompt if one is still open.

Prompts are bounded too:

- **Timeout.** A prompt left unanswered for `prompt_timeout` (default
  60 s) is killed, and the unlock fails with `prompt_cancelled`.
- **No prompt while the screen is known to be locked**, that is while the
  display session's `LockedHint` is true. The unlock fails with
  `no_display` instead. A locker that only sends the `Lock` signal never
  reports the unlock (threat model ASM-7), so kpa doesn't know the screen
  is locked, and the timeout bounds the cost.

`session_watch.rs` is the OS side of these triggers, and only reports: it
knows nothing about databases or locking. Its events are the display
session's state, a lock request (the `Lock` signal), suspend and a lost
watch, and the server reacts to them in one place,
`Server::on_session_event`. The other direction is a `SleepDelay`: the
server tells it after every change to what is unlocked, and a thread of
`session_watch` of its own holds or releases the sleep inhibitor, so no
request ever waits on D-Bus.

The logind watch reports **the display session's state** to the server: no display
session, or the display session's id with its `LockedHint` (locked or
unlocked) and its `Active`. It is read on subscribing, whenever
`User.Display` changes, and on each `LockedHint` or `Active` change, and
is "no display session" while the watch is down. The classification in §
Protocol reads the session's id, the prompt gate reads the session and
`LockedHint`: a prompt only for a requester on the desktop, and not while
the display session is locked. `copy`'s gate (§ Clipboard) also reads `Active`.
`Active` never feeds the prompt gate and never locks anything on its
own — only `LockedHint` does.

The prompt runs in its own process group, and killing it kills the whole
group, so a wrapper script's own prompt window goes too.

**Only one prompt is on screen at a time.** Concurrent unlocks across
different databases share a queue; a database's prompt still waiting its
turn is cancelled the instant a lock lands on it, rather than waiting for
its turn to come up first.

"What can be zeroized" is narrower than it sounds:

- **Cleared:** protected field values (`secrecy` types), `DatabaseKey`'s
  own copies of the password and keyfile, and every copy kpa itself makes
  — the prompt's output buffer, `list` entries, and the serialized
  response buffer are all zeroized on drop. A clipboard offer still being
  served by the database being locked is ended immediately rather than
  left to its own `clipboard_timeout`; a lock of a different database, or
  of none while nothing is on the clipboard, leaves the clipboard alone.
- **Not cleared, upstream:** unprotected field values (plain `String`s
  inside `keepass`), the decrypted and decompressed payload buffers
  `keepass` parses from, its key-derivation intermediates, its XML
  keyfile parser's working copies. These persist in freed heap pages until
  the allocator reuses them. The clipboard's copy of an offered secret is
  kpa's own, zeroized when its serving thread ends.

Lock stops serving the database and clears what kpa owns; it is not a
guarantee that no trace of the plaintext remains in the process's memory.

| Trigger      | Source                                                                        |
| ------------ | ----------------------------------------------------------------------------- |
| Screen lock  | logind session `Lock` signal, or `LockedHint` becoming true, on the user's display session (`User.Display` of `Manager.GetUser(uid)`), via `zbus`. Covers `loginctl lock-session` and `IdleAction=lock`; a locker that calls neither is invisible (threat model ASM-7) |
| Suspend      | logind `PrepareForSleep(true)`: lock everything, then release the `delay` sleep inhibitor. kpa holds it while anything is unlocked. Logind allows `InhibitDelayMaxUSec` (5 s default) before sleeping regardless |
| Bus loss     | every database locks; the subscription is re-established with backoff        |
| Idle         | per database: no successful `list` of it (`list` of all counts for each database it reads), and no `copy` or unlock that installs it, for `idle_timeout` (default 30m); `status` and `lock` don't count |
| Explicit     | `kpa lock`, or the tray menu                                                  |
| File changed | freshness guard (above)                                                       |

## Tray

`ksni` — StatusNotifierItem over D-Bus, with menus, dynamic icons and
tooltips. Any StatusNotifierItem host (waybar, quickshell, a KDE/GNOME panel,
...) picks it up with no extra work on kpa's side.

- Icon reflects aggregate state: all locked / some unlocked / error.
- Tooltip lists each database and its state.
- Menu: a per-database submenu (Lock, Unlock), then Lock all, then Quit.

This satisfies "autostarts, lives in the background until needed" directly
rather than by proxy through another application's tray.

No tray host at all — including `kpa serve` starting before one exists, or
one disappearing and coming back later — is a normal, non-fatal state: kpa
keeps running and registers (or re-registers) as soon as a host is there.

## Security

**Boundary: the user account.** Inside it, optimise for blast radius and
time, not caller identity — see `background.md` § "Security boundary".

Held while unlocked:

| Item               | Held?                                                    |
| ------------------ | --------------------------------------------------------- |
| Master password    | No — kpa's copies zeroized after key derivation¹          |
| Keyfile path       | Yes (a path; harmless)                                     |
| Keyfile contents   | No — kpa's buffer zeroized; `keepass`'s parse copies not²  |
| Decrypted database | **Yes** — the real exposure, same as any KeePass client    |

¹The password arrives on the prompt command's stdout, which kpa reads into
a fixed-size `Zeroizing` buffer that never grows (a growing buffer would
leave unwiped copies behind each time it reallocates), then into a
`Zeroizing<String>`. A password carried in an `unlock` request takes the
same path: the request line is read into a fixed-size `Zeroizing` buffer
of its own, and its base64 decoded from there. Both buffers are wiped once
the request is handled. `DatabaseKey` zeroizes its own copy. Two copies are
outside kpa's reach: whatever the prompt program (or the client) itself
held, and `keepass`'s key-derivation intermediates (e.g. the SHA-256 of
the password, which is password-equivalent), which are not zeroized
upstream.

²`DatabaseKey`'s keyfile bytes are zeroized, but `keepass`'s XML keyfile
parser makes several unzeroized intermediate copies, which together can
cover the whole key and can survive a lock. Upstream.

Two Linux properties that help here, worth verifying on the machine
running kpa:

- **`/proc/sys/kernel/yama/ptrace_scope` is `1`** on most modern distros —
  only a parent can ptrace a child, so a random same-uid process cannot
  attach to kpa.
- **zram swap** (RAM-backed, compressed) reduces the chance that key
  material is paged to disk, but doesn't eliminate it — hibernation, a zram
  writeback device, or any secondary disk-backed swap all defeat it. This is
  a property of the machine's configuration, not one kpa's process can
  guarantee about itself.

Every kpa process sets `PR_SET_DUMPABLE=0` at startup, before dispatching to
any subcommand — before `kpa serve` reads its config, and before `kpa
unlock` reads the master password from the terminal. That keeps a crash
from writing a user-readable core dump of whatever secret the process
holds — the decrypted database in the daemon, the master password in `kpa
unlock` — and also makes `/proc/<pid>/mem` root-owned, which blocks
same-uid ptrace regardless of the Yama setting above. One host caveat, like
the two bullets above: with `fs.suid_dumpable = 2` the kernel still writes
a root-owned dump.

**Non-goals, stated explicitly:** kpa does not defend against an attacker who
already has code execution as the user running it. Nothing at this layer can. It reduces
casual exposure — clipboard leakage into history managers, an unlocked vault
overnight, secrets in shell scrollback — and that is the whole claim.

## Dependencies

`keepass` (KDBX + Argon2 + TOTP via its `totp` feature;
`challenge_response` feature off in v1), `serde`/`serde_json`, `toml`,
`clap`, `zbus` (logind, the service manager's environment), `ksni` (tray),
`wayland-client` with `wayland-protocols`/`wayland-protocols-wlr`
(clipboard), `zeroize`, `rustix`
and `libc` (`SO_PEERPIDFD`, which `rustix` lacks).
Threads over async unless `ksni`'s runtime choice makes tokio simpler.

## Staging

See [`plan.md`](./plan.md) — several sequential steps, each with a testable
intermediate state. Total is roughly 900 LoC of Rust.

## Deferred

- YubiKey challenge-response (note for whenever this lands: don't reuse the
  key's own PIN as a vault credential — it collapses a two-factor property
  into one)
- `kpa get` behind an explicit flag
- `pinentry` as the prompt
- Attachments (binary content; out of scope for a line-delimited JSON
  protocol)
- The legacy KeeOtp `TimeOtp-*` fields: a different, older convention from
  the de-facto-standard `otp` field, which `keepass`'s `totp` feature does
  not parse

## Open questions

None blocking. Which launcher or frontend you build on top of kpa is
independent of this design — anything that can shell out to `kpa` or speak
the socket protocol works.
