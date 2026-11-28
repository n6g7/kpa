# kpa — the control protocol

What the CLI and any other client say to `kpa serve` on kpa's own socket.
[`design.md`](./design.md) § Protocol is the summary; this is the reference.
The types are in `src/frontends/control/proto/`, and the SSH agent's socket
speaks a different protocol ([`ssh-agent.md`](./ssh-agent.md)).

## Connections

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

A request line is capped at 64 KiB and must arrive within 5 seconds; a line
over the cap is answered `malformed_request`, and a connection that sends
nothing is dropped. Only the daemon's own uid may connect.

## Version

Both requests and responses carry `"v": 2`. On the request side, a mismatch
is rejected rather than negotiated — the daemon's response still carries its
own `v`, which is how the client learns which version the daemon is
actually running without a separate pair of fields for it. This is
deliberate too: rather than engineer backward compatibility, we make skew
impossible to ignore. The daemon holds only a cache of decrypted data, so
restarting it costs one re-unlock.

`v` is the *protocol* version, not the build. `status`'s `version` field is
the running daemon's build version (the string `kpa version` prints for the
CLI itself), piggybacked on `status` because it is the one extra thing `kpa
version` needs and `status` is already the no-argument "what's the daemon's
state" round trip. `kpa version` prints both, labelled `client:` and
`server:`, so an upgrade that replaces the binary but leaves the old daemon
running shows up as a mismatch. No daemon reachable (`server: not running`)
and an older daemon that predates the field (`server: unknown (daemon
predates version reporting)`) are reported, not failures: `kpa version`
always exits `0`.

## Requests

```json
{"v":2,"op":"status"}
{"v":2,"op":"unlock","db":"personal"}
{"v":2,"preferred_prompt":"terminal","op":"unlock","db":"personal"}
{"v":2,"op":"lock","db":"personal"}          // db omitted = lock all
{"v":2,"op":"list"}                          // db omitted = all unlocked
{"v":2,"op":"copy","db":"personal","uuid":"…","field":"password"}
{"v":2,"op":"copy","db":"personal","uuid":"…","field":"custom:Password"}
{"v":2,"op":"ssh_keys"}                     // db omitted = all unlocked
{"v":2,"op":"ssh_keys","db":"personal"}     // the SSH keys the vault holds
{"v":2,"op":"ssh_pending"}
{"v":2,"op":"ssh_approve","id":"6f1c0a52-3d8e-4c11-9a4b-0e5d2f7b8a31"}
{"v":2,"op":"ssh_grants"}
```

No request carries the master password. An `unlock` is asked for it by the
daemon, on screen or on the terminal the request passed.

| Op | What it does | Counts as activity |
|---|---|---|
| `status` | every database's lock state and entry count, the daemon's build version, and whether a `copy` from this requester would land | no |
| `unlock` | asks for the password and unlocks one database | the unlock does |
| `lock` | locks one database, or every database | no |
| `list` | the index of every unlocked database, or of one | yes, for each database read |
| `copy` | puts one field of one entry on the clipboard | yes |
| `ssh_keys` | the SSH keys the unlocked databases hold ([`ssh-agent.md`](./ssh-agent.md) § 6.4) | yes, for each database read |
| `ssh_pending` | the SSH requests refused for want of an approval (§ 6.8) | no |
| `ssh_approve` | approves one of them by its id | no |
| `ssh_grants` | the signature approvals currently granted (§ 6.8) | no |

A `list` or `ssh_keys` for every database reads each one under its own guard
of the core, one after another, so a lock can land between two of them. A
stale database fails the whole request, naming the first one; any stale ones
after it are locked too.

**A request may pass one terminal.** Any request may attach one file
descriptor, as `SCM_RIGHTS` ancillary data on the `sendmsg` that sends its
line. The JSON declares nothing. The daemon refuses a request with more than
one descriptor, or with one that isn't a terminal (`isatty`), as
`malformed_request`; a request with none has no terminal, which is fine. Only
`unlock` can ask, and `kpa unlock` is the only command that passes its
controlling terminal ([`headless.md`](./headless.md) § 4).

**Where an `unlock` asks.** On screen when the requester is on the desktop
and the screen isn't known to be locked, otherwise on the passed terminal. A
top-level `preferred_prompt` beside `v` and `op` names a place instead:
`"terminal"` (`kpa unlock --tty`) asks on the terminal even where the daemon
could ask on screen, and `"screen"` asks on screen or nowhere, never on the
terminal. The daemon answers `no_prompt` when it has nowhere to ask
([`headless.md`](./headless.md) §§ 3 and 4).

### `copy`'s `field`

`field` accepts any name `list`'s `fields` array returns for that entry:
`username`, `password`, `url`, `notes`, `totp`, or a custom (user-defined)
field by its KeePass key. Decoding never rejects a `field` value: any string
is accepted, and one that doesn't resolve to anything on the entry asked
about fails with `field_empty`, the same as an empty or absent field.

**Collision rule.** `username`, `password`, `url`, `notes`, `totp`, and
KeePass's own reserved `title` are matched case-insensitively and always
mean the built-in (`title` has no built-in `copy` serves, so a bare request
for it never resolves to anything). A custom field is legal in KeePass even
when its key collides with one of these only in case (e.g. a custom
`Password` field alongside the real one): that field is still listed and
copyable, but only via the `custom:` prefix (`custom:Password`), never its
bare key, so a bare request always means the built-in. Any other custom
field is addressed by its bare key.

**The `otp` field.** The entry's `otp` field holds the TOTP seed, so it is
never addressable: `copy` offers only the code made from it, as `totp`. `otp`
and `custom:otp` fail with `field_empty`, and `list` never names the field.
A custom field whose key differs only in case (`OTP`) is a different field
and is addressed like any other custom field.

## Responses

```json
{"ok":true,"v":2,"databases":[{"name":"personal","locked":false,"entries":341},
                              {"name":"work","locked":true}],"version":"1.2.3",
                "can_copy":true}

{"ok":true,"v":2,"entries":[{"db":"personal","uuid":"…","title":"GitHub",
                             "username":"alice","url":"https://github.com",
                             "group":"Dev",
                             "fields":["username","password","totp","custom:Password"]}]}

{"ok":true,"v":2,"copied":"password","expires_in":30}

{"ok":true,"v":2,"keys":[{"db":"personal","type":"ssh-ed25519",
                          "fingerprint":"SHA256:…","title":"Deploy",
                          "attachment":"id_ed25519"}],
                "skipped":[{"db":"personal","title":"Old","attachment":"id_rsa",
                            "reason":"PEM format; …"}],
                "locked":["work"]}

{"ok":false,"v":2,"error":"locked","db":"personal"}
{"ok":false,"v":2,"error":"unlock_in_progress","db":"personal"}
{"ok":false,"v":2,"error":"stale","db":"personal","detail":"database changed on disk"}
{"ok":false,"v":2,"error":"no_prompt","detail":"no screen or terminal to prompt on"}
{"ok":false,"v":2,"error":"no_display","detail":"no active, unlocked display session for the requester to paste into"}

{"ok":false,"v":2,"error":"version_mismatch","detail":"client sent v1; restart the daemon or upgrade the client"}
```

The last one is the version-skew rejection: the client sent `"v":1`, the
daemon is actually on `2`, and its own `v` in the response is what makes that
visible — no extra `client_v` and `daemon_v` fields needed.

`ssh_pending` lists, for each pending request, its id, `refused_at` (when it
was last refused, in Unix seconds, from which a client works out the age),
the `scope` the approval covers, `remember` (whether approving grants the
scope until lock) and the `request` that was refused; the shape is in
[`ssh-agent.md`](./ssh-agent.md) § 6.8. A host in the `scope` (`destination`,
`forwarding_host`) is an object, `{"fingerprint": "SHA256:…", "name": "…"}`,
whose `name` is there when the daemon found one. `ssh_approve` answers
`{"ok":true,"v":2}`. `ssh_grants` answers `{"ok":true,"v":2,"grants":[…]}`,
each grant as `ssh-agent.md` § 6.8 shows it; like `ssh_pending` it has no
failure, and nothing is logged for it.

`status`'s `can_copy` is `true` when a `copy` from the requester that asked
would be offered on the clipboard, and `false` when it would fail with
`no_display` ([`headless.md`](./headless.md) § 5). It is the answer of the
check `copy` runs, asked of the same requester and display session, and so is
the one field of `status` that differs by requester. It is advisory: it says
nothing of the database being unlocked or of the entry's field, and `copy`
decides again when it runs, so a display session that locks in between still
fails the copy. `kpa pick` reads it to stop before it lists anything
([`design.md`](./design.md) § The picker).

### Errors

An error response carries `error` (one of the codes below), usually the `db`
it is about, and sometimes a `detail` for a person. A `detail` is never
derived from a database file's contents.

| `error` | When |
|---|---|
| `version_mismatch` | the request's `v` isn't the daemon's |
| `malformed_request` | not JSON of a shape the daemon knows, an oversized line, bad descriptors |
| `unknown_db` | the name isn't configured |
| `locked` | the database is locked: asked of by `list`, `copy` or `ssh_keys`, or a `lock` ended this `unlock` while it prompted or derived (the lock wins: what the unlock opened is discarded, and a prompt still open is killed) |
| `stale` | the file changed on disk after it was unlocked, or while it was read; the database is dropped, unlock again |
| `unlock_in_progress` | an `unlock` of the same database is already prompting; refused, not queued |
| `no_prompt` | an `unlock` has nowhere to ask: no screen the request may be asked on, no terminal passed; names no database |
| `prompt_cancelled` | the prompt ended without a password: dismissed, timed out, the terminal hung up or the requester left |
| `wrong_credentials` | the password or keyfile didn't open the file |
| `not_found` | the file or its keyfile isn't where the config says |
| `corrupt` | the file isn't a database kpa can read: malformed, a format kpa doesn't read (only KDBX3 and KDBX4 are), or a database file or keyfile that is not a regular file or is larger than kpa reads (128 MiB, a keyfile 16 MiB); `detail` says which for all but the first |
| `io` | the file couldn't be read, the prompt couldn't be shown, or the clipboard couldn't take a secret (`detail` says which) |
| `unknown_uuid` | `copy`'s uuid names no entry |
| `field_empty` | the field is absent, empty or doesn't resolve |
| `no_display` | `copy` has no clipboard to put a secret on: the requester isn't on the desktop, or the display session isn't active and unlocked ([`headless.md`](./headless.md) § 5) |
| `not_pending` | `ssh_approve` names no pending request: it expired or a lock dropped it |

An `unlock` is refused in this order: `unknown_db`, then `unlock_in_progress`
(the claim on the database's one unlock is taken before anything else is
decided), then `no_prompt`. `no_display` is `copy`'s, `no_prompt` is
`unlock`'s.

On the terminal the daemon writes the prompt's message with echo off, reads
one line and puts the terminal back, so the master password goes from the
user's keyboard to the daemon without crossing the socket or passing through
the CLI. Like a screen prompt, any lock ends it, `prompt_timeout` applies,
and so does the requester closing its connection. It doesn't wait in the
screen prompt queue, and each database still allows one unlock at a time.
`kpa unlock` waits for the daemon to close the connection after `^C`, so the
daemon has put the terminal back before the shell takes it
([`headless.md`](./headless.md) § 4).

## What `list` returns

**`list` never returns secrets** — it is an index. That holds for any field
the user marked protected in their KeePass client, not just `Password`: a
protected `Title`, `UserName` or `URL` is omitted, not de-protected —
protection is a property of the field, not of which field name it happens to
be. A field counts as protected when its XML carries `Protected="True"` or
`ProtectInMemory="True"`. The pinned `keepass` crate (0.15.0) reads only
`Protected`, so until it reads `ProtectInMemory` too, `list` can return a
field that carries only that marker; the threat model (A-2, G-3) records
this as a known gap. The launcher does its own fuzzy matching; kpa stays dumb
and returns everything else.

**`fields` is the one exception, because it carries names, never values.**
Each entry's `fields` array names every field `copy` can be asked for on it:
the built-ins present and non-empty on the entry, in the order `username`,
`password`, `url`, `notes`, `totp`, then its custom fields by their KeePass
key (sorted: `keepass`'s own field storage is an unordered map, so the
database's own field order isn't recoverable), `custom:`-prefixed per the
collision rule. Protectedness never hides a field's *name* here, unlike
`title`, `username` and `url`: a protected `Password` still lists `password`,
and a custom field colliding with a protected built-in still lists
`custom:<key>`. `fields` is omitted from the wire when empty, like the other
optional fields.

`ssh_keys` is `list` for SSH keys. Like `list`, a request with no `db` covers
every unlocked database, and each key and skipped attachment says which
database it is in: a key two databases hold is reported once for each.
`locked` names the databases such a request could not scan, and is left out
when there are none. A request that names a locked database fails with
`locked` instead, as it does with `unknown_db` or `stale`; it never answers
from the key cache. Like `list`, it returns entry titles to the caller and
keeps them out of the daemon's log.

## CLI output

The protocol is what the CLI speaks; what it prints is a separate choice. A
subcommand with a text output (`kpa ssh keys`, `kpa ssh pending`) renders the
response for a person, with every string the vault or the requester supplied
escaped (threat model T-13). `--json`, a flag every client subcommand takes,
prints the daemon's response line instead, so a script keeps a stable shape
whatever text a command grows. The subcommands without a text output yet
print the response line with or without it. Because the protocol is plain
lines, it stays hand-debuggable with `socat`:

```sh
echo '{"v":2,"op":"status"}' | socat - UNIX-CONNECT:"$XDG_RUNTIME_DIR/kpa/sock"
```
