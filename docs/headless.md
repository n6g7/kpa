# kpa — headless use (proposal)

kpa assumes a desktop. `unlock` runs a graphical prompt, and `copy` offers
the secret on the Wayland clipboard. This proposal makes kpa usable from a
session outside the desktop: an SSH login or a terminal-server shell into
the machine that runs kpa, or a machine with no desktop session at all.

This is a proposal: nothing here is built. It changes the "daemon always
prompts" rule in [`design.md`](./design.md) and extends
[`threat-model.md`](./threat-model.md). § 8 lists those edits. The SSH agent
proposal builds on it: unlock on demand needs the prompt routing in § 3,
and remote use needs the terminal unlock in § 4.

## 1. Summary

- **Every request is classified by where it comes from**: from the desktop,
  or from outside it. kpa reads the requester's cgroup (§ 3).
- **Unlocking from outside the desktop happens on the terminal.** The
  daemon never raises a graphical prompt for such a request. `kpa unlock`
  reads the password on its own terminal and sends it over the socket
  (§ 4).
- **Copying needs a requester on the desktop, and the desktop unlocked**
  (§ 5). A `copy` from outside the desktop is refused, since the secret
  would land on a clipboard the requester can't paste from.
- **Prompts get a timeout, and a lock kills an open prompt** (§ 6).
- **`status`, `lock` and `list` work anywhere**, as they do today.

The daemon itself already runs without a desktop:

- It starts with the systemd user manager (`default.target`), not with the
  graphical session.
- The tray is optional: without a tray host, kpa logs it and carries on.
- The lock policy talks to logind on the system bus. With no display
  session, the idle timer, suspend and an explicit `kpa lock` still lock.

A machine reached only from outside the desktop needs a user manager
running before anyone logs in graphically. The remote session can open a
logind session, or lingering can be enabled.

## 2. Situations

| Requester                                      | `unlock`                                    | `copy`                                                 | `status`, `lock`, `list` |
| ---------------------------------------------- | ------------------------------------------- | ------------------------------------------------------ | ------------------------ |
| Desktop, screen unlocked                       | Graphical prompt, as today                  | Clipboard, as today                                    | As today                 |
| Desktop, screen locked                         | Refused, `no_display`. No prompt behind the locker | Refused, `no_display`                           | As today                 |
| Outside the desktop, desk screen unlocked      | Terminal prompt (§ 4)                       | Refused, `no_display`                                  | As today                 |
| Outside the desktop, desk screen locked        | Terminal prompt                             | Refused, `no_display`                                  | As today                 |
| No display session at all                      | Terminal prompt                             | Refused, `no_display`                                  | As today                 |
| Outside the desktop, no terminal (a cron job)  | Refused, `no_display`                       | Refused, `no_display`                                  | As today                 |

Both operations ask where the user is, from the requester's
classification. A prompt must appear where someone can answer it, and a
secret must land where the requester can paste it. `copy` also needs the
display session unlocked (§ 5).

## 3. Telling the desktop from outside it

kpa takes the peer's pid from the socket (`SO_PEERPIDFD` where the kernel
has it, `SO_PEERCRED` otherwise) and reads its cgroup from
`/proc/<pid>/cgroup`. A requester counts as **from the desktop** when a
display session exists (`User.Display` is not `/`) and the requester runs
in one of two places:

- inside `user@<uid>.service`, where the compositor and everything it
  spawns live;
- inside the display session's own scope.

Everything else is **outside the desktop**:

- an SSH login, which gets its own `session-N.scope`;
- a terminal server's shell. A terminal server either runs as a system
  service, outside the user's slice, or registers each connection as its
  own remote logind session, whose `session-N.scope` isn't the display
  session's;
- a cron job;
- anything at all while there is no display session.

A requester that exits before kpa reads its cgroup counts as outside. Any
failure to classify errs toward outside, which at worst asks for the
password on a terminal instead of on screen.

**This decides where to ask, not who may ask.** A same-uid process can
launder work into another cgroup, through `systemd-run --user` or by asking
the compositor to spawn it. The most it gets from that is a prompt on
screen (NG-7), or a terminal prompt it has to answer itself.

**Limits**

- **A terminal server shared between the desk and remote clients** runs
  every shell under its own service or in its own logind sessions. Its
  shells count as outside even when used at the desk. So `kpa unlock`
  there asks on the terminal, and `kpa copy` there is refused. The
  launcher and desktop terminals are unaffected.
- **A multiplexer started from the desktop and attached over SSH** runs in
  the desktop's cgroup. An unlock from it raises the graphical prompt on
  the desk's screen, which the remote user can't see. The prompt timeout
  (§ 6) bounds that. A `copy` from it lands on the desk's clipboard.

## 4. Unlocking from a terminal

The daemon answers an `unlock` from outside the desktop with a new error,
`no_display`, without prompting. `kpa unlock <db>` handles it when it has a
controlling terminal:

1. It opens `/dev/tty` and reads the password with echo off, as `ssh` and
   `sudo` do. Redirecting stdin doesn't change where it reads.
2. It sends the request again with the password in it, base64-encoded:
   `{"op":"unlock","db":"personal","password":"<base64>"}`. That is one
   line, like every other request.
3. The daemon decodes the field into the same fixed, zeroizing buffer as
   the prompt's output (`MAX_PASSWORD_LEN`), then unlocks as usual. The
   keyfile still comes from config.
4. The CLI marks itself non-dumpable and zeroizes its copy.

The first request is a plain `unlock`, and only `no_display` makes the CLI
read the terminal. So a terminal on the desktop still gets the graphical
prompt. `--tty` skips that first round trip, and is how a desktop terminal
asks for the terminal read. Without a controlling terminal, `kpa unlock`
reports `no_display` and exits non-zero. A request that carries a password
never raises a prompt, wherever it comes from.

**Why base64 rather than a JSON string.** A JSON string can contain escapes
(`\"`, `\\`, `\u…`), and `serde_json` unescapes them into an internal
scratch buffer that kpa can't zeroize. Base64 never needs escaping, so
`serde_json` hands the field over as a slice of the request buffer
(`visit_borrowed_str`), and kpa decodes it straight into its own buffer. A
`password` that would need unescaping is refused as malformed. `base64` is
already a dependency.

**The request line gets the same care.** The daemon reads it into a fixed,
zeroizing buffer of `MAX_REQUEST_LEN`, with no `BufReader` and no growing
`Vec`, so no unwiped copy of the line survives the request. Decode errors
carry no request content, and requests are never logged (T-4).

**Wrong passwords** fail with `wrong_credentials`, as from the prompt. kpa
adds no backoff: any same-uid process can already read the `.kdbx` and
guess offline (NG-6), so the socket is no better an oracle.

**Rejected alternatives**

- **Passing the terminal's fd with `SCM_RIGHTS`**, for the daemon to read
  from. If the client dies, the daemon races the shell for keystrokes and
  terminal modes.
- **Running a terminal pinentry on the client's tty**, as `gpg-agent` does
  with `GPG_TTY`. It has the same race, and the daemon's sandbox would have
  to allow opening arbitrary terminals.

## 5. Copying

`copy` succeeds only when both of these hold:

- the requester is on the desktop (§ 3);
- the display session is active and its `LockedHint` is false.

Otherwise it fails with `no_display` and the clipboard is left alone. A locker that only sends the `Lock` signal never
reports the unlock (ASM-7), so kpa can't track its state. With such a
locker, `copy` behaves as it does today. The `Lock` signal still locks
every database, so nothing is copied until the next unlock anyway.

Why:

- **A copy from outside the desktop can't help its requester.** The
  clipboard is the desk's, and the requester isn't there to paste. At best
  the copy is useless. At worst it leaves a secret on the clipboard of an
  unattended machine for `clipboard_timeout`.
- **A locked desk is where a copy would sit unseen**, even for a desktop
  requester such as a timer.
- **The cost falls on a shared terminal server used at the desk**, whose
  shells count as outside (§ 3). `kpa copy` there is refused, and the
  launcher or a desktop terminal does the job. Open question 1 covers an
  override.

Remote use of a secret means a vault client on the machine you sit at, over
the same synced vault. kpa adds no channel for it.

**Rejected alternatives**

- **Printing to stdout.** That is the `get` operation kpa doesn't have:
  secrets in shell history, scrollback and logs (T-4).
- **OSC 52.** kpa would write the secret to the requester's terminal as an
  `ESC ] 52 ; c ; <base64> BEL` escape sequence, and the terminal you sit at
  would put it on its own clipboard. It works over SSH and through
  multiplexers that pass the sequence on. It is ruled out for now:
  - It adds a second way out for secrets, which changes G-3 from "only to
    the clipboard".
  - The secret crosses every hop: the remote pty, a multiplexer or terminal
    server that may keep it in scrollback or a session recording, and the
    terminal itself. ACT-5 sits on all of them.
  - kpa can't expire it. A clearing sequence after `clipboard_timeout`
    reaches the terminal only if it's still attached, and many terminals
    ignore clipboard writes they consider empty or unsolicited. Nothing
    carries `x-kde-passwordManagerHint`, so clipboard managers on the far
    side record it (G-7).
  - Keeping "no operation returns a secret" means the daemon writes to the
    client's terminal itself, through an fd passed with `SCM_RIGHTS`. A
    same-uid process can pass a pty it reads instead. That is no worse than
    `kpa copy` followed by `wl-paste`, which T-18 already accepts, but it
    makes the scripted read one step shorter.

  A remote session with no local vault client has no way to copy. Any
  future OSC 52 design would need to be off by default, per entry or per
  call, require a terminal that supports clearing, and have the threat
  model name the new channel.

## 6. Prompt safety nets

These matter once some prompts are raised where nobody may be looking.

- **Timeout.** A prompt left unanswered for `prompt_timeout` (default 60 s)
  is killed, and the unlock fails with `prompt_cancelled`.
- **A lock kills an open prompt.** Any lock (screen lock, suspend, explicit)
  kills a prompt still open for that database. Today a prompt raised just
  before a screen lock waits behind the locker until the user returns.
- **No prompt while the screen is known to be locked.** A locker that only
  sends the `Lock` signal never reports the unlock (ASM-7). Then kpa doesn't
  know the screen is locked, and the timeout bounds the cost.

## 7. Lock policy without a desktop

The lock triggers don't change. What changes is which of them can fire:

- **No display session**: the idle timer, suspend, explicit lock, and the
  freshness guard.
- **A display session while working from outside it**: all of the above,
  plus the desk's screen lock. Screen lock is an event, not a state. It
  locks everything when it happens, including what a remote session
  unlocked. A terminal unlock while the desk is already locked stays
  unlocked until the next trigger.

Unlocking from a terminal while the display session is locked is allowed. The user
typed the master password, the same consent the graphical prompt collects.
The desk's lock protects the desk, and the desk still gets nothing: `copy`
stays refused while it is locked (§ 5).

## 8. Changes to existing docs

- **`design.md`**
  - Settled decision 9 and § Protocol: `unlock` prompts on screen from the
    desktop, and reads the password from the client's terminal otherwise.
  - § Clipboard: `copy` needs an active, unlocked display session.
  - § Lock policy: a lock kills open prompts; prompts time out.
  - § Configuration: `prompt_timeout`.
- **`threat-model.md`**
  - § 1 System: `unlock` can carry a password from the client.
  - **TB-1** gains inbound A-1: the master password, from a same-uid
    client, for an unlock from outside the desktop.
  - **G-3**: "A-1 never leaves the process" holds. A-1 now also enters it
    from the CLI, which holds it for one request and zeroizes it.
    `copy` offers only for a requester on the desktop, while the display
    session is active and unlocked.
  - **G-5** gains: "A lock ends any prompt in flight. A prompt ends after
    `prompt_timeout`."
  - **New goal: no prompt where nobody can see it.** A request from outside
    the desktop, or while the screen is locked, never raises a prompt on
    screen.
  - **T-4** extends to the CLI: the terminal-read password never reaches
    its argv, environment, stdout, stderr or a log, and the CLI zeroizes it.
  - **New threat: misrouted prompt** (S) — ACT-5, ACT-10. A prompt raised
    on an unattended screen, or a terminal read in the wrong place.
    Response: classification errs toward the terminal, timeouts, locks
    kill prompts. Residual: a multiplexer attached over SSH (§ 3).
- **`config.example.toml`**: `prompt_timeout`.
- **`TODO.md`**: this proposal is the "Support headless use" entry.

## 9. Implementation

**Modules**

| File          | Role                                                                                                     |
| ------------- | -------------------------------------------------------------------------------------------------------- |
| `authn.rs`   | Peer pidfd or pid → uid, cgroup path and command name, kept in a `Requester`. Plain facts, no rules |
| `authz.rs`   | The checks both sockets share, pure functions of a `Requester` and the display session as it is when asked: `may_connect`, `on_desktop`, `may_prompt_on_screen`. The cgroup-path classifier is table-tested |
| `request_policy.rs` | What kpa's own socket's requests may do, one pure function per request type: `copy` (the session whose clipboard may be used, or `no_display`) and `unlock` (a prompt may appear, or `no_display`). The SSH agent's counterpart is `ssh_agent::policy`; `policy.rs` is the auto-lock rules |
| `policy.rs`   | Also publishes the display session's state (no session, locked, unlocked), which `copy` and classification read      |
| `proto/unlock.rs` | `UnlockRequest` gains `password: Option<Password>`: a zeroizing newtype, decoded from base64 by a borrowing visitor, with a redacting `Debug`. `no_display` joins the error codes |
| `server.rs`   | Reads request lines into a fixed zeroizing buffer; prompt timeout; lock kills prompts; `copy` gated on origin and the display session's state |
| `main.rs`     | `kpa unlock` handles `no_display` with a `/dev/tty` read, and gains `--tty`                              |

**Tests**

- Classifier: cgroup paths for a compositor child, a session scope, an SSH
  scope, a system service, and malformed input.
- `tests/`: unlock with a password in the request, against the fixture
  database; a wrong password; an oversized one, invalid base64, and an
  escaped `password` string all refused; `copy` refused from outside the
  desktop, and while the fake display session state is locked or absent.
- The terminal read: a pty-driven test of `kpa unlock --tty`, echo off,
  password delivered.
- Fuzzing: the request decoder's target gains the `password` field.

**Phases**, each leaving a usable state:

1. Prompt timeout and lock kills prompts. These help the desktop today.
2. Classification, `no_display`, terminal unlock.
3. `copy` gated on origin and the display session's state.

## 10. Open questions

1. **Shared terminal servers.** Should config be able to name a service
   whose shells count as the desktop? That would bring back the graphical
   prompt and `copy` for those shells at the desk. The cost: for the same
   server's remote clients, prompts appear unseen and copies land on the
   desk's clipboard. The override would name a server that runs as a
   system service by its unit, and one that registers logind sessions by
   those sessions' `Service` name.
2. **Remote display sessions.** The desk is the one session logind names as
   the user's display, and the prompt starts with the daemon's own
   environment. A graphical session that isn't the desk, such as a remote
   desktop, is classified Outside. The prompt for a caller in such a
   session should open in that caller's session, not on the desk's screen.
   That needs the caller's session display environment, which logind
   doesn't expose and which isn't per-session in the user manager. The
   design for finding it is open.
