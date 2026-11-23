# kpa — headless use

kpa's `unlock` runs a graphical prompt and its `copy` offers the secret on
the Wayland clipboard, both of which assume a desktop. This doc says where each
request is asked and where a copy lands when the requester is outside the
desktop: an SSH login or a terminal-server shell into the machine that runs kpa,
or a machine with no desktop session at all.

[`design.md`](./design.md) § Unlocking has the flow these rules plug into, and
§ Clipboard the offer. The SSH agent ([`ssh-agent.md`](./ssh-agent.md)) builds on
it: unlock on demand needs the prompt routing in § 3, and remote use needs the
terminal unlock in § 4. The claims are
[`threat-model.md`](./threat-model.md)'s (G-12, T-19).

## 2. Situations

| Requester                                     | `unlock`                                           | `copy`                   |
| --------------------------------------------- | -------------------------------------------------- | ------------------------ |
| Desktop, screen unlocked                      | Prompt on screen                                   | Offered on the clipboard |
| Desktop, screen locked                        | Terminal prompt (§ 4). No prompt behind the locker | Refused, `no_display`    |
| Outside the desktop, desk screen unlocked     | Terminal prompt                                    | Refused, `no_display`    |
| Outside the desktop, desk screen locked       | Terminal prompt                                    | Refused, `no_display`    |
| No display session at all                     | Terminal prompt                                    | Refused, `no_display`    |
| Outside the desktop, no terminal (a cron job) | Refused, `no_prompt`                               | Refused, `no_display`    |

"Terminal prompt" means the terminal the request passed. Without one, the
rows that ask on the terminal answer `no_prompt` too. `status`, `lock` and
`list` answer the same wherever the requester is, except for `status`'s
`can_copy` (§ 5).

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
- **A graphical session that isn't the desk**, such as a remote desktop,
  counts as outside. logind names one display session per user, and a
  screen prompt opens with the daemon's own environment, on the desk.

## 4. Unlocking from a terminal

The daemon asks for the password, on screen or on the requester's terminal,
and the password never crosses the socket or passes through the CLI.

**The terminal comes with the request.** Any request may pass one terminal
file descriptor, as `SCM_RIGHTS` ancillary data on the same `sendmsg` that
sends its JSON line. The JSON declares nothing. The daemon keeps the
descriptor in the request's `Requester` and uses it only if it has to ask. It
refuses a request that comes with more than one descriptor, or with one that
isn't a terminal (`isatty`), as `malformed_request`, and receives it
close-on-exec so a prompt program never inherits it. `kpa unlock <db>`
passes its controlling terminal, `/dev/tty`, when it has one, as `ssh` and
`sudo` find theirs, so redirecting stdin doesn't change which terminal it is.
No other command passes one.

**Where the daemon asks.**

- On screen when the requester is on the desktop and the display session
  isn't known to be locked (§ 3). The terminal is ignored.
- Otherwise on the passed terminal.
- `"preferred_prompt":"terminal"`, which `kpa unlock --tty` sends, skips the
  screen: a desktop terminal asks to be asked on itself. The field sits
  beside `v` and `op` and has two values. `"screen"` is screen only, never
  the terminal.
- With nowhere to ask, `no_prompt`: no screen the requester may be asked on,
  and no terminal passed. `no_display` remains `copy`'s answer (§ 5).

**What the daemon does on the terminal.** It writes the prompt's message (the
one a screen prompt shows, such as `Unlock personal`, escaped the same way)
with echo off, reads one line, and puts the terminal's modes back. It
behaves like a screen prompt:

- any lock ends it (§ 6), and `prompt_timeout` applies;
- the requester closing its connection ends it too, as `prompt_cancelled`,
  and so does the terminal hanging up;
- it doesn't wait in the prompt queue, since it doesn't take the screen,
  but each database still allows one unlock at a time
  (`unlock_in_progress`, answered before the request is asked where to
  prompt, so it comes before `no_prompt`);
- an empty line is an empty password, the one way to reach a keyfile-only
  database from here, same as from the graphical prompt;
- the line goes into a fixed, zeroizing buffer of `MAX_ANSWER_LEN` bytes
  that never grows, and a longer one is refused.

The daemon never blocks on a terminal it doesn't own: it writes without
blocking, and every wait ends at the deadline, on a lock, when the
connection closes and when the terminal hangs up, with the modes put back on
each of those paths.

**Interrupts.** While the daemon reads, `^C`, `^Z` and a terminal hang-up
reach the CLI, not the daemon. The CLI doesn't exit at once. It shuts the
write side of its connection and waits for the daemon to close it, which the
daemon does once the terminal is back as it was, then exits. Without that
wait the shell takes the terminal over while the daemon still reads from
it, and the daemon restores modes the shell has changed since. If the daemon
hasn't closed within 2 seconds (an estimate), the CLI exits anyway. A daemon
asking on screen takes no notice of the interrupt, so the CLI lingers that
long after `^C` there.

**Wrong passwords** fail with `wrong_credentials`, as from a screen prompt.
kpa adds no backoff: any same-uid process can already read the `.kdbx` and
guess offline (NG-6), so the socket is no better an oracle.

**Any same-uid requester can aim a prompt at any terminal it can open**,
including one the user is typing in. Nothing the user types there reaches the
requester, only whether it unlocked, so this is no more than what a same-uid
process can already do (NG-1, NG-7, T-19).

**Rejected alternatives**

- **The CLI reads the password and sends it in the request.** The master
  password would cross the socket and sit in the CLI's memory. Keeping it
  out of serde's unwipeable scratch buffers needs a base64 field, a
  hand-written deserializer and a pre-pass that refuses escapes. A daemon
  that reads it from the terminal itself needs none of that.
- **Running a terminal pinentry on the client's tty**, as `gpg-agent` does
  with `GPG_TTY`. The daemon's sandbox would have to allow opening
  arbitrary terminals. A passed descriptor needs no such permission.

## 5. Copying

`copy` succeeds only when both of these hold:

- the requester is on the desktop (§ 3);
- the display session is active and its `LockedHint` is false.

Otherwise it fails with `no_display` and the clipboard is left alone. A
locker that only sends the `Lock` signal never reports the unlock (ASM-7),
so kpa can't track its state, and with such a locker only the requester
decides. The `Lock` signal still locks every database, so nothing is copied
until the next unlock anyway.

`status` reports the same check, for the requester that asks, as `can_copy`
(not built yet; [`protocol.md`](./protocol.md) § Responses), so a client such
as `kpa pick` can tell before it unlocks anything.

A copy's offer lasts until `clipboard_timeout` or until a lock ends the
unlock the entry was read from, whichever comes first. A lock of another
database leaves it. A `copy` that a lock overtakes before its offer is
recorded answers `locked` and leaves nothing on the clipboard.

Why:

- **A copy from outside the desktop can't help its requester.** The
  clipboard is the desk's, and the requester isn't there to paste. At best
  the copy is useless. At worst it leaves a secret on the clipboard of an
  unattended machine for `clipboard_timeout`.
- **A locked desk is where a copy would sit unseen**, even for a desktop
  requester such as a timer.
- **The cost falls on a shared terminal server used at the desk**, whose
  shells count as outside (§ 3). `kpa copy` there is refused, and the
  launcher or a desktop terminal does the job.

Remote use of a secret means a vault client on the machine you sit at, over
the same synced vault. kpa adds no channel for it.

**Rejected alternatives**

- **Printing to stdout.** That is the `get` operation kpa doesn't have:
  secrets in shell history, scrollback and logs (T-4).
- **OSC 52.** kpa would write the secret to the requester's terminal as an
  `ESC ] 52 ; c ; <base64> BEL` escape sequence, and the terminal you sit at
  would put it on its own clipboard. It works over SSH and through
  multiplexers that pass the sequence on. kpa doesn't use it:
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

  A remote session with no local vault client has no way to copy.

## 6. Prompt safety nets

Some prompts are raised where nobody may be looking, so each of these holds
for a prompt on a terminal as for one on screen (§ 4).

- **Timeout.** A prompt left unanswered for `prompt_timeout` (default 60 s)
  is ended, and the unlock fails with `prompt_cancelled`. A screen prompt is
  killed; a terminal prompt stops reading and puts the terminal back.
- **A lock ends an open prompt.** Any lock (screen lock, suspend, explicit)
  ends a prompt still open for that database, on screen or on a terminal.
  A prompt raised just before a screen lock would otherwise wait behind the
  locker until the user returns.
- **The requester leaving ends a terminal prompt.** A requester that closes
  its connection, or whose terminal hangs up, can't answer, so the prompt
  ends as `prompt_cancelled` and the terminal is put back.
- **No prompt on screen while the screen is known to be locked.** A locker
  that only sends the `Lock` signal never reports the unlock (ASM-7). Then
  kpa doesn't know the screen is locked, and the timeout bounds the cost.
  A terminal prompt isn't behind the locker, so it is still allowed.
- **The tray has no requester.** A click on its "Unlock" is asked on screen
  only while there is a display session that isn't known to be locked, and
  is `no_prompt` otherwise. Where the daemon runs (the desktop's cgroup or
  not) decides nothing: the tray is the daemon itself, and a click can't be
  traced to a caller.

## 7. Lock policy without a desktop

The daemon itself runs without a desktop. It starts with the systemd user
manager (`default.target`), not with the graphical session; the tray is
optional (without a tray host, kpa logs it and carries on); and the lock
policy talks to logind on the system bus. A machine reached only from outside
the desktop needs a user manager running before anyone logs in graphically:
the remote session can open a logind session, or lingering can be enabled.

The lock triggers are the same everywhere; what differs is which of them can
fire:

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
