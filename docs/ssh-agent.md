# kpa — SSH agent (proposal)

kpa serves the SSH keys stored in its databases, replacing KeePassXC's SSH
agent integration. KeePassXC remains a vault editor if wanted, but stops
handling SSH. Linux only, like the rest of kpa.

This is a proposal: nothing here is built. It reverses one line of
[`design.md`](./design.md) § Scope ("Is not: … an SSH agent") and extends
[`threat-model.md`](./threat-model.md); § 9 lists those edits.

## 1. Recommendation

- **kpa is the agent.** `kpa serve` listens on a second socket,
  `$XDG_RUNTIME_DIR/kpa/ssh-agent`, speaks the SSH agent protocol
  ([RFC 9987](https://www.rfc-editor.org/rfc/rfc9987.html)), and signs with
  keys read from unlocked databases. It never hands a key to another agent.
- **The agent is read-only.** It lists identities and signs. Every message
  that adds, removes, locks or unlocks gets `SSH_AGENT_FAILURE`.
- **Keys are declared in config by public key.** kpa finds the matching
  private key among entry attachments. Declared keys are listed even while
  their database is locked, which is what makes unlock-on-demand work.
- **Unlocking is the consent for local use.** The first signature from a
  locked database raises the unlock prompt; after that, local signatures
  need no approval. A key can opt into a confirmation on every use.
- **Forwarded use is off by default, and confirmed when on.** OpenSSH's
  `session-bind@openssh.com` tells kpa when a request arrives through
  `ssh -A`. A key opted into forwarding is confirmed on this machine's
  screen once per forwarding session and destination, and over a
  forwarded connection it signs SSH logins only, never arbitrary data.
- **No prompt where nobody can see it.** A request from outside the
  desktop (an SSH login, a Rex shell), or while the screen is locked, never
  raises a prompt on screen. Remote use works by forwarding the agent from
  the machine you are sitting at, or by unlocking from that terminal.
- **Keys never leave kpa.** Only signatures do. A lock drops the key at
  once, and a crash leaves nothing behind in another process.
- **Ed25519 and ECDSA.** RSA waits for a constant-time RSA implementation
  (§ 5.5).

## 2. What kpa adds over a client-managed agent

- **One unlock and one lock policy** for passwords and keys, with or
  without a GUI client running.
- **Keys exist only while the database is unlocked.** No other process holds
  a copy that has to be removed on lock.
- **Unlock at first use** instead of before use.
- **Per-request policy.** kpa sees where each request comes from (local or
  forwarded, which destination, what is being signed). An agent that only
  receives keys at unlock time sees none of that.

## 3. Approaches

**A. Push keys into an existing agent** (KeePassXC's model). On unlock, kpa
parses each key and sends it to `$SSH_AUTH_SOCK` with
`SSH_AGENTC_ADD_ID_CONSTRAINED` (lifetime, confirm). On lock it sends
`SSH_AGENTC_REMOVE_IDENTITY`.

**B. kpa is the agent** ← recommended.

**C. kpa in front of another agent.** kpa answers for its own keys and relays
everything else to an upstream agent. This only matters if keys from
outside the vault (a hardware token, say) must share one `SSH_AUTH_SOCK`.
Deferred, and nothing in B prevents adding it later.

|                             | A: push into an agent                                                                                                                        | B: kpa is the agent                                       |
| --------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------- |
| Private key leaves kpa      | Yes, into the agent's memory                                                                                                                 | No, only signatures                                       |
| Lock revokes the key        | Only if the `REMOVE` arrives. A crash or an agent restart leaves keys until their lifetime runs out                                          | Always: a locked database has nothing to sign with        |
| Use before unlock           | Impossible: the agent has no key yet                                                                                                         | Unlock prompt at the first signature                      |
| Sees each use               | No. Cannot log, confirm by context, or apply per-request policy                                                                              | Yes                                                       |
| Local vs forwarded          | Only via destination constraints, fixed when the key is added                                                                                | Decided per request                                       |
| Idle timer                  | kpa cannot see SSH use, so the idle lock removes keys mid-session                                                                            | kpa decides what counts as activity (§ 5.9)               |
| Crypto in kpa               | Parse and decrypt the OpenSSH key file, which the agent needs in its own wire format                                                         | The same, plus calling `sign`                             |
| Compatible agents           | OpenSSH's `ssh-agent`. Not `gpg-agent`: KeePassXC's docs note it cannot remove added keys                                                    | Any agent-protocol client                                 |

The "Write UI, not crypto" rule in [`background.md`](./background.md) still
holds under B. The new code is protocol framing, parsing and policy.
Signatures come from RustCrypto's `ssh-key` (backed by `ed25519-dalek`,
`p256`, `p384`), and kpa implements no primitives. Both A and B have to
parse and decrypt the key file, so all A saves is the call to `sign`.

## 4. Situations

The policy is a table over who asks and from where. "Prompt" always means a
prompt on this machine's screen.

| #   | Situation                                                    | Recognized by                                                           | Database locked                                                          | Database unlocked                                                                          |
| --- | ------------------------------------------------------------ | ----------------------------------------------------------------------- | ------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------ |
| S1  | At the desk: `ssh`, `git push`, an IDE                       | No binding, or an authentication binding from the local `ssh`           | Unlock prompt naming the key and destination                             | Sign. A key with `confirm = "always"` asks first                                          |
| S2  | Commit or tag signing (`ssh-keygen -Y sign`)                 | `SSHSIG` data, no binding                                               | As S1                                                                    | As S1                                                                                      |
| S3  | `ssh -A` from here; the remote host uses the key             | First binding has `is_forwarding` (§ 5.2)                               | Refused unless the key has `forwarding = "confirm"`. Then an unlock prompt naming the forwarding host and destination, which counts as the confirmation | Refused unless opted in. Then a confirmation once per (forwarding session, destination), remembered until lock. SSH logins only |
| S4  | Working on this machine from elsewhere: an SSH login, a Rex shell | The requester runs outside the desktop (§ 5.8)                     | Refused, no prompt. Run `kpa unlock` in that shell, which prompts on the terminal (§ 5.10), or forward an agent from where you sit | As S1, except that keys needing confirmation are refused                                   |
| S5  | Screen locked or machine suspended                           | logind (existing lock policy)                                           | Everything is already locked. No prompt                                  | Not possible: a screen lock locks every database                                           |
| S6  | Background jobs: user timers, IDE auto-fetch                 | Indistinguishable from S1. Jobs outside the user manager (cron, system services) fall under S4 | Unlock prompt, with backoff after a cancel (§ 5.6)    | Sign                                                                                       |
| S7  | Sandboxed app, container                                     | No socket unless granted (T-15)                                         | —                                                                        | —                                                                                          |

**Why local use is not confirmed by default.** Inside the uid boundary a
per-use approval is theater (NG-1). A process that can talk to the agent
can also wait for an unlock and `copy` every password, and the threat model
already accepts that while unlocked (T-18). Prompts on every `git fetch`
train the user to accept without reading. The precedents converge on
remembering an approval until lock: 1Password's default, Bitwarden's
"remember until lock" option, Strongbox's approval timeout. `confirm =
"always"` remains available for a key whose every use should be visible
(production root, say).

**Why forwarded use is confirmed.** The requester is another machine: its
root, or anything there that can reach the forwarded socket. That is a real
boundary, unlike the uid boundary above. The prompt also appears on the
screen of the person who typed `ssh -A`. Bitwarden reportedly makes the same
call, prompting for forwarded requests even when approvals are otherwise
off. Scoping the approval to one forwarding session and one destination
keeps the friction to one prompt per `ssh -A` session per destination.

The design favours **the agent lives where you sit**: the machine with the
screen runs the agent over the synced vault, and remote hops reach it by
forwarding. ProxyJump (`ssh -J`) is better still where it fits, because the
key never needs forwarding: each hop authenticates from the local `ssh`.

## 5. Mechanism

### 5.1 Socket and protocol

- **Socket**: `$XDG_RUNTIME_DIR/kpa/ssh-agent`, bound and checked exactly
  like the JSON socket (`socket::bind_socket`, `SO_PEERCRED`, T-1). It is
  inside the directory the systemd sandbox already allows. It has its own
  connection cap, separate from the JSON socket's.
- **Framing**: `uint32` length, then the message. Frames over 256 KiB
  (OpenSSH's `AGENT_MAX_LEN`) close the connection. Unlike the JSON socket,
  connections are long-lived and carry many requests: `ssh` holds one open
  while it talks to the server, and a forwarded channel can sit idle for
  hours. So there is no idle deadline between frames, but once a frame
  starts, the rest of it must arrive within 5 s.
- **Messages handled**:

  | Request                             | Response                                                                       |
  | ----------------------------------- | ------------------------------------------------------------------------------ |
  | `REQUEST_IDENTITIES` (11)           | `IDENTITIES_ANSWER` (12): every declared key, comment = its `name`             |
  | `SIGN_REQUEST` (13)                 | `SIGN_RESPONSE` (14), or `FAILURE` (5) per § 4                                 |
  | `EXTENSION` (27) `session-bind@openssh.com` | `SUCCESS` (6), or `EXTENSION_FAILURE` (28) if verification fails       |
  | `EXTENSION` (27) `query`            | The supported extensions                                                       |
  | Anything else: add, remove, remove-all, smartcard, `LOCK` (22), `UNLOCK` (23), other extensions | `FAILURE` (5) |

  `ssh-add -D` therefore does nothing, and `ssh-add -x`/`-X` do nothing
  either. Locking goes through `kpa lock`, and the agent socket never
  accepts a secret (§ 5.10).

### 5.2 Telling local from forwarded

The `session-bind@openssh.com` extension message contains:

```
string   hostkey               server host key
string   session identifier    exchange hash of the initial key exchange
string   signature             the server's signature over the session identifier
bool     is_forwarding
```

OpenSSH's `ssh` (8.9 and later) sends it on each agent connection it opens.
That includes the connection it opens on behalf of a forwarded channel,
which is bound with `is_forwarding` set before any byte from the remote
side crosses it (`client_request_agent` in `clientloop.c`). A remote `ssh`
using the forwarded agent to reach a further host binds that hop over the
same connection. kpa verifies each signature and records up to 16 bindings
per connection, as `ssh-agent` does, refusing any new binding on a
connection already bound for authentication.

Each connection is classified as one of:

- **Local, unbound**: no binding. `ssh-keygen -Y sign`, and clients other
  than OpenSSH.
- **Local, bound**: authentication bindings only. The destination is the
  last binding's host key.
- **Forwarded**: the first binding has `is_forwarding`. The first hop is
  that binding's host. The destination is the last non-forwarding binding,
  if the remote `ssh` sent one.

A binding that fails verification but claims `is_forwarding` still marks
the connection forwarded. Failure always errs toward the strict side.

Limit: forwarding that bypasses the OpenSSH client looks local. That covers
an `ssh` older than 8.9, and tools that relay `SSH_AUTH_SOCK` themselves
(container runtimes, Eternal Terminal). nixpkgs ships a newer OpenSSH, so
this is a threat-model note, not a blocker.

### 5.3 What is being signed

kpa parses the data to be signed the way `ssh-agent`'s
`parse_userauth_request` does:

- **SSH login**: session identifier, `SSH2_MSG_USERAUTH_REQUEST`, user,
  `ssh-connection`, `publickey` (or `publickey-hostbound-v00@openssh.com`
  plus a host key), the signature flag, the algorithm, and a key blob equal
  to the signing key. Trailing bytes are rejected.
- **SSHSIG**: the `SSHSIG` magic, namespace (`git`, `file`, …), reserved,
  hash algorithm, `H(message)`.
- **Other**: anything else.

Rules:

- **Forwarded**: SSH logins only. The session identifier must equal the
  last binding's, and that binding must name a destination, so the
  confirmation can say truthfully where the signature will be accepted. A
  remote `ssh` older than 8.9 therefore cannot use a forwarded key. rhea
  runs NixOS, so this doesn't bite.
- **Local, bound**: an SSH login must match the last binding's session
  identifier.
- **Local, unbound**: any purpose. Git signing lives here.

### 5.4 Which keys

Keys are declared in config (§ 6) by public key and database. When a
database unlocks, nothing happens. On the first signature that needs a
key, kpa scans that database:

1. Look at current entries only: no history, and nothing in the recycle bin.
2. Pick attachments whose bytes start with
   `-----BEGIN OPENSSH PRIVATE KEY-----`.
3. Compare each file's public key, stored unencrypted in its header, with
   the declaration.
4. An optional `entry = "<uuid>"` in the declaration pins the lookup to one
   entry.

An encrypted key's passphrase is the entry's Password field, the convention
KeePassXC already uses. The decrypted key is cached in the
database's `Slot` until lock. Each decryption runs bcrypt-pbkdf, so it
happens outside the vault mutex, under the same epoch check as unlock.

Authorization lives in config, not in the vault:

- **Config is trusted, vault content is not.** Config is ASM-3. Entry
  content is authored by ACT-4, and an attachment cannot make kpa serve a
  key nobody declared.
- **No XML parser.** KeePassXC's `KeeAgent.settings` attachment and its
  per-entry options are ignored.
- **The public key is what makes locked listing possible.** It is also
  usually in the dotfiles already, for `authorized_keys` or git's
  `allowed_signers`.

`kpa ssh-keys <db>` prints a ready-to-paste declaration for each private
key found in an unlocked database. It is the one-time discovery step.

kpa lists keys in config order. With many keys, a server can hit
`MaxAuthTries`. The usual answer is `IdentitiesOnly yes` plus a per-host
`IdentityFile` that points at a `.pub` file: `ssh` then offers only that
agent key. The home-manager module writes those `.pub` files (§ 6).

### 5.5 Key types and dependencies

- **Supported**: `ssh-ed25519`, `ecdsa-sha2-nistp256`, `ecdsa-sha2-nistp384`.
- **RSA: deferred.** RustCrypto's `rsa` crate is still affected by
  RUSTSEC-2023-0071 (Marvin, timing side channel on private-key
  operations, no patched release as of September 2026). The advisory says
  to avoid it wherever an attacker can observe timing, and a forwarded
  agent is exactly that. If RSA keys must be served before a fix lands:
  local use only, never forwarded, and `rsa-sha2-256`/`-512` only (never
  SHA-1 `ssh-rsa`).
- **Not supported**: `sk-*` (FIDO) keys and certificates.
- **Dependency**: `ssh-key` with `ed25519`, `p256`, `p384` and `encryption`
  (bcrypt-pbkdf with aes256-ctr, OpenSSH's default for key files). 0.6.x is
  the stable line, on `sha2` 0.10 next to kpa's 0.11. 0.7 is in release
  candidates and aligns the versions.

### 5.6 Unlock on demand

A signature for a declared key whose database is locked runs the normal
`unlock` path.

**When kpa prompts**

- Prompts must be allowed (§ 5.8).
- The database must not be in backoff.
- There is at most one prompt per database. Concurrent signers wait on the
  in-flight unlock instead of getting `unlock_in_progress`.

**What the prompt says.** It names its reason, for example "Unlock
personal: key github for git@github.com". Today `prompt` runs exactly as
configured, so the prompt can't even say which database it is for. A
`{message}` placeholder in the argv fixes that for every unlock:

```toml
prompt = ["fuzzel", "--dmenu", "--password", "--prompt", "{message}"]
```

The message is always passed as an option's value, never as a positional
argument.

**Timeouts and cancels.**

- A prompt left unanswered for `prompt_timeout` (default 60 s) is killed.
- Cancelling or timing out puts that database in backoff for 2 minutes.
  Signatures from it then fail at once without prompting, which stops
  prompt storms from loops, submodules and background fetches.

**Locks kill prompts.** Any lock (screen lock, suspend, explicit) kills a
prompt that is still open. Today a prompt raised just before a screen lock
waits behind the locker until the user returns. With on-demand prompts that
becomes common, so the fix is needed regardless.

### 5.7 Confirmation

`ssh_agent.confirm` is an argv with the same contract as `prompt`, in
dmenu style:

- kpa writes the choices on stdin and reads the chosen line from stdout.
- A non-zero exit, or any other output, means deny.
- `fuzzel --dmenu` works as is.

Choices:

- **Forwarded**: `Allow for this session`, `Allow once`, `Deny`.
- **Local, for a key with `confirm = "always"`**: `Allow`, `Deny`.

The message carries:

- the key name and purpose;
- the first hop and the destination, by host-key fingerprint, plus the
  host name when `~/.ssh/known_hosts` has an unhashed entry for it;
- the remote user name from the login request.

Request-derived text passes through the same escaping the CLI uses for
terminal output (T-13) and is length-capped.

A session approval is remembered under (key, first-hop session identifier,
destination host key), in memory only, and dropped on lock. A new `ssh -A`
session or a new destination asks again. The first-hop session identifier
is bound by the local `ssh` before the remote side can send anything, so a
remote host cannot claim another session's approval.

Only one prompt is on screen at a time: unlock and confirm prompts share a
queue.

### 5.8 Where prompts may appear

A prompt is raised only when both of these hold. Otherwise the signature
fails without one.

- **The screen is not known to be locked.** kpa already follows the
  display session for `Lock` and `LockedHint`. While `LockedHint` is true
  or the session is inactive, no prompt is raised. A locker that only
  answers the `Lock` signal never reports the unlock (ASM-7). In that case
  kpa does not know the screen is locked, and the prompt timeout (§ 5.6)
  bounds the cost.
- **The requester runs in the desktop.** kpa takes the peer's pid from
  `SO_PEERCRED` and reads its cgroup from `/proc/<pid>/cgroup`. It
  recognizes two places: inside `user@<uid>.service`, where `niri.service`
  and everything it spawns live, or inside the display session's own scope
  (`User.Display`). Everything else is outside the desktop:
  - an SSH login, which gets its own `session-N.scope`;
  - a Rex shell, which lives under Rex's system service;
  - a cron job.

  For a forwarded request the peer is the local `ssh`, so the check is
  about where that `ssh` runs. `ssh -A` typed in a desktop terminal prompts
  here. The same command typed in an SSH login or a Rex shell does not.

This decides where a prompt goes, not who is authorized. A same-uid
process can launder work into another cgroup, through `systemd-run --user`
or by asking the compositor to spawn it. The most that gets it is a prompt
on screen (NG-7). User services such as timers and Syncthing count as
desktop; that is S6.

The same rule governs an explicit `kpa unlock` (§ 5.10).

### 5.9 Lock and idle

- **Lock** drops the decrypted-key cache with the database. It zeroizes the
  cache and follows the same epoch rules as unlock.
- **Freshness.** The freshness guard runs before each signature, as it does
  for `copy` (G-8).
- **Signing does not reset the idle timer.** The timer protects every
  secret in the database against an unattended, unlocked session. SSH is
  the activity most likely to come from automation: timers, cron, IDE
  auto-fetch. Counting it would let a background `git fetch` keep the vault
  open indefinitely. Because of unlock on demand, an idle lock costs one
  prompt at the next real use.

### 5.10 Unlocking from a terminal

S4 needs a way to unlock that doesn't involve the screen. The usual case
is a Rex shell or an SSH login into the machine that runs kpa, with no
agent forwarded. For example, Rex's `dotfiles_update` runs `dfu`, which
pulls over SSH.

The daemon applies § 5.8 to `unlock` requests as well:

- **From the desktop**, it prompts with the configured `prompt`, as today.
- **From outside the desktop**, it answers a new error, `no_display`.

`kpa unlock <db>` handles `no_display` when its stdin is a terminal:

1. It reads the password on that terminal, with echo off.
2. It sends the request again with the password following the JSON request
   line, as raw bytes. The password never goes through `serde_json`.
3. The daemon reads it into the same fixed, zeroizing buffer as prompt
   output.
4. The CLI marks itself non-dumpable and zeroizes its copy.

`--tty` skips the first round trip.

This changes "the daemon always prompts". The password now crosses TB-1
inbound, from a same-uid client.

Rejected alternatives:

- **Passing the terminal's fd with `SCM_RIGHTS`.** If the client dies, the
  daemon races the shell for keystrokes and terminal modes.
- **Agent `UNLOCK` (`ssh-add -X`).** The agent socket is reachable from
  forwarded hosts, so any forwarding kpa failed to recognize would make it a
  remote password-guessing oracle.

## 6. Configuration

```toml
[ssh_agent]
# socket = "$XDG_RUNTIME_DIR/kpa/ssh-agent"   (default)
confirm = ["fuzzel", "--dmenu", "--prompt", "{message}"]
prompt_timeout = "60s"

[[ssh_key]]
name = "github"                       # identity comment; shown in prompts and logs
database = "personal"
public_key = "ssh-ed25519 AAAAC3Nza… github"
forwarding = "deny"                   # deny (default) | confirm
confirm = "never"                     # never (default) | always — local use
# entry = "8a1c…"                     # optional: pin the lookup to one entry
```

The agent socket exists only if at least one `[[ssh_key]]` is declared.

The home-manager module gains:

```nix
services.kpa.sshAgent = {
  enable = true;
  keys.github = {
    database = "personal";
    publicKey = "ssh-ed25519 AAAAC3Nza… github";
    forwarding = "confirm";
  };
};
```

It generates the `[[ssh_key]]` tables and writes each public key to
`~/.ssh/kpa/<name>.pub` for `IdentityFile`. It also wires the socket into
the session (§ 7).

## 7. Wiring on saturn

kpa runs only on saturn, the one Linux machine with the vault. The setup it
replaces, from `~/.dotfiles`:

- **gcr-ssh-agent owns `SSH_AUTH_SOCK`.** gnome-keyring is enabled by the
  niri module, and it brings gcr-ssh-agent with it. gcr-ssh-agent puts
  `SSH_AUTH_SOCK=/run/user/1000/gcr/ssh` into the systemd user
  environment, which `niri.service` and everything it spawns inherit.
- **KeePassXC feeds it.** KeePassXC autostarts with
  `SSHAgent.Enabled = true` and loads keys into whatever `SSH_AUTH_SOCK`
  points at when the database unlocks.
- **Logins into saturn see no local agent.** SSH logins and Rex shells have
  nothing set. From a Mac, `ForwardAgent yes` (all of `*.home.gaberel.fr`)
  brings Strongbox along.
- **rhea has no agent of its own.** `dfu` (pulling from ranger) and GitHub
  fetches there use the agent forwarded from the desktop. git's `insteadOf`
  rewrites every GitHub URL to SSH.
- **Git signs with GPG on the YubiKey.** No SSH signing is used today, so S2
  is unused.

**Changes**

1. **Deploy kpa on saturn** (flake input, `services.kpa`) and declare the
   keys in `sshAgent.keys`.
   - Declare the home key (`nathan@home.gaberel.fr`, already in the
     dotfiles for `authorized_keys`), the GitHub key, and whatever else
     Strongbox serves today.
   - Keys used from rhea need `forwarding = "confirm"`. That means the home
     key, for ranger, and the GitHub key.
   - Agent forwarding is on for every home host today. Every other key
     stays at `forwarding = "deny"`.
2. **Turn off what kpa replaces.**
   - Set `services.gnome.gcr-ssh-agent.enable = false`. gnome-keyring keeps
     its Secret Service role.
   - Set KeePassXC's `SSHAgent.Enabled = false`.
   - gcr injects its own `SSH_AUTH_SOCK` value into the user manager, and
     it would win over step 3.
3. **Point the desktop at kpa.** The home-manager module sets
   `systemd.user.sessionVariables.SSH_AUTH_SOCK =
   "\${XDG_RUNTIME_DIR}/kpa/ssh-agent"` (environment.d). That reaches
   niri and everything it starts, including tools that read
   `SSH_AUTH_SOCK` directly rather than `ssh_config`, such as `ssh-add`
   and libssh2-based git clients.
4. **Point everything else at kpa as a fallback.** Extend the macOS
   `Match` block in `home/ssh.nix` to saturn, with the same condition and
   `IdentityAgent /run/user/%i/kpa/ssh-agent`.
   - A forwarded agent that has keys wins: Strongbox, when logged in from a
     Mac.
   - Otherwise kpa answers. That is what lets `dfu` work in a Rex shell
     once `kpa unlock` has run there.
5. **Narrow `ForwardAgent yes` to where work happens.** That means rhea,
   plus saturn when coming from a Mac. The Pis and ranger are only ever
   destinations, never hops, so forwarding to them only widens what their
   root can reach.

**Day to day**

| Action                                          | What happens                                                                                                                                  |
| ----------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------- |
| `git push` at the desk, vault locked            | fuzzel asks "Unlock personal: key github for git@github.com", then the push goes through                                                     |
| `ssh rhea`, then `dfu` on rhea                  | Logging into rhea is local use. The pull from ranger is forwarded, and fuzzel on saturn asks once: rhea → ranger, key `home`, user `nathan`. "Allow for this session" covers the rest of that SSH session |
| VS Code Remote-SSH to rhea, then a GitHub fetch | The same, one confirmation per destination per VS Code connection                                                                            |
| From a Mac: `ssh saturn`, then `git pull`       | Strongbox, forwarded from the Mac. kpa is not involved                                                                                        |
| From a Mac via Rex: `dfu` on saturn             | No agent is forwarded, so kpa answers. If the vault is locked the request is refused without a prompt. `kpa unlock personal` in the Rex shell asks on the terminal |
| Screen locks (hypridle, after 5 minutes)        | kpa has locked everything. Nothing signs until the next unlock                                                                                |

**Notes**

- **hypridle runs `loginctl lock-session`**, so kpa sees the `Lock` signal.
  Nobody has checked whether hyprlock sets `LockedHint`. If it doesn't, a
  prompt raised while the screen is locked waits out its timeout (§ 5.8).
- **Prompts go through fuzzel**, which is already the unlock prompt.
  quickshell never renders tray menus, and mako's notification actions
  need an extra key binding, so neither can carry an approval.
- **Two dotfiles docs change with this.** `nix/docs/kpa-design.md` and
  `password-manager-stack.md` say KeePassXC keeps SSH.

## 8. Threat model changes

**§ 1 System**

- Adds the agent socket.
- "There is no operation that returns a secret to the caller" still holds:
  a signature is not the key.

**Assets**

- **A-2** gains SSH private keys held in attachments, and their passphrases.
- **A-6 (new) · Signing capability: a signature the user didn't intend.**
  It authenticates as the user elsewhere, or signs commits and files.
  Sensitivity: High.

**Actors**

- **ACT-11 (new) · A host the user forwards the agent to.** This means its
  root, or anything there that can reach the forwarded socket. In scope,
  for keys opted into forwarding.

**Boundaries**

- **TB-8 (new) · The agent socket.**
  - Same-uid clients reach it directly.
  - Remote hosts reach it through a forwarding channel the user opened.
  - Untrusted inputs: request bytes, session-bind contents, and the data to
    be signed.

**Goals**

- **G-3** gains: "SSH private keys never leave the process. Only
  signatures do, only on the agent socket, only for declared keys."
- **G-12 (new) · Signatures need an unlocked database and a declared key.**
  An on-demand unlock is a prompt the user answers.
- **G-13 (new) · Forwarded requests are refused unless the key opts in.**
  When it does:
  - they sign SSH logins only, for a session the destination has bound;
  - each (forwarding session, destination) is confirmed on this machine
    first.
- **G-14 (new) · The agent never accepts a key or a secret.** Add, remove,
  `LOCK` and `UNLOCK` all fail.
- **G-5** gains: "Signatures are not activity. A lock ends any prompt in
  flight."
- **G-11** extends to the agent socket.

**Threats**

- **T-2** is amended. Forwarding is the one path from the network. It is
  reached only through the user's own `ssh` client, and G-13 confines it.
- **T-18** is extended. While a database is unlocked, ACT-10 can sign with
  any of its declared keys for local use, unless the key has
  `confirm = "always"`. This is accepted, on the same terms as `copy`, and
  is less severe than `copy` because the key itself doesn't leave.
- **T-19 (new) · Forwarded-agent abuse** (S, E) — ACT-11 · TB-8 · A-6 → G-13.
  - Response: off by default, confirmation scoped to session and
    destination, SSH logins only.
  - In scope:
    - signing over a forwarded connection without a matching confirmation;
    - forwarded signing of non-login data;
    - a session-bind accepted without verification;
    - an approval reused across sessions or destinations.
  - Residual: during an approved session, the remote host can use the key
    for that destination; this is inherent to forwarding. Forwarding that
    bypasses the OpenSSH client looks local.
- **T-20 (new) · Malformed agent traffic** (D, T) — ACT-5, ACT-11 · TB-8 →
  G-11.
  - Covers frames, lengths, session-bind contents and the data to be signed.
  - Fuzzed like `decode_request`.
- **T-21 (new) · Key material in memory** (I) — ACT-7, ACT-11 · TB-7 ·
  A-2 → G-6.
  - Decrypted keys are cached only while unlocked, and zeroized on lock.
  - RSA timing (§ 5.5) keeps RSA out of forwarding.
- **T-22 (new) · Prompts on demand** (S) — ACT-10, ACT-11.
  - Anything that can reach the agent can raise an unlock or confirm
    prompt.
  - Response: the prompt names its reason, backoff after a cancel, one
    prompt at a time, timeouts, no prompts while locked or outside the
    desktop.
  - Residual: NG-7 (nuisance) and NG-8 (look-alike prompts).

## 9. Changes to existing docs

- **`design.md`**
  - § Scope: replace "an SSH agent" in **Is not**, and say kpa serves SSH
    keys under the same read-only rule.
  - § Architecture: add the agent socket.
  - § Lock policy: lock drops cached keys and kills open prompts.
  - Settled decisions: one row for "kpa is the agent, keys declared by
    public key".
- **`background.md`**: the "SSH agent" row of the gap table changes. A
  full client covers SSH, but only while it runs, and only by pushing keys
  into a separate agent.
- **`threat-model.md`**: § 8 above.
- **`config.example.toml`**: an `[ssh_agent]` section and one `[[ssh_key]]`
  against a fixture key.

## 10. Implementation

**Modules** (new `src/agent/`):

| File          | Role                                                                                                                                            |
| ------------- | ----------------------------------------------------------------------------------------------------------------------------------------------- |
| `wire.rs`     | Frame decode and encode into `enum AgentRequest` and `enum AgentResponse`. Pure, fuzzed                                                         |
| `bind.rs`     | session-bind verification and per-connection binding state                                                                                      |
| `classify.rs` | Data to be signed → `Purpose::{Login, SshSig, Other}`. Pure, fuzzed                                                                             |
| `policy.rs`   | (key settings, connection class, purpose, database state, prompt availability) → `Sign`, `Confirm`, `Unlock`, `Refuse(reason)`. Pure, with exhaustive tests like `policy::Policy` |
| `keys.rs`     | Attachment scan, public-key match, decryption, the per-`Slot` cache                                                                             |
| `serve.rs`    | Listener, per-connection thread, connection cap                                                                                                 |

**Server changes**

- `Slot` gains the key cache, cleared in `Slot::lock()`.
- A `SshSign` trait sits beside `CopyEntry`.
- Unlock waiters use a condvar.
- Lock kills open prompts.
- The prompt and confirm runner gains `{message}`, a timeout and the
  shared queue.
- `log_response` gains agent events: key name, purpose, connection class,
  destination fingerprint and decision. Like `list`, `REQUEST_IDENTITIES`
  is not logged.

**Tests**

- **Fixture**: `tests/fixture.sh` adds an entry with an ed25519 key
  attachment (`ssh-keygen -N ''`, `keepassxc-cli attachment-import`) and
  one with a passphrase-protected key.
- **`tests/agent.rs`** spawns `kpa serve` and drives it with the real
  OpenSSH tools:
  - `ssh-add -L` lists the key while the database is locked;
  - `ssh-keygen -Y sign` fails when the scripted prompt cancels, succeeds
    after unlock, and `ssh-keygen -Y verify` accepts the result;
  - a lock makes signing fail again;
  - `ssh-add <key>` and `ssh-add -D` fail.
- **Forwarding**: an unprivileged `sshd` on a high port with a temporary
  host key, then `ssh -A` to localhost. This covers session-bind for real:
  a forwarded login refused by default, allowed with a scripted confirm,
  and forwarded `SSHSIG` refused.
- **Fuzzing**: `fuzz_targets/agent_request.rs` covers `wire`, the
  session-bind parser and `classify`.

**Size**: roughly 1,000–1,300 lines of Rust plus tests. That is about as
much as kpa's existing code, so it warrants its own security-audit pass
once it lands.

**Phases**, each leaving a usable state:

1. **Local agent.**
   - Socket, identities, signing (Ed25519 and ECDSA), declared keys,
     lookup, cache, lock coupling.
   - session-bind parsing, with every forwarded request refused.
   - Logging, fixtures, fuzz target, threat-model and design edits.
   - The user unlocks from the launcher or tray first.
   - Enough to switch off KeePassXC's agent on Linux.
2. **Unlock on demand.**
   - `{message}`, timeouts, backoff, lock kills prompts.
   - Prompt routing (§ 5.8), unlock waiters.
   - Unlocking from a terminal (§ 5.10).
3. **Forwarding.**
   - `forwarding = "confirm"`, the confirm prompt, session approvals.
   - `known_hosts` names, the end-to-end `sshd` test.

Later, if needed: RSA once `rsa` is constant-time, read notifications
covering both `copy` and signatures (T-16), and an upstream agent relay
(approach C).

## 11. Open questions

1. **RSA keys.** Strongbox serves 2 RSA keys among its 5. Which hosts still
   need them? Migrating them to Ed25519 keeps the design as is. The other
   option is local-only RSA (§ 5.5).
2. **Idle.** Should signatures keep the vault unlocked? This proposal says
   no (§ 5.9). With hypridle locking the screen after 5 minutes, the idle
   timer rarely fires first anyway.
