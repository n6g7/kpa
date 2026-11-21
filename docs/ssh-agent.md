# kpa — SSH agent

kpa serves the SSH keys stored in its databases, replacing a KeePass
client's SSH agent integration. The client remains a vault editor if
wanted, but stops handling SSH. Linux only, like the rest of kpa: a machine without kpa keeps
its own KeePass client's agent over the same synced vault (§ 2).

[`design.md`](./design.md) § Scope covers it: kpa serves SSH keys under the
same read-only rule as everything else. Its claims are in
[`threat-model.md`](./threat-model.md) (A-6, ACT-11, TB-8, G-13 to G-15,
T-20 to T-23), and it builds on [`headless.md`](./headless.md) for prompt
routing, prompt timeouts and unlocking from a terminal.

## 1. Overview

- **kpa is the agent.** `kpa serve` listens on a second socket,
  `$XDG_RUNTIME_DIR/kpa/ssh-agent`, speaks the SSH agent protocol
  ([RFC 9987](https://www.rfc-editor.org/rfc/rfc9987.html)), and signs with
  keys read from unlocked databases. It never hands a key to another agent.
- **The agent is read-only.** It lists identities and signs. Every message
  that adds, removes, locks or unlocks gets `SSH_AGENT_FAILURE`.
- **Databases opt in, and kpa finds the keys.** A database with
  `serve_ssh_keys = true` has every OpenSSH private key among its entries'
  attachments served. kpa caches their public keys, and nothing else, so
  they are listed even while the database is locked. That is what makes
  unlock on demand work. Optional per-key settings under the database in
  config, matched by fingerprint, override the defaults.
- **Each key's first use for a given destination, after an unlock, is
  approved.** The approval holds until the database locks. When a
  signature has to unlock the database first, the unlock prompt names the
  key and destination, and the confirm prompt follows it. A key can
  instead ask on every use, or never.
- **Forwarded use is approved the same way, per forwarding session.** OpenSSH's
  `session-bind@openssh.com` tells kpa when a request arrives through
  `ssh -A`. The first forwarded signature per key, forwarding session,
  forwarding host and destination asks on this machine's screen. Over a
  forwarded connection kpa signs SSH logins only, never arbitrary data. A
  key can be kept off forwarding entirely.
- **No prompt where nobody can see it.** A request from outside the desktop
  (an SSH login, a terminal-server shell), or while the screen is locked,
  never raises a prompt on screen. If it only lacks an approval, kpa
  refuses it and remembers it, and `kpa ssh pending` and `kpa ssh approve`
  in that shell approve it. If its database is locked, `kpa unlock` asks for
  the password on the terminal.
- **Keys never leave kpa.** Only signatures do. A lock drops the key at
  once, and a crash leaves nothing behind in another process.
- **Ed25519, ECDSA and RSA**, through RustCrypto's `ssh-key` 0.7 and its
  constant-time `rsa` 0.10 (§ 6.5).

## 2. Use cases

What the agent has to serve, and what it leaves to something else.

**Served, with keys from the vault**

- SSH logins and git over SSH from the desktop: `ssh`, `git pull`,
  `git push`, an IDE's background fetch.
- The same commands from a session outside the desktop: an SSH login into
  this machine, or a terminal server's shell. A client-managed agent fails
  here. The client locks on its own, its GUI can't be reached from that
  session to unlock it, and the session usually doesn't even have the
  agent socket in its environment (§ 8).
- Headless hosts with no vault of their own. They borrow keys through agent
  forwarding (S3).

**Not served**

- **Keys outside the vault.** A key file on disk keeps working through
  `IdentityFile`: `ssh` reads it directly and needs no agent. A vault-only
  agent can't take such a key through `ssh-add`, so it can't forward it
  either. The same goes for a hardware token's keys and another agent's:
  kpa relays nothing to another agent.
- **Consumers of the key itself.** Some tools need the private key rather
  than a signature, such as converting an SSH key into an age identity to
  decrypt secrets. An agent never hands out keys. Such tools need their own
  key file.
- **GPG commit signing.** It goes through `gpg-agent`, which is a separate
  socket. SSH signing (`gpg.format = ssh`) is S2 and is served.
- **Other uids, root included.** `sudo` drops `SSH_AUTH_SOCK` by default,
  and the socket accepts only its own uid (T-1). So a build that runs as
  root and fetches over SSH gets no agent. An example is `sudo
  nixos-rebuild` evaluating a `git+ssh` flake input. Run the fetch as the
  user instead: `nixos-rebuild --sudo` evaluates and builds as the caller
  and elevates only to activate. A public repository fetched over HTTPS
  needs no agent at all.

**Machines without kpa.** kpa is Linux-only. A machine without it, such as
a macOS laptop, keeps the SSH agent of its own KeePass client over the same
synced vault, and kpa changes nothing there. So every machine with a screen
runs an agent backed by the vault, and headless hosts borrow one by
forwarding (§ 5). Such a machine also keeps its client's limits: a remote
shell into it gets keys only while the client is unlocked on that
machine's screen.

## 3. What kpa adds over a client-managed agent

- **One unlock and one lock policy** for passwords and keys, with or
  without a GUI client running.
- **Keys exist only while the database is unlocked.** No other process holds
  a copy that has to be removed on lock.
- **Unlock at first use** instead of before use.
- **Per-request policy.** kpa sees where each request comes from (local or
  forwarded, which destination, what is being signed). An agent that only
  receives keys at unlock time sees none of that.

## 4. Why kpa is the agent

KeePass clients push keys into an existing agent: on unlock they send each
key to `$SSH_AUTH_SOCK` with `SSH_AGENTC_ADD_ID_CONSTRAINED` (lifetime,
confirm), and on lock `SSH_AGENTC_REMOVE_IDENTITY`. kpa answers the agent
protocol itself instead:

|                        | Pushing keys into an agent                                                                     | kpa as the agent                                   |
| ---------------------- | ---------------------------------------------------------------------------------------------- | -------------------------------------------------- |
| Private key leaves kpa | Yes, into the agent's memory                                                                   | No, only signatures                                |
| Lock revokes the key   | Only if the `REMOVE` arrives. A crash or an agent restart leaves keys until their lifetime runs out | Always: a locked database has nothing to sign with |
| Use before unlock      | Impossible: the agent has no key yet                                                           | Unlock prompt at the first signature               |
| Sees each use          | No. Cannot log, approve by context, or apply per-request policy                                | Yes                                                |
| Local vs forwarded     | Only via destination constraints, fixed when the key is added                                  | Decided per request                                |
| Idle timer             | kpa cannot see SSH use, so the idle lock removes keys mid-session                              | kpa decides what counts as activity (§ 6.9)        |
| Crypto in kpa          | Parse the OpenSSH key file, which the agent needs in its own wire format                       | The same, plus calling `sign`                      |
| Compatible agents      | OpenSSH's `ssh-agent`. Not `gpg-agent`, which cannot remove added keys                         | Any agent-protocol client                          |

kpa implements no cryptography. Its agent code is protocol framing,
parsing and policy. Signatures come from RustCrypto's `ssh-key` (backed by
`ed25519-dalek`, `p256`, `p384`, `rsa`). Pushing keys would need the same
parse of the key file, so all it saves is the call to `sign`.

Passphrase-protected key files on disk, with OpenSSH's `ssh-agent` and
`AddKeysToAgent`, need no kpa at all and work in any session. But the keys
become a second store with its own passphrase, copied to each machine
separately and not tied to any lock. They remain the answer for keys that
can't live in the vault (§ 2).

## 5. Situations

The policy is a table over who asks and from where. "Prompt" always means a
prompt on this machine's screen, and "approval" is the one § 6.7 describes:
once per key and destination until lock by default.

| #   | Situation                                                    | Recognized by                                                           | Database locked                                                          | Database unlocked                                                                          |
| --- | ------------------------------------------------------------ | ----------------------------------------------------------------------- | ------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------ |
| S1  | At the desk: `ssh`, `git push`, an IDE                       | No binding, or an authentication binding from the local `ssh`           | Unlock prompt naming the key and destination, then the confirm prompt for a key that needs one | Sign if the key is approved for that destination. Otherwise a confirm prompt first                          |
| S2  | Commit or tag signing (`ssh-keygen -Y sign`)                 | `SSHSIG` data, no binding                                               | As S1                                                                    | As S1                                                                                      |
| S3  | `ssh -A` from here; the remote host uses the key | First binding has `is_forwarding` (§ 6.2)                               | Unlock prompt naming the forwarding host and destination, then the confirm prompt for the forwarding session | Sign if this forwarding session is approved for the key and destination. Otherwise a confirm prompt first. SSH logins only. A key with `forwarded = false` is neither listed nor used |
| S4  | Working on this machine from elsewhere, with no agent forwarded: an SSH login, a terminal-server shell | The requester runs outside the desktop (§ 6.8) | Refused, no prompt. `kpa unlock` in that shell asks on the terminal (§ 6.10) | Sign if approved for that destination. Otherwise refused and remembered; `kpa ssh pending` lists it and `kpa ssh approve <id>` approves it, and the retry signs (§ 6.8). An `ssh -A` started from that shell works the same way |
| S5  | Screen locked or machine suspended                           | logind (existing lock policy)                                           | Everything is already locked. No prompt                                  | Not possible: a screen lock locks every database                                           |
| S6  | Background jobs: user timers, IDE auto-fetch                 | Indistinguishable from S1. Jobs outside the user manager (cron, system services) fall under S4 | Unlock prompt, with backoff after a cancel (§ 6.6)    | As S1: one confirm prompt per key per destination per unlock, with backoff after a cancel |
| S7  | Sandboxed app, container                                     | No socket unless granted (T-15)                                         | —                                                                        | —                                                                                          |
| S8  | `ssh -A` from here to another machine that runs kpa          | As S3                                                                    | As S3                                                                   | As S3. On the remote, the forwarded agent answers for every key it lists, and the remote's own kpa answers for the rest (§ 8) |

**Why local use is approved once per destination per unlock.** Inside the
uid boundary a per-use approval is not a security boundary (NG-1). A
process that can talk to the agent can also wait for an unlock and `copy`
every password, and the threat model already accepts that while unlocked
(T-18). What an approval buys is visibility: the first use of each key for
each destination after each unlock shows on screen, so an unexpected one
stands out. Remembering it until lock keeps that to one prompt per key per
destination per unlock, not one per `git fetch`, which would train the
user to accept without reading. The precedents converge on remembering an
approval until lock: 1Password's default, Bitwarden's "remember until
lock" option, Strongbox's approval timeout. `confirm = "always"` asks on
every use, for a key whose every use should be visible (production root,
say). `confirm = "never"` skips the approval.

**Why forwarded use is scoped to the forwarding session.** The requester is
another machine: its root, or anything there that can reach the forwarded
socket. That is a real boundary, unlike the uid boundary above. The prompt
also appears on the screen of the person who typed `ssh -A`. Bitwarden
reportedly makes the same call, prompting for forwarded requests even when
approvals are otherwise off. An approval covers one forwarding session, so
a later `ssh -A` to the same host asks again rather than letting that
host's root sign silently for as long as the database stays unlocked.

The design favours **the agent lives where you sit**: the machine with the
screen runs the agent over the synced vault, and remote hops reach it by
forwarding. ProxyJump (`ssh -J`) is better still where it fits, because the
key never needs forwarding: each hop authenticates from the local `ssh`.

## 6. Mechanism

### 6.1 Socket and protocol

- **Socket**: `$XDG_RUNTIME_DIR/kpa/ssh-agent`, bound and checked exactly
  like the JSON socket (`socket::bind_socket`, `SO_PEERCRED`, T-1). It is
  inside the directory the systemd sandbox already allows. It has its own
  connection cap (64), separate from the JSON socket's, and within it at
  most 16 forwarded connections: one that a session-bind makes forwarded
  while 16 are open is closed. It exists only while at least one database
  has `serve_ssh_keys = true`.
- **Framing**: `uint32` length, then the message. Frames over 256 KiB
  (OpenSSH's `AGENT_MAX_LEN`) close the connection. Unlike the JSON socket,
  connections are long-lived and carry many requests: `ssh` holds one open
  while it talks to the server, and a forwarded channel can sit idle for
  hours. So there is no idle deadline between frames, but once a frame
  starts, the rest of it must arrive within 5 s.
- **Messages handled**:

  | Request                             | Response                                                                       |
  | ----------------------------------- | ------------------------------------------------------------------------------ |
  | `REQUEST_IDENTITIES` (11)           | `IDENTITIES_ANSWER` (12): the keys this connection may use (§ 6.4), comment = the key's name, plus a hint for a requester outside the desktop (§ 6.8) |
  | `SIGN_REQUEST` (13)                 | `SIGN_RESPONSE` (14), or `FAILURE` (5) per § 5                                 |
  | `EXTENSION` (27) `session-bind@openssh.com` | `SUCCESS` (6), or `EXTENSION_FAILURE` (28) if verification fails       |
  | `EXTENSION` (27) `query`            | The supported extensions                                                       |
  | Anything else: add, remove, remove-all, smartcard, `LOCK` (22), `UNLOCK` (23), other extensions | `FAILURE` (5) |

  `ssh-add -D` therefore does nothing, and `ssh-add -x`/`-X` do nothing
  either. Locking goes through `kpa lock`, and the agent socket never
  accepts a secret (§ 6.10).

### 6.2 Telling local from forwarded

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
- **Forwarded**: the first binding has `is_forwarding`. The forwarding
  host is that binding's host key, and the **forwarding session** is its
  session identifier. The destination is the last non-forwarding binding,
  if the remote `ssh` sent one.

A binding that fails verification but claims `is_forwarding` still marks
the connection forwarded. Failure always errs toward the strict side.

Limit: forwarding that bypasses the OpenSSH client looks local. That covers
an `ssh` older than 8.9, and tools that relay `SSH_AUTH_SOCK` themselves
(container runtimes, Eternal Terminal). nixpkgs ships a newer OpenSSH, so
this is a threat-model note, not a blocker.

### 6.3 What is being signed

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
  confirm prompt can say truthfully where the signature will be accepted.
  A remote `ssh` older than 8.9 therefore cannot use a forwarded key.
  Current distributions ship newer, so this rarely bites.
- **Local, bound**: an SSH login must match the last binding's session
  identifier.
- **Local, unbound**: any purpose. Git signing lives here.

### 6.4 Which keys

A database opts in with `serve_ssh_keys = true` (§ 7). When it unlocks, kpa
scans it:

1. Look at current entries only: no history, and nothing in the recycle bin.
2. Pick attachments whose bytes start with
   `-----BEGIN OPENSSH PRIVATE KEY-----`. Other formats (PEM PKCS#1 or
   PKCS#8) are skipped. `ssh-keygen -p -f <file>` rewrites one in OpenSSH
   format.
3. Parse each key file in full, to learn its type and public key, then
   drop the parsed key. Passphrase-protected keys are skipped too, since
   kpa has no passphrase to open them with. Each skipped attachment is
   logged at unlock with its reason.
4. Drop keys that one of the database's overrides marks `serve = false`.
   A key found in two opted-in databases is served from the first one in
   config order.

The private key is read again at its first signature and cached in the
database's `SshState` until lock.

**The key cache.** After each scan, kpa writes the database's public keys
to `$XDG_CACHE_HOME/kpa/ssh-keys/<database>`, where `<database>` is the
config name, mode 0600. The file holds public keys only: no entry titles
and no key comments, so G-4 holds as written. While a database is locked,
its keys are listed from this file.

- A key removed from the vault stays listed until the next unlock rewrites
  the file. Signing with it then fails.
- A key added to the vault is listed from the next unlock on.
- With no cache file yet, as on a fresh machine, a locked database lists
  nothing until its first unlock.
- Tampering with the file needs the user's uid. The most it does is list a
  key: signing still needs the private key from the vault.

**Names.** A key goes by its override's `name` if it has one. Otherwise it
is the entry's title while the database is unlocked, and `<database>
<fingerprint>` (`personal SHA256:3fQ…`) while it is locked, since the cache
holds no titles. Titles are escaped and length-capped like other entry
content (T-13). The name is the identity comment `ssh-add -l` shows, and
what prompts and logs use.

**Which keys a connection sees.** A local connection lists every served
key. A forwarded connection lists only keys with `forwarded = true`,
the default. So a remote host that also runs kpa uses its own agent for
the keys the desk keeps off forwarding (S8).

**Authorization lives in config, not in the vault.**

- **Config is trusted, vault content is not.** Config is ASM-3. Entry
  content is authored by ACT-4. A database's content decides which keys
  exist. Config decides whether that database is served at all, and every
  policy setting: approvals, forwarding, `serve = false`. No vault content
  can make a key forwardable or exempt from approval.
- **No XML parser.** Per-entry agent settings that KeePass clients store
  in the vault, such as a `KeeAgent.settings` attachment, are ignored. A
  key switched off for a client's agent is still served by kpa unless an
  override says `serve = false`.

`kpa ssh keys` prints each key found in the unlocked databases (database,
entry title, attachment name, type, fingerprint), the attachments it skipped
and why, and the databases it could not scan because they are locked.
`--database <name>` limits it to one database. It reads databases that have
not opted in too, which shows what opting in would serve. `--toml` prints
only a ready-to-paste override block per key, grouped under the database it
belongs in, so it can go straight into the config file.

kpa lists keys in config order, then entry order. With many keys, a server
can hit `MaxAuthTries`. The usual answer is `IdentitiesOnly yes` plus a
per-host `IdentityFile` that points at a `.pub` file, which `ssh-add -L`
can produce: `ssh` then offers only that agent key.

### 6.5 Key types and dependencies

- **Supported**: `ssh-ed25519`, `ecdsa-sha2-nistp256`,
  `ecdsa-sha2-nistp384`, and `ssh-rsa` keys of 2048 bits or more, which
  sign with `rsa-sha2-256` or `rsa-sha2-512` only. A request for a SHA-1
  `ssh-rsa` signature gets `FAILURE`. RSA keys follow the same policy as
  every other key, forwarding included.
- **Not supported**: `sk-*` (FIDO) keys, certificates, DSA, and private
  keys in PEM format or protected by a passphrase (§ 6.4).
- **Dependency**: `ssh-key` 0.7 with `ed25519`, `p256`, `p384`, and `rsa`.
  0.7 builds on `rsa` 0.10, the first release with constant-time
  private-key operations (RUSTSEC-2023-0071, the Marvin attack, is patched
  there), and on `sha2` 0.11, the version kpa already uses. 0.7 is still in
  release candidates: kpa pins the current one exactly (`=0.7.0-rc.N`) and
  bumps it deliberately. The SSH release waits for 0.7.0 itself.
- **Known limitation of 0.7.0-rc.12**: it can't read an
  `ecdsa-sha2-nistp256` private key whose scalar OpenSSH encoded in 31
  bytes, which about 1 generated key in 512 is
  ([RustCrypto/SSH#620](https://github.com/RustCrypto/SSH/issues/620),
  [#623](https://github.com/RustCrypto/SSH/issues/623); fixed upstream
  after rc.12). The scan skips such a key and logs it with the remedy:
  regenerate the key. The bump to 0.7.0 lifts the limitation.

### 6.6 Unlock on demand

A signature for a served key whose database is locked runs the normal
`unlock` path.

**When kpa prompts**

- Prompts must be allowed (§ 6.8). Otherwise the signature is refused, with
  no prompt.
- The database must not be in backoff.
- There is at most one prompt per database. A signature that needs a
  prompt takes the database's turn first, and concurrent signers wait for it
  instead of getting `unlock_in_progress`. Each looks again once the turn is
  its own, so it sees what the prompt before it got: an unlocked database,
  an approval, or a backoff. N identical requests for a key that needs an
  approval therefore show one confirm prompt.
- A signature that needs no prompt signs at once. It never waits for
  another signature's turn, and a requester who may not be asked is refused
  before it would wait.

A signature that needs both asks for them one after the other: the unlock,
and when it is answered, the approval (§ 6.7).

The unlock is the one `kpa unlock` runs: the same `prompt`, in the same
queue. A `kpa unlock` typed while a signature's unlock prompt is up gets
`unlock_in_progress`, as it does for any unlock already prompting.

**What the prompt says.** It asks to unlock, and says what for in the
confirm prompt's words (§ 6.7): "Unlock database personal to use key
"github" to log in as git?" for a connection with no binding, and "Unlock
database personal to use key "github" to log in to git@github.com?" for
one bound to a destination. A key without a `name` override is named
`<database> <fingerprint>` there, since the vault is locked and its entry
titles are unknown. Answering it approves nothing: the confirm prompt follows
it for a key that needs one (§ 6.7). `prompt` runs exactly as configured; kpa
sets `KPA_PROMPT_MESSAGE` in its environment instead, so a prompt program that
reads it — directly, or through a wrapper script — can show the reason:

```toml
prompt = ["sh", "-c", "exec fuzzel --dmenu --password --prompt \"$KPA_PROMPT_MESSAGE\""]
```

A wrapper puts the message right back into its own argv, so it's visible
to other uids via `/proc/<pid>/cmdline` either way. Only a program that
reads the variable itself avoids that.

**Timeouts and cancels.** Prompts time out after `prompt_timeout`, the
confirm prompt after `ssh_agent.confirm_prompt_timeout` if that is set,
and a lock kills an open prompt ([`headless.md`](./headless.md) § 6). On top of
that, cancelling or timing out an unlock or confirm prompt raised by a
signature puts that database in backoff for `ssh_agent.backoff` (default
2 minutes). A deny, a prompt that fails to run and a lock that ends the
prompt don't. Backoff only suppresses prompts: during it, a signature that
needs one fails at once, without prompting, which stops prompt storms from
loops, submodules and background fetches, and a signature that needs none
(the database is unlocked and the key already approved, or `confirm =
"never"`) still signs. Only time, or an unlock of the database, the user's
`kpa unlock` included, ends a backoff early; a lock does not. A `kpa
unlock` or `kpa ssh approve` typed by the user is never held back by it.

### 6.7 Approval

Two per-key settings decide when a signature needs approval:

- **`confirm`**, for local use:
  - `"once"` (default): the first signature with the key, for a given
    destination, after each unlock asks. The approval holds until the
    database locks.
  - `"always"`: every signature asks, forwarded ones included.
  - `"never"`: local signatures never ask.
- **`forwarded`**, for use through `ssh -A`:
  - `true` (default): the first signature per (key, forwarding session,
    forwarding host, destination) asks. The approval holds until the
    database locks; a later `ssh -A` session never reuses it. At most 64
    forwarded approvals are kept per database unlock, and past that the
    oldest is dropped. Forwarded use always needs an approval: `confirm =
    "never"` doesn't exempt it.
  - `false`: the key is neither listed nor used over a forwarded
    connection.

An unlock prompt raised by a signature is not an approval: when the key
needs one, the confirm prompt follows the unlock (§ 6.6).

**The confirm prompt.** `ssh_agent.confirm_prompt` is an argv with the same
contract as `prompt`, in dmenu style:

- kpa writes the choices, `Allow` and `Deny`, on stdin and reads the chosen
  line from stdout.
- A non-zero exit, or any other output, means deny.
- Any dmenu-style program works. Run it through `sh -c` so the message
  reaches its argv:

  ```toml
  confirm_prompt = ["sh", "-c", "exec fuzzel --dmenu --prompt \"$KPA_PROMPT_MESSAGE\""]
  ```

  A dialog-style program (`zenity`, `kdialog`) needs a wrapper script that
  prints `Allow` once the user confirms.
- It is required once any database has `serve_ssh_keys = true`. Without it,
  `kpa serve` refuses to start.

The message, delivered the same way `prompt`'s is (`KPA_PROMPT_MESSAGE`),
is one question, "Approve use of key (name) to (purpose)?":

| Request | Message |
| --- | --- |
| Login, no binding | `Approve use of key "github" to log in as git?` |
| Login, bound to a host `~/.ssh/known_hosts` names | `Approve use of key "github" to log in to git@github.com?` |
| Login, bound to any other host | `Approve use of key "github" to log in as git to host key SHA256:…?` |
| `SSHSIG` | `Approve use of key "github" to sign for namespace git?`, with `on github.com` or `on host key SHA256:…` after the namespace for a bound connection |
| Anything else | `Approve use of key "github"?`, with the same `on …` for a bound connection |
| Forwarded login, through a host `~/.ssh/known_hosts` names, to a host it names | `Approve use of key "github" on build-box to log in to git@github.com?` |
| Forwarded login, through a host it doesn't name | `Approve use of key "github" on host key SHA256:… to log in to git@github.com?`, the destination worded as above |

The destination is the connection's last binding's host key, named by the
host name `~/.ssh/known_hosts` has an unhashed entry for, else by its
fingerprint. On a forwarded connection the forwarding host, the first
binding's host key, is named the same way after the key, and the unlock
prompt (§ 6.6) says the same: `Unlock database personal to use key "github"
on build-box to log in to git@github.com?`. Every piece that comes from
outside kpa's own text (the key name, the database name, the remote user, the
namespace, the host name) passes through the escaping the CLI uses for
terminal output (T-13), with tab and newline escaped too so the message stays
one line, and gets its own length budget, so no piece can push the destination
past the prompt's cap. The key name's quotes are escaped, so a name can't end
its quotation and carry on the sentence.

Approvals live in memory only and are dropped on lock. A forwarded
approval is remembered under (key, forwarding session identifier,
forwarding host key, destination host key). The forwarding session is
bound by the local `ssh` before the remote side can send anything, so a
remote host cannot claim another session's approval.

Two `ssh -A` sessions through the same host look the same to the user, so
kpa numbers the forwarding sessions it sees after an unlock, 1, 2, … in the
order a grant or a pending request first refers to them, per database
(`kpa ssh pending` and `kpa ssh grants` show the number as SESSION). The
number is made up by kpa and never derived from the session identifier, which
is never shown, and it is no part of what an approval covers. kpa forgets a
session's number once no grant and no pending request refers to it, which
bounds the numbering by what they hold; a session that comes back after that
gets a new number, and a number is never used twice in an unlock. Nothing
tells kpa a session has ended, so an approval stays until the database locks
(§ 6.8, "Listing what is approved", shows when it last covered a signature).

Only one prompt is on screen at a time: unlock and confirm prompts share a
queue.

### 6.8 Where prompts may appear

Prompts follow [`headless.md`](./headless.md) § 3: no prompt for a
requester outside the desktop, or while the screen is known to be locked.
Two points are specific to the agent:

- **For a forwarded request the peer is the local `ssh`**, so the check is
  about where that `ssh` runs. `ssh -A` typed in a desktop terminal prompts
  here. The same command typed in an SSH login or a terminal-server shell
  does not.
- **User services such as timers and Syncthing count as desktop.** That is
  S6.

**Approving a refused request.** A request from outside the desktop that
needs an approval is refused, and kpa remembers it as pending:

- a random id, the approval it asks for (the key, the destination of a
  bound connection, the forwarding host of a forwarded one, and whether it
  is kept until lock), what the request
  was (the purpose, the connection class, the remote user or the
  namespace, the requester's command name), and the time it was last
  refused;
- at most 16 pending requests, identical ones merged (a repeat keeps its id
  and is kept another 5 minutes), each kept for 5 minutes by the wall clock
  (the one time it keeps is `refused_at`, so a clock set back keeps a
  request longer and one set forward expires it sooner), all dropped on
  lock.

`kpa ssh pending` lists them, one line each, with the id, and `kpa ssh
approve <id>` approves one. Neither needs a terminal: they send
`ssh_pending` and `ssh_approve`. A request nobody approves just expires
after 5 minutes; nothing is blocked meanwhile. One request `ssh_pending`
lists is its id, `refused_at` (when it was last refused, in Unix
seconds, from which a client works out the age), the `scope` the approval covers,
`remember`, which says whether approving grants the scope until lock
(`true`) or for one signature (`false`), and the `request` that was
refused:

```json
{
  "id": "6f1c0a52-3d8e-4c11-9a4b-0e5d2f7b8a31",
  "refused_at": 1700000000,
  "scope": {
    "key": {
      "db": "personal", "type": "ssh-ed25519", "fingerprint": "SHA256:…",
      "name": "github", "entry": "3f2a9c1e-5b7d-4e08-8a62-1d4c9b0e7f35",
      "title": "GitHub", "attachment": "id_ed25519"
    },
    "destination": "SHA256:…",
    "forwarding_host": "SHA256:…",
    "forwarding_session": 2
  },
  "remember": true,
  "request": { "purpose": "login", "user": "git", "class": "forwarded", "command": "ssh" }
}
```

`scope.key` is the object `ssh_keys` reports for a key, with the key's
`name` (its override's, else its entry's title) and its entry's `entry`
uuid. `destination` is there for a bound connection only, and
`forwarding_host`, the forwarding host's host key, and
`forwarding_session`, the number of its forwarding session (§ 6.7), for a
forwarded one (`kpa ssh pending` shows them as FORWARDING HOST and SESSION; the
forwarding session identifier itself is never shown). `request.user`
for a login and `request.namespace` for an `SSHSIG`. Titles, names, users
and command names reach the caller of this request, and never the
daemon's log.

A request is named by its id, which is random: it never comes back after a
lock, so an id from before one can't approve some other request, and it
says nothing of the scope the approval covers, so a forwarded request's
larger scope needs no change to `ssh_approve`. Approving an id grants the
approval its request asked for, and answers every request pending for the
same scope.

An approval it grants is the same as one granted on screen, with the same
scope. For a key with `confirm = "once"` it holds until lock. For a key
with `confirm = "always"`, it covers one signature: the retry. The retry is
a separate request that comes later, so the approval waits for it for
`ssh_agent.retry_window` (default 1 minute), and is gone once the
signature is made, or the window has passed, or the database locks. A
signature that fails leaves it for the next try. The user then retries the
command, and it signs. A forwarded request's approval is scoped to its
forwarding session, so the retry has to run in the same `ssh -A` session.
Approving doesn't unlock: a refusal caused by a locked database is
answered with `kpa unlock`.

A one-signature approval is not tied to the process that was refused: it is
spent by whichever request for the same key and destination arrives first
within the window. Any same-uid process could ask for it, and could as
well have approved on screen, so this is the uid boundary again (NG-1,
T-18), and the window keeps it short.

`ssh_pending` and `ssh_approve` are on the JSON socket, which forwarding
never reaches, so a forwarded host cannot approve its own requests. Any
same-uid process can send them, with or without a terminal, which is the
same as approving on screen within the uid boundary (NG-1, T-18): that a
person types at a terminal is not what the approval rests on.

**The hint.** The agent protocol's `FAILURE` carries no text, but `ssh`
prints the key's comment when the agent refuses: `signing failed for
ED25519 "github" from agent: agent refused operation`. So when the
requester runs outside the desktop, kpa puts the remedy in the comment it
lists:

- an unapproved key: `github (needs approval: kpa ssh pending)`;
- a key from a locked database: `personal SHA256:3fQ… (locked: kpa unlock
  personal)`.

Each is the refusal the sign flow itself would give the key there. A key
that needs neither gets no hint, and neither does a key listed to a
forwarded connection, whose requester can't run either command. The hint
follows the key's name, which is escaped and capped, so a hostile name
can't hide it or drive the terminal.

kpa also logs each refusal.

**Listing what is approved.** `kpa ssh grants` lists the approvals now in
force, without changing any: `ssh_grants` reads them, is never logged, and
needs no terminal. Like every request on the JSON socket it is for the same
uid (NG-1). Each grant, oldest first within its database, is:

- `granted_at`, in Unix seconds, from which a client works out the age;
- `scope`: the `scope` `ssh_pending` shows, with the key, the
  destination of a bound connection, and the forwarding host and the
  forwarding session number of a forwarded one;
- `remember`: `true` for an approval kept until lock, `false` for one that
  covers a single signature, which also has `expires_in`, the seconds its
  retry window still has;
- `by`: `on_screen` for an `Allow` on the confirm prompt, `cli` for
  `kpa ssh approve`;
- `uses`, the signatures it has covered. A signature counts once it is
  made. The signature the user allowed on screen counts as the first. A
  one-signature approval is gone with its signature, so it always lists
  `0`;
- `last_used_at`, in Unix seconds, when it last covered a signature, absent
  if it never has. A one-signature approval never has one. A user who sees a
  forwarding session's approval go unused knows the session is over, which
  kpa itself cannot see;
- `idle_lock_in`, the seconds before its database locks for being idle, if
  nothing uses it. A forwarded signature never counts as use (§ 6.9).

```json
{
  "granted_at": 1700000000,
  "scope": {
    "key": { "db": "personal", "…": "…" },
    "destination": "SHA256:…",
    "forwarding_host": "SHA256:…",
    "forwarding_session": 2
  },
  "remember": true,
  "by": "on_screen",
  "uses": 3,
  "last_used_at": 1700000060,
  "idle_lock_in": 1740
}
```

The table's columns are KEY, DATABASE, DESTINATION, FORWARDING HOST, SESSION,
LASTS (`until lock`, or `1 signature, 42s left`), AGE, GRANTED BY (`screen`
or `cli`), USES, LAST USED (an age, `-` if never) and IDLE LOCK. A locked
database lists nothing, since a lock drops its approvals. There is no way to revoke one: `kpa lock
<database>` drops a database's.

### 6.9 Lock and idle

- **Lock** drops the private-key cache and every approval with the
  database, and zeroizes the cache. As for unlock, it ends what is in
  flight for the database: a confirm prompt on screen is killed, and a
  signature whose database locked after it was decided is not made.
- **Freshness.** The freshness guard runs before each signature, as it does
  for `copy` (G-8).
- **Local signatures are activity; forwarded ones never are.** A
  successful local signature resets its database's idle timer, like a
  `list` or `copy`. A forwarded signature doesn't, so a remote host's root
  cannot keep the vault unlocked by signing. Refused signatures never
  count.
- **The cost of counting local signatures.** Local automation (an IDE's
  auto-fetch, a timer pulling over SSH) keeps an approved database
  unlocked for as long as it runs. On the desk, the screen lock still
  locks everything. Outside the desktop the idle timer is the only lock
  trigger, so local automation there keeps the database unlocked.

### 6.10 Unlocking from a terminal

S4 unlocks with `kpa unlock` on the terminal, as
[`headless.md`](./headless.md) § 4 describes: `kpa unlock` passes its
terminal along with the request, and the daemon asks for the password on it,
so the password never crosses the socket or passes through the CLI. The
usual case is an SSH login or a terminal-server shell into the machine that
runs kpa, with no agent forwarded, used to pull a git repository over SSH.

The agent socket takes no terminal. A signature's unlock on demand (§ 6.6)
asks on screen, where § 6.8 allows a prompt, and nowhere else.

Nor does the agent socket take a password: agent `UNLOCK` (`ssh-add -X`)
fails. The socket is reachable from forwarded hosts, so any forwarding kpa
failed to recognize would make it a remote password-guessing oracle.

## 7. Configuration

**Settings**

| Setting | Where | Default | Meaning |
| --- | --- | --- | --- |
| `serve_ssh_keys` | `[[database]]` | `false` | Serve this database's SSH keys (§ 6.4) |
| `socket` | `[ssh_agent]` | `$XDG_RUNTIME_DIR/kpa/ssh-agent` | The agent socket |
| `confirm_prompt` | `[ssh_agent]` | none; required once a database opts in | The approval program, dmenu style (§ 6.7) |
| `confirm_prompt_timeout` | `[ssh_agent]` | `prompt_timeout` | How long the confirm prompt may stay open unanswered before it is killed and the signature refused |
| `backoff` | `[ssh_agent]` | `"2m"` | How long a cancelled prompt holds back prompts for its database (§ 6.6) |
| `retry_window` | `[ssh_agent]` | `"1m"` | How long an approval of a `confirm = "always"` key from `ssh_approve` stays usable for the retry (§ 6.8) |
| `fingerprint` | `[[database.ssh_key]]` | required | Which key the override is for, as `ssh-add -l` and `kpa ssh keys` print it |
| `name` | `[[database.ssh_key]]` | the entry's title | Identity comment, shown in prompts and logs |
| `confirm` | `[[database.ssh_key]]` | `"once"` | Local approval: `"once"`, `"always"` or `"never"` (§ 6.7) |
| `forwarded` | `[[database.ssh_key]]` | `true` | Usable through `ssh -A`, with approval (§ 6.7) |
| `serve` | `[[database.ssh_key]]` | `true` | `false` keeps the key out of the agent entirely |

Overrides sit under the database that holds the key, and a fingerprint is
matched within that database only. An override that matches no key found
there is a warning in the log, not an error: the database may not have
been unlocked on this machine yet. Overrides under a database without
`serve_ssh_keys = true` are a config error.

**Example.** Two databases, one of them serving SSH keys. Most keys need no
override; the two below are the exceptions.

```toml
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
  fingerprint = "SHA256:Jk2rVx…"
  name = "prod-root"
  confirm = "always"
  forwarded = false

  # An old key that is kept in the vault but no longer used.
  [[database.ssh_key]]
  fingerprint = "SHA256:9aQwLm…"
  serve = false

[[database]]
name = "work"
path = "~/vaults/work.kdbx"
# No `serve_ssh_keys`: this database's keys are never served.
```

A `[[database.ssh_key]]` table belongs to the `[[database]]` above it; the
indentation is only for the reader.

With this config:

- every other key in `personal` is listed as soon as kpa has seen it once,
  asks for approval at its first use after each unlock, and can be used
  through `ssh -A` with an approval per forwarding session;
- `prod-root` asks on every signature and is invisible to forwarded hosts;
- nothing in `work` is served, even while it is unlocked.

The home-manager module has `services.kpa.sshAgent.enable`, which wires
the agent into the session (§ 8). Databases and keys stay in
`services.kpa.settings`:

```nix
services.kpa = {
  enable = true;
  sshAgent.enable = true;
  settings = {
    prompt = [ "sh" "-c" ''exec fuzzel --dmenu --password --prompt "$KPA_PROMPT_MESSAGE"'' ];
    ssh_agent.confirm_prompt = [ "sh" "-c" ''exec fuzzel --dmenu --prompt "$KPA_PROMPT_MESSAGE"'' ];
    database = [
      {
        name = "personal";
        path = "/home/you/vaults/personal.kdbx";
        serve_ssh_keys = true;
        ssh_key = [
          { fingerprint = "SHA256:Jk2rVx…"; name = "prod-root"; confirm = "always"; forwarded = false; }
          { fingerprint = "SHA256:9aQwLm…"; serve = false; }
        ];
      }
      { name = "work"; path = "/home/you/vaults/work.kdbx"; }
    ];
  };
};
```

## 8. Wiring a desktop

The setup kpa replaces, on a typical NixOS desktop with a KeePass client:

- **gcr-ssh-agent owns `SSH_AUTH_SOCK`.** Some NixOS desktop modules
  enable gnome-keyring by default, and it brings gcr-ssh-agent with it.
  Its socket unit puts `SSH_AUTH_SOCK=$XDG_RUNTIME_DIR/gcr/ssh` into the
  systemd user manager's environment, which the graphical session
  inherits.
- **The KeePass client feeds it.** With its SSH agent integration on, the
  client adds its keys to whatever `SSH_AUTH_SOCK` points at when a
  database unlocks, and removes them on lock. It is a client of the agent,
  not the agent.
- **Sessions outside the desktop get nothing.** An SSH login or a
  terminal-server shell doesn't read the user manager's environment, so
  `SSH_AUTH_SOCK` is unset there. Even with it set, the agent is empty
  whenever the client is locked, and the client can't be unlocked without
  its GUI.

**Steps**

1. **Run kpa and opt the databases in** with `serve_ssh_keys = true`. Add a
   `[[database.ssh_key]]` override for a key that must stay off forwarding
   (`forwarded = false`) or that needs a different approval policy.
   `kpa ssh keys --toml` prints the blocks to paste.
2. **Turn off what kpa replaces.**
   - Set `services.gnome.gcr-ssh-agent.enable = false`. gnome-keyring keeps
     its Secret Service role.
   - Turn off the KeePass client's SSH agent integration.
   - gcr injects its own `SSH_AUTH_SOCK` value into the user manager, and
     it would win over step 3.
3. **Point the desktop at kpa.** `services.kpa.sshAgent.enable` sets
   `systemd.user.sessionVariables.SSH_AUTH_SOCK =
   "\${XDG_RUNTIME_DIR}/kpa/ssh-agent"` (environment.d). That reaches the
   compositor and everything it starts, including tools that read
   `SSH_AUTH_SOCK` directly rather than `ssh_config`, such as `ssh-add`
   and libssh2-based git clients.
4. **Point sessions outside the desktop at kpa.** environment.d doesn't
   reach them, so the same option adds two fallbacks:
   - An `ssh_config` block,
     `Match host * exec "test -z '$SSH_AUTH_SOCK' || ! ssh-add -l >/dev/null 2>&1"`
     with `IdentityAgent /run/user/%i/kpa/ssh-agent`, which doesn't depend
     on `XDG_RUNTIME_DIR` being set in that session. A forwarded
     agent that lists keys wins: someone logging in with `ssh -A` from a
     laptop keeps using the laptop's agent. Otherwise kpa answers. When
     the laptop runs kpa too, its forwarded agent lists only the keys it
     allows forwarding, so this machine's kpa still answers when it lists
     none (S8).
   - In login shells, `SSH_AUTH_SOCK` defaults to kpa's socket when it is
     unset, for tools that don't read `ssh_config`. A forwarded agent's
     socket, set by `sshd`, is left alone.
   - kpa itself has to be running there. The module installs it under
     `default.target`, so it runs whenever the user manager does. A
     machine reached only from outside the desktop needs a user manager
     before anyone logs in graphically: either the remote session opens a
     logind session, or lingering is enabled.
5. **Narrow `ForwardAgent yes` to the hosts you work from.** A host that is
   only ever a destination, never a hop, gains nothing from forwarding,
   and its root can reach the forwarded socket.

The module documents steps 2 and 5 but doesn't do them: they change other
programs' settings.

**Day to day**

| Action                                                     | What happens                                                                                                                                         |
| ---------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------- |
| `git push` at the desk, vault locked                       | The unlock prompt asks "Unlock database personal to use key "github" to log in to git@github.com?", then a confirm prompt asks for the key. Once approved, the destination doesn't ask until lock    |
| `git push` at the desk, vault unlocked, key not yet used   | A confirm prompt names the key and destination. Later uses of that destination don't ask until lock                                                |
| `ssh -A` to a headless host, then `git pull` there         | The login is local use. The pull is forwarded, and the desktop asks once, naming the host, the destination, the key and the remote user. The approval covers the rest of that SSH session |
| IDE remote session to a headless host, then a fetch        | The same: one approval per destination per connection                                                                                                |
| From a laptop: `ssh -A` into the desktop, then `git pull`  | The laptop's forwarded agent answers. kpa on the desktop is not involved                                                                             |
| From elsewhere, a terminal-server shell on the desktop: `git pull` | No agent is forwarded, so kpa answers. If the vault is locked, the request is refused and `ssh`'s error names `kpa unlock personal`. If the key isn't approved yet, the error names `kpa ssh pending`; run it, approve the request it lists with `kpa ssh approve <id>`, then retry |
| Screen locks                                               | kpa has locked everything. Nothing signs until the next unlock                                                                                       |

**Notes**

- **Screen lockers.** kpa sees the `Lock` signal when the idle daemon runs
  `loginctl lock-session`. Some lockers don't set `LockedHint`. With one of
  those, a prompt raised while the screen is locked waits out its timeout
  ([`headless.md`](./headless.md) § 6).
- **The approval program has to return a choice.** Tray menus and
  notification actions only work where the desktop renders them, so a
  dmenu-style program is the portable choice.
