# kpa — SSH agent (proposal)

kpa serves the SSH keys stored in its databases, replacing a KeePass
client's SSH agent integration. The client remains a vault editor if
wanted, but stops handling SSH. Linux only, like the rest of kpa: a machine without kpa keeps
its own KeePass client's agent over the same synced vault (§ 2).

This is a proposal: nothing here is built. It reverses one line of
[`design.md`](./design.md) § Scope ("Is not: … an SSH agent") and extends
[`threat-model.md`](./threat-model.md); § 10 lists those edits. It builds
on [`headless.md`](./headless.md) for prompt routing, prompt timeouts and
unlocking from a terminal.

## 1. Recommendation

- **kpa is the agent.** `kpa serve` listens on a second socket,
  `$XDG_RUNTIME_DIR/kpa/ssh-agent`, speaks the SSH agent protocol
  ([RFC 9987](https://www.rfc-editor.org/rfc/rfc9987.html)), and signs with
  keys read from unlocked databases. It never hands a key to another agent.
- **The agent is read-only.** It lists identities and signs. Every message
  that adds, removes, locks or unlocks gets `SSH_AGENT_FAILURE`.
- **Databases opt in, and kpa finds the keys.** A database with
  `ssh_agent = true` has every OpenSSH private key among its entries'
  attachments served. kpa caches their public keys, and nothing else, so
  they are listed even while the database is locked. That is what makes
  unlock on demand work. Optional per-key settings under the database in
  config, matched by fingerprint, override the defaults.
- **Each key's first use after an unlock is approved.** The approval holds
  until the database locks. When a signature has to unlock the database
  first, the unlock prompt names the key and counts as its approval. A key
  can instead ask on every use, or never.
- **Forwarded use is approved the same way, per forwarding session.** OpenSSH's
  `session-bind@openssh.com` tells kpa when a request arrives through
  `ssh -A`. The first forwarded signature per key, forwarding session,
  forwarding host and destination asks on this machine's screen. Over a
  forwarded connection kpa signs SSH logins only, never arbitrary data. A
  key can be kept off forwarding entirely.
- **No prompt where nobody can see it.** A request from outside the desktop
  (an SSH login, a terminal-server shell), or while the screen is locked,
  never raises a prompt on screen. If it only lacks an approval, kpa
  refuses it and remembers it, and `kpa ssh approve` in that shell approves
  it from the terminal. If its database is locked, `kpa unlock` asks for
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
  either. Hardware tokens and other agents' keys sharing one socket is what
  approach C (§ 4) would add.
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

## 4. Approaches

**A. Push keys into an existing agent**, as KeePass clients do. On unlock, kpa
parses each key and sends it to `$SSH_AUTH_SOCK` with
`SSH_AGENTC_ADD_ID_CONSTRAINED` (lifetime, confirm). On lock it sends
`SSH_AGENTC_REMOVE_IDENTITY`.

**B. kpa is the agent** ← recommended.

**C. kpa in front of another agent.** kpa answers for its own keys and relays
everything else to an upstream agent. This only matters if keys from
outside the vault (a hardware token, say) must share one `SSH_AUTH_SOCK`.
Deferred, and nothing in B prevents adding it later.

**D. Leave the vault out.** Passphrase-protected key files on disk, with
OpenSSH's `ssh-agent` and `AddKeysToAgent`. It needs no kpa code and works
in any session. But the keys become a second store with its own
passphrase, copied to each machine separately and not tied to any lock.
Rejected. It stays the answer for keys that can't live in the vault (§ 2).

|                             | A: push into an agent                                                                                                                        | B: kpa is the agent                                       |
| --------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------- |
| Private key leaves kpa      | Yes, into the agent's memory                                                                                                                 | No, only signatures                                       |
| Lock revokes the key        | Only if the `REMOVE` arrives. A crash or an agent restart leaves keys until their lifetime runs out                                          | Always: a locked database has nothing to sign with        |
| Use before unlock           | Impossible: the agent has no key yet                                                                                                         | Unlock prompt at the first signature                      |
| Sees each use               | No. Cannot log, approve by context, or apply per-request policy                                                                              | Yes                                                       |
| Local vs forwarded          | Only via destination constraints, fixed when the key is added                                                                                | Decided per request                                       |
| Idle timer                  | kpa cannot see SSH use, so the idle lock removes keys mid-session                                                                            | kpa decides what counts as activity (§ 6.9)               |
| Crypto in kpa               | Parse and decrypt the OpenSSH key file, which the agent needs in its own wire format                                                         | The same, plus calling `sign`                             |
| Compatible agents           | OpenSSH's `ssh-agent`. Not `gpg-agent`, which cannot remove added keys                                                                       | Any agent-protocol client                                 |

The "Write UI, not crypto" rule in [`background.md`](./background.md) still
holds under B. The new code is protocol framing, parsing and policy.
Signatures come from RustCrypto's `ssh-key` (backed by `ed25519-dalek`,
`p256`, `p384`, `rsa`), and kpa implements no primitives. Both A and B have
to parse and decrypt the key file, so all A saves is the call to `sign`.

## 5. Situations

The policy is a table over who asks and from where. "Prompt" always means a
prompt on this machine's screen, and "approval" is the one § 6.7 describes:
once per key until lock by default.

| #   | Situation                                                    | Recognized by                                                           | Database locked                                                          | Database unlocked                                                                          |
| --- | ------------------------------------------------------------ | ----------------------------------------------------------------------- | ------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------ |
| S1  | At the desk: `ssh`, `git push`, an IDE                       | No binding, or an authentication binding from the local `ssh`           | Unlock prompt naming the key and destination. Answering it approves the key | Sign if the key is approved. Otherwise an approval prompt first                          |
| S2  | Commit or tag signing (`ssh-keygen -Y sign`)                 | `SSHSIG` data, no binding                                               | As S1                                                                    | As S1                                                                                      |
| S3  | `ssh -A` from here; the remote host uses the key             | First binding has `is_forwarding` (§ 6.2)                               | Unlock prompt naming the forwarding host and destination. Answering it approves the forwarding session | Sign if this forwarding session is approved for the key and destination. Otherwise an approval prompt first. SSH logins only. A key with `forwarded = false` is neither listed nor used |
| S4  | Working on this machine from elsewhere, with no agent forwarded: an SSH login, a terminal-server shell | The requester runs outside the desktop (§ 6.8) | Refused, no prompt. `kpa unlock` in that shell asks on the terminal (§ 6.10) | Sign if approved. Otherwise refused and remembered; `kpa ssh approve` in that shell approves it, and the retry signs (§ 6.8). An `ssh -A` started from that shell works the same way |
| S5  | Screen locked or machine suspended                           | logind (existing lock policy)                                           | Everything is already locked. No prompt                                  | Not possible: a screen lock locks every database                                           |
| S6  | Background jobs: user timers, IDE auto-fetch                 | Indistinguishable from S1. Jobs outside the user manager (cron, system services) fall under S4 | Unlock prompt, with backoff after a cancel (§ 6.6)    | As S1: one approval prompt per key per unlock, with backoff after a cancel                 |
| S7  | Sandboxed app, container                                     | No socket unless granted (T-15)                                         | —                                                                        | —                                                                                          |
| S8  | `ssh -A` from here to another machine that runs kpa          | As S3                                                                    | As S3                                                                   | As S3. On the remote, the forwarded agent answers for every key it lists, and the remote's own kpa answers for the rest (§ 8) |

**Why local use is approved once per unlock.** Inside the uid boundary a
per-use approval is not a security boundary (NG-1). A process that can
talk to the agent can also wait for an unlock and `copy` every password,
and the threat model already accepts that while unlocked (T-18). What an
approval buys is visibility: the first use of each key after each unlock
shows on screen, so an unexpected one stands out. Remembering it until
lock keeps that to one prompt per key per unlock, not one per `git fetch`,
which would train the user to accept without reading. The precedents
converge on remembering an approval until lock: 1Password's default,
Bitwarden's "remember until lock" option, Strongbox's approval timeout.
`confirm = "always"` asks on every use, for a key whose every use should be
visible (production root, say). `confirm = "never"` skips the approval.

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
  connection cap, separate from the JSON socket's. It exists only while at
  least one database has `ssh_agent = true`.
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
  approval prompt can say truthfully where the signature will be accepted.
  A remote `ssh` older than 8.9 therefore cannot use a forwarded key.
  Current distributions ship newer, so this rarely bites.
- **Local, bound**: an SSH login must match the last binding's session
  identifier.
- **Local, unbound**: any purpose. Git signing lives here.

### 6.4 Which keys

A database opts in with `ssh_agent = true` (§ 7). When it unlocks, kpa
scans it:

1. Look at current entries only: no history, and nothing in the recycle bin.
2. Pick attachments whose bytes start with
   `-----BEGIN OPENSSH PRIVATE KEY-----`. Other formats (PEM PKCS#1 or
   PKCS#8) are skipped. `ssh-keygen -p -f <file>` rewrites one in OpenSSH
   format.
3. Read each key's public key from the file's header, which is stored
   unencrypted. Nothing is decrypted yet.
4. Drop keys that one of the database's overrides marks `serve = false`.
   A key found in two opted-in databases is served from the first one in
   config order.

The private key is decrypted at its first signature. An encrypted key's
passphrase is the entry's Password field, the convention KeePass clients
already use. The decrypted key is cached in the database's `Slot` until lock. Each
decryption runs bcrypt-pbkdf, so it happens outside the vault mutex, under
the same epoch check as unlock.

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

`kpa ssh keys <database>` prints each key found in an unlocked database
(type, fingerprint, entry title) with a ready-to-paste override block, and
lists the attachments it skipped and why.

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
  keys in PEM format (§ 6.4).
- **Dependency**: `ssh-key` 0.7 with `ed25519`, `p256`, `p384`, `rsa` and
  `encryption` (bcrypt-pbkdf with aes256-ctr, OpenSSH's default for key
  files). 0.7 builds on `rsa` 0.10, the first release with constant-time
  private-key operations (RUSTSEC-2023-0071, the Marvin attack, is patched
  there), and on `sha2` 0.11, the version kpa already uses. 0.7 is still in
  release candidates: kpa pins the current one exactly (`=0.7.0-rc.N`) and
  bumps it deliberately. The SSH release waits for 0.7.0 itself.

### 6.6 Unlock on demand

A signature for a served key whose database is locked runs the normal
`unlock` path.

**When kpa prompts**

- Prompts must be allowed (§ 6.8).
- The database must not be in backoff.
- There is at most one prompt per database. Concurrent signers wait on the
  in-flight unlock instead of getting `unlock_in_progress`.

**What the prompt says.** It names its reason, for example "Unlock
personal: key github for git@github.com". Answering it approves that key
(§ 6.7), and for a forwarded request, that forwarding session and
destination. Today `prompt` runs exactly as configured, so the prompt can't
even say which database it is for. A `{message}` placeholder in the argv
fixes that for every unlock:

```toml
prompt = ["fuzzel", "--dmenu", "--password", "--prompt", "{message}"]
```

The message is always passed as an option's value, never as a positional
argument.

**Timeouts and cancels.** Prompts time out after `prompt_timeout`, and a
lock kills an open prompt ([`headless.md`](./headless.md) § 6). On top of
that, cancelling or timing out an unlock or approval prompt raised by a
signature puts that database in backoff for `ssh_agent.backoff` (default
2 minutes). Signatures from it then fail at once without prompting, which
stops prompt storms from loops, submodules and background fetches. A
`kpa unlock` or `kpa ssh approve` typed by the user is never held back by
it.

### 6.7 Approval

Two per-key settings decide when a signature needs approval:

- **`confirm`**, for local use:
  - `"once"` (default): the first signature with the key after each unlock
    asks. The approval holds until the database locks.
  - `"always"`: every signature asks, forwarded ones included.
  - `"never"`: local signatures never ask.
- **`forwarded`**, for use through `ssh -A`:
  - `true` (default): the first signature per (key, forwarding session,
    forwarding host, destination) asks. The approval holds until the
    database locks or the forwarding session ends, whichever comes first.
    Forwarded use always needs an approval: `confirm = "never"` doesn't
    exempt it.
  - `false`: the key is neither listed nor used over a forwarded
    connection.

An unlock prompt raised by a signature counts as that signature's approval
(§ 6.6).

**The approval prompt.** `ssh_agent.confirm` is an argv with the same
contract as `prompt`, in dmenu style:

- kpa writes the choices, `Allow` and `Deny`, on stdin and reads the chosen
  line from stdout.
- A non-zero exit, or any other output, means deny.
- `fuzzel --dmenu` works as is.
- It is required once any database has `ssh_agent = true`. Without it,
  `kpa serve` refuses to start.

The message carries:

- the key name and purpose;
- for a forwarded request, the forwarding host and the destination, by
  host-key fingerprint, plus the host name when `~/.ssh/known_hosts` has
  an unhashed entry for it;
- the remote user name from the login request.

Request-derived text passes through the same escaping the CLI uses for
terminal output (T-13) and is length-capped.

Approvals live in memory only and are dropped on lock. A forwarded
approval is remembered under (key, forwarding session identifier,
forwarding host key, destination host key). The forwarding session is
bound by the local `ssh` before the remote side can send anything, so a
remote host cannot claim another session's approval.

Only one prompt is on screen at a time: unlock and approval prompts share a
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

**Approving from a terminal.** A request from outside the desktop that
needs an approval is refused, and kpa remembers it as pending:

- the key, the purpose, the connection class, the forwarding host and
  destination, the remote user, the requester's command name, and the
  time;
- at most 16 pending requests, identical ones merged, each kept for
  5 minutes, all dropped on lock.

`kpa ssh approve` lists the pending requests on its terminal and asks
about each one: allow or deny. It reads the answers from its controlling
terminal, as terminal unlock does, so it needs one. An approval it grants
is the same as one granted on screen, with the same scope. For a key with
`confirm = "always"`, it covers one signature: the retry. The user then
retries the command, and it signs. A forwarded request's approval is
scoped to its forwarding session, so the retry has to run in the same
`ssh -A` session. `kpa ssh approve` doesn't unlock: a refusal caused by a
locked database is answered with `kpa unlock`.

`kpa ssh approve` talks to the JSON socket, which forwarding never reaches,
so a forwarded host cannot approve its own requests. Any same-uid process
can run it, which is the same as approving on screen within the uid
boundary (NG-1, T-18).

**The hint.** The agent protocol's `FAILURE` carries no text, but `ssh`
prints the key's comment when the agent refuses: `signing failed for
ED25519 "github" from agent: agent refused operation`. So when the
requester runs outside the desktop, kpa puts the remedy in the comment it
lists:

- an unapproved key: `github (needs approval: kpa ssh approve)`;
- a key from a locked database: `personal SHA256:3fQ… (locked: kpa unlock
  personal)`.

kpa also logs each refusal.

### 6.9 Lock and idle

- **Lock** drops the decrypted-key cache and every approval with the
  database. It zeroizes the cache and follows the same epoch rules as
  unlock.
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
[`headless.md`](./headless.md) § 4 describes. The usual case is an SSH
login or a terminal-server shell into the machine that runs kpa, with no
agent forwarded, used to pull a git repository over SSH.

The agent adds one rejected alternative: **agent `UNLOCK`
(`ssh-add -X`)**. The agent socket is reachable from forwarded hosts, so
any forwarding kpa failed to recognize would make it a remote
password-guessing oracle.

## 7. Configuration

**Settings**

| Setting | Where | Default | Meaning |
| --- | --- | --- | --- |
| `ssh_agent` | `[[database]]` | `false` | Serve this database's SSH keys (§ 6.4) |
| `socket` | `[ssh_agent]` | `$XDG_RUNTIME_DIR/kpa/ssh-agent` | The agent socket |
| `confirm` | `[ssh_agent]` | none; required once a database opts in | The approval program, dmenu style (§ 6.7) |
| `backoff` | `[ssh_agent]` | `"2m"` | How long a cancelled prompt holds back signatures from its database (§ 6.6) |
| `fingerprint` | `[[database.ssh_key]]` | required | Which key the override is for, as `ssh-add -l` and `kpa ssh keys` print it |
| `name` | `[[database.ssh_key]]` | the entry's title | Identity comment, shown in prompts and logs |
| `confirm` | `[[database.ssh_key]]` | `"once"` | Local approval: `"once"`, `"always"` or `"never"` (§ 6.7) |
| `forwarded` | `[[database.ssh_key]]` | `true` | Usable through `ssh -A`, with approval (§ 6.7) |
| `serve` | `[[database.ssh_key]]` | `true` | `false` keeps the key out of the agent entirely |

Overrides sit under the database that holds the key, and a fingerprint is
matched within that database only. An override that matches no key found
there is a warning in the log, not an error: the database may not have
been unlocked on this machine yet. Overrides under a database without
`ssh_agent = true` are a config error.

**Example.** Two databases, one of them serving SSH keys. Most keys need no
override; the two below are the exceptions.

```toml
idle_timeout = "30m"
clipboard_timeout = "30s"
prompt = ["fuzzel", "--dmenu", "--password", "--prompt", "{message}"]
prompt_timeout = "60s"

[ssh_agent]
confirm = ["fuzzel", "--dmenu", "--prompt", "{message}"]

[[database]]
name = "personal"
path = "~/vaults/personal.kdbx"
ssh_agent = true

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
# No `ssh_agent`: this database's keys are never served.
```

A `[[database.ssh_key]]` table belongs to the `[[database]]` above it; the
indentation is only for the reader.

With this config:

- every other key in `personal` is listed as soon as kpa has seen it once,
  asks for approval at its first use after each unlock, and can be used
  through `ssh -A` with an approval per forwarding session;
- `prod-root` asks on every signature and is invisible to forwarded hosts;
- nothing in `work` is served, even while it is unlocked.

The home-manager module gains `services.kpa.sshAgent.enable`, which wires
the agent into the session (§ 8). Databases and keys stay in
`services.kpa.settings`:

```nix
services.kpa = {
  enable = true;
  sshAgent.enable = true;
  settings = {
    prompt = [ "fuzzel" "--dmenu" "--password" "--prompt" "{message}" ];
    ssh_agent.confirm = [ "fuzzel" "--dmenu" "--prompt" "{message}" ];
    database = [
      {
        name = "personal";
        path = "/home/you/vaults/personal.kdbx";
        ssh_agent = true;
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

**Changes**

1. **Run kpa and opt the databases in** with `ssh_agent = true`. Add a
   `[[database.ssh_key]]` override for a key that must stay off forwarding
   (`forwarded = false`) or that needs a different approval policy.
   `kpa ssh keys <database>` prints the blocks to paste.
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
| `git push` at the desk, vault locked                       | The prompt asks "Unlock personal: key github for git@github.com", then the push goes through. The key is approved until lock                         |
| `git push` at the desk, vault unlocked, key not yet used   | An approval prompt names the key and destination. Later uses don't ask until lock                                                                    |
| `ssh -A` to a headless host, then `git pull` there         | The login is local use. The pull is forwarded, and the desktop asks once, naming the host, the destination, the key and the remote user. The approval covers the rest of that SSH session |
| IDE remote session to a headless host, then a fetch        | The same: one approval per destination per connection                                                                                                |
| From a laptop: `ssh -A` into the desktop, then `git pull`  | The laptop's forwarded agent answers. kpa on the desktop is not involved                                                                             |
| From elsewhere, a terminal-server shell on the desktop: `git pull` | No agent is forwarded, so kpa answers. If the vault is locked, the request is refused and `ssh`'s error names `kpa unlock personal`. If the key isn't approved yet, the error names `kpa ssh approve`; run it, then retry |
| Screen locks                                               | kpa has locked everything. Nothing signs until the next unlock                                                                                       |

**Notes**

- **Screen lockers.** kpa sees the `Lock` signal when the idle daemon runs
  `loginctl lock-session`. Some lockers don't set `LockedHint`. With one of
  those, a prompt raised while the screen is locked waits out its timeout
  ([`headless.md`](./headless.md) § 6).
- **The approval program has to return a choice.** Tray menus and
  notification actions only work where the desktop renders them, so a
  dmenu-style program is the portable choice.

## 9. Threat model changes

**§ 1 System**

- Adds the agent socket and the key cache.
- "There is no operation that returns a secret to the caller" still holds:
  a signature is not the key.

**Assets**

- **A-2** gains SSH private keys held in attachments, and their passphrases.
- **A-6 (new) · Signing capability: a signature the user didn't intend.**
  It authenticates as the user elsewhere, or signs commits and files.
  Sensitivity: High.
- Public keys are not assets. They are public by design, which is what
  lets the key cache hold them.

**Actors**

- **ACT-11 (new) · A host the user forwards the agent to.** This means its
  root, or anything there that can reach the forwarded socket. In scope,
  for keys allowed on forwarded connections.

**Boundaries**

- **TB-8 (new) · The agent socket.**
  - Same-uid clients reach it directly.
  - Remote hosts reach it through a forwarding channel the user opened.
  - Untrusted inputs: request bytes, session-bind contents, and the data to
    be signed.

**Goals**

- **G-3** gains: "SSH private keys never leave the process. Only
  signatures do, only on the agent socket, only for keys in databases
  that opt in."
- **G-4** is unchanged. The key cache holds public keys under config
  database names, which are none of A-1–A-3.
- **G-5** gains: "A successful local signature is activity for its
  database. A forwarded signature never is. Approvals and pending requests
  end on lock."
- **G-11** extends to the agent socket.
- **G-12** extends to approval prompts. A request from outside the desktop
  that needs one is refused and kept pending for `kpa ssh approve`.
- **G-13 (new) · Signatures need an unlocked database that opts in, and an
  approval when the key's policy asks for one.** An on-demand unlock is a
  prompt the user answers. Vault content cannot change a key's policy.
- **G-14 (new) · Forwarded signatures are confined.**
  - A key with `forwarded = false` is never listed or used over a
    forwarded connection.
  - The others sign SSH logins only, for a session the destination has
    bound, after an approval for that (key, forwarding session, forwarding
    host, destination).
  - Only the JSON socket can approve, and forwarding never reaches it.
- **G-15 (new) · The agent never accepts a key or a secret.** Add, remove,
  `LOCK` and `UNLOCK` all fail.

**Threats**

- **T-2** is amended. Forwarding is the one path from the network. It is
  reached only through the user's own `ssh` client, and G-14 confines it.
- **T-18** is extended. While a database is unlocked, ACT-10 can sign with
  any key already approved. It can also get its own local requests
  approved: on screen its request looks like the user's own, and from
  outside the desktop it can run `kpa ssh approve` itself. This is
  accepted, on the same terms as `copy`, and is less severe than `copy`
  because the key itself doesn't leave.
- **T-20 (new) · Forwarded-agent abuse** (S, E) — ACT-11 · TB-8 · A-6 → G-14.
  - Response: logins only, approval scoped to the forwarding session and
    destination, `forwarded = false` per key, no approval path over the
    agent socket.
  - In scope:
    - signing over a forwarded connection without a matching approval;
    - forwarded signing of non-login data;
    - a session-bind accepted without verification;
    - an approval reused across forwarding sessions or destinations;
    - a denied key listed or used over a forwarded connection;
    - a forwarded signature resetting the idle timer.
  - Residual: during an approved forwarding session, the remote host can
    use the key for that destination; this is inherent to forwarding.
    Forwarding that bypasses the OpenSSH client looks local.
- **T-21 (new) · Malformed agent traffic** (D, T) — ACT-5, ACT-11 · TB-8 →
  G-11.
  - Covers frames, lengths, session-bind contents and the data to be signed.
  - Fuzzed like `decode_request`.
- **T-22 (new) · Key material in memory** (I) — ACT-7, ACT-11 · TB-7 ·
  A-2 → G-6.
  - Decrypted keys are cached only while unlocked, and zeroized on lock.
  - Private-key operations must be constant-time, so a forwarded host
    cannot recover a key from signature timing. This is why kpa needs
    `rsa` 0.10 or later (§ 6.5).
- **T-23 (new) · Prompts on demand** (S) — ACT-10, ACT-11.
  - Anything that can reach the agent can raise an unlock or approval
    prompt.
  - Response: the prompt names its reason, backoff after a cancel, one
    prompt at a time, timeouts, no prompts while locked or outside the
    desktop.
  - Residual: NG-7 (nuisance) and NG-8 (look-alike prompts).

## 10. Changes to existing docs

- **`design.md`**
  - § Scope: replace "an SSH agent" in **Is not**, and say kpa serves SSH
    keys under the same read-only rule.
  - § Architecture: add the agent socket and the key cache.
  - § Lock policy: lock drops cached keys and approvals, and kills open
    prompts. Local signatures are activity.
  - Settled decisions: one row for "kpa is the agent, databases opt in,
    approval once per key per unlock".
- **`background.md`**: the "SSH agent" row of the gap table changes. A
  full client covers SSH, but only while it runs, and only by pushing keys
  into a separate agent.
- **`threat-model.md`**: § 9 above.
- **`config.example.toml`**: an `[ssh_agent]` section, `ssh_agent = true`
  on one fixture database, and one `[[database.ssh_key]]` against a fixture key.
- **`nix/hm-module.nix`**: `services.kpa.sshAgent.enable` (§ 8).

## 11. Implementation

**Modules** (new `src/agent/`):

| File          | Role                                                                                                                                            |
| ------------- | ----------------------------------------------------------------------------------------------------------------------------------------------- |
| `wire.rs`     | Frame decode and encode into `enum AgentRequest` and `enum AgentResponse`. Pure, fuzzed                                                         |
| `bind.rs`     | session-bind verification and per-connection binding state                                                                                      |
| `classify.rs` | Data to be signed → `Purpose::{Login, SshSig, Other}`. Pure, fuzzed                                                                             |
| `policy.rs`   | (key settings, connection class, purpose, database state, approvals, prompt availability) → `Sign`, `Approve`, `Unlock`, `Refuse(reason)`. Pure, with exhaustive tests like `policy::Policy` |
| `keys.rs`     | Attachment scan, public-key cache file, overrides, lazy decryption, the per-`Slot` key cache                                                    |
| `approve.rs`  | Approvals and pending requests: their scopes, limits and expiry                                                                                 |
| `serve.rs`    | Listener, per-connection thread, connection cap                                                                                                 |

**Server changes**

- `Slot` gains the key cache and its approvals, cleared in `Slot::lock()`.
- A `SshSign` trait sits beside `CopyEntry`.
- Unlock waiters use a condvar.
- The prompt and approval runner gains `{message}` and the shared queue.
  The timeout and lock-kills-prompt come from
  [`headless.md`](./headless.md).
- The JSON protocol gains three requests: `ssh_keys` (the scan behind
  `kpa ssh keys`), `ssh_pending` and `ssh_approve`. The CLI gains
  `kpa ssh keys` and `kpa ssh approve`.
- `log_response` gains agent events: key name, purpose, connection class,
  destination fingerprint and decision. Like `list`, `REQUEST_IDENTITIES`
  is not logged.

**Tests**

- **Fixture**: `tests/fixture.sh` adds entries with an Ed25519 key, a
  passphrase-protected key, an RSA key, and a PEM key that must be skipped
  (generated with `ssh-keygen`, imported as attachments).
- **`tests/agent.rs`** spawns `kpa serve` and drives it with the real
  OpenSSH tools:
  - `ssh-add -L` lists the keys from the cache while the database is
    locked, and nothing on a first run without a cache;
  - `ssh-keygen -Y sign` fails when the scripted prompt cancels, succeeds
    after unlock, and `ssh-keygen -Y verify` accepts the result, for each
    key type;
  - a second signature doesn't prompt; `confirm = "always"` does;
  - from outside the desktop (`Server::assume_origin`), a signature is
    refused, `ssh_pending` lists it, and after `ssh_approve` the retry
    signs;
  - a lock makes signing fail again and clears approvals;
  - `ssh-add <key>` and `ssh-add -D` fail.
- **Forwarding**: an unprivileged `sshd` on a high port with a temporary
  host key, then `ssh -A` to localhost. This covers session-bind for real:
  a forwarded login approved by a scripted confirm, a second `ssh -A`
  session asking again, a `forwarded = false` key absent from the
  forwarded listing, and forwarded `SSHSIG` refused.
- **Fuzzing**: `fuzz_targets/agent_request.rs` covers `wire`, the
  session-bind parser and `classify`.

**Size**: roughly 1,500–2,000 lines of Rust plus tests. That is about as
much as kpa's existing code, so it warrants its own security-audit pass
once it lands.

**Phases**, each leaving a usable state. The SSH release ships all three.

1. **Local agent.**
   - Socket, identities, signing (Ed25519, ECDSA, RSA), database opt-in,
     discovery, the key cache, overrides, lock coupling, idle activity.
   - Approvals on screen, with the approval program.
   - session-bind parsing, with every forwarded request refused.
   - `kpa ssh keys`, logging, fixtures, fuzz target, threat-model and
     design edits, `services.kpa.sshAgent.enable`.
   - The user unlocks from the launcher or tray first.
   - Enough to switch off a KeePass client's agent on Linux.
2. **Unlock on demand, and requests from outside the desktop.**
   - `{message}`, backoff, unlock waiters.
   - Pending requests, `kpa ssh approve`, the hints in key comments.
3. **Forwarding.**
   - `forwarded`, forwarded listing, forwarding-session approvals.
   - `known_hosts` names, the end-to-end `sshd` test.

Later, if needed: read notifications covering both `copy` and signatures
(T-16), and an upstream agent relay (approach C).

## 12. Open questions

1. **Shared terminal servers.** [`headless.md`](./headless.md) open
   question 1 asks whether config should name a terminal server whose
   shells count as the desktop. If it does, the same override decides
   whether those shells get on-screen approval prompts or
   `kpa ssh approve`.
