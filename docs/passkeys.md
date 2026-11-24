# kpa — passkeys

kpa signs in to websites with the passkeys stored in its databases. To a
browser it is a USB security key: a virtual device that speaks the
security-key protocol (CTAP2), which Chromium and Firefox use unmodified. A
KeePass client creates the passkeys and kpa uses them, as it does TOTP seeds
and SSH keys.

**Not built yet.** This doc is the design the implementation follows.
Nothing in `src/` implements it, and the other docs don't describe it. The
steps are in [`TODO.md`](../TODO.md).

It follows the rules the SSH agent set ([`ssh-agent.md`](./ssh-agent.md)): a
database opts in, private keys never leave kpa, a use is approved on screen,
a locked database is unlocked on demand, and a lock ends everything. Prompt
timeouts and the screen-lock rules are [`headless.md`](./headless.md) § 6.

## 1. Overview

- **kpa is the security key.** While there is a screen to ask on, `kpa
  serve` keeps an emulated USB security key plugged in, created through
  `/dev/uhid`. Browsers find it the way they find a hardware key.
- **Sign-in only.** The key answers `get` (a signature over the site's
  challenge). It never registers a passkey: that would write the database,
  and kpa is read-only (§ 9).
- **Databases opt in, and kpa finds the passkeys.** A database with
  `serve_passkeys = true` has every passkey among its entries served: the
  `KPEX_PASSKEY_*` attributes KeePass clients store one under (§ 4).
- **Every sign-in is approved on screen**, in a prompt that names the site
  and the account, and doubles as the account picker when a site has
  several. A per-site setting can ask once per unlock instead, or never
  (§ 5.3).
- **A locked database is unlocked on demand.** kpa caches a hash of each
  passkey's site and credential id, and nothing else, so it knows which
  locked database to offer. The unlock prompt names the site.
- **No prompt where nobody can see it.** Prompts appear on screen only. The
  key is unplugged while the screen is locked or the display session isn't
  the active one, and there is no key at all without a display session.
- **Private keys never leave kpa.** Only signatures do. `copy` refuses the
  attribute that holds one and `list` doesn't name it.
- **ES256, EdDSA and RS256**, through the RustCrypto crates the SSH agent
  already brings in. kpa implements no cryptography.

## 2. Use cases

**Served**

- Signing in from a browser on this machine, Chromium-based or
  Firefox-based: the site's "sign in with a passkey" or "use a security
  key" button, with or without a username typed first, as the only factor
  or as a second one.
- Any other program that talks to FIDO2 keys over USB HID, such as
  `libfido2`'s tools.

**Not served**

- **Creating a passkey.** Registration happens in a KeePass client (§ 9).
- **Passkey autofill.** A browser lists passkeys under a username field
  only from authenticators it can query silently, and neither browser asks
  a USB key. The site's passkey button reaches kpa, and so does the "use a
  security key" entry of Chromium's autofill list.
- **More than a signature.** The `prf` and `hmac-secret` extensions (a site
  deriving an encryption key from the passkey) and the legacy U2F AppID
  extension aren't supported. kpa speaks CTAP2 only.
- **A sign-in from outside the desktop.** There is no terminal route: a
  sign-in is approved on screen or not at all (§ 5.3).
- **Passkeys kpa can't read**: an algorithm outside the three above, or a
  key that doesn't parse (§ 4.1). `kpa passkeys` says which and why.

**Machines without kpa** keep their KeePass client's browser integration
over the same synced vault. kpa changes nothing in the file.

## 3. Why an emulated security key

A password manager reaches a browser at one of three layers:

| Route | How it works | For kpa |
| --- | --- | --- |
| Browser extension and native host | The extension replaces `navigator.credentials` in the page and forwards to a local program | One extension per browser to write, ship and keep up to date, to do what a KeePass client's extension already does |
| OS credential service | The browser asks a system service, which asks a registered provider | Linux's (`credentialsd`, the experimental Credential portal) has no provider interface a password manager can implement, and no browser calls it without an extension |
| Emulated security key | A virtual USB HID device speaks CTAP2 | Works with unmodified browsers |

kpa takes the third. What it costs:

- **The key can't tell who is asking.** A HID device has no peer the way a
  socket has, so kpa can't classify a requester as on or outside the
  desktop. Every process that can open the device can ask (§ 10), and
  prompts appear on screen only.
- **It is the security-key flow.** The browser shows its security-key
  dialog, not a passkey list, and never autofills (§ 2).
- **Browsers offer every plugged-in key a registration.** kpa refuses
  (§ 6.4). Chromium then ignores it and carries on with the other
  authenticators. Firefox, when kpa's key is the only one plugged in, fails
  the registration at once: plug the hardware key in before starting.
- **Firefox with a hardware key also plugged in** asks every key to blink
  and uses the one that is touched. kpa never passes for touched, so
  Firefox signs in with the hardware key; to use kpa there, unplug it.
  Chromium asks every key at once and takes the first answer, so the two
  work side by side.
- **A system-level grant.** Creating the device needs `/dev/uhid`, which
  only root opens by default (§ 8).

## 4. Passkeys in a database

### 4.1 What kpa reads

KeePass clients store a passkey as string attributes on an ordinary entry.
There is no written standard; the names and encodings below are the ones
the clients share.

| Attribute | Content |
| --- | --- |
| `KPEX_PASSKEY_RELYING_PARTY` | The site's id (`github.com`), as text |
| `KPEX_PASSKEY_CREDENTIAL_ID` | The credential id, base64url. An entry that has the older `KPEX_PASSKEY_GENERATED_USER_ID` uses that instead |
| `KPEX_PASSKEY_PRIVATE_KEY_PEM` | The private key, PKCS#8 |
| `KPEX_PASSKEY_USER_HANDLE` | The user handle the site gave the account, base64url |
| `KPEX_PASSKEY_USERNAME` | The account name. An entry that has the older `KPXC_PASSKEY_USERNAME` uses that instead |
| `KPEX_PASSKEY_FLAG_BE`, `KPEX_PASSKEY_FLAG_BS` | The backup-eligible and backed-up flags: `1` or `true` is set, a missing attribute is set too, and BS is only ever set with BE |

A database opts in with `serve_passkeys = true` (§ 7). When it unlocks, kpa
scans it:

1. Look at current entries only: no history, and nothing in the recycle
   bin.
2. Pick the entries that have a relying party, a credential id, a user
   handle and a private key. An entry holds one passkey, and it may be a
   login entry
   too, with a password and a TOTP seed next to it. The entry's group,
   title, URL and tags play no part.
3. Decode each one. base64url is read with or without padding, and
   standard base64 is accepted. The private key is read with or without its
   `BEGIN`/`END` lines and with any line breaks, since clients differ.
4. Read the algorithm from the key itself: ES256 (P-256), EdDSA (Ed25519)
   or RS256 (RSA, 2048 bits or more).
5. Skip what can't be served, each with its reason: an attribute that
   doesn't decode, another algorithm, a shorter RSA key, a relying party
   that isn't a domain name of at most 253 bytes. Each is logged at unlock
   by its entry's uuid, and listed by `kpa passkeys`.

A credential id found in two opted-in databases is served from the first in
config order.

**The account name** kpa shows is the passkey's username, else the entry's
username, else the entry's title. It is entry content, escaped and
length-capped like the rest (T-13).

**Authorization lives in config, not in the vault**, as for SSH keys. A
database's content decides which passkeys exist. Config decides whether the
database is served at all and how each site is approved. No vault content
can exempt a passkey from approval.

### 4.2 The private key stays in

The attribute that holds a passkey's private key is not a field for the
rest of kpa, in any database, opted in or not: `list` leaves it out of an
entry's `fields`, and a `copy` that names it answers `field_empty`. Only
the passkey code reads it.

kpa parses the key for each signature and zeroizes the parsed copy
afterwards. Nothing about a passkey is kept between requests beyond what
the unlocked database already holds, so a lock has no key cache to clear.

### 4.3 The cache of hashes

After each scan, kpa writes `$XDG_CACHE_HOME/kpa/passkeys/<database>`,
where `<database>` is the config name, mode 0600. For each passkey the file
holds two SHA-256 hashes: of the relying party's id, and of the credential
id. No site name, account name or entry title is in it. While a database is
locked, this file is how kpa knows that a request is for one of its
passkeys (§ 5.2).

- A passkey removed from the vault stays in the file until the next unlock
  rewrites it. The unlock it causes then finds nothing and the sign-in is
  refused.
- A passkey added to the vault is known from the next unlock on.
- With no cache file yet, as on a fresh machine, a locked database answers
  nothing until its first unlock.
- Tampering with the file needs the user's uid. The most it does is raise
  an unlock prompt for a site the database has no passkey for.

The hash of a site's id is no secret: it is in every assertion the site
receives. What the file gives its reader is a way to test a guessed site
name against it, and the number of passkeys. The credential id is hashed
because clients store it as a protected value, and equality is all the
lookup needs.

## 5. Signing in

### 5.1 Situations

| # | Situation | Database unlocked | Database locked |
| --- | --- | --- | --- |
| P1 | Sign-in to a site with one passkey | The approval prompt, unless the site's `confirm` says otherwise, then the signature | The unlock prompt naming the site, then as unlocked |
| P2 | Sign-in to a site with several accounts | The account prompt | The unlock prompt, then the account prompt |
| P3 | A site kpa holds no passkey for | Refused at once, no prompt | The same: the cache has no hash for it |
| P4 | A registration | Refused at once (§ 6.4) | The same |
| P5 | Screen locked, display session not active, or no display session | The key is unplugged | The key is unplugged |
| P6 | Another program that opens the device: a script, a second browser | Indistinguishable from P1 | Indistinguishable from P1 |
| P7 | A sandboxed app without device access | It has no device | It has no device |

### 5.2 Which passkey answers

A request names a site (its relying party id), carries the hash to sign,
and may list the credential ids the site accepts (the allow list, sent when
the site already knows the account). kpa works through it in this order:

1. **Candidates** are the passkeys of unlocked, opted-in databases whose
   relying party equals the request's, byte for byte, and whose credential
   id is on the allow list if there is one. There is no subdomain or suffix
   matching: the browser has already checked the site's id against the
   page's origin.
2. **With no candidate**, kpa looks at the caches of the locked, opted-in
   databases, for the site's hash and, with an allow list, one of its ids'
   hashes. If none has it, the request is refused with no prompt. Otherwise
   kpa unlocks the first such database in config order (below), and starts
   again from step 1 with what the database really holds.
3. **A probe** is answered here (§ 6.5): no prompt, and not a sign-in.
4. **Approval** (§ 5.3) picks the one passkey that signs.
5. **The signature** is made (§ 5.4) if the database is still in the unlock
   the approval was for. A lock in between refuses the request.

Unlocked databases answer first: a locked database is only offered an
unlock when no unlocked one has a passkey for the site.

**Unlock on demand** is the unlock `kpa unlock` runs, with the same
`prompt` in the same queue, and the four steps every front end follows
([`design.md`](./design.md) § Unlocking): take the database's unlock and
its token, check that the display session allows a prompt, ask, finish. The
question says what for: `Unlock database personal to sign in to
github.com?`. Answering it approves nothing; the approval follows. A
database whose unlock is already in progress refuses the request.

### 5.3 Approval

A per-site setting, `confirm`, decides when a sign-in asks:

- `"always"` (default): every sign-in asks.
- `"once"`: the first sign-in with a passkey after each unlock asks. The
  approval holds until the database locks, and is for that passkey, not for
  the site's other accounts.
- `"never"`: a sign-in never asks.

When a site has several candidates the prompt always appears, whatever
their `confirm`: choosing the account is the question. So `"once"` and
`"never"` change something only where one passkey can answer.

**The prompt.** `passkeys.confirm_prompt` is an argv with the contract of
the SSH agent's `confirm_prompt` ([`ssh-agent.md`](./ssh-agent.md) § 6.7):
kpa writes the choices on stdin, one per line, and reads the chosen line
from stdout. A non-zero exit, or any other output, means deny. The question
is in `KPA_PROMPT_MESSAGE` and its pieces in `KPA_PROMPT_DATA`. One program
can serve both settings. It is required once a database has
`serve_passkeys = true`: without it `kpa serve` refuses to start.

| Request | Message | Choices |
| --- | --- | --- |
| One candidate | `Approve sign-in to github.com as "alice"?` | `Allow`, `Deny` |
| Several candidates | `Sign in to github.com with which account?` | One line per account, `alice [personal]`, then `Deny` |

An account line is the account name and its database. Two lines that would
be equal are numbered (`alice [personal] (2)`), so every line is distinct
and none can equal `Deny`. The answer is matched against the lines kpa
wrote, never parsed.

`KPA_PROMPT_DATA` has the members `relying_party`, the site's id, and
`accounts`, a list of `{"name", "database"}` in the order of the lines (one
element for an Allow/Deny prompt). The unlock prompt has `database` and
`relying_party`. Every piece that isn't kpa's own text (the site's id, an
account name, a database name) is escaped as the SSH agent's prompt pieces
are, and each has its own length budget. The site's id is never cut.

**Where prompts may appear.** On screen only, and only while there is a
display session that isn't known to be locked: the tray's gate
(`authz::display_allows_prompt`), since the key has no requester to
classify. The display session is read after the unlock's token is taken,
the order every unlock keeps. There is no pending list and no approval from
a terminal. A prompt is ended by its timeout (`prompt_timeout` for the
unlock, `passkeys.confirm_prompt_timeout` for the approval), by a lock of
its database, and by the browser cancelling the request (§ 6.6). Unlock and
approval prompts share the one prompt queue, with the SSH agent's and `kpa
unlock`'s.

### 5.4 The assertion

kpa answers with one assertion, for the passkey the approval picked:

- **Authenticator data**: the SHA-256 of the site's id, the flags, and a
  signature counter of 0. Passkeys that sync between devices report 0
  always and sites accept it, so no sign-in needs a write.
- **Flags**: user present and user verified are both set on every sign-in.
  Backup-eligible and backed-up come from the entry (§ 4.1), so a site sees
  the same flags from kpa as from the client that made the passkey.
- **The user handle** is always returned, and never the account name: a
  response that carries a name makes Chromium show a picker of its own.
- **The signature** over the authenticator data and the request's hash:
  ASN.1 DER for ES256, the raw 64 bytes for EdDSA, PKCS#1 v1.5 with SHA-256
  for RS256.

**What "user verified" rests on.** Sites that accept a passkey as the only
factor require the flag, and Chromium won't ask a USB key for a passkey
without it. kpa's basis is the unlocked database: the user gave its master
password for this unlock, and the database has been under kpa's lock policy
since. kpa doesn't verify the user again for each sign-in, and with
`"once"` or `"never"` it sets both flags without asking anything. KeePass
clients set them the same way.

### 5.5 Lock, idle and the log

- **Lock** drops the database's `"once"` approvals, kills a prompt on
  screen for it, and refuses a sign-in whose database locked after it was
  approved.
- **Freshness.** The freshness guard runs before each read of a database,
  as it does for `copy` (G-8).
- **Idle.** A sign-in the user approved on screen resets its database's
  idle timer. One that asked nothing (`"once"` already approved, `"never"`)
  doesn't, and neither does a probe or a refusal: nothing that can reach
  the key keeps a database unlocked without a person answering.
- **The log** has one line per sign-in and per sign-in refused after a
  prompt or for want of a screen: the site's id, the database, the outcome,
  and whether it asked. Never the account name, the entry's title or the
  credential id. A probe, and a request for a site kpa has no passkey for,
  are logged at `debug` only: with the key plugged in, a browser sends it
  every site's requests.

## 6. The emulated key

### 6.1 The device

- **Created through `/dev/uhid`** as a USB HID device with the FIDO usage
  page and 64-byte reports. The system then treats it as it treats a
  hardware key: on a systemd machine the device node goes to the user of
  the seat's active session, with no rule of kpa's.
- **It exists only while a database has `serve_passkeys = true`**, and kpa
  opens `/dev/uhid` once, at startup. If that fails (no permission, no
  `uhid` module) kpa logs an error and serves everything else; `kpa status`
  reports the key as unavailable, with the reason (§ 7). kpa doesn't try
  again until it restarts.
- **It is plugged in only while the display session is active and not known
  to be locked.** kpa creates the device when the session becomes so and
  destroys it when it stops, so the key comes and goes like a key on a
  keyring. Without a display session there is no device.

**Why it follows the display session.** A prompt can only be answered
there, so a key that is plugged in at other times could do nothing but sign
for `"once"` and `"never"` passkeys unseen. And the system grants the
device node to whoever is at the seat: after a switch to another user's
session, that user could open a key left plugged in. Destroying the device
also ends every descriptor already open on it.

### 6.2 Transport and commands

The device speaks CTAPHID, the FIDO framing over HID reports: `INIT`,
`PING`, `CBOR` and `CANCEL`, one transaction at a time, with a second
channel answered `CHANNEL_BUSY` meanwhile. It declares CBOR and no U2F
messages. A message is at most 7609 bytes, CTAPHID's own limit. While a
request waits on a prompt, kpa sends a keepalive every 100 ms, which is
what keeps a browser waiting.

| Command | Answer |
| --- | --- |
| `authenticatorGetInfo` | Version `FIDO_2_0`; options `rk`, `up` and `uv`; transport `usb`; kpa's AAGUID; the allow-list limits |
| `authenticatorGetAssertion` | § 5, or the refusal of § 6.3 |
| `authenticatorMakeCredential` | Refused, or left unanswered (§ 6.4) |
| Anything else: PIN, reset, credential management, `getNextAssertion`, selection | `CTAP1_ERR_INVALID_COMMAND` |

Why `getInfo` says what it says:

- **`FIDO_2_0` and nothing later.** A key that claims a later version and
  verifies its user must implement the PIN and token protocol, and several
  extensions with it. Under 2.0 a key may verify by itself, and both
  browsers then ask it with a plain `uv` option and no PIN.
- **`uv`**, because kpa's sign-ins carry the user-verified flag (§ 5.4),
  and because Chromium requires it of a USB key for any request without an
  allow list.
- **No PIN, no extensions, no algorithm list.** The algorithm list is for
  creating credentials.
- **`maxCredentialCountInList` and `maxCredentialIdLength`**, large enough
  that an ordinary allow list goes out in one request. Chromium probes a
  key one credential at a time when they are missing.
- **The AAGUID** is a fixed value of kpa's own. It names the model of
  authenticator and appears in no assertion.

Since kpa picks the account itself and answers with one assertion, there is
no `getNextAssertion`.

### 6.3 Refusing a sign-in

Every sign-in kpa doesn't make gets the same answer, `CTAP1_ERR_OTHER`: no
passkey for the site, a deny, a prompt that was cancelled or timed out or
couldn't run, no screen to ask on, a lock that came first. The two codes
CTAP has for these are the wrong ones to send a browser:

| Answer | Chromium | Firefox |
| --- | --- | --- |
| `CTAP2_ERR_NO_CREDENTIALS` | Ends the whole request, for every key: a hardware key answers this only once it is touched | Ends the request |
| `CTAP2_ERR_OPERATION_DENIED` | Ends the whole request as denied | Having asked the key to verify the user, takes it for a failed attempt and sends the request again, with no limit |
| `CTAP1_ERR_OTHER` | Drops this key and carries on with the others | Ends the request, if this key is the one in use |

So a key that is always plugged in must never answer `NO_CREDENTIALS`, or a
sign-in meant for a hardware key would die on kpa's answer, and it can't
answer `OPERATION_DENIED` without Firefox raising the prompt again and
again. The cost is in Chromium: after a deny its dialog stays open, as it
would for a key nobody touched, until the user closes it.

This is the browsers' behaviour as their sources stood in November 2026.

### 6.4 Registration and touch requests

- **`authenticatorMakeCredential` is refused at once** with
  `CTAP1_ERR_INVALID_COMMAND`, without reading past the relying party's id.
  Chromium drops the key and carries on, and Firefox fails fast instead of
  waiting on a key that will never answer (§ 3).
- **A touch request is left unanswered.** Browsers also send a
  `makeCredential` that registers nothing, only to make a key blink and see
  whether it is touched. kpa takes one for a touch request when its relying
  party id is no domain name, as Chromium's placeholder `.dummy` isn't.
  During a sign-in, Chromium takes any answer to it, an error included, for
  a touch, and ends a request another key could have served. kpa answers it
  with keepalives only, until the browser cancels, as a key nobody touches
  does.

### 6.5 Probes

A request with user presence switched off (`up: false`) is a probe: a
browser sends one to learn which key holds a credential on the allow list
before it asks for the real signature. Firefox sends one before every
sign-in with an allow list.

- **With an allow list**, kpa answers a probe without a prompt, with an
  assertion whose user-present and user-verified flags are clear. No site
  accepts that as a sign-in. It tells the caller that a credential id it
  already knew is in the vault.
- **Without an allow list**, a probe is refused. Nothing lists a site's
  accounts silently.
- **For a locked database's passkey**, the probe raises the unlock prompt
  and is held until it is answered. Refusing it would end the sign-in: no
  browser probes again after an unlock. The real request follows, and with
  it the approval.

A probe counts as no activity and needs no approval, and `confirm` has no
say in it.

### 6.6 Cancelling and timeouts

- **`CANCEL`** from the browser (the user closed its dialog, another key
  answered, the page's time ran out) ends the prompt kpa has on screen for
  that request, which is answered `CTAP2_ERR_KEEPALIVE_CANCEL`. A new
  `INIT` on the channel does the same.
- **The browser's patience** is the page's timeout: at most two minutes in
  Firefox, three minutes or more in Chromium. kpa's own prompt timeouts
  apply inside it.
- **Firefox never cancels a probe.** A probe held for an unlock prompt
  (§ 6.5) stays until the prompt is answered or times out.
- **A separate thread reads the device.** The kernel queues few reports and
  drops the rest, so a `CANCEL` must not wait behind the request it
  cancels.

## 7. Configuration and commands

| Setting | Where | Default | Meaning |
| --- | --- | --- | --- |
| `serve_passkeys` | `[[database]]` | `false` | Serve this database's passkeys (§ 4.1) |
| `confirm_prompt` | `[passkeys]` | none; required once a database opts in | The approval program, dmenu style (§ 5.3) |
| `confirm_prompt_timeout` | `[passkeys]` | `prompt_timeout` | How long the approval prompt may stay open unanswered before it is killed and the sign-in refused |
| `relying_party` | `[[database.passkey]]` | required | Which site the override is for, as `kpa passkeys` prints it. Matched exactly, and within that database only |
| `confirm` | `[[database.passkey]]` | `"always"` | `"always"`, `"once"` or `"never"` (§ 5.3) |

An override that matches no passkey in its database is a warning in the
log, not an error: the database may not have been unlocked on this machine
yet. Overrides under a database without `serve_passkeys = true` are a
config error.

```toml
prompt = ["sh", "-c", "exec fuzzel --dmenu --password --prompt \"$KPA_PROMPT_MESSAGE\""]

[passkeys]
confirm_prompt = ["sh", "-c", "exec fuzzel --dmenu --prompt \"$KPA_PROMPT_MESSAGE\""]

[[database]]
name = "personal"
path = "~/vaults/personal.kdbx"
serve_passkeys = true

  # A self-hosted service signed in to many times a day.
  [[database.passkey]]
  relying_party = "git.example.org"
  confirm = "once"

[[database]]
name = "work"
path = "~/vaults/work.kdbx"
# No `serve_passkeys`: this database's passkeys are never served.
```

**`kpa passkeys`** prints each passkey found in the unlocked databases (the
site, the account name and the database; `--full` adds the algorithm, the
entry's title and the `confirm` in force), the entries it skipped and why,
and the databases it could not scan because they are locked. `--database
<name>` limits it to one. It reads databases that have not opted in too,
which shows what opting in would serve. It sends one request, `passkeys`,
which reads like `ssh_keys`: it counts as activity for each database it
reads, and it never returns a credential id, a user handle or a key.

**`kpa status`** reports the key while a database opts in: `plugged_in`,
`unplugged` (no active, unlocked display session) or `unavailable` with the
reason `/dev/uhid` couldn't be used.

## 8. Setting up a machine

kpa runs as the user, and `/dev/uhid` belongs to root. Three things, done
once by whoever administers the machine, let the daemon create its key:

1. A system group, `uhid`, with the user in it. udev (systemd 258 and
   later) ignores a rule that names a group that isn't a system group.
2. A udev rule that gives the device to the group:
   `KERNEL=="uhid", SUBSYSTEM=="misc", GROUP="uhid", MODE="0660"`.
3. The `uhid` kernel module loaded at boot.

The flake's NixOS module does all three behind
`hardware.kpaSecurityKey.enable`; adding a user to the group stays that
machine's own line. The home-manager unit needs no change: its sandbox
doesn't hide `/dev/uhid`.

**What the grant gives.** `/dev/uhid` creates any HID device, not only a
security key. Every process of a user in the group can create a keyboard
that types into whichever session is in front. A group is used, and not an
automatic grant to whoever sits at the seat, so that the machine's
administrator names who gets it. A root helper that held `/dev/uhid` and
relayed only FIDO reports would confine the grant; kpa doesn't have one, as
it would be a second, privileged program with a protocol of its own.

**Sandboxed browsers** reach the key only if their sandbox has device
access, which the Chromium Flatpak asks for. A sandboxed browser may miss a
key that is plugged in while one of its requests is already open.

**Day to day**

| Action | What happens |
| --- | --- |
| "Sign in with a passkey" on a site, vault unlocked | The browser's security-key dialog opens and kpa asks `Approve sign-in to github.com as "alice"?`. Allow signs in |
| The same, vault locked | kpa asks `Unlock database personal to sign in to github.com?`, then for the approval |
| A site with two accounts | kpa asks `Sign in to github.com with which account?` and lists them |
| A site with `confirm = "once"`, used earlier in this unlock | The sign-in goes through with no prompt |
| A site whose passkey is on a hardware key | kpa refuses silently and the browser waits for the hardware key. In Firefox, have it plugged in first |
| Registering a passkey | kpa refuses. Create it in the KeePass client; kpa serves it from the next unlock |
| Screen locks | kpa has locked everything and unplugged the key |

## 9. Registration

kpa never creates a passkey. Registering one means storing a new private
key, and kpa writes no database: read-only is what makes it safe to run
next to a KeePass client that has the same file open
([`design.md`](./design.md) § Scope, G-1). So `serve_passkeys` adds no write
path, the key refuses `authenticatorMakeCredential` in one place (§ 6.4),
and no type or setting exists for registration.

What registration would take, and why each part is out of reach of this
design: `keepass` built with its save feature, which the read-only
guarantee rests on leaving out; a way to save without losing what another
client wrote to the same file meanwhile; and a threat model in which a
request to the key can change the vault. `TODO.md` lists it as an idea.

## 10. Claims

What this design claims and what it accepts, in the terms of
[`threat-model.md`](./threat-model.md), which doesn't carry them yet.

**The boundary** is the emulated key's device node. Its untrusted side is
every process that can open it: on a systemd machine, every process of the
user whose session is active at the seat, and a sandbox given device
access. That grant is the system's, as it is for a hardware key. Requests
are untrusted bytes.

**Claims**

- **Read-only holds** (G-1). No request to the key writes a database. The
  one file kpa writes for passkeys is the cache of hashes, in its own cache
  directory.
- **A passkey's private key never leaves the process** (G-3). Only
  assertions do, only through the key, only for databases that opt in.
  `copy` and `list` treat the attribute as absent in every database.
- **A sign-in needs an unlocked database that opts in, and the approval its
  site's `confirm` asks for.** By default that is a prompt naming the site
  and the account for every sign-in. An on-demand unlock is a prompt the
  user answers. Vault content cannot change a site's policy.
- **No prompt where nobody can see it** (G-12). Prompts are on screen only,
  never while the screen is known to be locked, and the key is unplugged
  then.
- **A lock ends it** (G-5, G-6). Approvals and open prompts go with the
  database, and kpa keeps no parsed key between sign-ins.
- **Nothing from a vault is persisted but hashes** (G-4): the cache holds
  the two hashes of § 4.3.
- **The key's input is only data** (G-11). Reports, messages and CBOR are
  bounded, a malformed or flooding client is refused without crashing the
  daemon, and the decoders are fuzzed. A passkey entry is file input like
  any other (G-9): a crafted key is skipped.

**Accepted**

- **Any process that can open the key can ask it to sign in** (NG-1, T-18).
  What it gets is what the site's `confirm` allows: a prompt the user sees
  by default, a silent signature for a `"once"` passkey already approved
  and for every `"never"` one. The prompt is visibility, not a boundary,
  inside the uid.
- **Every process that has the key open reads its answers.** HID reports go
  to all openers, so an assertion, with its credential id and user handle,
  is seen by same-uid listeners. An assertion is bound to its challenge.
- **A probe confirms a credential id** the caller already knew (§ 6.5).
- **kpa trusts the browser for which site is asking**, as every security
  key does: the site's id arrives already checked against the page. The
  prompt shows the id kpa signs for, and a look-alike domain has no passkey
  in the vault to match.
- **Whoever writes entries in a served database can add an account.** An
  entry planted in a shared vault shows up as one more account for its
  site, under the name its author chose (ACT-4).
- **The moment of a user switch.** The device node changes hands when the
  seat's active session does, and kpa unplugs the key as soon as it hears.
  A process of the other user that opens the key in between can ask it for
  what needs no prompt.
- **The `/dev/uhid` grant** is the machine's (§ 8), like the rest of its
  hardening (ASM-6).
- **Prompts on demand** (NG-7, NG-8). Only a request for a site the vault
  or a cache has a passkey for raises one, one at a time, with timeouts.
  There is no backoff: no browser repeats a refused sign-in by itself.
- **The log names sites.** A sign-in's line has the site's id (§ 5.5).
- **"User verified" is the unlocked database** (§ 5.4), not a check per
  sign-in.

## 11. Code

Two subsystems ([`module-structure.md`](./module-structure.md)), and small
additions to two others.

| Subsystem | Is | Uses |
| --- | --- | --- |
| `passkeys` | what `control` and the key share about passkeys: finding them in an open database, the cache of hashes, making an assertion | `databases` (reads only), `config`, `paths` |
| `frontends::security_key` | the emulated key: the device, the protocol, the sign-in flow, the `"once"` approvals | `databases`, `passkeys`, `authz`, `prompt`, `display_session`, `config` |

```
src/
  passkeys/
    mod.rs              Passkey, and what the subsystem exports
    find.rs             finding passkeys in an open database; why an entry is skipped
    key.rs              the private key: PKCS#8 in, a signature out
    assertion.rs        authenticator data and the signed assertion
    cache.rs            the cache of hashes
  frontends/security_key/
    mod.rs              the key's lifetime: plugged in with the display session
    uhid.rs             /dev/uhid: create, destroy, reports in and out
    hid.rs              CTAPHID: reports to messages, channels, keepalive, cancel
    ctap.rs             CTAP2: decoding requests, encoding answers
    cbor.rs             the CBOR subset CTAP2 uses
    sign_in.rs          the sign-in flow (§ 5.2)
    approvals.rs        "once" approvals, per database and unlock
    prompts.rs          the questions and their data
```

- **`databases`** gains one read on `Open`: the current entries outside the
  recycle bin that have a given attribute. Which entries are in the bin is
  the core's to know.
- **`control`** gains the `passkeys` request and its report, and leaves the
  private-key attribute out of `list` and `copy` (§ 4.2).
- **Lock state.** `security_key`'s approvals are an observer, registered
  with the others that hold what must die with a lock. The cache is written
  by an observer of `passkeys` that hears `unlocked`.
- **Portability.** `uhid.rs` is the Linux side and exports 64-byte reports
  in and out; everything above it is OS-neutral. `passkeys` takes a site's
  id, a hash and an allow list and returns an assertion, and knows no HID
  or CTAP type, so a front end for an OS credential service sits over it
  without changing it. macOS lets a program create a HID device only under
  a restricted entitlement, so its front end is a credential-provider
  extension over `passkeys`, not a second `uhid.rs`.
- **Dependencies.** No new crate. `p256`, `ed25519-dalek` and `rsa` are in
  the tree through `ssh-key`; kpa names them directly, at the same
  versions, for their PKCS#8 parsing. `rsa` 0.10 is constant-time (T-22).
  The transport, the two CTAP2 messages and CBOR are kpa's own code: CTAP2
  allows a small canonical subset of CBOR (definite lengths, four levels of
  nesting), and the crates that implement an authenticator are async, tied
  to embedded hardware, or bring a credential store and key types of their
  own.

**Testing**

- **`passkeys`** alone: entries as each client writes them (the three
  algorithms, keys without line breaks, both flag spellings, the older
  attribute names), every skip reason, and assertions checked against the
  public key.
- **`security_key`** against a real `Databases`, with scripted prompts and
  an in-memory stand-in for the device at the lowest seam, the reports.
  The races are tests: a lock while a prompt is up, a `CANCEL` while a
  prompt is up, a lock between the approval and the signature, the display
  session locking mid-request.
- **Fuzzing**: the reports-to-request path (CTAPHID reassembly, CBOR, the
  two messages), and passkey entries (attributes and keys).
- **End to end**: a NixOS VM test in the flake's `checks` loads `uhid`,
  runs the daemon with a database of throwaway passkeys, and drives the key
  with `libfido2`'s tools, verifying each assertion against its public key.

## Sources

- [Web Authentication, Level 3](https://www.w3.org/TR/webauthn-3/)
- [Client to Authenticator Protocol 2.2](https://fidoalliance.org/specs/fido-v2.2-ps-20250714/fido-client-to-authenticator-protocol-v2.2-ps-20250714.html)
- [UHID, the kernel's user-space HID transport](https://docs.kernel.org/hid/uhid.html)
