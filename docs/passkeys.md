# kpa — passkeys

kpa signs in to websites with the passkeys stored in its databases, through
its own browser extension for Chromium and Firefox. The extension takes a
page's passkey requests, hands those kpa can answer to `kpa serve` through
a native messaging host the browser starts, and gives every other one back
to the browser untouched. A KeePass client creates the passkeys and kpa
uses them, as it does TOTP seeds and SSH keys.

**Not built yet.** This doc is the design the implementation follows.
Nothing in `src/` implements it, the extension doesn't exist yet, and the
other docs don't describe it. The steps are in [`TODO.md`](../TODO.md).

It follows the rules the SSH agent set ([`ssh-agent.md`](./ssh-agent.md)): a
database opts in, private keys never leave kpa, a use is approved on screen,
a locked database is unlocked on demand, and a lock ends everything. Prompt
timeouts and the screen-lock rules are [`headless.md`](./headless.md) § 6.

## 1. Overview

- **The extension takes the request.** It replaces the page's call for a
  passkey. A request for a site kpa has a passkey for goes to `kpa serve`;
  any other goes to the browser's own implementation, so hardware keys,
  phones and the browser's own passkeys work as they did.
- **Sign-in only.** kpa answers `get`, a signature over the site's
  challenge. It never registers a passkey: that would write the database,
  and kpa is read-only (§ 9). The extension leaves registration to the
  browser.
- **Autofill.** Under a username field marked for passkeys, the extension
  lists the site's accounts kpa holds, in a menu of its own that the page
  can't read (§ 6.4).
- **Databases opt in, and kpa finds the passkeys.** A database with
  `serve_passkeys = true` has every passkey among its entries served: the
  `KPEX_PASSKEY_*` attributes KeePass clients store one under (§ 4).
- **Every sign-in is approved on screen**, in a prompt that names the site
  and the account, and doubles as the account picker when a site has
  several. A per-site setting can ask once per unlock instead, or never
  (§ 5.3).
- **A locked database is unlocked on demand.** kpa caches a hash of each
  passkey's site and credential id, and nothing else, so it knows which
  locked databases to offer, beside the accounts of the unlocked ones. The
  unlock prompt names the site.
- **No prompt where nobody can see it.** Prompts appear on screen only, for
  a browser on the desktop. With no screen to ask on, kpa answers nothing
  and the browser carries on as if kpa weren't there.
- **kpa checks the origin.** The extension takes the page's origin from the
  browser, never from the page. kpa checks the site's id against it and
  writes the client data it signs (§ 6.3).
- **Private keys never leave kpa.** Only signatures do. `copy` refuses the
  attribute that holds one and `list` doesn't name it.
- **ES256, EdDSA and RS256**, through the RustCrypto crates the SSH agent
  already brings in. kpa implements no cryptography.

## 2. Use cases

**Served**

- Signing in from a Chromium-based or Firefox-based browser that has the
  extension: the site's "sign in with a passkey" button, with or without a
  username typed first, as the only factor or as a second one.
- Passkey autofill: picking an account from the extension's menu under the
  site's username field.

**Not served**

Each of these goes to the browser, which handles it as it would without
kpa.

- **Creating a passkey.** Registration happens in a KeePass client (§ 9).
- **More than a signature.** WebAuthn extensions such as `prf` (a site
  deriving an encryption key from the passkey) and `largeBlob` get no
  output from kpa. A site that needs one falls back or fails.
- **A sign-in from outside the desktop**, such as a browser in a remote
  desktop session ([`headless.md`](./headless.md) § 3): a sign-in is
  approved on screen or not at all (§ 5.3).
- **A request from an embedded frame** of another origin than the page's,
  and a site id that isn't the page's host or one of its parent domains
  (WebAuthn's related origins) (§ 6.3).
- **Programs other than a browser with the extension**: a browser without
  it, one whose sandbox can't start the host (§ 8), an application that
  embeds a browser engine, `libfido2`'s tools.
- **Passkeys kpa can't read**: an algorithm outside the three above, or a
  key that doesn't parse (§ 4.1). `kpa passkeys` says which and why.

**Machines without kpa** keep their KeePass client's browser integration
over the same synced vault. kpa changes nothing in the file.

## 3. Why a browser extension

A password manager reaches a browser at one of three layers:

| Route | How it works | For kpa |
| --- | --- | --- |
| Browser extension and native host | The extension replaces the page's `navigator.credentials` calls and forwards them to a local program | One extension for both browsers. It serves autofill, and leaves every other request to the browser |
| OS credential service | The browser asks a system service, which asks a registered provider | Linux's (`credentialsd`, the experimental Credential portal) has no provider interface a password manager can implement, and no browser calls it without an extension |
| Emulated security key | A virtual USB HID device speaks CTAP2 | Works with unmodified browsers, as a security key only |

kpa takes the first. The emulated key, turned down, would serve programs
other than browsers, at these costs:

- **No autofill.** A browser lists passkeys under a username field only
  from authenticators it can query silently, and it asks no USB key.
- **A system-level grant.** Creating the device needs `/dev/uhid`, which
  creates any HID device, a keyboard included, and which only root opens
  by default.
- **Refusals chosen around each browser.** A key that is always plugged in
  can't answer CTAP's "no credential", which ends the whole request in
  Chromium, hardware keys included, nor "denied", which Firefox answers by
  asking again with no limit. And Firefox with a hardware key also plugged
  in signs in with whichever key is touched, which an emulated key never
  is.
- **A device the system hands to whoever is at the seat**, so the key would
  have to come and go with the display session.
- **Code of kpa's own** for the USB transport, CTAP2 and its CBOR, all
  input from any process that opens the device.

Chromium also gives extensions a call that receives every WebAuthn request
the browser handles (`webAuthenticationProxy`), made for remote desktops.
Once an extension attaches, the browser handles no request itself, so none
could go to a hardware key, and Firefox has nothing like it.

What the extension costs:

- **An extension to write and ship**, in JavaScript, for two browsers and
  through their stores (§ 8). It runs in every page, and it stands in for
  part of a browser API that sites test against, so it follows WebAuthn as
  the API changes.
- **Pages can tell it is there.** The calls it replaces aren't the
  browser's own.
- **The origin is the extension's word.** For a security key the browser
  checks a site's id against the page; here kpa does, with the origin the
  browser gave the extension. Any process of the user can reach kpa's
  socket and claim one (§ 10).
- **One such extension per browser profile.** Another extension that
  replaces the same calls, as a KeePass client's own does, takes them from
  kpa's or loses them, depending on which installs its replacement last.
- **Sandboxed browsers** start a native host only through a desktop portal.
  The Firefox snap does; a Flatpak browser can't (§ 8).

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
config order of those unlocked, and a locked database isn't offered for a
credential an unlocked one already serves (§ 5.2).

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
  rewrites it. An unlock picked for it then finds nothing, and the sign-in
  is refused.
- A passkey added to the vault is known from the next unlock on.
- With no cache file yet, as on a fresh machine, a locked database answers
  nothing until its first unlock.
- Tampering with the file needs the user's uid. The most it does is offer
  the database's unlock for a site it has no passkey for.

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
| P3 | Sign-in to a site with passkeys in two databases, one of them locked | The account prompt: the unlocked database's accounts, and a line to unlock the other | Picking that line raises the unlock prompt, then as unlocked |
| P4 | Autofill: a page with a username field marked for passkeys | The extension's menu lists the accounts. One picked is approved as in P1 | The menu has a line to unlock the database. Picking it is P1 |
| P5 | A site kpa holds no passkey for | The browser handles it, with no prompt from kpa | The same: the cache has no hash for it |
| P6 | A registration | The browser handles it (§ 9) | The same |
| P7 | Screen locked, or no display session | kpa asks nothing and signs nothing; the browser handles the request | The same |
| P8 | Another program that reaches kpa's socket | Indistinguishable from P1, for whatever origin it claims | Indistinguishable from P1 |
| P9 | A browser without the extension, or that can't start the host | The browser handles everything | The same |

### 5.2 Which passkey answers

The extension's request names the page's origin and the site's id (its
relying party id), carries the challenge to sign, and may list the
credential ids the site accepts (the allow list, sent when the site already
knows the account). kpa works through it in this order:

1. **Who is asking.** A request from outside the desktop, or while the
   display session doesn't allow a prompt (§ 5.3), goes back to the
   browser at once. kpa doesn't look at the vault for it.
2. **The origin** is checked against the site's id (§ 6.3). A request that
   fails the check goes back to the browser, which refuses it or serves it
   by its own rules.
3. **Candidates** are the passkeys of unlocked, opted-in databases whose
   relying party equals the request's, byte for byte, and whose credential
   id is on the allow list if there is one. There is no subdomain or suffix
   matching: the site's id is what the passkey was made for.
4. **Locked databases on offer** are the locked, opted-in databases whose
   cache has the site's hash and, with an allow list, one of its ids'
   hashes, for a passkey that isn't a candidate already. A database whose
   unlock is already in progress isn't offered.
5. **With neither**, the request goes back to the browser, with no prompt.
6. **Approval** (§ 5.3) picks the one passkey that signs. With one
   candidate and no locked database on offer, it is the approval prompt,
   or nothing, as the site's `confirm` says. With one locked database and
   no candidate, it starts with that database's unlock prompt. Otherwise
   the account prompt lists them all: an account picked is approved, and a
   database picked raises its unlock prompt. A request from the autofill
   menu names what the user picked there, and that alone is on offer.
7. **After an unlock**, the request goes on from step 3 with that
   database's passkeys alone. The approval follows, for the account the
   database really holds.
8. **The signature** is made (§ 5.4) if the database is still in the unlock
   the approval was for. A lock in between refuses the request.

A locked database is offered beside the unlocked ones, not only when they
have nothing for the site: the account this sign-in is for may be in
either, and only the user knows which. kpa can't name a locked database's
accounts, so its line names the database. One whose cached passkeys for
the site are all candidates already has nothing to add, and isn't offered.

**Unlock on demand** is the unlock `kpa unlock` runs, with the same
`prompt` in the same queue, and the four steps every front end follows
([`design.md`](./design.md) § Unlocking): take the database's unlock and
its token, check that the display session allows a prompt, ask, finish. The
question says what for: `Unlock database personal to sign in to
github.com?`. Answering it approves nothing; the approval follows.

### 5.3 Approval

A per-site setting, `confirm`, decides when a sign-in asks:

- `"always"` (default): every sign-in asks.
- `"once"`: the first sign-in with a passkey after each unlock asks. The
  approval holds until the database locks, and is for that passkey, not for
  the site's other accounts.
- `"never"`: a sign-in never asks.

With more than one choice, candidates or locked databases on offer, the
account prompt always appears, whatever their `confirm`: choosing is the
question. So `"once"` and `"never"` change something only where one
passkey can answer and no locked database is on offer.

**The prompt.** `passkeys.confirm_prompt` is an argv with the contract of
the SSH agent's `confirm_prompt` ([`ssh-agent.md`](./ssh-agent.md) § 6.7):
kpa writes the choices on stdin, one per line, and reads the chosen line
from stdout. A non-zero exit, or any other output, means deny. The question
is in `KPA_PROMPT_MESSAGE` and its pieces in `KPA_PROMPT_DATA`. One program
can serve both settings. It is required once a database has
`serve_passkeys = true`: without it `kpa serve` refuses to start.

| Request | Message | Choices |
| --- | --- | --- |
| One candidate | `Approve sign-in to github.com as "alice"?` | `Allow`, `Use another authenticator`, `Deny` |
| Several candidates, or locked databases on offer | `Sign in to github.com with which account?` | One line per account, `alice [personal]`, one per locked database, `Unlock work`, then `Use another authenticator` and `Deny` |
| An account picked in the autofill menu | `Approve sign-in to github.com as "alice"?` | `Allow`, `Deny` |

An account line is the account name and its database, and a locked
database's line is `Unlock` and its name. Two lines that would be equal are
numbered (`alice [personal] (2)`), so every line is distinct and none can
equal `Deny`. The answer is matched against the lines kpa wrote, never
parsed.

**`Use another authenticator`** hands the request back to the browser, as
if kpa had no passkey for the site: the extension takes every request
before the browser does, so this is how a site that also has the user's
hardware key or phone reaches them. A request from the autofill menu
doesn't offer it: the user has already picked kpa's account.

`KPA_PROMPT_DATA` has the members `relying_party`, the site's id,
`origin`, the page's origin, and `accounts`, a list of `{"name",
"database"}` in the order of the lines (one element for an Allow/Deny
prompt), and `unlock`, the names of the locked databases on offer, in the
order of their lines after the accounts'. The unlock prompt has
`database`, `relying_party` and `origin`. Every piece that isn't kpa's own
text (the site's id, the origin, an account name, a database name) is
escaped as the SSH agent's prompt pieces are, and each has its own length
budget. The site's id is never cut.

**Where prompts may appear.** On screen only, for a requester on the
desktop, and only while there is a display session that isn't known to be
locked. The requester is the host the browser starts (§ 6.6), which runs in
the browser's own cgroup, so it is classified as `control` classifies its
peers ([`headless.md`](./headless.md) § 3). A request that may not prompt
goes back to the browser (§ 5.2, step 1). The display session is read after
the unlock's token is taken, the order every unlock keeps. There is no
pending list and no approval from a terminal. A prompt is ended by its
timeout (`prompt_timeout` for the unlock, `passkeys.confirm_prompt_timeout`
for the approval), by a lock of its database, and by the page or the
browser ending the request (§ 6.5). Unlock and approval prompts share the
one prompt queue, with the SSH agent's and `kpa unlock`'s.

### 5.4 The assertion

kpa answers with one assertion, for the passkey the approval picked:

- **Client data**: the JSON object the site checks, written by kpa: the
  type `webauthn.get`, the challenge, the page's origin as kpa checked it,
  and `crossOrigin` false, in the order and form WebAuthn's serialization
  gives. Its SHA-256 is the hash the signature covers.
- **Authenticator data**: the SHA-256 of the site's id, the flags, and a
  signature counter of 0. Passkeys that sync between devices report 0
  always and sites accept it, so no sign-in needs a write.
- **Flags**: user present and user verified are both set on every sign-in.
  Backup-eligible and backed-up come from the entry (§ 4.1), so a site sees
  the same flags from kpa as from the client that made the passkey.
- **The signature** over the authenticator data and the client data's
  hash: ASN.1 DER for ES256, the raw 64 bytes for EdDSA, PKCS#1 v1.5 with
  SHA-256 for RS256.
- **The user handle**, from the entry.

The extension gives the page these with the credential id, as the
`PublicKeyCredential` a browser would: attachment `platform`, as KeePass
clients' extensions report, and no extension outputs.

**What "user verified" rests on.** Sites that accept a passkey as the only
factor require the flag. kpa's basis is the unlocked database: the user
gave its master password for this unlock, and the database has been under
kpa's lock policy since. kpa doesn't verify the user again for each
sign-in, and with `"once"` or `"never"` it sets both flags without asking
anything. KeePass clients set them the same way.

### 5.5 Lock, idle and the log

- **Lock** drops the database's `"once"` approvals, kills a prompt on
  screen for it, and refuses a sign-in whose database locked after it was
  approved.
- **Freshness.** The freshness guard runs before each read of a database,
  as it does for `copy` (G-8).
- **Idle.** A sign-in the user approved on screen resets its database's
  idle timer. One that asked nothing (`"once"` already approved, `"never"`)
  doesn't, and neither does an autofill listing or a refusal: nothing that
  can reach the socket keeps a database unlocked without a person
  answering.
- **The log** has one line per sign-in and per sign-in refused after a
  prompt: the site's id, the database, the outcome, and whether it asked.
  Never the account name, the entry's title or the credential id. An
  autofill listing, and a request kpa hands back to the browser, are logged
  at `debug` only: the extension sends kpa every site's requests.

## 6. The browser extension

### 6.1 What runs where

```
page ──── navigator.credentials.get ────▶ page script      (the page's world)
                                              │ DOM events
                                          content script   (the extension's world)
                                              │ extension messages, with the sender's origin
                                          background
                                              │ native messaging: stdin and stdout
                                          kpa browser-host
                                              │ $XDG_RUNTIME_DIR/kpa/browser
                                          kpa serve        (frontends::browser)
```

- **The page script** runs in the page's own JavaScript world, installed
  before any of the page's scripts run (a content script in the main world,
  at `document_start`). It replaces the calls of § 6.2, keeps the
  browser's originals, and calls them for every request kpa doesn't take.
  It holds nothing the page couldn't: the page's own request, and the
  answer the page gets.
- **The content script** runs in the extension's isolated world, in every
  frame. It relays between the page script and the background, and places
  the autofill menu (§ 6.4).
- **The background** (a service worker in Chromium, an event page in
  Firefox) is the one part that talks to kpa. It adds the frame's origin
  and the tab's, from the browser's own record of who sent the message,
  and opens one native port per request.
- **The host**, `kpa browser-host`, is started by the browser for each
  port. It relays messages between the browser's pipes and kpa's socket
  without reading them, and exits when the port closes (§ 6.6).
- **`kpa serve`** answers through its `browser` front end.

The page can see and send the DOM events between the page script and the
content script. That gives it nothing: everything on that path is the
page's own request and the answer to it. The origin is never taken from
it, and account names never cross it.

The extension's toolbar button says whether kpa answers: reachable, not
reachable (no host installed, `kpa serve` not running, or no database that
serves passkeys), or speaking another version of the socket's protocol.

### 6.2 Which calls kpa takes

| Call | What the extension does |
| --- | --- |
| `navigator.credentials.get` with `publicKey`, from the site's button (`mediation` absent, `optional` or `required`) | Asks kpa (§ 5.2). If kpa hands it back, calls the browser's own `get` with the same options |
| The same with `mediation: "conditional"` | Asks kpa for the site's accounts and shows the autofill menu (§ 6.4), or calls the browser's own when kpa has none |
| `get` with `mediation: "silent"`, or without `publicKey` (passwords, federated sign-in) | The browser's own |
| `navigator.credentials.create` and `store` | Not replaced: the browser's own |
| `PublicKeyCredential.isConditionalMediationAvailable()` | `true` |
| `PublicKeyCredential.getClientCapabilities()` | The browser's own answer, with `conditionalGet` set |

The page script hands the browser, without asking kpa, every request from a
page that isn't a secure context and every request from a frame whose
origin isn't the top-level page's.

When the page script calls the browser's own `get` after kpa had the
request, it first waits for the page to have the focus again: Firefox
refuses a WebAuthn call from a page without it, and kpa's prompt has just
had it.

### 6.3 The origin

- **From the browser.** The background takes the frame's origin and the
  tab's top-level origin from the browser's description of the message's
  sender, which a page can't write, and sends both to kpa.
- **What kpa serves.** An `https` origin, or `http://localhost`; a frame
  whose origin is the top-level page's; and a site's id that equals the
  origin's host or is one of its parent domains, on a label boundary
  (`github.com` from `gist.github.com`, never from `evilgithub.com`).
  Anything else goes back to the browser, which refuses it or applies its
  own rules, such as related origins.
- **No public suffix list.** A browser doesn't let a page use a public
  suffix (`co.uk`) as its site's id, so no passkey a browser made has one.
  An entry planted with such an id holds a key its author made, so a
  signature with it gives nothing away.
- **The client data names the origin** kpa checked (§ 5.4), so a site
  rejects an assertion relayed from a page of another origin.

### 6.4 Autofill

- **The request.** A page asks for autofill with a conditional `get`, and
  marks a field `autocomplete="username webauthn"`. The extension asks kpa
  for the site's accounts: the account names and databases of its
  candidates, and the locked databases on offer, the same lines the account
  prompt shows. The listing needs the same requester and screen as a
  prompt (§ 5.3, step 1 of § 5.2), raises no prompt, and counts as no
  activity.
- **Nothing for the site**: the extension hands the request to the
  browser, so the browser's own suggestions appear.
- **The menu.** Otherwise, when the field has the focus, the content script
  places the menu under it: a page of the extension's in a frame, which the
  page can neither read nor script. The names go from the background to
  that frame directly, never through the page.
- **Picking.** An account picked sends kpa a sign-in for that passkey
  alone, approved as § 5.3 says, and a locked database's line sends its
  unlock. The page's pending `get` resolves with the assertion. Escape, or
  leaving the field, closes the menu, and the request stays pending, as the
  page expects of a conditional request.
- **The extension's own menu**, because neither browser lets an extension
  add a line to the browser's autofill list.

### 6.5 Cancelling, timeouts and errors

- **The page ends the request** (its `AbortSignal`, a navigation, a closed
  tab): the background closes the native port, the browser stops the host,
  the host's connection to kpa closes, and kpa ends the prompt for that
  request. A prompt never outlives its page.
- **The page's `timeout`** is the extension's too: when it runs out the
  extension ends the request the same way. kpa's own prompt timeouts apply
  inside it.
- **Errors.** A refusal (a deny, a prompt that timed out or couldn't run, a
  lock first) reaches the page as `NotAllowedError`, the error WebAuthn
  gives when the user declines. An abort is `AbortError`. A request handed
  back to the browser gets whatever the browser answers.

### 6.6 The host and kpa's socket

- **Starting the host.** The browser starts the program a host manifest
  names, and only for the extensions it lists (§ 8). It gives the program
  arguments of its own: the extension's origin in Chromium, the manifest's
  path and the extension's id in Firefox.
- **Relaying.** Native messaging frames are a 32-bit length in the
  machine's byte order and that many bytes of UTF-8 JSON, at most 1 MB
  toward the browser. The host sends each frame's JSON as one line on a
  new connection to `$XDG_RUNTIME_DIR/kpa/browser`, and the answer back as
  a frame.
- **The socket** follows the control socket's rules
  ([`protocol.md`](./protocol.md) § Connections): mode 0600, only the
  daemon's uid, line-delimited JSON, one request and one response per
  connection, a request line capped at 64 KiB. A sign-in's connection stays
  open until its answer, and its closing ends the request. The socket
  exists while a database has `serve_passkeys = true`; failing to bind it
  stops `kpa serve`, as the agent's socket does.
- **The version.** `v` is this protocol's own. The extension updates from
  its store and kpa from its package, so the two can differ: a request
  with another version is answered with the one kpa speaks, and the
  extension hands every request to the browser until they match.

| Request | Carries | Answer |
| --- | --- | --- |
| `accounts` | the origin, the top-level origin, the site's id, the allow list | the account lines and the locked databases on offer, possibly none |
| `sign_in` | the same, the challenge, and what the autofill menu picked, if it did | the assertion (§ 5.4), `refused`, or `to_browser` |

`to_browser` is the answer for every request kpa doesn't take: one from
outside the desktop or without a screen, one that fails the origin check,
one for a site kpa has no passkey for, and `Use another authenticator`.
The extension can't tell these apart.

### 6.7 Browser versions

Chromium 111 and Firefox 128 are the first that run a content script in
the page's own world, which the page script needs.

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

## 8. Installing the extension

kpa needs nothing from the system: no group, rule or kernel module. Three
things are installed per user:

1. **The extension**, in each browser profile: from the Chrome Web Store,
   from addons.mozilla.org, or unpacked from the repo's `extension/` in
   Chromium's developer mode. Firefox installs only an extension Mozilla
   has signed, except in its Developer Edition, Nightly and ESR builds with
   that check turned off.
2. **A host manifest**, `kpa.json`, in each browser's own directory for
   them: `~/.mozilla/native-messaging-hosts/` for Firefox,
   `~/.config/chromium/NativeMessagingHosts/` and
   `~/.config/google-chrome/NativeMessagingHosts/` for Chromium and Chrome.
   Other Chromium-based browsers each have their own. It names the host
   program by absolute path, and the extension that may start it.
3. **The host program**, a wrapper that runs `kpa browser-host`: a browser
   starts the program with arguments of its own and none of kpa's.

The extension's id is fixed, so the manifests can name it: Firefox's by the
id in the extension's manifest, Chromium's by the public key it carries.
The home-manager module writes the host manifests and the wrapper for the
browsers it is told of, behind one option. Installing the extension in a
profile is the user's step.

**Sandboxed browsers.** The Firefox snap starts a native host through the
desktop portal, which reads the manifests in
`~/.mozilla/native-messaging-hosts/` and runs the host outside the sandbox.
A Flatpak browser has no such path: its extension can't start the host,
and the browser handles every request itself. This is the state of both as
of November 2026.

**Day to day**

| Action | What happens |
| --- | --- |
| "Sign in with a passkey" on a site, vault unlocked | kpa asks `Approve sign-in to github.com as "alice"?`. Allow signs in. No browser dialog opens |
| The same, vault locked | kpa asks `Unlock database personal to sign in to github.com?`, then for the approval |
| A site with two accounts | kpa asks `Sign in to github.com with which account?` and lists them |
| The username field of a site kpa has a passkey for | The extension's menu lists the accounts; one picked is approved as above |
| A site with `confirm = "once"`, used earlier in this unlock | The sign-in goes through with no prompt |
| A site whose passkey is on a hardware key or a phone | kpa has none for it, and the browser's own dialog opens |
| A site with one in kpa and one on a hardware key | Pick `Use another authenticator` to reach the hardware key |
| Registering a passkey | The browser's own dialog opens, as without kpa. To have kpa serve it, create it in a KeePass client: on a phone, or in a browser profile with the client's own extension instead of kpa's |
| Screen locks | kpa has locked everything, and leaves requests to the browser until it unlocks |

## 9. Registration

kpa never creates a passkey. Registering one means storing a new private
key, and kpa writes no database: read-only is what makes it safe to run
next to a KeePass client that has the same file open
([`design.md`](./design.md) § Scope, G-1). So `serve_passkeys` adds no write
path, the extension doesn't replace `navigator.credentials.create`, and no
type or setting exists for registration. A site's registration reaches the
browser as if kpa weren't installed.

What registration would take, and why each part is out of reach of this
design: `keepass` built with its save feature, which the read-only
guarantee rests on leaving out; a way to save without losing what another
client wrote to the same file meanwhile; and a threat model in which a
request from the browser can change the vault. `TODO.md` lists it as an
idea.

## 10. Claims

What this design claims and what it accepts, in the terms of
[`threat-model.md`](./threat-model.md), which doesn't carry them yet.

**The boundaries.** kpa's browser socket, whose untrusted side is every
process of the user: the host a browser starts, and anything else running
as the user. And, inside the browser, the page, whose untrusted side is
everything it sends the page script. Requests are untrusted bytes on both.

**Claims**

- **Read-only holds** (G-1). No request writes a database. The one file kpa
  writes for passkeys is the cache of hashes, in its own cache directory.
- **A passkey's private key never leaves the process** (G-3). Only
  assertions do, only through the browser socket, only for databases that
  opt in. `copy` and `list` treat the attribute as absent in every
  database.
- **A sign-in needs an unlocked database that opts in, and the approval its
  site's `confirm` asks for.** By default that is a prompt naming the site
  and the account for every sign-in. An on-demand unlock is a prompt the
  user answers. Vault content cannot change a site's policy.
- **The origin is the browser's, and kpa checks it** (§ 6.3). A page can't
  name its own origin, and gets no signature for a site its origin isn't
  under. The client data kpa signs names that origin.
- **A page gets only the answer to its own request.** Account names reach
  the extension's menu frame, never the page. A refused request tells the
  page nothing beyond the refusal, and a request handed back to the browser
  looks to it as if kpa weren't installed.
- **No prompt where nobody can see it** (G-12). Prompts are on screen only,
  for a requester on the desktop, never while the screen is known to be
  locked, and kpa signs nothing then, `"never"` passkeys included.
- **A lock ends it** (G-5, G-6). Approvals and open prompts go with the
  database, and kpa keeps no parsed key between sign-ins.
- **Nothing from a vault is persisted but hashes** (G-4): the cache holds
  the two hashes of § 4.3. The extension stores nothing.
- **The socket's input is only data** (G-11). Requests are bounded, a
  malformed or flooding client is refused without crashing the daemon, and
  the decoder is fuzzed. The host relays bytes it doesn't read. A passkey
  entry is file input like any other (G-9): a crafted key is skipped.

**Accepted**

- **Any process of the user can reach the socket and ask for a sign-in,
  for any origin it claims** (NG-1, T-18). What it gets is what the site's
  `confirm` allows: a prompt the user sees by default, a silent signature
  for a `"once"` passkey already approved and for every `"never"` one. The
  prompt is visibility, not a boundary, inside the uid.
- **Any process of the user can list a site's accounts** while a database
  that holds them is unlocked and the screen allows a prompt, as `list`
  lists every entry's username.
- **The extension is trusted inside the browser.** It sees every passkey
  request a page makes, the assertions, and the account names it lists. A
  compromised extension, such as a malicious update through a store, gets
  those, never a private key.
- **The browser is trusted for the origin**, as it is by every security
  key and every extension. The prompt shows the site's id kpa signs for,
  and a look-alike domain has no passkey in the vault to match.
- **Pages can tell the extension is installed** (§ 3).
- **Whoever writes entries in a served database can add an account.** An
  entry planted in a shared vault shows up as one more account for its
  site, in the prompt and in the autofill menu, under the name its author
  chose (ACT-4).
- **Prompts on demand** (NG-7, NG-8). Only a request for a site the vault
  or a cache has a passkey for raises one, one at a time, with timeouts.
  There is no backoff: no browser repeats a refused sign-in by itself.
- **The log names sites.** A sign-in's line has the site's id (§ 5.5).
- **"User verified" is the unlocked database** (§ 5.4), not a check per
  sign-in.

## 11. Code

Two subsystems ([`module-structure.md`](./module-structure.md)), small
additions to two others, and the extension.

| Subsystem | Is | Uses |
| --- | --- | --- |
| `passkeys` | what `control` and the browser front end share about passkeys: finding them in an open database, the cache of hashes, making an assertion | `databases` (reads only), `config`, `paths` |
| `frontends::browser` | the extension's side in the daemon: the socket and its protocol, the origin check and the client data, the sign-in flow, the autofill listing, the `"once"` approvals, and the host | `databases`, `passkeys`, `authn`, `authz`, `prompt`, `display_session`, `config`, `paths` |

```
src/
  passkeys/
    mod.rs              Passkey, and what the subsystem exports
    find.rs             finding passkeys in an open database; why an entry is skipped
    key.rs              the private key: PKCS#8 in, a signature out
    assertion.rs        authenticator data and the signed assertion
    cache.rs            the cache of hashes
  frontends/browser/
    mod.rs              the socket: one connection, one request
    proto.rs            requests and answers
    origin.rs           the page's origin against the site's id
    client_data.rs      the client data kpa signs
    sign_in.rs          the sign-in flow (§ 5.2)
    accounts.rs         the autofill listing
    approvals.rs        "once" approvals, per database and unlock
    prompts.rs          the questions and their data
    host.rs             kpa browser-host: frames in and out, one connection each
extension/
  manifest.json         one source; each browser's package differs only where it must
  page.js               the replaced calls, in the page's world
  content.js            the relay, and the autofill menu's frame
  background.js         one native port per request; the sender's origin
  menu.html, menu.js    the autofill menu
```

- **`databases`** gains one read on `Open`: the current entries outside the
  recycle bin that have a given attribute. Which entries are in the bin is
  the core's to know.
- **`control`** gains the `passkeys` request and its report, and leaves the
  private-key attribute out of `list` and `copy` (§ 4.2).
- **Lock state.** The browser front end's approvals are an observer,
  registered with the others that hold what must die with a lock. The cache
  is written by an observer of `passkeys` that hears `unlocked`.
- **Portability.** The socket, the host and the extension are OS-neutral.
  On macOS the host manifests have other directories and the socket's path
  comes from `paths.rs`, so Chromium and Firefox there use the same code.
  Who is asking goes through the request-origin seam
  ([`portability.md`](./portability.md)). `passkeys` takes a site's id, a
  hash and an allow list and returns an assertion, and knows nothing of
  browsers, so a front end for an OS credential service sits over it
  without changing it.
- **Dependencies.** No new crate. `p256`, `ed25519-dalek` and `rsa` are in
  the tree through `ssh-key`; kpa names them directly, at the same
  versions, for their PKCS#8 parsing. `rsa` 0.10 is constant-time (T-22).
  The extension uses no libraries, and its packages are its files as
  written, so what is reviewed is what ships.

**Testing**

- **`passkeys`** alone: entries as each client writes them (the three
  algorithms, keys without line breaks, both flag spellings, the older
  attribute names), every skip reason, and assertions checked against the
  public key.
- **The browser front end** against a real `Databases`, with scripted
  prompts, through its socket: the origin rules, the client data's bytes,
  each step of § 5.2. The races are tests: a lock while a prompt is up, a
  connection closed while a prompt is up, a lock between the approval and
  the signature, the display session locking mid-request.
- **The host**: frames in and out against a socket, an oversized frame, a
  pipe closed mid-request.
- **The extension**, with Node's own test runner and no other tool: which
  calls go to kpa and which to the browser, the objects a page receives
  (`instanceof PublicKeyCredential`, `toJSON()`), aborts and timeouts.
- **Fuzzing**: the socket's requests, and passkey entries (attributes and
  keys).
- **End to end**: a NixOS VM test in the flake's `checks` runs a browser
  with the extension against a test site in the VM, signs in from an
  unlocked database, from one unlocked on demand, through the autofill
  menu, and with a deny, and verifies each assertion against its public
  key.

## Sources

- [Web Authentication, Level 3](https://www.w3.org/TR/webauthn-3/)
- [Native messaging (MDN)](https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/Native_messaging)
- [Native messaging (Chrome)](https://developer.chrome.com/docs/extensions/develop/concepts/native-messaging)
