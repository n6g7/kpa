# kpa — passkeys (proposal)

kpa holds `.kdbx` files unlocked and copies secrets out of them. This
proposal adds a second way out: signing in to websites and apps with the
passkeys stored in those files, so that a browser can use kpa as its
authenticator.

This is a proposal: nothing here is built, and none of it has been tried
against a real browser. Several external facts below come from secondary
sources and are marked as such in § 10. It changes the "no operation
returns a secret" framing in [`design.md`](./design.md) and extends
[`threat-model.md`](./threat-model.md). § 8 lists those edits.

## 1. Summary

- **kpa signs in; it doesn't register.** Sign-in (`get`) reads a stored
  private key and signs a challenge. Registration (`create`) has to store
  a new key, which is a write. kpa refuses it, so the browser falls back
  to another authenticator, and passkeys are created in KeePassXC or
  Strongbox (§ 3).
- **The private key never leaves the daemon.** kpa signs internally, the
  way it generates TOTP codes from the seed. No operation returns a key
  or a signature to a same-uid client other than the front end that is
  serving the ceremony (§ 4).
- **Every use is confirmed on screen, naming the site and the account.**
  Anything running as the user can ask a virtual authenticator for a
  signature; the prompt is the defence (§ 5).
- **The platform front end is a thin adapter around a shared core.** On
  Linux, the first front end is an emulated USB security key; the
  desktop credential service (`credentialsd`) is the later one. On macOS,
  the only supported route is a credential-provider app extension (§ 6,
  § 7).

## 2. Background: how a passkey sign-in works

Three parties take part:

- The **relying party** (the website) identifies itself by an rpId such as
  `github.com`, and sends a random challenge.
- The **client** (usually the browser) adds the origin it checked, hashes
  the lot into `clientDataHash`, and forwards the request.
- The **authenticator** holds the private keys. It finds a credential for
  the rpId, checks the user is present (UP) and optionally verified (UV),
  signs `authenticatorData ‖ clientDataHash`, and returns the assertion.

An authenticator does two things:

| Operation | Does                                                           | Writes the vault? |
| --------- | -------------------------------------------------------------- | ----------------- |
| `create`  | Generates a keypair, stores it with rpId, user handle, username | Yes               |
| `get`     | Finds credentials for the rpId, confirms, signs                | No                |

The sign counter in `authenticatorData` is the only state `get` would
update. Synced passkeys (the multi-device kind) report a counter of 0
always, which relying parties accept, so kpa needs no write there.

A password manager reaches the browser at one of three layers:

1. **A browser extension** replaces `navigator.credentials.create/get` in
   the page and forwards to a native host. KeePassXC-Browser and Bitwarden
   work this way. It covers browsers with the extension and nothing else.
2. **An OS credential-provider API.** The browser asks the OS, the OS
   shows a picker, and a registered provider supplies the credential.
   macOS, iOS, Android and Windows 11 work this way. It also covers
   native apps.
3. **An emulated hardware key.** The software presents itself as a FIDO2
   security key and speaks CTAP2. The browser needs no changes.

## 3. What kpa reads

KeePassXC stores a passkey as attributes on an ordinary entry:

| Attribute                      | Content                                  |
| ------------------------------ | ---------------------------------------- |
| `KPEX_PASSKEY_CREDENTIAL_ID`   | The credential id                        |
| `KPEX_PASSKEY_PRIVATE_KEY_PEM` | Private key, PKCS#8 PEM (protected)      |
| `KPEX_PASSKEY_RELYING_PARTY`   | The rpId                                 |
| `KPEX_PASSKEY_USERNAME`        | The account name                         |
| `KPEX_PASSKEY_USER_HANDLE`     | The WebAuthn user handle                 |
| `KPEX_PASSKEY_FLAG_BE`, `_BS`  | Backup-eligible and backup-state flags   |

The algorithm is carried by the key's OID. ES256, EdDSA and RS256 appear
in KeePassXC's documentation. kpa starts with ES256 and EdDSA and reports
an unsupported algorithm as "no credential" (RS256 later, if an entry
needs it).

Strongbox has said it intends to follow this format. kpa should read a
Strongbox-created entry before relying on that (§ 10).

**Registration.** Three options:

- **(a)** kpa signs in only. New passkeys come from KeePassXC or
  Strongbox. This matches how TOTP works: kpa reads what another client
  wrote.
- **(b)** kpa registers. This breaks G-1 and the defining property in
  `design.md`.
- **(c)** kpa answers `create` with "not supported" so the browser offers
  another authenticator.

Recommendation: (a) with (c).

## 4. The signing core

The core is independent of the platform. Its operations:

1. **Match.** Given an rpId and, optionally, a list of allowed credential
   ids, find entries in unlocked databases whose `KPEX_PASSKEY_RELYING_PARTY`
   equals the rpId exactly. No suffix or subdomain matching: the rpId was
   already validated against the origin by the client.
2. **Choose.** Zero matches: "no credential". One or more: ask the user
   (§ 5), which doubles as the account picker.
3. **Sign.** Build `authenticatorData` (rpIdHash, flags UP | UV when
   appropriate | BE | BS from the entry, counter 0), sign with the key
   parsed from the PEM, return the assertion.

The key is parsed from the entry for each signing and the parsed copy
zeroized afterwards. Nothing about keys is cached in the daemon beyond
what the unlocked database already holds, so a lock (G-5, G-6) ends
availability with no extra work.

**Library.** 1Password's `passkey-rs` crates implement the authenticator
side of WebAuthn and CTAP2 in Rust, and are worth evaluating before
writing it by hand. The point to check is whether they let the key stay in
kpa's zeroizing memory rather than requiring their own store.

**Protocol.** The core is reached through the daemon, not a new socket. It
adds ops (names provisional) `passkey_match` and `passkey_assert`, used
only by the front ends in § 6 and § 7. `assert` returns a signature to its
caller, which is the first protocol response derived from A-2 key
material. It carries nothing that lets a caller recover the key. § 8 lists
the threat-model change.

## 5. Confirmation

A signature is only released after an on-screen confirmation raised by the
daemon, through the existing prompt mechanism, showing:

- the rpId, and the origin if the front end knows it;
- the username on the chosen entry;
- when several entries match, a list to choose from.

Reasons:

- **Any process running as the user can talk to a virtual authenticator.**
  A hidraw device node (§ 6) or the credential service's session-bus name
  is reachable by same-uid code in every sandbox that hasn't been denied
  it. A physical key has the same exposure, where the touch is the check.
  The prompt is kpa's touch.
- **Showing the rpId defends against a confused front end.** The prompt
  shows what kpa is about to sign for.
- **Unlocking the database is not consent for one site.** UV is set only
  after the prompt, never from the unlock.

The confirmation reuses the rules from [`headless.md`](./headless.md): it
is not raised while the screen is known to be locked, it times out, and a
lock kills it. A request that arrives with nobody to ask is refused.

Whether the prompt program can show structured text (rpId, username) the
way `fuzzel --dmenu` does for a list, rather than only collect a password,
is open (§ 10). The existing prompt is built for passwords.

## 6. Linux

### 6.1 Emulated security key (first front end)

kpa creates a virtual HID device through `/dev/uhid` and speaks CTAP2 over
it. Browsers and `libfido2` see a plugged-in security key, so no browser
change is needed. The browser shows its security-key flow, not a passkey
picker. It works today, and it's clunky in that way.

Costs:

- **Device access.** `/dev/uhid` is root-owned by default. A udev rule
  (or group membership) is needed, and the systemd unit's
  `DeviceAllow`/`PrivateDevices` settings in `nix/hm-module.nix` must be
  loosened for that one device.
- **The device is reachable by every same-uid process** (§ 5).
- **Capabilities.** The virtual key advertises resident credentials and
  the PIN-less verification kpa can honestly provide. It must not
  advertise attestation of anything it does not do.
- **Discoverable credentials.** A browser asking for a discoverable
  credential with no allow list gets every matching entry for the rpId,
  through the § 5 picker.

### 6.2 `credentialsd` (later front end)

The Credentials for Linux project builds `credentialsd`, a D-Bus service
that browsers call, and a proposed XDG portal. Per its tracker, support
for third-party password-manager providers is still being designed and
Firefox support is under review, so there is no stable provider interface
to build against. When one exists, kpa would claim a name on the session
bus and implement the provider interface with `zbus`, which kpa already
uses for logind and the tray. This is the Linux counterpart of the macOS
extension: the system calls a fixed API, kpa answers. No bundle or signing
is involved.

Until it lands, the core should sit behind an interface that does not
assume the CTAP2 framing, so both front ends can call it.

### 6.3 Rejected

- **Own browser extension and native host.** It rebuilds KeePassXC-Browser
  per browser, adds a native-messaging channel, and `background.md` already
  sets full browser-protocol reimplementation aside.

## 7. macOS

The supported route is an `ASCredentialProviderExtension`
(AuthenticationServices): an app extension in a signed `.app`, which the
user enables under System Settings → General → AutoFill & Passwords.
Safari, Chromium-based browsers and native apps all route through it.

- **Shape.** The extension is a short-lived sandboxed process the OS starts
  per request. It is a thin Swift layer that forwards to a long-running
  daemon and returns the assertion. The signing stays in Rust.
- **Reaching the daemon.** The sandbox does not allow connecting to
  arbitrary Unix sockets. The two standard routes are a socket in an App
  Group container shared with the extension, or an XPC service published
  by a launchd agent. Both need the daemon inside the same signed bundle
  or team.
- **Signing and entitlements.** The credential-provider entitlement and
  code signing in practice mean an Apple Developer account. A Nix-built
  loose binary cannot be the provider.
- **Identity store.** The extension can publish rpIds and usernames to
  `ASCredentialIdentityStore` so the system picker lists them without
  launching it. That writes the OS store, not the `.kdbx`, and exposes
  A-3-class metadata to the OS (§ 8).
- **Overlap.** Strongbox is already a provider on macOS for the same
  vaults. A kpa provider is justified only if kpa replaces Strongbox
  there, which the SSH agent proposal's macOS section also depends on.

macOS is therefore a later phase, tied to the broader macOS port, not a
prerequisite for Linux.

## 8. Changes to existing docs

- **`design.md`**
  - § Scope and settled decision 4: the daemon signs on a user's behalf
    and returns the signature, as well as copying.
  - § Protocol: `passkey_match` and `passkey_assert`.
  - § Configuration: whether passkeys are on, per database.
  - § Dependencies: an authenticator library, `/dev/uhid` access.
- **`threat-model.md`**
  - **A-2** gains passkey private keys. **A-3** gains rpIds and
    usernames.
  - **G-3** gains: a passkey private key never leaves the process. An
    assertion is released only after the confirmation in § 5, and
    includes only a signature over the challenge.
  - **New goal: no signature without confirmation.** Every assertion
    follows an on-screen confirmation naming the rpId, in the same
    process that signs.
  - **New boundary: the front end** (uhid device or `credentialsd` bus
    name). Untrusted side: any same-uid or sandboxed process able to reach
    it (ACT-6, ACT-10).
  - **New threat: signature for a site the user didn't intend.** A
    process asks the virtual key for an assertion for an rpId. Response:
    the confirmation names the rpId. Residual: a browser that forwards a
    wrong rpId is the client's bug, not kpa's; a user who approves any
    prompt (T-18 applies).
  - **NG-1** unchanged: persistent same-uid code can wait for an
    approval or read the `.kdbx`.
  - **ASM-3**: the front end's device permissions (`/dev/uhid` rule) are
    the user's.
- **`config.example.toml`**: the passkey toggle.
- **`TODO.md`**: this proposal is the "Passkey provider" entry.

## 9. Implementation

**Phases**, each leaving a usable state:

1. Read side: parse `KPEX_PASSKEY_*` attributes, match by rpId, expose the
   matches in `list`'s `fields`-style metadata without values. Fixtures
   made with KeePassXC.
2. Core: assertion signing for ES256 and EdDSA, unit-tested against
   published WebAuthn test vectors, plus the confirmation.
3. Linux uhid front end, `create` refused with a clean error.
4. `credentialsd` provider, when its interface is stable.
5. macOS extension, with the macOS port.

**Testing limits.** The development machine is macOS and kpa builds on
Linux only, so phases 3 and 4 can't be exercised here. The core in phases
1 and 2 is platform-independent and can be tested with fixtures and
vectors anywhere it builds. Front-end testing needs a Linux machine and a
real browser, and a Linux CI job can drive the uhid device with
`libfido2`'s tools without a browser.

**Fuzzing.** The PEM and entry parsers join the existing fuzz targets: a
crafted `.kdbx` (ACT-3, ACT-4) supplies the key bytes.

## 10. Open questions

1. **Strongbox's format.** Does it read and write `KPEX_PASSKEY_*`? The
   evidence is a developer's stated intent in a KeePassXC discussion
   thread, not a spec. Create a passkey in Strongbox and look.
2. **Prompt content.** Can the configured prompt program show a
   structured confirmation and a picker, or does that need a new
   mechanism?
3. **UV semantics.** Browsers may demand user verification. Is the
   confirmation enough to report UV, or should kpa report UP only and let
   the relying party decide? Some sites refuse UP-only for passkeys.
4. **`credentialsd` timeline.** Provider support is in design as of the
   sources read (the project's FOSDEM 2026 talk and its tracker); check
   the tracker before starting phase 4.
5. **`passkey-rs` fit.** Does it keep keys in caller-controlled memory?
6. **Registration, later.** If kpa ever gets an opt-in write path for
   other reasons, passkey creation is the first thing that would use it.
   Until then, (a) with (c).

## Sources

- [Credentials for Linux, FOSDEM 2026](https://archive.fosdem.org/2026/schedule/event/838A8N-credentials-for-linux-bringing-passkeys-to-linux/)
- [Credentials for Linux on GitHub](https://github.com/linux-credentials)
- [credentialsd #26: third-party password management](https://github.com/linux-credentials/credentialsd/issues/26)
- [KeePassXC passkeys documentation](https://git.hackliberty.org/Git-Mirrors/keepassxc/src/branch/develop/docs/topics/Passkeys.adoc)
- [KDBX Standard discussion #6229](https://www.github.com/keepassxreboot/keepassxc/discussions/6229)
