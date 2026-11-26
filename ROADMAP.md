# Roadmap

The milestones kpa works toward, in order. The first one not yet shipped is
the current one. Each gets its design written in `docs/` before its
implementation starts, and its tasks are listed in [`TODO.md`](./TODO.md)
under the same name.

Each milestone is one minor release. The numbers are tentative: a patch
release can come between two milestones, and a change of order or scope
moves them.

Every milestone keeps kpa read-only (`docs/design.md` § Scope). Creating a
passkey, saving a new login or editing an entry happens in a KeePass client
over the same file.

## Where each capability lands

| Capability | Linux | macOS | Android |
|---|---|---|---|
| Search and copy: the CLI, `kpa pick`, the tray | Built | 0.7.0 | Not planned: autofill covers it |
| SSH agent | Built, ships in 0.4.0 | 0.7.0 | 0.8.0, if an SSH client there can use an outside agent |
| Passkey sign-in | 0.5.0: an emulated security key | 0.7.0: a credential provider extension | 0.8.0: Credential Manager |
| Login autofill | 0.6.0: a browser extension | 0.7.0: the same extension, and the credential provider extension | 0.8.0: the Autofill service and Credential Manager |

Windows is out of scope ([`docs/portability.md`](./docs/portability.md)).

## 0.4.0: SSH agent

The SSH agent ([`docs/ssh-agent.md`](./docs/ssh-agent.md)), `kpa pick`
and everything else merged since 0.3.0. The code is done.

- **Gate:** a security audit of all of kpa against
  [`docs/threat-model.md`](./docs/threat-model.md), with its high and medium
  findings fixed, and the threat model covering the agent.
- **`ssh-key` 0.7.0:** kpa pins `=0.7.0-rc.12`. The release takes `ssh-key`
  0.7.0 if it is out by the time the audit is done; otherwise it ships on
  the release candidate, and the move to `ssh-key` 0.7.0 is kpa 0.4.1. kpa is a
  binary built from its committed `Cargo.lock`, so an exact pin on a
  release candidate affects no one else's build.

## 0.5.0: Passkey sign-in on Linux

kpa signs in to websites with the passkeys stored in its databases, as an
emulated USB security key that unmodified Chromium and Firefox use. Design:
`docs/passkeys.md`, in review on
[#45](https://github.com/n6g7/kpa/pull/45).

- Sign-in only, following the SSH agent's rules: a database opts in, every
  use is approved on screen, a locked database is unlocked on demand.
- The browser shows its security-key dialog. Passkey autofill under a
  username field is out of reach for a USB key.
- Linux only: the key is created through `/dev/uhid`.

## 0.6.0: Login autofill in browsers

A browser extension for Chromium and Firefox, and the native messaging host
it starts, which talks to kpa's socket. The extension fills usernames,
passwords and TOTP codes into a site's login form, from the entries whose
URL matches the page.

- **Why an extension:** desktop browsers on Linux take no outside password
  provider. Their own password managers keep their own stores, and the
  routes below the browser (the emulated key, `credentialsd`) carry
  passkeys, never passwords.
- **Passwords only.** Passkeys stay on the emulated key (0.5.0).
- **Scope:** `docs/design.md` § Scope lists a browser backend under *Is
  not*. This milestone's design changes that.
- **Its design settles:** how a page matches entries, what a fill asks of
  the user, how the extension is distributed (the Chrome Web Store, and
  addons.mozilla.org signing for Firefox), how the home-manager module
  installs the host for each browser, and sandboxed (Flatpak, Snap)
  browsers.
- The extension and host follow [`docs/portability.md`](./docs/portability.md),
  so they carry over to macOS.

## 0.7.0: macOS

In two steps:

1. **kpa on a Mac:** `kpa serve` as a launchd agent, the CLI and `kpa
   pick`, the clipboard, prompts, auto-lock, the tray, the SSH agent and
   the browser extension's host. Each seam in
   [`docs/portability.md`](./docs/portability.md) gets its macOS side.
2. **Autofill and passkeys across the OS**, through a credential provider
   extension (AuthenticationServices), which Safari and native apps use.
   It needs a signed app bundle and a paid Apple Developer Program
   membership.

The emulated security key stays Linux-only. The milestone comes after the
browser work because the extension and its host carry over, and on a Mac
an existing KeePass client already covers autofill and passkeys.

## 0.8.0: Android

A read-only kpa app on the same Rust core. It serves logins to other apps
through the Autofill service and Credential Manager, and passkey sign-in
through Credential Manager. Not designed yet.

- **SSH agent:** depends on an Android SSH client that can use an agent
  outside its own app, and on how it reaches one.
- **Its design settles:** how the app reads a database file another app
  syncs, how it unlocks and locks, and which parts of the core it shares.
