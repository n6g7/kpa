# kpa — Android

kpa for Android is an app that reads the same `.kdbx` files as the desktop
daemon, read-only, and serves them to other apps through Android's own
services: logins through the Autofill service and Credential Manager, and
passkey sign-in through Credential Manager. It is milestone 0.8.0 on the
[roadmap](../ROADMAP.md), and it builds on the milestones before it: the
login matching of the browser extension (0.5.0) and the `passkeys`
subsystem ([`passkeys.md`](./passkeys.md), 0.6.0).

**Not built yet.** This doc is the design the implementation follows.
Nothing in the repository implements it, and the other docs don't describe
it. The steps are in [`TODO.md`](../TODO.md).

It keeps the desktop's rules: kpa writes no database, a database opts in
to serving passkeys, private keys never leave kpa, a locked database is
unlocked on demand, and a lock ends everything. What changes is the
platform. There is no daemon, no socket and no prompt program, and the
system names the app a request is for.

## 1. Overview

One app, one process: a Kotlin layer over kpa's Rust core, which the app
loads as a native library. It has four parts:

| Part | Android component | Does |
| --- | --- | --- |
| The app | an activity | lists the databases, picks their files, unlocks and locks them, turns quick unlock on and off, and lists what each database serves and what it skipped, as `kpa passkeys` does |
| The fill service | an `AutofillService` | offers logins and one-time codes in the forms of other apps and of browsers |
| The credential service | a `CredentialProviderService` | offers passkeys and logins to apps and browsers that ask Credential Manager |
| The request screen | an activity no other app can start | unlocks, lets the user search for an entry, runs the device check (§ 6.3), and returns what a fill or a sign-in needs |

kpa runs on Android 14 (API 34) and later, the first version that lets an
app other than Google's provide passkeys.

The Android app has no SSH agent (unscheduled on the roadmap), no search
and copy (not planned on the roadmap), no way to create or save anything
(§ 9), and no network access (§ 7).

## 2. Situations

| # | Situation | Database unlocked | Database locked |
| --- | --- | --- | --- |
| F1 | A login form in an app that an entry names (§ 6.2) | The system's suggestions list the entry; picking one fills the form | One suggestion per locked database, `Unlock personal`; picking it unlocks, then lists |
| F2 | A login form on a page, in a browser on kpa's list (§ 6.1) | The entries that match the page's domain | As F1 |
| F3 | A login form nothing matches | One suggestion, `Search kpa`, which opens the request screen on every entry of the unlocked databases; the one picked fills the form | As F1 |
| F4 | A one-time code field | The matching entries that hold a TOTP seed; the code is made when the user picks one | As F1 |
| F5 | A form with no login or code field | Nothing | Nothing |
| C1 | A passkey sign-in in a browser on kpa's list | The system's sheet lists kpa's accounts for the site. Picking one runs the device check, then signs | The sheet has `Unlock personal` for a database whose cache has the site (§ 6.3) |
| C2 | A passkey sign-in in any other app | kpa offers nothing (§ 6.3) | The same |
| C3 | A password request through Credential Manager | As F1 and F2 | As F1 |
| C4 | A registration, or a save | kpa offers nothing (§ 9) | The same |
| X1 | Android stops kpa's process | Every database is locked | — |

## 3. The app and the core

### 3.1 One process, no daemon

The core, `Databases`, lives in the app's process and is created the
first time the process needs it. The services and screens call it
directly: there is no socket and no protocol between them. The fill
service and the credential service are the Android front ends, the
counterparts of `control` and the SSH agent, and like them they unlock,
lock and read the core.

Android stops a background process whenever it needs the memory. For kpa
that is a lock of every database (§ 5.3). No foreground service keeps the
process alive.

### 3.2 What runs in Rust, and what in Kotlin

Rust holds the databases and makes every decision: which fields a form
has, which entries match, which passkeys answer, whether a caller's origin
holds, and what a request screen shows. Kotlin turns Android's objects into
plain data for those decisions, turns their answers back into Android's
objects (`FillResponse`, `Dataset`, `CredentialEntry`, the WebAuthn
response), and draws the screens.

The Kotlin layer can't be avoided. Android starts a service or an activity
by its class name, and each part of kpa that serves other apps subclasses a
framework class: `AutofillService`, `CredentialProviderService`, and
`BiometricPrompt.AuthenticationCallback`. JNI lets Rust call Java but not
define a class, so an app written only in Rust could draw its own screens
but could serve nothing to another app.

UniFFI generates the Kotlin side of the Rust API, so the boundary is
written once, as Rust types.

### 3.3 Crates

kpa becomes a Cargo workspace of three crates:

| Crate | Is | Uses |
| --- | --- | --- |
| `kpa-core` | `databases`, `passkeys`, login matching, `cancel`, `log` | — |
| `kpa` | the daemon and the CLI for Linux and macOS: every other subsystem | `kpa-core` |
| `kpa-android` | a `cdylib`: the Android front ends, the document source (§ 4.2), and the API UniFFI exports | `kpa-core` |

Android can't build `zbus`, the Wayland client or `ksni`, and the app has
no use for them. A crate boundary is the one dependency rule Cargo
enforces, so `kpa-android` can't reach into the daemon by accident. The
subsystem rules of [`module-structure.md`](./module-structure.md) hold
within each crate. The test helpers other subsystems use
(`Databases::for_test`, `databases::testing`) move behind a `testing`
feature of `kpa-core`.

`databases` takes its own description of a database: its name, its source,
its keyfile, whether it serves passkeys, and its idle timeout. The daemon
builds it from the config file, and the app from its settings.

## 4. Database files

### 4.1 Choosing a file

The app adds a database through the system file picker, and keeps a
persistable, read-only grant to the document the user picks. kpa never asks
for write access, so the grant itself can't write the file: read-only
holds below kpa's own code (G-1). Any document provider works, such as the
phone's storage, a sync app's folder, or a cloud drive. A keyfile is
chosen the same way.

Settings live in the app, not in a TOML file: each database's name,
document, keyfile, whether it serves passkeys, and idle timeout. They are
kept in the app's private storage and left out of backups (§ 7).

### 4.2 Reading, and the freshness guard

The core reads a database through a source. On Linux and macOS the source
is a path. On Android it is a document: `kpa-android` opens it read-only
through the content resolver, and the core reads it whole and closes it
before key derivation, as it does a file.

The change token is the size and last-modified time the provider reports,
read before and after the read, as the desktop's `fstat` calls bracket
it. A provider that reports no last-modified time gets the SHA-256 of the
document's bytes as its token, at the cost of reading the document again
for each check.

The freshness guard is the desktop's (G-8). Before each read of an
unlocked database (a fill, a search, a sign-in), the core asks the source
for the current token under a deadline. A changed token, or a provider
that doesn't answer in time, locks the database.

**The seam.** `databases` defines a `Source` trait with two methods: open
for reading, and the current change token. The file source is in
`kpa-core`. The document source is in `kpa-android`, over a callback into
Kotlin, because the content resolver is reachable only through the JVM.
That makes it a callback that can't be avoided, which is when a subsystem
defines a trait, rather than an OS switch inside `kpa-core`. The trait
names bytes and a token, never a URI or a descriptor type.

## 5. Unlocking and locking

### 5.1 The unlock

The app or the request screen asks for the master password on a screen of
kpa's own. The window is secure, so it can't be captured and shows blank
among recent apps. The field uses the password keyboard, with the
keyboard's personalized learning off, and is excluded from autofill, so no
other autofill service sees it. The keyfile is read through its grant.

The password goes to Rust as bytes and is held in a zeroizing buffer for
the unlock (G-3). On the way it passes through the UI toolkit's own
strings, which kpa can't zeroize (§ 10).

**Unlock on demand** is a fill or a sign-in whose user picked `Unlock
<database>`. It follows the steps every front end follows
([`design.md`](./design.md) § Unlocking): take the database's unlock and
its token, ask, finish, then go on with the request. The desktop's check
that the display session allows a prompt has no counterpart: the request
screen opens only on an unlocked phone (§ 6.4). It shows which app or
site the unlock is for.

### 5.2 Quick unlock

After a full unlock the user can turn on quick unlock for that database.
kpa then creates an AES-GCM key in Android Keystore, in StrongBox where the
phone has it and in its trusted execution environment otherwise. The key
can be used only after a strong biometric check, once per use, and is
invalidated when a new fingerprint or face is enrolled. Android also
invalidates it if the screen lock is removed. kpa encrypts the master password with it
and keeps the ciphertext in the app's private storage, out of backups.

A quick unlock is a `BiometricPrompt` bound to that key. The decrypted
password goes to Rust as for a full unlock, and the unlock runs the
database's KDF as usual. kpa stores the password, never a key derived from
it, so a quick unlock is no shortcut past the KDF, and a password or KDF
changed in another client just makes it fail.

Quick unlock ends when the user turns it off, when Android invalidates the
key, and when an unlock with it fails. kpa then deletes the ciphertext and
asks for the password.

This is the one way A-1 is persisted on Android (G-4): encrypted under a
key that never leaves the phone's secure hardware, and usable only with a
strong biometric each time.

### 5.3 What locks a database

- **The screen turning off** locks every database. It is the phone's
  counterpart of the desktop's screen lock (G-5).
- **Idle**, after each database's own timeout, 30 minutes by default. A
  fill or a sign-in the user picked resets it, and so does an unlock. A
  listing of suggestions doesn't.
- **The file changing** (§ 4.2).
- **The app's Lock button**, for one database or all.
- **The process ending.** Android stops it at will. The memory goes back to
  the kernel without kpa zeroizing it (§ 10).

A lock closes a request screen open for that database, and a fill or a
sign-in picked before the lock fails.

## 6. Requests

### 6.1 Who is asking

The system names the app each request is for. For a fill, it is the
package of the activity whose form is being filled. For Credential
Manager, it is the caller's package and signing certificates.

**Browsers.** kpa ships the list of browsers Google publishes for
credential providers: each browser's package and its signing certificates.
A browser on that list is trusted for the web origin it names, which is
Credential Manager's origin, and the page's domain in a fill request. Any
other app is only its package name, and a web domain in its form is
ignored. An app writes its own view structure, so any app can put any
domain in a fill request; only a listed browser's word for it means
anything. The list is updated with each kpa release, and a browser missing
from it is treated as an app.

kpa declares the listed browsers in its manifest's `<queries>`, so it can
read their signing certificates. It never asks to see every installed app.

### 6.2 Logins: the fill service

On a fill request, Kotlin flattens the form into plain data: each fillable
field's autofill id, autofill hints, input type and HTML attributes, plus
the page's domain and the app's package. Rust decides which fields hold
the username, the password and a one-time code, trying hints first, then
the input type, then the HTML attributes. A form with none of them gets no
answer, and the system shows nothing.

**Which entries match** depends on the caller:

- **A listed browser**: the entries whose URLs match the page's domain, by
  the browser extension's rules (0.5.0).
- **Any other app**: the entries that name its package, through an
  `androidapp://<package>` URL, the form Keepass2Android writes, or an
  `AndroidApp` or `AndroidApp_<n>` field, the form KeePassDX writes.

Every database serves logins, as every database serves `copy` on the
desktop. Only passkeys need a database to opt in.

**What the response holds.** Each matching entry is one suggestion, in the
system's dropdown and among the keyboard's inline suggestions. It shows
the entry's title and username, escaped and length-capped like any entry
content (G-10). A suggestion holds no secret. It carries an authentication
intent: picking it opens the request screen, which answers with the values
at once and shows nothing. So the password, and a TOTP code made at that
moment, reach the system only for the entry the user picked.

After the matches come one `Unlock <database>` suggestion per locked
database, and last, `Search kpa`, which opens the request screen on every
entry of the unlocked databases. The entry the user picks there fills the
form.

The fill service never asks to save a login (§ 9).

### 6.3 Passkeys and logins: the credential service

Credential Manager asks in two phases. kpa answers the first without any
screen, and the user's pick starts the second.

**First phase.** For each option in the request:

- **A passkey**: the request's JSON names the site's id and may list the
  credential ids the site accepts. A caller that isn't a listed browser
  gets nothing. A listed browser's origin is checked against the site's id
  by the rules the desktop uses ([`passkeys.md`](./passkeys.md) § 6.3).
  The candidates and the locked databases on offer are those of
  [`passkeys.md`](./passkeys.md) § 5.2, steps 3 and 4: one entry per
  candidate account, named by the account and its database, and one
  `Unlock <database>` action per locked database whose cache of hashes has
  the site.
- **A password**: the entries that match the caller by § 6.2's rules, and
  one `Unlock <database>` action per locked database.

**Second phase.** The pick opens the request screen with what was picked.
It reads the request again, checks the caller and the origin again, and
checks that the database is still in the unlock the entry came from. Then:

- **A passkey sign-in** runs the device check, then answers with the
  assertion the `passkeys` subsystem makes ([`passkeys.md`](./passkeys.md)
  § 5.4). A listed browser sends the hash of the client data it wrote, with
  the page's origin in it, and kpa signs over that hash.
- **A password** answers with the username and password, with no check.

**The device check** is a `BiometricPrompt` that takes a strong biometric
or the phone's screen lock. Every passkey sign-in asks it, after the pick,
unless the same request's unlock has just asked (a quick unlock, or the
master password). So the "user verified" flag rests on a check made for
that sign-in, not only on the unlocked database as on the desktop. There is
no `confirm` setting on Android. The pick in the system's sheet is the
approval, and nothing can skip the check.

**Apps get no passkeys.** A passkey request from an app that isn't a listed
browser gets nothing from kpa, and the phone's other providers answer it.
Android leaves it to the provider to check that an app may use a site's
passkeys: the site lists its apps in `/.well-known/assetlinks.json`, and
kpa has no network access to read it (§ 7).

### 6.4 The request screen

The request screen is an activity that isn't exported. Only the pending
intents kpa hands the system can start it, so no app can open it directly.
Its window is secure.

It shows only what a request needs: an unlock, the search list, or the
device check. A pick that needs no question is answered without drawing
anything. It ends when its database locks, when the system cancels the
request, or when the user backs out, and the request then fails.

It opens only from the user's pick in the system's own UI, on an unlocked
phone. Nothing in kpa opens a screen by itself (G-12).

## 7. Permissions, backups and the network

- **Permissions.** Each service requires its binding permission
  (`BIND_AUTOFILL_SERVICE`, `BIND_CREDENTIAL_PROVIDER_SERVICE`), which only
  the system holds, so only the system can bind them. The app asks for
  `USE_BIOMETRIC` and nothing else: no `INTERNET`, no storage permission,
  and no permission to see every installed app.
- **Backups.** Backup is off, and the data extraction rules exclude
  everything: the settings, the quick-unlock ciphertext and the cache of
  hashes.
- **No network.** kpa has no network surface on Android either (ACT-2). It
  costs two things: apps get no passkeys (§ 6.3), and the list of browsers
  is updated only by updating kpa.

## 8. Build and release

- **The app** is a Gradle project under `android/`: Kotlin, Jetpack
  Compose, `androidx.credentials` and `androidx.biometric`.
- **The library.** `cargo-ndk` builds `kpa-android` for `arm64-v8a`, and
  for `x86_64` for the emulator. Gradle packs the libraries, and the
  UniFFI bindings are generated during the build.
- **The release.** CI builds the APK, signs it with kpa's release key, and
  attaches it to the GitHub release that release-please makes, so the app's
  version is kpa's. It is not in Google Play.
- **The dev shell.** The flake's dev shell provides the SDK, the NDK and
  `cargo-ndk`, from nixpkgs' `androidenv`.

## 9. Creating and saving

kpa never creates a passkey or saves a login on Android either. The reason
is the desktop's ([`passkeys.md`](./passkeys.md) § 9): writing a database
safely next to another client is out of reach of a read-only design. And
here the read-only grant couldn't write the file anyway. Credential
Manager's create requests get nothing from kpa, and the fill service never
asks to save. Passkeys and logins come from KeePassXC, KeePassDX or another
client writing the same file.

## 10. Claims

What this design claims and what it accepts, in the terms of
[`threat-model.md`](./threat-model.md), which doesn't carry them yet.

**The boundaries.** The system services that bind kpa's services and
start its screens are part of the platform, and trusted. The apps they ask
for are not: a form, a request's JSON, and any origin or domain that isn't
a listed browser's are untrusted data. So are the bytes of a document
(ACT-3).

**The actors on Android.** Other apps each run as their own uid, which is
ACT-1's place. A listed browser is trusted for the origin it names, as the
desktop browser is. The keyboard and accessibility services are trusted
with the screen, as the compositor is (ASM-4). Someone holding the phone
is ACT-7. Root, an unlocked bootloader and a compromised secure element
are NG-2.

**Claims**

- **Read-only holds** (G-1). The grants are read-only, and kpa has no
  create or save path.
- **No network, and no way in but the system** (G-2). Only the system binds
  the services, and the request screen isn't exported.
- **A secret leaves only for the user's pick** (G-3). A login's password,
  and its TOTP code, go only into the answer for the entry picked. A
  passkey's private key never leaves: only assertions do, for databases
  that opt in, to listed browsers.
- **What is persisted** (G-4): the settings, the cache of hashes
  ([`passkeys.md`](./passkeys.md) § 4.3), and the quick-unlock ciphertext
  (§ 5.2). None of it is in a backup.
- **Bounded exposure** (G-5, G-6): § 5.3.
- **Freshness, file input and entry content** hold as on the desktop (G-8,
  G-9, G-10).
- **No screen where nobody can see it** (G-12): § 6.4.
- **A passkey sign-in needs an unlocked database that opts in, the user's
  pick, and the device check** (G-13).
- **A web origin is a listed browser's word**, checked against the site's
  id. Any other app's domain is ignored.

**Accepted**

- **An app installed under the package an entry names is offered that
  entry.** Android lets only one app hold a package name, but not that it
  is the app the entry meant. The suggestion shows the entry's title, and
  picking it is the user's call.
- **Whoever writes entries in a database can name any package** (ACT-4),
  and so add a suggestion to that app's forms.
- **The master password passes through the UI toolkit's strings**, which
  kpa can't zeroize (NG-4).
- **A stopped process isn't zeroized by kpa**: its memory goes back to the
  kernel as it was.
- **The system's autofill and credential services see what kpa answers**,
  as the compositor sees the clipboard.
- **The keyboard sees the master password typed**, and accessibility
  services see the screen and can tap it.
- **Quick unlock trusts the phone's biometrics and secure hardware.**
  Whoever passes the strong biometric unlocks the database, and a
  compromised secure element gives up the master password.
- **No passkeys for apps** (§ 6.3).

## 11. Code

`kpa-android` holds the Android front ends, the document source and the
exported API. `kpa-core` gains the `Source` trait (§ 4.2) and an Android
backend for `log`, which writes to logcat. That backend is picked at
compile time, the way [`portability.md`](./portability.md) picks an OS's
code.

```
kpa-android/
  src/
    lib.rs              the exported API: Core, its records, its callbacks
    source.rs           the document source, over the Kotlin callback
    callers.rs          the list of browsers, and checking a caller against it
    fill/               the fill service's decisions: fields, matches, the response
    credentials/        the credential service's: options, entries, answers
android/
  app/src/main/
    AndroidManifest.xml
    res/xml/            the autofill service and credential provider metadata
    kotlin/.../
      KpaApplication.kt   loads the library and creates the core
      MainActivity.kt     the app
      FillService.kt      AutofillService: the form in, a FillResponse out
      CredentialService.kt  CredentialProviderService: the first phase
      RequestActivity.kt  the request screen: the second phase, and fills
      QuickUnlock.kt      Keystore and BiometricPrompt
      Documents.kt        the Kotlin side of the document source
```

`fill/` and `credentials/` are front ends, and don't use each other. What
they share is in `callers.rs` and in `kpa-core`: the login matching and
`passkeys`.

**Testing**

- **`kpa-core`** as today, plus the document source's token rules against a
  fake source.
- **`kpa-android`'s decisions** on the host, with no device: forms as
  Kotlin flattens them, recorded from real apps and browsers; Credential
  Manager requests as JSON; the caller and origin rules; assertions checked
  against the public key; and the races: a lock between the pick and the
  answer, and a file that changes between two reads.
- **On an emulator in CI**: instrumented tests with a test app that has a
  login form and one that calls Credential Manager. Debug builds accept a
  test list of browsers, so a sign-in can be tested end to end.
- **Fuzzing**: flattened forms and request JSON.

## Sources

- [`AutofillService`](https://developer.android.com/reference/android/service/autofill/AutofillService)
- [`CredentialProviderService` (Jetpack)](https://developer.android.com/reference/androidx/credentials/provider/CredentialProviderService)
- [Credential Manager calls from privileged apps](https://developer.android.com/identity/sign-in/privileged-apps)
- [`KeyGenParameterSpec.Builder`](https://developer.android.com/reference/android/security/keystore/KeyGenParameterSpec.Builder)
- [Passkeys on Android (passkeys.dev)](https://passkeys.dev/docs/reference/android/)
- [Passkey support on Android and Chrome](https://developers.google.com/identity/passkeys/supported-environments)
- [KeePassDX: AutoFill](https://github.com/Kunzisoft/KeePassDX/wiki/AutoFill)
