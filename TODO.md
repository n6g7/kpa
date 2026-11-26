# TODO

## Open

Grouped by the milestones in [`ROADMAP.md`](./ROADMAP.md), in order. Each milestone gets its design written before its implementation.

### 0.4.0: SSH agent

Per `docs/ssh-agent.md`.

- [x] Local agent: discovery, key cache, on-screen approvals, `kpa ssh keys`, session wiring
- [x] Unlock on demand, and `kpa ssh approve` for requests from outside the desktop
- [x] Forwarding with per-session approvals
- [ ] Final security audit of all of kpa, the core rewrite included
- [ ] Threat model: cover the agent's prompt data, host naming through `known_hosts` and certificates, and the forwarding chain
- [ ] Move to `ssh-key` 0.7.0 once it is released (still 0.7.0-rc.12). The release doesn't wait for it

### 0.5.0: Login autofill in browsers

- [ ] Design: the browser extension and its native messaging host

### 0.6.0: Passkey sign-in on Linux

- [ ] Design: an emulated security key, per `docs/passkeys.md` (in review)

### 0.7.0: macOS

- [ ] Design: the macOS side of each seam in `docs/portability.md`
- [ ] Design: autofill and passkeys through a credential provider extension

### 0.8.0: Android

- [ ] Design: the read-only app, its autofill and its passkeys

### Unscheduled

- [ ] Document assumptions (Linux only, logind, etc)
- [ ] A desktop notification on each `copy` and SSH signature, so a read you didn't make gets noticed (`docs/threat-model.md` T-16)
- [ ] YubiKey challenge-response as a vault credential, without reusing the key's PIN as one
- [ ] The legacy KeeOtp `TimeOtp-*` fields, which `keepass`'s `totp` feature doesn't parse
- [ ] Refactor the other existing commands to use the new output/reply system
- [ ] Consider PGP agent support
- [ ] Passkey support via credentialsd, once it has a provider interface a password manager can implement
- [ ] An SSH agent on Android, for the clients that can use another app's keys: Termux through a bridge serving `SSH_AUTH_SOCK` (as OkcAgent does), and the OpenIntents SSH Authentication API (TermBot, Android Password Store)

## Done

- [x] Fix `cargo run -- ...` rebuilding on each run in git worktrees
- [x] Add release-please, similar to https://github.com/n6g7/fin/blob/main/.github/workflows/release.yml
- [x] Flake module to make installing easy
- [x] Better logging
- [x] `kpa version` prints the commit used when not a tagged release
- [x] `kpa version` reports the server's version too, and `kpa serve` prints its version on start
- [x] One more security audit
- [x] Fix the high and medium findings from the latest security audit
- [x] `kpa list` returns a list of copyable fields for each entry
- [x] Triage the low and informational findings from the latest security audit
- [x] Support headless use (no window manager or GUI), per `docs/headless.md`
  - [x] Prompt safety nets: prompt timeout, a lock kills open prompts, no prompt while the screen is locked
  - [x] Zeroizing request buffer
  - [x] Origin classifier
  - [x] Terminal unlock
  - [x] Copy gated on origin and the desk's state
- [x] `kpa pick`, a terminal entry picker over fzf, per `docs/design.md` § The picker
  - [x] `status` reports `can_copy`, whether a `copy` from the requester would land
  - [x] The `pick` subcommand
  - [x] home-manager module: kpa on `PATH`, and an optional shell key binding for `kpa pick`
