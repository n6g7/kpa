# TODO

## Open

Roadmap, in release order. Each item gets its design written before its implementation.

1. [x] Support headless use (no window manager or GUI), per `docs/headless.md`
  - [x] Prompt safety nets: prompt timeout, a lock kills open prompts, no prompt while the screen is locked
  - [x] Zeroizing request buffer
  - [x] Origin classifier
  - [x] Terminal unlock
  - [x] Copy gated on origin and the desk's state
2. [ ] SSH agent, per `docs/ssh-agent.md`. The release waits for `ssh-key` 0.7.0
  - [x] Local agent: discovery, key cache, on-screen approvals, `kpa ssh keys`, session wiring
  - [x] Unlock on demand, and `kpa ssh approve` for requests from outside the desktop
  - [x] Forwarding with per-session approvals
  - [ ] Move to `ssh-key` 0.7.0 once it is released (still 0.7.0-rc.12)
  - [ ] Final security audit of all of kpa, the core rewrite included
  - [ ] Threat model: cover the agent's prompt data, host naming through `known_hosts` and certificates, and the forwarding chain
3. [ ] Passkey sign-in through kpa's browser extension, per `docs/passkeys.md`
  - [ ] Find passkeys: discovery, `serve_passkeys`, `kpa passkeys`, and the private key out of `copy` and `list`
  - [ ] The browser front end: its socket and protocol, `kpa browser-host`, the origin check and the client data
  - [ ] Sign-in from an unlocked database: the approval and account prompts, `Use another authenticator`, the assertion
  - [ ] The extension for Chromium and Firefox: the page script, the content script, the background, the toolbar button
  - [ ] Unlock on demand, with the cache of hashes
  - [ ] `confirm` per site: `"once"` and `"never"`
  - [ ] Autofill: the `accounts` request and the extension's menu
  - [ ] Installing: the host manifests and wrapper in the home-manager module, the Chrome Web Store, addons.mozilla.org signing
  - [ ] Fuzz targets for the socket's requests and for passkey entries, and a NixOS VM test that signs in through a browser with the extension
  - [ ] The other docs: `design.md` (its scope, which rules out a browser backend), `protocol.md`, `module-structure.md`, `portability.md`, `config.example.toml`, the README
  - [ ] Threat model: cover the browser socket, the extension, the origin check and the cache of hashes (`docs/passkeys.md` § 10)
4. [ ] Add macOS support (some time later)
5. [ ] Passkey support via credentialsd (later): it has no interface for a password manager to provide passkeys through yet

Unscheduled:

- [ ] Document assumptions (Linux only, logind, etc)
- [ ] A desktop notification on each `copy` and SSH signature, so a read you didn't make gets noticed (`docs/threat-model.md` T-16)
- [ ] YubiKey challenge-response as a vault credential, without reusing the key's PIN as one
- [ ] The legacy KeeOtp `TimeOtp-*` fields, which `keepass`'s `totp` feature doesn't parse
- [ ] Refactor the other existing commands to use the new output/reply system
- [ ] Consider PGP agent support
- [ ] Consider creating passkeys, which needs a way to write a database (`docs/passkeys.md` § 9)
- [ ] Consider an emulated USB security key over `/dev/uhid`, for programs other than browsers with the extension (`docs/passkeys.md` § 3)
- [ ] `kpa pick`, a terminal entry picker over fzf, per `docs/design.md` § The picker
  - [x] `status` reports `can_copy`, whether a `copy` from the requester would land
  - [x] The `pick` subcommand
  - [ ] home-manager module: kpa on `PATH`, and an optional shell key binding for `kpa pick`

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
