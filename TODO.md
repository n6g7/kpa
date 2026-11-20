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
  - [ ] Local agent: discovery, key cache, on-screen approvals, `kpa ssh keys`, session wiring
  - [ ] Unlock on demand, and `kpa ssh approve` for requests from outside the desktop
  - [ ] Forwarding with per-session approvals
3. [ ] Passkey "agent" / provider (FIDO2 emulation). Shape to be decided
4. [ ] Add macOS support (some time later)
5. [ ] Passkey support via credentialsd (later)

Unscheduled:

- [ ] Document assumptions (Linux only, logind, etc)
- [ ] Read notifications that cover both `copy` and SSH signatures (`docs/threat-model.md` T-16)
- [ ] An upstream agent relay: kpa in front of another agent (`docs/ssh-agent.md` § 4, approach C)

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
