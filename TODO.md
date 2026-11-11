# TODO

## Open

- [ ] Add macOS support
- [ ] Document assumptions (Linux only, logind, etc)
- [ ] SSH agent (continued from https://github.com/n6g7/kpa/pull/22)
- [ ] Find out why `cargo run -- ...` rebuilds on each run, even with no changes
- [ ] Passkey provider
- [ ] Support headless use (no window manager or GUI), per `docs/headless.md`
  - [x] Prompt safety nets: prompt timeout, a lock kills open prompts, no prompt while the screen is locked
  - [ ] Zeroizing request buffer
  - [ ] Origin classifier
  - [ ] Terminal unlock
  - [ ] Copy gated on origin and the desk's state

## Done

- [x] Add release-please, similar to https://github.com/n6g7/fin/blob/main/.github/workflows/release.yml
- [x] Flake module to make installing easy
- [x] Better logging
- [x] `kpa version` prints the commit used when not a tagged release
- [x] `kpa version` reports the server's version too, and `kpa serve` prints its version on start
- [x] One more security audit
- [x] Fix the high and medium findings from the latest security audit
- [x] `kpa list` returns a list of copyable fields for each entry
- [x] Triage the low and informational findings from the latest security audit
