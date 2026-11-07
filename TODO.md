# TODO

## Open

- [ ] Add macOS support
- [ ] Document assumptions (Linux only, logind, etc)
- [ ] SSH agent?
- [ ] Find out why `cargo run -- ...` rebuilds on each run, even with no changes
- [ ] `kpa list` returns a list of copyable fields for each entry

## Done

- [x] Add release-please, similar to https://github.com/n6g7/fin/blob/main/.github/workflows/release.yml
- [x] Flake module to make installing easy
- [x] Better logging
- [x] `kpa version` prints the commit used when not a tagged release
- [x] `kpa version` reports the server's version too, and `kpa serve` prints its version on start
- [x] One more security audit
