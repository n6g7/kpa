# kpa

> This is untested, incomplete software. I can't guarantee that this won't leak
> passwords anywhere, or that it will work at all. Don't use it with sensitive
> password databases. Or, better yet, don't use it at all.

> Full disclosure: this is almost completely designed and implemented by AI.
> I'm doing my best to review its work and make sure it is secure and bug free,
> but I cannot guarantee that this isn't fundamentally flawed. Be warned.

A small, read-only KeePass agent: holds `.kdbx` files (KDBX3 and KDBX4)
unlocked in memory and serves free-text search plus secret-copy-to-clipboard
to a launcher and a CLI over a Unix socket. Read-only by design — no code
path can write to a database — so it's meant to be safe to run alongside a
client that already has write access to the same files.

See [`docs/design.md`](./docs/design.md) for the design and
[`docs/plan.md`](./docs/plan.md) for what's built versus planned.

## Build & test

A Nix flake provides the whole toolchain (`cargo`, `rustc`, `clippy`,
`rustfmt`, plus `keepassxc-cli`/`pykeepass` for building throwaway test
fixtures):

```sh
nix develop -c cargo build
nix develop -c cargo test
```

`direnv allow` drops the `nix develop -c` prefix. CI
(`.github/workflows/ci.yml`) runs the same commands on every push and PR.

## Try the probe command

```sh
nix develop -c cargo run -- probe path/to/some.kdbx
```

Prompts for a password (hidden input) and an optional `--keyfile`, then
prints each entry's title. Temporary scaffolding, removed once the real
socket protocol lands (`docs/plan.md`, step 2).
