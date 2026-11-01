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

## Platform

Linux only. Locking on screen-lock and suspend needs systemd-logind
reachable on the session/system bus. Without it, kpa still runs and the
per-database idle timer still locks databases — screen-lock and suspend
just never trigger a lock, silently.

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

## Try it

[`config.example.toml`](./config.example.toml) points at the throwaway test
fixtures instead of a real vault, and its password prompt is a scripted
one-liner, so this needs no GUI and nothing to type. Build the fixtures
first — they're generated, not committed:

```sh
sh tests/fixture.sh
```

(These assume the dev shell, via `direnv allow` or `nix develop`; otherwise
prefix each command with `nix develop -c` as above.)

Then start the daemon in one terminal:

```sh
cargo run -- serve --config config.example.toml
```

and drive it from another:

```sh
cargo run -- status            # lock state of every configured database
cargo run -- unlock personal   # runs the configured prompt for a password
cargo run -- list              # every entry in every unlocked database (alias: ls)
cargo run -- list personal     # just the one
cargo run -- lock personal     # lock one
cargo run -- lock              # lock all of them
```

Each client subcommand prints the daemon's raw JSON response and exits
non-zero when `ok` is `false`. The socket defaults to
`$XDG_RUNTIME_DIR/kpa/sock`; pass `--socket <path>` to both sides to use a
different one.

The protocol is line-delimited JSON, one request and one response per
connection, so it's typeable by hand:

```sh
echo '{"v":1,"op":"status"}' | socat - UNIX-CONNECT:"$XDG_RUNTIME_DIR/kpa/sock"
```

`serve` logs each unlock and lock to stdout, successes and failures alike.
Reads (`status`, `list`) are deliberately not logged: they change nothing,
and `list` carries entry titles and usernames, which shouldn't accumulate
in a log.
