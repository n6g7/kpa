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

## Install

The flake exposes a package (`nix build`, or `nix profile install
github:n6g7/kpa`) and a home-manager module:

```nix
{
  inputs.kpa.url = "github:n6g7/kpa";

  # In your home-manager configuration:
  imports = [ kpa.homeManagerModules.default ];
  services.kpa = {
    enable = true;
    settings = {
      idle_timeout = "30m";
      prompt = [ "fuzzel" "--dmenu" "--password" "--prompt" ];
      database = [
        { name = "personal"; path = "/home/you/passwords.kdbx"; }
      ];
    };
  };
}
```

`settings` is written to `~/.config/kpa/config.toml` in the shape
documented by [`config.example.toml`](./config.example.toml). The module
runs `kpa serve` as a user systemd service (`systemctl --user status kpa`).

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
