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
      prompt = [ "sh" "-c" "exec fuzzel --dmenu --password --prompt \"$KPA_PROMPT_MESSAGE\"" ];
      database = [
        { name = "personal"; path = "/home/you/passwords.kdbx"; }
      ];
    };
  };
}
```

`settings` is written to `~/.config/kpa/config.toml` in the shape
documented by [`config.example.toml`](./config.example.toml). The module
runs `kpa serve` as a user systemd service (`systemctl --user status kpa`),
sandboxed by default (`NoNewPrivileges`, a restricted syscall filter,
`AF_UNIX`-only sockets, and more — see `nix/hm-module.nix`). Each setting
is applied with `lib.mkDefault`, so it can be loosened per directive with
`systemd.user.services.kpa.Service.<name> = lib.mkForce ...;`.

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

Three tests in `tests/clipboard.rs` drive the live Wayland clipboard, which
anything else in your session can interfere with, so `cargo test` skips them.
They need a compositor that exports `WAYLAND_DISPLAY` to the service
manager, and a logind display session. Run them when you change the
clipboard logic:

```sh
nix develop -c cargo test --test clipboard -- --ignored
```

[`fuzz/`](./fuzz) fuzzes request decoding (`src/proto/`) with `cargo-fuzz`,
in its own Cargo workspace so it's not part of the commands above.
`cargo-fuzz` needs a nightly rustc, which lives in its own `fuzz` dev shell
(`devShells.fuzz` in `flake.nix`) rather than the default one, so it never
touches `cargo build`/`cargo test`/`cargo clippy`:

```sh
nix develop .#fuzz -c cargo fuzz run decode_request -- -max_total_time=180
```

The target feeds random bytes through the same two steps the server runs
on a request line: a UTF-8 check, then `kpa::proto::decode_request`. The
property it checks is that every input returns `Ok` or `Err` — a panic, a
hang, or a timeout/out-of-memory kill is a failure. It does not check that
*valid* requests get handled correctly (no server, no vaults involved), and
it doesn't exercise the socket's own request-size cap.

Reading the output: a `#N NEW cov: ... ft: ... corp: ...` line means input
`N` reached new code (`cov`/`ft` are coverage counters, `corp` is the
growing set of saved interesting inputs); `pulse` lines are just progress
pings. `Done N runs in Ns` with no `ERROR`/`SUMMARY: ... Sanitizer` line or
panic above it means the run found nothing. A crash prints the panic and
saves the input to `fuzz/artifacts/decode_request/crash-*`; rerun the same
command with that path appended to reproduce it outside libFuzzer's loop.
`fuzz/corpus/` (the saved inputs) is git-ignored and grows across runs.

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
                                # (or reads it from your terminal if there's
                                # no display to prompt on; --tty skips
                                # straight to that)
cargo run -- list              # every entry in every unlocked database (alias: ls)
cargo run -- list personal     # just the one
cargo run -- lock personal     # lock one
cargo run -- lock              # lock all of them
cargo run -- ssh keys          # the SSH keys every unlocked database holds, and
                                # the attachments skipped (--database <name>
                                # for one; --toml prints a config block per
                                # key instead)
cargo run -- version           # the CLI's build version, and the running daemon's
```

Each client subcommand prints the daemon's raw JSON response and exits
non-zero when `ok` is `false`. `ssh keys` is the exception: it prints text,
and a refusal as an error on stderr. `--json`, which every client command
takes, before or after the subcommand, prints the raw JSON response line
for it too; the commands without a text output yet print it either way,
and `version`, which has no JSON form, ignores it. The
socket defaults to `$XDG_RUNTIME_DIR/kpa/sock`; pass `--socket <path>` to
both sides to use a different one.

`version` is the exception: it prints plain text, not JSON, and always
exits `0`. It always prints the CLI's own build version as `client: …`,
then `server: …` for the running daemon's, so an upgrade that replaces the
binary but leaves the old `kpa serve` running shows up as a mismatch
instead of silently serving the previous build. With no daemon reachable,
or one old enough to not report a version, `server:` says so instead —
that's not a failure of the command itself.

The protocol is line-delimited JSON, one request and one response per
connection, so it's typeable by hand:

```sh
echo '{"v":1,"op":"status"}' | socat - UNIX-CONNECT:"$XDG_RUNTIME_DIR/kpa/sock"
```

`serve` logs each unlock, lock and copy to stderr, successes and failures
alike. A copy names the field, the entry's title and the database, never the
secret. Reads (`status`, `list`) are deliberately not logged: they change
nothing, and `list` carries entry titles and usernames, which shouldn't
accumulate in a log. Set the level with `log_level` in the config
(`error`, `warn`, `info` or `debug`) or `serve --log-level`; under systemd the
levels show up as journal priorities, so `journalctl --user -u kpa -p warning`
works.
