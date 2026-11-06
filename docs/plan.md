# kpa — implementation plan

Sequential steps, each leaving a testable state. Design is in
[`design.md`](./design.md); the research behind it is in
[`background.md`](./background.md).

## Test fixtures

`keepassxc-cli` can build a throwaway database non-interactively enough for
tests (`db-create`, `mkdir`, `add`); `pykeepass` fills the one gap it has —
producing a genuine KDBX4 file. `tests/fixture.sh` builds both, and **every
step below tests against those, never a real vault** — these steps only
ever need the fixtures.

## Step 1 — core, no IPC

Cargo skeleton, `config.rs`, `vault.rs`, and a temporary `kpa probe <db>` that
prompts, opens, and prints titles to stdout. Ships `tests/fixture.sh`.

- **License:** MIT OR Apache-2.0, decided at repo creation — no copyleft
  anywhere in the dependency tree (`keepass`, `zbus`, `ksni` are all
  MIT/Apache-2.0 or Unlicense), so this is the frictionless default.
- **Test:** `cargo test` — fixture opens, wrong password fails cleanly,
  keyfile path works, a KDBX4 fixture opens too, malformed input errors
  rather than panics. Manual `kpa probe tests/fixtures/fixture.kdbx`.
- **After this:** `keepass` (the crate) is proven against real KDBX3 and
  KDBX4 files, and config parsing works. **This step exists first on
  purpose** — "can the library actually open a real database" is the only
  real technical risk in the project, and it should cost an afternoon to
  find out, not a week of building a daemon around it.

## Step 2 — daemon and socket

`src/proto/`, `server.rs`, `main.rs` dispatch. Ops: `status`, `unlock`, `lock`,
`list`. Socket at `$XDG_RUNTIME_DIR/kpa/sock`, mode `0600`, `v` field enforced
with a clear error naming both versions. `probe` deleted.

- **Test:** integration test that spawns `kpa serve` on a temp socket and
  exercises each op. By hand: `kpa serve` in one terminal, `kpa list` in
  another. Do the `socat - UNIX-CONNECT:…` hand-typed request once — it
  confirms the JSON-debuggability argument actually pays off.
- **After this:** fully working from a shell.

## Step 3 — copy and clipboard

`clip.rs` on `wl-clipboard-rs`, the `copy` op, timeout-based expiry.

- **Test:** `kpa copy …`, then `wl-paste` returns it and
  `wl-paste --list-types` shows `x-kde-passwordManagerHint`. After
  `clipboard_timeout`, `wl-paste` is empty.
- **Test the ownership property:** copy, immediately `wl-copy hello`, wait
  past the timeout, confirm `hello` **survives**. This is what verifies
  expiry-by-dropping-the-source doesn't clobber someone else's clipboard —
  the main reason kpa owns the offer instead of shelling out to `wl-copy`.
- **After this:** the whole password workflow works from a shell.

## Step 4 — tray

`tray.rs` on `ksni` — icon state (all locked / some unlocked / error),
tooltip, menu (Unlock…, Lock all, a per-database submenu, Quit). Menu
actions call `Server` directly (`Server::snapshot`, `Unlock::unlock`,
`Lock::lock`), the same calls the socket's `unlock`/`lock` ops make — no
second client, no second locking implementation.

- **Test:** icon appears in a StatusNotifierItem host, changes on
  lock/unlock, menu items act.
- **After this:** lock state is visible at a glance.

## Step 5 — lock policy

`policy.rs` — idle timer, logind `Lock`/`PrepareForSleep` via zbus, and the
`(dev, ino, mtime, size)` freshness guard.

- **Test:** set `idle_timeout = "10s"` temporarily and watch it lock.
  Trigger a logind `Lock` signal → `kpa status` locked.
- **Test freshness:** unlock, save the database from another client (or
  `touch` the fixture), then `kpa list` → `stale`.
- **Test the sync case explicitly**, if a vault syncs across machines —
  replace the file on another host and let it sync over. That scenario is
  what motivated the guard; a `touch` doesn't exercise the inode change a
  real sync produces.
- **After this:** safe to leave running indefinitely.

## Step 6 — hardening

`PR_SET_DUMPABLE=0` at startup, a zeroize audit, and `cargo-fuzz` against
the JSON parser.

Partly pulled forward into step 2 after the September robustness and
secret-hygiene reviews (`docs/review-2026-09-robustness.md`,
`docs/review-2026-09-secrets.md`): `PR_SET_DUMPABLE=0`, the request-size
cap, read/write timeouts, bounded connection handling, and a first zeroize
pass already landed there. The zeroize audit was repeated with `copy` and
the clipboard in place; its one kpa-owned
finding — `lock` left a still-served clipboard offer outliving
the lock it was supposed to be covered by — is fixed.

`fuzz/` is a checked-in `cargo-fuzz` harness: its one target,
`decode_request`, runs arbitrary bytes through the exact same UTF-8-check-
then-`decode_request` path `src/server.rs`'s `handle_connection` runs on a
request line. It's its own Cargo workspace (`fuzz/Cargo.toml`) and its own
Nix dev shell (`devShells.fuzz`, with the nightly rustc `cargo-fuzz`
needs), so neither ever touches `cargo build`/`cargo test`/`cargo clippy`
or the default dev shell. See README.md § Build & test for the exact
command.

- **Test:** `fuzz/`'s `decode_request` target for a few minutes; malformed
  input must error, never panic or hang. A run of ten million+ mutated
  requests has produced no panics or hangs so far.
- **After this:** done.

---

## Ordering notes

**Step 1 front-loads the only real technical risk.** Everything else is
plumbing that's well understood; whether `keepass` can actually open a
given KDBX file is the one thing that could invalidate the design, so it
goes first and cheap.

**Steps 2 and 5 are the two points where the whole system is meaningfully
better than before.** By step 2, kpa is fully working from a shell; by step
5, it's safe to leave running indefinitely. Both are natural stopping
points if the project stalls.

**Hardening (step 6) shouldn't be skipped, even though it's last.** These
steps only ever touch the test fixtures — but whenever kpa does end up
pointed at a real vault, every corner cut before then becomes relevant.
