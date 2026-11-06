# Secret-hygiene review — 2026-11

A repeat of [`review-2026-09-secrets.md`](./review-2026-09-secrets.md),
scoped to what changed since: `copy` (`src/proto/copy.rs`) and the
clipboard (`src/clip.rs`), from `docs/plan.md` step 3. The September
findings (master password, keyfile, dumpability, key-derivation
intermediates, the serialized `list` response) were all fixed before this
review and are not re-litigated — `docs/audits/2026-11-01.md`'s W2
workstream and Appendix A already reverified them against a later commit
(68/68 unit tests, a direct heap scan of the fixed code) and found nothing
open; this review's own reads of `vault.rs`/`server.rs` agree. That audit
explicitly left `copy`/`clip.rs` out of scope (its §1 Limitations, and
Appendix B's "G-7/T-6/T-13 clipboard clauses"), since PR #8 hadn't merged
to the commit it pinned — this review is exactly the follow-up it deferred.

Claims marked **verified** were reproduced by running code. Claims marked
**reasoned** were established by reading source only. The heap-residue
number in Finding 2 comes from an out-of-tree scanner crate that depends
on `kpa` by path, built and run in `/tmp/kpa-clip-scan` (outside this
repo — see [Method](#method)); nothing in this repository was modified to
run it, and no real database, config, or socket of the author's own was
touched. Wayland-dependent checks ran against this sandbox's own
development session's compositor; every clipboard offer kpa's test code
or the scanner started was confirmed ended (`wl-paste` showed nothing of
kpa's left behind) and no `kpa serve`/scanner process was left running.

## Secret lifecycle map (the `copy` addition)

**Entry point**

| Secret                        | Enters at                                                                                      |
| ------------------------------ | ----------------------------------------------------------------------------------------------- |
| A field value named by `copy` | `src/vault.rs:444` `entry_field`, reading straight through `Value::get()` — protected or not, since the request already named the one field it wants |

**Copies on the path**

- `entry_field` builds exactly one new copy: `v.get().as_str().to_string()`
  immediately wrapped by `Zeroizing::new(..)` (`vault.rs:460`) — no
  intermediate unwrapped `String` outlives that expression. For a
  protected field, `Value::get()` itself (inside `keepass`'s
  `secrecy`-backed `SecretBox`) is the one copy outside kpa's reach — same
  shape as the September review's keyfile/key-derivation findings, NG-4.
- `server.rs`'s `copy` (`CopyEntry::copy`, `:498`) passes that
  `Zeroizing<String>` by value into `Clipboard::offer`, which passes it by
  value into `Backend::start` — no `.clone()`, no `&str` parameter
  anywhere on this path (checked: `grep -n "fn .*&str"` across
  `vault.rs`/`clip.rs`/`proto/*.rs`/`server.rs` finds no secret-typed `&str`
  parameter).
- `WaylandBackend::start` (`clip.rs:162`) makes the one copy this feature
  adds that kpa itself owns: `secret.as_bytes().to_vec().into_boxed_slice()`
  — a `Box<[u8]>`, forced by `wl_clipboard_rs::copy::Source::Bytes`'s
  signature, which takes ownership and gives no zeroizing alternative. The
  `Zeroizing<String>` parameter itself is zeroized when the function
  returns (it is not moved into the spawned thread — only the `Box<[u8]>`
  copy is). This is Finding 2, below.
- The timeout thread `copy` spawns (`server.rs:555`) holds only
  `Arc<dyn Offer>` — an opaque handle (an `AtomicBool` behind the real
  backend, or a test double) — and `Arc<Clipboard>`. **Verified by
  reading**: neither is, or contains, the secret; `Offer`'s trait methods
  are `is_live(&self) -> bool` and `end(&self)`, nothing that returns or
  stores secret bytes.

**Sinks**

| Sink                               | What crosses it today                                                                                             |
| ----------------------------------- | ------------------------------------------------------------------------------------------------------------------ |
| The clipboard (Wayland data-control) | the field value, tagged `x-kde-passwordManagerHint: secret`, as designed — the one sink `copy` exists to use      |
| Socket → client                    | which field and database (`copy`'s own `db`/`field`), and `expires_in` — never the value (`proto/copy.rs`'s own doc comment, confirmed at `proto/mod.rs:142-146`: only `outcome.field` and `outcome.expires_in` are serialized) |
| Daemon stdout (operation log)       | `"copied {field} from {db}"` on success, `"copy failed: {err:?}"` on failure — `CopyError::Clipboard`'s `detail` is `ClipboardError`'s `Display` text, which is `wl-clipboard-rs`'s own connection/protocol error text, never the secret (checked: `ClipboardError` is only ever constructed from `err.to_string()` on a `wl_clipboard_rs::copy::Error` or a thread-spawn failure, both before any secret is in scope) |
| Error `detail` on the wire          | same as above — only `ClipboardError`'s text, which cannot carry the secret                                        |
| Child process argv/env              | none — `clip.rs` never shells out; `grep -n "Command::new"` across `src/` finds exactly one call site, the prompt in `server.rs`, unrelated to `copy` |
| Clipboard outliving its database's lock | **Finding 1** — not a sink for a new secret, but the existing offer continuing to serve one past the moment `docs/threat-model.md` G-6 says it should stop |

## Summary

| #   | Finding                                                                         | Severity | Fix lives     | Status            |
| --- | -------------------------------------------------------------------------------- | -------- | ------------- | ------------------ |
| 1   | `lock` left an outstanding clipboard offer being served past the lock           | Medium   | this repo     | **fixed** (verified) |
| 2   | The clipboard backend's own `Box<[u8]>` copy of the secret is never zeroized     | Low      | upstream      | verified, accepted |
| 3   | A narrow window between a successful `copy` and its own bookkeeping update       | Informational | this repo (documented, not closed) | reasoned |
| 4   | `design.md`'s Lock policy section didn't mention the clipboard                  | Informational | doc       | **fixed**          |

Finding 1 is the only kpa-owned defect this review found, and it is fixed
in this same change (`src/clip.rs`'s `Clipboard::end_now`, and
`server.rs`'s three call sites — see below), with five regression tests
covering the single-database, cross-database, lock-all, and idle-timeout
cases. Finding 2 is the clipboard's analogue of the September review's
already-accepted NG-4 residue — kpa makes the copy, but the only API
`wl-clipboard-rs` 0.9.5 offers for serving a paste request takes ownership
of a plain buffer, so kpa cannot zero it once handed over. See
[What is solid](#what-is-solid) for everything this review checked and
found already correct.

---

## 1. `lock` left an outstanding clipboard offer being served past the lock

**Severity:** Medium (fixed). It directly contradicts
`docs/threat-model.md` G-6 ("lock clears what kpa owns") for the one thing
`copy` makes kpa own on the user's behalf — the clipboard offer — and the
user-visible consequence is exactly what G-6 exists to prevent: a database
the user just locked can still have its password sitting on the clipboard.

**Where:** `src/server.rs`'s `Lock::lock`, `policy::Locks::lock_all`, and
`Server::expire_idle` (idle timeout) — none of them touched `self.clip`
before this review.

**Verified.** Before the fix, a unit test reproducing the scenario (copy a
password, then lock that same database, using `clip::RecordingBackend`'s
new liveness tracking — see Method) failed: the offer's `is_live()` stayed
`true` after `Lock::lock`. All three lock paths were affected:

- `Lock::lock` with a named database (`kpa lock personal`) — the explicit
  case a user would reach for specifically to shut a database down.
- `Lock::lock` with no database (`kpa lock`) and `policy::Locks::lock_all`
  (screen lock, suspend, bus loss) — the "lock everything" case, where
  there is no longer any unlocked database for a copied secret to
  legitimately belong to.
- `Server::expire_idle` (the per-database idle timer) — a lock the user
  didn't even ask for in the moment, making an unexpectedly-long-lived
  clipboard entry the more surprising of the two.

`docs/threat-model.md` T-8 already named this exact scenario — "a
clipboard offer outliving its database's lock" — in its "in scope" list,
with no response describing one; this review treats that as the
open gap it reads as, not as an accepted non-goal.

**Fix (this repo).** `Clipboard` gains `end_now` (`clip.rs`): ends
whatever offer is current, regardless of which `copy` started it —
unlike `expire`, which only acts on the one specific offer it's handed.
`Server` gains `clip_db: Arc<Mutex<Option<String>>>`, recording which
database the clipboard's current offer (if any) came from; `copy` sets it
right after a successful handoff, and the timeout thread clears it once
its own `clipboard_timeout` fires with nothing newer in place. Two new
`Server` helpers read it:

- `end_clipboard_for(name)` — ends the clipboard only if its current
  content came from `name`. Used by `Lock::lock`'s named-database arm and
  by `expire_idle`, so locking (or idle-locking) one database never
  touches a legitimately still-live secret copied from a different,
  still-unlocked one.
- `end_clipboard_all()` — ends the clipboard unconditionally. Used by
  `Lock::lock`'s bare `lock` form and `policy::Locks::lock_all`, where
  every database is locking at once.

**Regression tests** (all passing, `src/server.rs`'s test module):
`locking_the_db_a_copy_came_from_ends_the_clipboard_offer`,
`locking_an_unrelated_db_does_not_end_the_clipboard_offer`,
`locking_every_database_ends_the_clipboard_offer`,
`policy_lock_all_ends_the_clipboard_offer`,
`idle_lock_ends_the_clipboard_offer_for_that_db`. They use
`clip::RecordingBackend::new_tracking`, a small extension to the existing
test-only `RecordingBackend` that makes its stand-in offers actually
track `is_live`/`end`, rather than being permanently "live" no-ops — the
previous version couldn't have distinguished "lock ended it" from "lock
did nothing," so it would have passed either way. `clip.rs`'s own unit
tests gained three cases for `end_now` directly: dropping a live current
offer, doing nothing on an empty clipboard, and doing nothing once
something else has already superseded the offer (the same "nothing to
do" rule `expire` already followed).

**Not changed:** `clipboard_timeout` itself — an offer that outlives its
own timeout without any lock happening is unaffected; this fix only adds
a second, earlier way an offer can end.

---

## 2. The clipboard backend's own `Box<[u8]>` copy of the secret is never zeroized

**Severity:** Low. Kpa makes this copy itself, but the only API available
to serve it a Wayland paste request takes ownership of a plain buffer —
there is no zeroizing variant to hand it instead, and no way to reach back
in and zero it once it's been handed over. Classified the same way the
September review classified `keepass`'s unzeroized key-derivation
intermediates: a real residue, outside this repo's reach to fix.

**Where:** `src/clip.rs:170` (`WaylandBackend::start`):
`secret.as_bytes().to_vec().into_boxed_slice()`, passed into
`wl_clipboard_rs::copy::Source::Bytes`. The module's own doc comment
already named this shape ("a second copy that `wl-clipboard-rs` holds
unzeroized for as long as it serves the offer") without having verified
it empirically; this review does.

**Verified.** A scratch binary (`/tmp/kpa-clip-scan`, depending on `kpa`
by path — see [Method](#method)) offered a 33-byte unique needle string
through a real `Clipboard`/`WaylandBackend` against this sandbox's own
Wayland session, then scanned this process's own `/proc/self/maps` `rw`
regions via `/proc/self/mem` before, during, and after ending the offer:

```
[baseline]   count=0
[offered]    count=1
[after-end]  count=1
[after-second-offer] count=0
```

The needle is in process memory exactly once while offered (the `Box<[u8]>`
— the `Zeroizing<String>` parameter dropped and zeroized at the end of
`start`'s synchronous part, before the needle could be counted twice), and
it **still reads 1 after `end()` runs** — `clear()` tears down the
Wayland-side selection, and the serving thread's `prepared.serve()` call
returns and drops `PreparedCopy` (taking the `Box<[u8]>` down with it),
but nothing zeroizes that buffer; it is simply freed, unwiped. A second,
unrelated offer-then-end cycle of equal length reused the same freed
chunk and overwrote it (`count` drops to 0) — the same allocator-luck
caveat the September review already states for every "0" in these scans:
a zero means reuse happened to occur, not that anything was deliberately
cleared. No stray process or real-clipboard content was left behind by
this scan (confirmed: `wl-paste` after the run showed only what the
session already had, and no `scan`/`kpa` process remained).

**Classification.** kpa-owned up to the moment of handoff (the copy is
kpa's own `to_vec()`, not something `keepass` or `wl-clipboard-rs` made on
their own), but dependency-constrained from that point on: `Source::Bytes`
takes `Box<[u8]>`, full stop, and `wl-clipboard-rs` 0.9.5 has no zeroizing
equivalent. Fixing this upstream would need either a new `Source` variant
that owns a `Zeroizing<Box<[u8]>>` (or accepts any `AsRef<[u8]> + Drop`)
and zeroizes it once the offer stops being served, or kpa reimplementing
`ext-data-control`/`wlr-data-control` itself — the same two options
`clip.rs`'s existing doc comment already weighs for the `end`/`clear` race,
and not worth it for the same reason: narrow, allocator-dependent residue,
not a channel the secret leaves through.

**Fix:** None in this repo. `docs/design.md`'s Lock policy section now
lists this buffer under "Not cleared, upstream" (see this review's code
changes), matching how the September findings' residues are documented.

---

## 3. A narrow window between a successful `copy` and its own bookkeeping

**Severity:** Informational — a race, not a defect with a known
reproduction, and already the same shape as a gap `clip.rs` documents for
itself elsewhere.

**Where:** `src/server.rs`'s `CopyEntry::copy`: `self.clip.offer(value)`
succeeds and the offer becomes current inside `Clipboard`, and then —
a few instructions later, not atomically with the line above — `clip_db`
is set to record which database it came from.

**Reasoned, not reproduced.** If a `lock` for that same database lands in
the gap between those two lines, `end_clipboard_for` reads the old
`clip_db` value (whatever it was before this `copy`), finds no match, and
does nothing — the brand-new offer then only expires via its own
`clipboard_timeout`, exactly the bug Finding 1 otherwise fixes. The window
is a handful of instructions on one thread with no I/O in it, between two
operations that don't block on each other; closing it fully would need
`Clipboard` and `clip_db` to update as one atomic step, which the current
backend-agnostic split between `Clipboard` (doesn't know about databases)
and `Server` (tracks the association externally) doesn't support without
either giving `Clipboard` a notion of "database" or giving `Server`'s
lock paths a way to peek inside `Clipboard`'s own mutex.

**Fix:** None applied — recorded here, and in `server.rs`'s own code
comment at the `clip_db` assignment in `copy`, rather than overclaimed.
Matches this repo's practice for the `WaylandOffer::end`/`is_live`
two-round-trip race `clip.rs` already documents instead of closing.

---

## 4. `docs/design.md`'s Lock policy section didn't mention the clipboard

**Severity:** Informational (fixed). Before this review, § Lock policy's
"Cleared"/"Not cleared, upstream" lists predated `copy` entirely and said
nothing about what happens to an offer on lock — not wrong at the time
written, just silent about a case that didn't exist yet.

**Fix (doc).** § Lock policy now states that locking ends any clipboard
offer that database's `copy` started (Finding 1's fix), and lists the
clipboard backend's own unzeroized buffer (Finding 2) under "Not cleared,
upstream," alongside `keepass`'s pre-existing residues.

---

## What is solid

- **The CLI never sees the secret.** `proto/mod.rs`'s `Response`
  serialization for `Response::Copy(Ok(outcome))` writes only `ok`,
  `copied` (the field name), and `expires_in` — never `outcome.db`, never
  a value. `main.rs`'s `run_client` only ever prints the escaped response
  line it's handed; there is no code path that could print a secret `copy`
  received, because `copy` never puts one on the wire in the first place
  (**verified** by reading `proto/mod.rs:142-146` and `main.rs:184-220`,
  and by the existing `tests/clipboard.rs` integration tests, which assert
  exactly this for both the success and the no-compositor-reachable cases).
- **The operation log never carries the secret.** `copy`'s two log lines
  (`server.rs`'s `log_response`) use only the field name, database name,
  and — on failure — `ClipboardError`'s own `Display` text, which can only
  ever be a `wl_clipboard_rs::copy::Error`'s message or a thread-spawn
  failure string, both from before any secret is in scope.
- **No child process.** `copy`/`clip.rs` never shells out — the one
  `Command::new` in `src/` is the unrelated password prompt. `clip.rs`'s
  own module doc states this is deliberate (own the Wayland offer
  in-process rather than fork `wl-copy`), and the code matches.
- **The expiry thread holds no secret.** `copy`'s spawned timeout thread
  (`server.rs:555`) captures `Arc<Clipboard>`, `Arc<dyn Offer>`, and now
  `Arc<Mutex<Option<String>>>` (a database *name*, not a secret) plus the
  timeout `Duration` and the database name as a plain `String` — none of
  which is, or contains, the copied value. **Verified** by reading every
  type the closure captures.
- **No `&str` parameter anywhere takes a secret.** Checked across
  `vault.rs`, `clip.rs`, `proto/copy.rs`, `proto/mod.rs`, and `server.rs`'s
  `copy` path: the only `&str`-typed functions are test helpers and
  non-secret lookups (`field_key`, `decode_request`'s input line); the
  secret itself is `Zeroizing<String>` end to end, passed by value.
- **`Debug`/`Display` never expose the value.** `CopyRequest`, `CopyError`,
  `CopyOutcome`, and `ClipboardError` all derive or implement `Debug`; none
  of their fields is, or wraps, the secret (`db`, `uuid`, `field`,
  `expires_in`, and backend error text only). `log_response`'s `{err:?}`
  on a failed `copy` is therefore safe for the same reason the September
  review already established for `unlock`/`lock`'s own `{err:?}` logging.
- **`list` still omits protected fields; `copy` deliberately doesn't.**
  `vault::unprotected_field` (used by `list`) and `vault::entry_field`
  (used by `copy`) are two different functions for exactly this reason —
  re-verified by reading, consistent with `vault.rs`'s own doc comment on
  `entry_field` explaining why that's correct (the request already named
  one specific field of one specific entry; there's nothing left for
  "protected" to mean in that context that the request didn't already ask
  for).
- **The September findings stay fixed.** `prompt_password` still reads
  into a fixed-capacity `Zeroizing` buffer that never grows
  (`server.rs:634` onward); `run_serve` still calls `forbid_core_dumps`
  before config or any vault access; `wire_entries`/`EntrySummary` still
  derive `ZeroizeOnDrop`. None of this changed under `copy`, and
  `docs/audits/2026-11-01.md`'s own W2 workstream already reverified all
  of it independently against a slightly later commit.

---

## Method

- **Static read.** Every copy and sink on the `copy`/clipboard path was
  traced by reading `src/vault.rs` (`entry_field`), `src/server.rs`
  (`CopyEntry::copy`, `Lock::lock`, `policy::Locks for Server`,
  `Server::expire_idle`, `log_response`), `src/clip.rs` (all of it),
  `src/proto/copy.rs`, `src/proto/mod.rs` (dispatch and wire
  serialization), `src/output.rs`, and `src/main.rs` (`run_client`,
  `Command::Copy`), following `docs/threat-model.md` G-3/G-4/G-6 and
  T-4/T-5/T-9's own "in scope" lists.
- **Unit tests, no Wayland needed.** The lock/clipboard interaction
  (Finding 1) is covered by `src/server.rs`'s and `src/clip.rs`'s own test
  suites, using `clip::RecordingBackend`/`FakeBackend` — no real
  compositor involved, so these run (and ran, as part of `cargo test`)
  anywhere.
- **Real-compositor scan for Finding 2.** A scratch crate at
  `/tmp/kpa-clip-scan` — outside this repository, not committed — with
  `kpa = { path = "<this worktree>" }` as its only non-`zeroize`
  dependency. Its one binary builds a real `clip::Clipboard` over
  `clip::WaylandBackend`, offers a unique 33-byte needle string against
  this sandbox's own Wayland session (`$WAYLAND_DISPLAY`/
  `$XDG_RUNTIME_DIR` were already set and live here), and scans this
  process's own `/proc/self/maps` `rw` regions via `/proc/self/mem` in a
  reused buffer, with a warm-up scan first — same technique the September
  review used, simplified (no XOR-masking: a 33-byte ASCII tag that will
  never collide with real content is not worth the extra machinery a real
  password's masked-needle technique earns). After the run, `wl-paste`
  was checked empty of the scanner's content and no `scan`/`kpa` process
  was left running — the existing `tests/clipboard.rs` integration tests
  already establish this is safe to do against this sandbox's own
  session, and this review followed the same practice.
- **No real vault, config, or socket touched.** Every test and scan here
  used either `tests/fixture.sh`'s fixtures (through the existing test
  suite) or synthetic in-memory databases built directly with `keepass`'s
  own builder API (the existing `unlock_with_entry` test helper); the
  scratch scan crate never opens a `.kdbx` at all. No `--socket`/`--config`
  pointed anywhere but a test's own temp directory or the scratch crate's
  in-process `Server`.
- **Verification commands.** `cargo build`, `cargo test`, and
  `cargo clippy --all-targets -- -D warnings` all run clean, both directly
  and under `nix develop`; `cargo fmt --check` reports no changes needed.
