# Robustness review — 2026-09

An adversarial pass over the working tree after step 2 (daemon, socket,
protocol), looking for ways the process can crash, abort, hang or silently
do the wrong thing on input it does not control: the `.kdbx` file, the
keyfile, the socket, and the process environment. Leaks are out of scope
here; they are covered by the secret-hygiene review.

This builds on [`review-2026-09.md`](./review-2026-09.md) (called "the first
review" below). Where a finding there has changed because the daemon now
exists, this document says so.

Every claim is labelled **verified** (reproduced by running code; output
pasted) or **reasoned** (read from source, not exercised). All experiments
ran out of tree: the repo binary was built with `CARGO_TARGET_DIR` pointing
at a scratch directory, and internals were exercised from a separate crate
that depends on `kpa` by path. Nothing in this repo was modified to run a
check. Scratch paths are shown as `<scratch>` below.

## Verdict on memory safety

**No memory-corruption or use-after-free path was found, and none is
plausible from this repo's own code.**

- `grep -rn unsafe src tests` returns nothing. **Verified.**
- `keepass` 0.15.0 contains no `unsafe` either (it does not
  `#![forbid(unsafe_code)]`, so this is a property of the current release,
  not a guarantee). `quick-xml` 0.42.0 and `miniz_oxide` 0.9.1 (the
  `flate2` backend actually selected) both `#![forbid(unsafe_code)]`.
  **Verified** by grep over the vendored sources.
- **Correction to the first review:** the path from file bytes to a
  `Database` is not entirely safe Rust. `rust-argon2` 3.0.0 has `unsafe`
  code in `core.rs` (`fill_segment`, `fill_memory_blocks_mt`) that indexes
  the Argon2 memory matrix unchecked, and its shape comes from file-controlled
  parameters (`lanes`, `mem_cost`, `time_cost`). Every unchecked access is
  preceded by `assert!`s on the exact bounds and aliasing conditions it
  relies on (`core.rs:338-347`), and `Context::new` range-checks every
  parameter before the memory is sized. An inconsistent parameter therefore
  panics rather than corrupting memory. **Reasoned**, but from a close read
  of the code, not the README.
- The crypto crates (`aes`, `chacha20`, `sha2`, `blake2b_simd`) use `unsafe`
  for SIMD intrinsics over fixed-size blocks. `serde_json` (socket input)
  and `toml_parser` (config) also contain `unsafe`. These were **not**
  audited line by line. They are widely used and heavily fuzzed upstream,
  and the shapes they operate on do not depend on input length, but this
  review makes no claim about them beyond that.

So the realistic failure modes are aborts, hangs, resource exhaustion and
silent misbehaviour, not undefined behaviour. What has changed since the
first review is that a daemon now exists. **An abort now takes down every
unlocked database, not just one CLI invocation**, and several of the
findings below are daemon-lifecycle problems that did not exist before.

## Summary

| #   | Finding                                                                      | Severity   | Fix lives             |
| --- | ---------------------------------------------------------------------------- | ---------- | --------------------- |
| 1   | One unterminated request line aborts the daemon (unbounded `read_line`)      | Medium     | this repo             |
| 2   | Idle connections pin a thread each; a failed `thread::spawn` kills the daemon | Medium     | this repo             |
| 3   | A `lock` issued while an `unlock` is in flight is silently undone            | Medium     | this repo             |
| 4   | Logging to a closed stdout panics: the daemon dies, or ops succeed but report failure | Medium | this repo       |
| 5   | KDBX3 header corruption silently yields wrong protected values               | Medium     | upstream (+ doc)      |
| 6   | KDF parameters: hang and abort, re-measured inside the daemon                | Low–Medium | upstream / this repo  |
| 7   | `accept()` errors busy-loop at 100% CPU                                      | Low        | this repo             |
| 8   | Short header fields panic inside `keepass`                                   | Low        | upstream / this repo  |
| 9   | `bind_socket` deletes non-socket files and chmods arbitrary directories      | Low        | this repo             |
| 10  | Claims that do not match behaviour                                           | Nit        | this repo / the doc   |

Findings 1–4 are new with step 2 and are the ones to fix before the daemon
runs unattended. None of them needs a fixture file to test. For them the
socket is the attack surface, and only the same user can reach it (mode
`0600`). They are still worth fixing, for two reasons. `docs/plan.md` step 6
sets the bar at "malformed input must error, never panic or hang the
daemon". And finding 2 in particular can be triggered by resource pressure
from any process of that user, with no malicious client involved.

---

## 1. One unterminated request line aborts the daemon

**Severity:** Medium. **Fix lives:** this repo.

**Where:** `src/server.rs:334-339` (`handle_connection`),
`BufReader::read_line` into an unbounded `String`.

`read_line` keeps appending until it sees `\n` or EOF. A client that sends
bytes without a newline makes the daemon grow one `String` without limit.
Growth doubles the capacity each time, so the allocation that finally fails
is an `abort`, not a `Result`. That kills every session, including every
unlocked database.

**Verified**, with the daemon under a 1 GiB address-space limit so the test
does not threaten the host:

```
unlock good -> {"v":1,"ok":true,"db":"good"}
send stopped after 512 MiB: [Errno 32] Broken pipe
daemon exit code (RLIMIT_AS=1GiB, one client, no newline): -6
stderr: memory allocation of 1073741824 bytes failed
```

With no limit, the same client drives the machine into the OOM killer. That
was not run.

**Fix (this repo).** Bound the read:
`BufReader::new(&stream).take(MAX_REQUEST_LEN + 1).read_line(&mut line)`,
with `MAX_REQUEST_LEN` in the tens of KiB (the largest legitimate request is
under 200 bytes today). If the limit is hit without a newline, reply
`malformed_request` and close. Add a read timeout at the same time
(finding 2).

**Verify.** A unit test in `server.rs` that builds a `Server` from an empty
`Config`, calls `handle_connection` on one end of `UnixStream::pair()`,
writes 1 MiB of `a` from the other end, and asserts a `malformed_request`
response. No fixture needed.

---

## 2. Idle connections pin a thread each; a failed spawn kills the daemon

**Severity:** Medium. **Fix lives:** this repo.

**Where:** `src/server.rs:289-294` (`serve`) and `:334-339`.

Two properties combine here:

1. Accepted streams have no read timeout, so a client that connects and
   sends nothing holds its handler thread forever.
2. `thread::spawn` panics if the OS refuses to create a thread, and it is
   called on the **main** thread inside the accept loop. A panic there ends
   `serve`, and with it the process.

**Verified**, the first property:

```
threads at start: 1
threads after 500 idle connections: 501
threads 5s later (no timeout reaps them): 501
status still served -> {"v":1,"ok":true,"databases":[{"name":"g
threads after clients close: 1
```

**Verified**, the second property. `RLIMIT_NPROC` was set to the user's
current thread count + 50, then connections were opened:

```
connect 52 failed: [Errno 111] Connection refused
daemon exit code: 101
stderr: thread 'main' panicked at .../std/src/thread/functions.rs:131:29:
        failed to spawn thread: Os { code: 11, kind: WouldBlock, ... }
```

`RLIMIT_NPROC` counts **all** of the user's threads, not just the daemon's.
So the daemon can die simply because *something else* the user runs is using
threads when a client connects. That includes a fork-happy build or the
Argon2 thread fan-out in finding 6. No misbehaving client is needed.

**Fix (this repo).**

- `stream.set_read_timeout(Some(Duration::from_secs(5)))` (and a write
  timeout) on every accepted stream.
- Use `thread::Builder::new().spawn(...)` and, on `Err`, drop the connection
  and carry on. Never let the accept loop panic.
- Optionally, cap concurrent handlers (an `AtomicUsize` checked before
  spawning) so that a flood degrades into refused connections rather than
  unbounded threads.

**Verify.** A test that opens N idle connections with a short configured
timeout and asserts that the thread count (`/proc/self/task`) returns to
baseline. For the spawn failure, the in-repo test is simply that `serve`
contains no panicking spawn. This is easier to assert by review than to
provoke portably in CI.

---

## 3. A `lock` issued while an `unlock` is in flight is silently undone

**Severity:** Medium. It defeats the lock policy the design is built
around. **Fix lives:** this repo.

**Where:** `src/server.rs:81-126` (`impl Unlock for Server`).

`unlock` checks "already unlocked?" under the mutex. It then releases the
mutex, runs the prompt and the KDF (seconds: human typing plus about 20 ms to
400 ms of key derivation), and finally re-takes the mutex and inserts the
`Database` unconditionally. A `lock` that lands in that window succeeds and
is acknowledged, and then the finishing `unlock` overwrites it.

**Verified** with a prompt that takes 2 s to answer:

```
t=0.5s  lock (all) -> {"v":1,"ok":true}
t=0.5s  status     -> {"v":1,"ok":true,"databases":[{"name":"good","locked":true},...
t~2s    unlock returns -> {"v":1,"ok":true,"db":"good"}
after   status     -> {"v":1,"ok":true,"databases":[{"name":"good","locked":false,"entries":1},...
```

This matters most once step 5 lands. For example, a `PrepareForSleep` lock
fires while a key derivation is still running, and the machine resumes with
the vault open even though the lock reported success before suspend.

The same window also means concurrent `unlock`s of one database each run
their own prompt. **Verified:** three simultaneous `unlock good` requests
spawned three prompt processes at once:

```
prompt children of the daemon while 3 unlocks of one db are in flight: 3
```

**Fix (this repo).** Keep a lock epoch (a `u64` in the mutex-guarded state,
bumped by every `lock`). `unlock` reads the epoch before prompting and
inserts only if it is unchanged. Otherwise it drops the freshly opened
`Database` and returns an error: `locked` fits, or a dedicated code. Track a
per-database "unlock in progress" flag in the same state, so that a second
`unlock` waits for or joins the first instead of prompting again. That also
bounds finding 6's CPU stacking to one core per database.

**Verify.** Extend `tests/server.rs`. Configure a prompt of
`["sh", "-c", "sleep 1; printf %s <password>"]`, start `unlock` on a thread,
send `lock` after 200 ms, join, and assert that `status` reports the
database as locked.

---

## 4. Logging to a closed stdout panics

**Severity:** Medium. **Fix lives:** this repo.

**Where:** `src/main.rs:126` (`println!("kpa: listening ...")`) and
`src/server.rs:311-328` (`log_response`, every `println!`). Ordering is set
at `src/server.rs:355-359`: the log line is written before the response.

`println!` panics if the write fails. Rust ignores `SIGPIPE`, so when stdout
is a pipe whose reader has gone away, every log line is an `EPIPE` and
therefore a panic.

**Verified**, reader gone before startup: the main thread panics and the
daemon exits.

```
daemon exit code with stdout reader closed at startup: 101
stderr: thread 'main' panicked at .../std/src/io/stdio.rs:1166:9:
        failed printing to stdout: Broken pipe (os error 32)
```

**Verified**, reader gone after startup. This is the worse case, because
the state change has already happened when the panic hits:

```
status    -> {"v":1,"ok":true,"databases":[{"name":"good","lock...   (reads don't log)
unlock    -> <connection closed, no response>
status    -> {"v":1,"ok":true,"databases":[{"name":"good","locked":false,...
lock      -> <connection closed, no response>
status    -> {"v":1,"ok":true,"databases":[{"name":"good","locked":true},...
```

`kpa unlock` and `kpa lock` both exit 1 with "daemon closed the connection
without responding (is `kpa serve` running? ...)". But the database *was*
unlocked, and then *was* locked. A caller that trusts the exit status of
`kpa lock` is told the lock failed when it succeeded. More dangerously, a
caller that retries or falls back after a "failed" unlock believes the vault
is closed when it is open.

Separately, if the reader stays alive but stops draining, the pipe fills up
(about 64 KiB of log lines) and every `unlock`/`lock` handler blocks inside
`println!` before it can reply. **Reasoned**, not run.

**Fix (this repo).** Make logging infallible and non-blocking with respect
to the reply:

- Write the response first, then log.
- Log with `let _ = writeln!(std::io::stdout().lock(), ...)` rather than
  `println!`. The startup line in `main.rs` needs the same treatment.

**Verify.** Spawn `kpa serve` with its stdout attached to a pipe, close the
read end, then send `unlock`. Assert that a response arrives and that the
process is still alive.

---

## 5. KDBX3 header corruption silently yields wrong protected values

**Severity:** Medium. Today it is latent: `list` omits protected fields,
so nothing wrong is shown. It becomes live with step 3's `copy`, which
would put a wrong password on the clipboard with no error. **Fix lives:**
upstream, plus a doc note here.

**Where:** `keepass` 0.15.0 `format/kdbx3.rs` (the header is parsed and
used without authentication). `grep -rni header_hash` over the crate finds
only the KDBX4 path, so nothing checks the KDBX 3.1 `<Meta><HeaderHash>`
that KeePass clients write for exactly this purpose.

**Verified**, and found by the fuzzer rather than constructed. Of 3000
KDBX3 mutations, 7 opened *successfully*. Six of them changed a single byte
inside the `ProtectedStreamKey` header field (type 8). That key decrypts
every protected value, so the database opens and every protected field
comes back as garbage:

```
== original
Password   protected=true  "entrypass1"
== m53  (one byte changed, inside header field 8)
Password   protected=true  "ٹ��F\u{b}M��"
Title      protected=false "Example"          (unprotected fields intact)
```

The seventh success (`m1397`) changed one byte in the final ciphertext
block and decoded to identical content. It is benign.

KDBX4 is not affected: its header is covered by a SHA-256 checked before
anything else is used (438 of 2000 KDBX4 mutations were rejected with
`Header hash mismatch`).

**Fix (upstream).** Verify `Meta/HeaderHash` against the SHA-256 of the
outer header when it is present (KDBX 3.1). This is small and belongs in
`keepass`.

**Fix (this repo), priced.** `keepass` does not surface `HeaderHash`, so
checking it here means decrypting the XML a second time
(`Database::get_xml`) just to read one element. That runs the KDF twice per
unlock and adds a second XML read to keep in step with the real one. It is
not worth it for a format KeePassXC stopped writing by default. The
recommendation is to file upstream, and to give `copy` (step 3) a comment
stating that KDBX3 protected values are unauthenticated until upstream
checks the header hash.

**Verify.** Once fixed upstream: flip one byte of header field 8 in
`fixture.kdbx` (a 20-line script, given in "Reproducing" below) and assert
that `vault::open` returns `Corrupt` rather than `Ok`.

---

## 6. KDF parameters: hang and abort, re-measured inside the daemon

**Severity:** Low–Medium. It was Low in the first review; an abort now
kills the daemon and every unlocked database. **Fix lives:** mostly
upstream. In-repo containment is possible and priced below.

The first review's finding 7 stands. The daemon changes its consequences,
and several of its details need correcting.

**Hang: verified, and it is worse than "one hung request".** A KDBX3 file
with `TransformRounds = u64::MAX`, unlocked through the real daemon:

```
status while hang in flight -> {"v":1,"ok":true,...}      <- other ops still served
  daemon CPU during 3s of hung unlock: 2.98s
unlock hang   -> <no response within 8s>
lock all      -> {"v":1,"ok":true}
  daemon CPU in 3s after client gave up and db locked: 2.98s
after 1 abandoned unlock attempts of "hang": daemon CPU 1.0 cores
after 2 abandoned unlock attempts of "hang": daemon CPU 2.0 cores
after 3 abandoned unlock attempts of "hang": daemon CPU 3.0 cores
open fds on r3max.kdbx held by daemon: 3
```

- **Correction:** the first review said one such file "wedges every
  database" through the mutex. That no longer holds. `unlock` does not hold
  the mutex during `vault::open`, and `status` was answered throughout.
- The hung thread outlives its client and outlives `lock`. Each retry adds
  another core spinning forever. Finding 3's per-database "unlock in
  progress" flag bounds this at one core per database.
- Each hung unlock also keeps the `.kdbx` fd open indefinitely
  (`vault::open` holds `file` until `Database::open` returns). That
  contradicts `docs/design.md` § Concurrency rule 1, "Never hold an fd.
  Open, read whole file, close, parse." Reading into a `Vec` and closing the
  file before calling `Database::parse` makes the rule true.
- A KDBX4 `I` (iterations) of `2^32-1` hangs in the same way. **Verified**
  (`timeout 10` → exit 124), after rewriting the keyless header SHA-256.

**Abort: verified in the daemon.** A KDBX4 file with `M = 4 GiB` (header
SHA-256 fixed up), daemon under a 3 GiB address-space limit:

```
unlock good   -> {"v":1,"ok":true,"db":"good"}
unlock oom    -> <connection closed, no response>
  daemon exit code: -6
  stderr: memory allocation of 4294967296 bytes failed
status        -> ConnectionRefusedError [Errno 111] Connection refused
```

**How often accidental corruption hits this.** Of 3000 random 1–16-byte
mutations of the KDBX3 fixture, 43 hung (1.4%), and every one of the 43
touched header field 6 (`TransformRounds`). Of 2000 mutations of the KDBX4
fixture, **0** hung or aborted, because the header SHA-256 caught random
damage before the KDF ran. So the note at `src/vault.rs:143-152` ("Ordinary
file corruption is sufficient to hit this") is accurate for KDBX3 only. For
KDBX4 it takes a deliberate edit that also rewrites the SHA-256. The comment
should say so.

**Argon2 parallelism, verified.** `keepass` runs Argon2 in
`ThreadMode::Parallel` (`crypt/kdf.rs:72`), and `rust-argon2` spawns one
scoped thread per lane per slice, with the lane count taken from the file
(`P`, up to 2^24−1; memory must be at least 8 KiB per lane). `P = 20000`
opened in 2.95 s using 20 000 threads per slice. With a tight thread budget,
it panics:

```
[P=4096, ulimit -u = current+5] exit=101
panicked at crossbeam-utils-0.8.23/src/thread.rs:273:14:
failed to spawn scoped thread: Os { code: 11, kind: WouldBlock, ... }
```

On its own this is a survivable panic in a handler thread. But it draws on
the same per-user thread budget as finding 2's accept loop, so a large `P`
can make the *daemon's* next `thread::spawn` fail too. **Reasoned** for the
combination.

**Silent truncation, reasoned.** `crypt/kdf.rs:80-82` computes
`(memory / 1024) as u32` and `iterations as u32`. Out-of-range values wrap
instead of erroring, so kpa can derive a different key than another client
would from the same header. The result is a spurious "wrong password"
rather than a crash.

**Fix (upstream).** Ceilings on rounds, memory, iterations and parallelism,
checked with `try_from` rather than `as`, before the KDF runs.

**Fix (this repo), re-priced.** The first review recommended waiting,
because the cost is a second, partial header parser to keep in step with
`keepass`. The trade-off has moved: an abort now loses every unlocked
database, and a hang now leaks a core per retry. The cheap in-repo steps are
the finding 3 dedupe and reading into a `Vec` before parsing. Both are worth
doing regardless. A header pre-check (about 80 lines: KDBX3 TLV, or KDBX4
TLV plus the VariantDictionary) that rejects implausible values before
`Database::parse` is still the only in-repo fix for the abort. Its
maintenance cost is real but bounded, because the KDBX header layout has not
changed since 2017. The recommendation is to file upstream now and to add
the pre-check if upstream has not moved by step 5, when the daemon is meant
to be "safe to leave running indefinitely".

A timeout around the unlock is still *not* a mitigation. Rust threads cannot
be cancelled, so the KDF keeps its core, and the allocation abort ends the
process from whatever thread it happens on.

---

## 7. `accept()` errors busy-loop at 100% CPU

**Severity:** Low. **Fix lives:** this repo.

**Where:** `src/server.rs:291`, `let Ok(stream) = conn else { continue };`.

When `accept` fails with a persistent error (for example `EMFILE` when the
fd limit is reached), the pending connection stays in the backlog and the
next `accept` fails immediately in the same way. The loop spins.

**Verified** with `RLIMIT_NOFILE = 32` and 40 idle clients:

```
RLIMIT_NOFILE=32, 40 idle conns: daemon CPU over 3s = 2.96s, threads=29
status -> <no response within 3s>
after idle conns closed: CPU over 2s = 0.00s
status -> {"v":1,"ok":true,"databases":[...
```

It recovers once fds free up. But the combination of finding 2's missing
timeout and this loop means that idle clients alone can put the daemon into
a full-CPU state in which it serves nothing. The doc comment on `serve`
("Accept connections until the listener errors out") also describes
behaviour the loop does not have: it never stops on an error.

**Fix (this repo).** On `Err`, sleep briefly (for example 50–100 ms) before
the next `accept`, and log once per burst. Finding 2's read timeout removes
the usual way into this state.

---

## 8. Short header fields panic inside `keepass`

**Severity:** Low. It is a panic in a handler thread and the daemon
survives, but the client gets a misleading error and nothing is logged.
**Fix lives:** upstream, with a cheap in-repo guard.

**Where (upstream, reasoned from source, each one verified below):**
`byteorder::read_u32`/`read_u64` is called on a header value whose length
was never checked:

- `format/kdbx3.rs:87` (compression), `:97` (`TransformRounds`), `:111`
  (inner stream ID)
- `format/kdbx4/parse.rs:199` (compression), `:319` (inner stream ID)
- `format/variant_dictionary.rs:90-94` (typed KDF parameters)

Separately, `format/kdb.rs:405-408` `expect`s that a lone key element is
exactly 32 bytes. An XML keyfile whose `<Data>` decodes to any other length
breaks that assumption. In KDBX4 all of these run *before* the header
SHA-256 check.

**Verified**, crafted:

```
[r3short]  exit=101  range end index 8 out of range for slice of length 2   (kdbx3 field 6)
[c3short]  exit=101  range end index 4 out of range for slice of length 2   (kdbx3 field 3)
[c4short]  exit=101  range end index 4 out of range for slice of length 2   (kdbx4 field 3)
[p4short]  exit=101  range end index 4 out of range for slice of length 2   (kdbx4 KDF "P")
legacy .kdb + <Data>AAAA</Data> keyfile, empty password:
           panicked at keepass-0.15.0/src/format/kdb.rs:408:14:
           initializing from single element should always succeed: TryFromSliceError(())
```

(The same short keyfile against the KDBX3 fixture returns `WrongCredentials`
cleanly. Only the legacy KDB path panics.)

**Verified** in the daemon: it stays up and the mutex is not poisoned (it is
not held during `vault::open`, and every lock site uses
`unwrap_or_else(|e| e.into_inner())` anyway). But the client prints:

```
error: daemon closed the connection without responding (is `kpa serve` running? socket: ...)
```

The daemon *is* running. `log_response` never runs, so the failed unlock
leaves no log line, although `log_response`'s own doc comment calls it "the
event most worth having a record of".

The fuzzer found one of these by accident (1 in 3000 KDBX3 mutations
changed the length prefix of field 6). It found none in 2000 KDBX4
mutations: random flips of a length byte nearly always overshoot into an EOF
error rather than landing on a short value.

A further arithmetic hazard, **reasoned**: `format/kdb.rs`
`payload_padded.len() - padlen` would panic on underflow in a build with
overflow checks. The release profile has them off, so it wraps and the
following `.get()` fails cleanly.

**Fix (upstream).** Length-check each entry before `read_u*`, and replace
the `expect` in `kdb.rs` with an error.

**Fix (this repo), cheap.** Wrap the `vault::open` call in
`server::unlock` in `std::panic::catch_unwind(AssertUnwindSafe(...))` and
map a panic to `UnlockError::Corrupt`. This is sound because `vault::open`
touches no shared state, and `DatabaseKey`'s `ZeroizeOnDrop` still runs
during unwinding. It stops working if anyone sets `panic = "abort"` in a
profile, so add a comment next to it saying that. Also make the client's
`EmptyResponse` message stop suggesting that the daemon is not running.

**Verify.** A unit test that writes the 140-byte KDB file (124-byte header, 16 zero bytes) plus the
`AAAA` keyfile from "Reproducing" to a tempdir and asserts `Corrupt`
through `server::unlock`. The file is generated in the test, so no committed
fixture is needed.

---

## 9. `bind_socket` deletes non-socket files and chmods arbitrary directories

**Severity:** Low. It needs a mistyped or unusual `--socket` path, but the
damage is silent. **Fix lives:** this repo.

**Where:** `src/server.rs:260-282`.

- **Any non-socket file at the socket path is deleted.** The stale-socket
  logic treats "bind failed with `AddrInUse` and connect failed" as proof of
  a stale socket. A regular file satisfies both conditions. **Verified:**

  ```
  -rw-r--r-- 1 ... 15 notes.txt
  $ kpa serve --socket <scratch>/notes.txt ...
  srw------- 1 ...  0 notes.txt
  ```

  The doc comment ("only a failed connect means it's safe to remove the
  file") states exactly the assumption that fails here.
- **The parent directory is `chmod 0700`ed, whatever it is.**
  **Verified:** a pre-existing `0755` directory became `0700`. This is
  harmless for the default `$XDG_RUNTIME_DIR/kpa`, but surprising for
  `--socket ~/kpa.sock` (it changes `$HOME`) or for a shared directory. For a
  directory the user does not own (`/tmp`), startup fails with `EPERM`
  instead.
- **A bare relative name fails.** `Path::new("sock").parent()` is
  `Some("")`, and `set_permissions("")` fails. **Verified:**
  `error: binding sock-rel: No such file or directory`.
- Two daemons starting at the same moment can both judge the socket stale,
  and the second unlinks the first's live socket. **Reasoned.**

**Fix (this repo).** Before `remove_file`, check
`symlink_metadata(path)?.file_type().is_socket()` and refuse otherwise.
Only `chmod` a parent directory that this call created (or only the default
`kpa/` directory). Treat an empty parent as `.`.

**Verify.** A unit test that writes a regular file at a tempdir path, calls
`bind_socket`, and asserts an error with the file still intact.

---

## 10. Claims that do not match behaviour

Each of these asserts something that was checked and found false or
incomplete. Most are covered above; they are gathered here so the comments
and docs can be fixed in one pass.

- `docs/plan.md:87` (step 6): "malformed input must error, never panic or
  hang the daemon". Findings 1 and 2 break both halves today, with socket
  input alone. The JSON parser itself is fine (see negative results).
- `src/main.rs:169`: the "no `.unwrap()`/`.expect()`" rule. `src/` has none
  outside tests (**verified**). But `println!` and `thread::spawn` are
  implicit `expect`s, and each was demonstrated to kill the daemon
  (findings 2 and 4).
- `src/server.rs:330-333`: "Any I/O failure just drops the connection".
  True of socket I/O. False of stdout I/O, which panics (finding 4).
  Also, a request line that is not valid UTF-8 is dropped with no response,
  not answered `malformed_request`. **Verified:** raw `\xff\xfe\n` gets
  `<closed, no response>`.
- `src/server.rs:284`: "Accept connections until the listener errors out".
  It never stops, and it spins (finding 7).
- `src/server.rs:256-259`: "only a failed connect means it's safe to remove
  the file". A regular file also fails connect (finding 9).
- `src/server.rs:285-287` and `docs/design.md:179`: "requests are
  sub-millisecond". `unlock` takes 20 ms to seconds. This is harmless *only
  because* `unlock` drops the mutex during the slow part, and that is
  precisely what opens finding 3's window. Say both things in the comment.
- `src/vault.rs:143-152`: "Ordinary file corruption is sufficient". True
  for KDBX3 and not for KDBX4 (finding 6). The same note also lacks the
  daemon-specific consequences: a leaked core per retry, a held fd, and an
  abort that ends every session.
- `docs/design.md:170` (rule 1, "Never hold an fd"): a hung unlock holds it
  indefinitely (finding 6).
- `docs/review-2026-09.md` finding 7, "one such file wedges every
  database". Superseded: the mutex is not held during the KDF.
- `docs/review-2026-09.md` "Verdict on memory safety": the file-to-database
  path does include `unsafe` code, in `rust-argon2` (see the verdict above).
  The conclusion holds; the stated reason was incomplete.

---

## Negative results

Checks that came back clean, with what was actually observed.

- **Protocol decoding.** 1 000 000 in-process mutations of the four valid
  request shapes through `proto::decode_request`, each under
  `catch_unwind`:
  `decoded=22820 malformed=974013 version_mismatch=3167 panics=0`.
  Over the real socket: 100 000 nested `[` produced `malformed_request`
  (`serde_json`'s default recursion limit of 128), and `v` values of
  `2^64+1` and `-1` produced `malformed_request`. The daemon stayed up
  throughout. **Verified.**
- **`collect_entries` recursion.** It is now an explicit worklist. The
  in-repo test `list_survives_deeply_nested_groups` (100 000 levels) passes
  under the test harness's 2 MiB threads. `keepass` 0.15 stores groups in an
  id-keyed arena, so dropping a deep tree does not recurse either.
  **Verified** (test run) and **reasoned** (arena).
- **XML parse depth on a 2 MiB handler thread.** `unlock` now parses on a
  connection thread with the default 2 MiB stack. The deepest group nesting
  that parses at all is 122 (quick-xml's default `max_depth: 128`, at
  `de/mod.rs:2608`; `keepass` never sets it). Minimum stack needed, measured
  by bisection:

  ```
  depth   0 -> ~71 KiB     depth  60 -> ~206 KiB
  depth  30 -> ~116 KiB    depth 122 -> ~394 KiB
  ```

  That is about 3 KiB per level, so 2 MiB leaves roughly 5× headroom.
  **Verified.** Without the quick-xml cap, a 2 MiB thread would overflow at
  roughly 650 levels, which would be an abort. That figure is extrapolated,
  so **reasoned**. The safety still rests on a transitive dependency's
  default, as the first review warned, and it now matters more because the
  thread is smaller than the old CLI's main thread. Cheapest guard: a test
  that generates a 200-deep KDBX4 in a tempdir (`keepass`'s `save_kdbx4`
  feature enabled in `[dev-dependencies]` only), opens it on a thread built
  with a 2 MiB stack, and asserts `Corrupt`. A regression then fails as an
  abort in CI rather than in the daemon.
- **Legacy KDB nesting.** The KDB parser builds groups iteratively with no
  depth cap, but everything downstream is iterative now, so an arbitrarily
  deep KDB is not a stack risk. **Reasoned.**
- **Keyfile mutation.** 1500 mutations of the XML keyfile against the
  keyfile fixture produced `WrongCredentials` ×1482 and opened ×18. All 18
  changed only whitespace, markup, or the `Hash="..."` attribute, never the
  key hex, so they are correct opens. `keepass` does not verify the `Hash`
  attribute (a `TODO` in `key/mod.rs`); this is harmless because the key
  itself is what gets checked. **Verified.**
- **Mutex poisoning.** Every lock site recovers with `into_inner`, and no
  handler holds the lock across `vault::open` or the prompt. A panicking
  unlock (finding 8) left `status` working. **Verified.**
- **Decompression bombs.** `compression.rs:43` inflates with `read_to_end`
  and no limit, but only after decryption with the correct key. This is
  content the user wrote, not an attack surface. **Reasoned.**
- **Oversized or special database paths.** `Database::open` reads the whole
  file. A config entry pointing at `/dev/zero` or a FIFO would exhaust
  memory or hang. The path is config-controlled, so this is noted, not a
  finding. **Reasoned.**

## Fuzzing record

Each iteration ran as a subprocess under `timeout 5`, with a 2 GiB
address-space limit and a 2 MiB thread stack for `vault::open`. That
mirrors the daemon's handler threads.

| Target              | Reached     | Err  | Opened | Hang (124) | Panic (101) | Abort (134) |
| ------------------- | ----------- | ---- | ------ | ---------- | ----------- | ----------- |
| KDBX3 fixture       | 3000 / 3000 | 2949 | 7      | 43         | 1           | 0           |
| KDBX4 fixture       | 2000 / 2000 | 2000 | 0      | 0          | 0           | 0           |
| XML keyfile         | 1500 / 1500 | 1482 | 18     | 0          | 0           | 0           |
| `decode_request`    | 1 000 000   | —    | —      | —          | 0           | 0           |

The 7 KDBX3 opens are finding 5 (6 of them) plus one benign case. All 43
hangs are finding 6. The panic is finding 8. The 18 keyfile opens are
benign (see negative results).

## Reproducing

All of this runs without touching the repo:

- Build the binary with `CARGO_TARGET_DIR=<scratch>/target cargo build --release`.
- Create a scratch crate with `kpa = { path = "<repo>" }` and
  `keepass = { version = "0.15.0", default-features = false, features = ["save_kdbx4"] }`
  (the feature is only for generating deep-nesting files). Give it small
  binaries:
  - `open_one <db> <pw|-> [keyfile|-] [stack_kib]` calls
    `kpa::vault::open` on a thread with the given stack and exits
    0/1/101/134.
  - `deep <n> <out>` writes an `n`-deep KDBX4.
  - `dump_fields` prints fixture fields, protected ones included.
  - `fuzz_proto` is the in-process JSON mutator.
- Use a roughly 80-line Python header editor that walks the KDBX3 TLV (u16
  lengths) or the KDBX4 TLV (u32 lengths) plus the VariantDictionary.
  It rewrites one field or truncates it, and for KDBX4 recomputes the keyless
  header SHA-256 that follows the header's end marker.
- Crafted inputs:
  - `TransformRounds = u64::MAX` (KDBX3).
  - `M = 4294967296` or `I = 4294967295` (KDBX4).
  - `P = 4096` with `M = 32 MiB` and `I = 1`.
  - Header field 3 or 6 truncated to 2 bytes.
  - KDF `P` truncated to 2 bytes.
  - A 124-byte KDB header (signatures `0x9AA2D903 0xB54BFB65`, flags `2`)
    plus 16 zero bytes, used with the keyfile
    `<KeyFile><Meta><Version>1.00</Version></Meta><Key><Data>AAAA</Data></Key></KeyFile>`
    and an empty password.
- Drive the daemon tests from a small Python client over the socket: start
  `kpa serve` with a scratch config, apply limits with `setrlimit` in the
  child (`RLIMIT_AS`, `RLIMIT_NPROC`, `RLIMIT_NOFILE`), and read thread
  counts and CPU time from `/proc/<pid>/task` and `/proc/<pid>/stat`.
  Configure the prompt as `["printf", "%s", "<password>"]` (or wrap it in
  `sh -c "sleep 2; ..."` for finding 3).
