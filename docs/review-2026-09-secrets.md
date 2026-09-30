# Secret-hygiene review — 2026-09

A secrets-only adversarial read of the working tree after step 2 (daemon
and socket), on top of commit `9fe1d95`. It follows every password, keyfile
byte and decrypted field from where it enters the process to every place a
copy comes to rest, and checks each security claim in `docs/design.md`
against the code. Crashes and hangs are out of scope. They are covered in
[`review-2026-09.md`](./review-2026-09.md), whose findings 1–4 and addendum
this review re-checks against the current code.

Claims marked **verified** were reproduced by running code. Claims marked
**reasoned** were established by reading source only. Every heap-residue
number below comes from an out-of-tree harness crate that depends on `kpa`
by path (see [Method](#method)). Nothing in this repository was modified to
run it.

## Secret lifecycle map

**Entry points**

| Secret                     | Enters at                                                                                                                         |
| -------------------------- | --------------------------------------------------------------------------------------------------------------------------------- |
| Master password            | stdout of the configured `prompt` command, `src/server.rs:240` (`Command::output()`), then `:245` into `Zeroizing<String>`         |
| Keyfile bytes              | `src/vault.rs:165-168`: `File` handed to `keepass`'s `DatabaseKey::with_keyfile`, which reads and parses it                        |
| Decrypted database         | `src/vault.rs:171` `Database::open`. The payload is decrypted, decompressed and parsed entirely inside `keepass`                   |

**Copies on the path**

- Password: `output.stdout` (a plain `Vec<u8>`) → `String::from_utf8_lossy(..).into_owned()` in `Zeroizing` → `&str` into `DatabaseKey::with_password`, which makes a `String` copy inside a `ZeroizeOnDrop` struct → `get_key_elements()` returns `sha256(password)` in a plain `Vec<u8>` (`keepass` `key/mod.rs:208`).
- Keyfile: `with_keyfile` `read_to_end` (`key/mod.rs:173`, kept inside `DatabaseKey`, so zeroized) → `parse_xml_keyfile` makes about six plain copies (`quick_xml` event buffer, `into_owned()` at `:46`, `key_value`, `key_bytes` at `:65`, then the `trim()/replace()` chain at `:70`) → a hex-decoded 32-byte key element in a plain `Vec`.
- Derived keys: composite, transformed and master keys are `GenericArray`s on the stack. The master key is also copied into `AES256Cipher { key: Vec<u8> }` (`crypt/ciphers.rs:36-44`), which is dropped unwiped.
- Entry fields: `Value::Unprotected(String)` / `Value::Protected(SecretBox<String>)` → `EntrySummary` (`ZeroizeOnDrop`) → `WireEntry` (`src/server.rs:183-195`, plain `String`s) → `serde_json::to_string` (`src/server.rs:357`, plain, growable `String`).

**Sinks**

| Sink                                  | What crosses it today                                                                           |
| ------------------------------------- | ----------------------------------------------------------------------------------------------- |
| Socket → client                       | db names, lock state, entry counts; `list` sends unprotected title/username/url/group           |
| Daemon stdout (operation log)         | op + db name only, `{:?}`-escaped; reads are not logged (`src/server.rs:297-328`)               |
| Daemon stderr                         | config/bind errors only (`src/main.rs`), no vault content                                       |
| Client stdout (`kpa list`)            | the raw response line, which is the index above and lands in terminal scrollback by design       |
| Error `detail` on the wire            | only `PromptFailed`'s `io::Error` text (spawn failure). No parser text (see Solid)               |
| Core dump / `/proc/<pid>/mem`         | **everything the process holds**. The daemon is dumpable (finding 3)                              |
| Clipboard                             | not implemented yet (step 3)                                                                     |

## Summary

| #   | Finding                                                                 | Severity   | Fix lives                  | Status   |
| --- | ----------------------------------------------------------------------- | ---------- | -------------------------- | -------- |
| 1   | Master password survives unlock and lock via the prompt's stdout buffer | Medium     | this repo + doc            | verified |
| 2   | Keyfile key material is fully recoverable after lock                    | Medium     | upstream + doc             | verified |
| 3   | The daemon is dumpable: `PR_SET_DUMPABLE=0` is claimed but not done     | Medium     | this repo + doc            | verified |
| 4   | Key-derivation intermediates are not zeroized                           | Low–Medium | upstream + doc             | verified (partly) |
| 5   | The serialized `list` response survives lock                            | Low        | this repo                  | verified |
| 6   | Stale security comments and an unused `rpassword` dependency            | Nit        | doc / this repo            | reasoned |

The in-repo fixes for 1, 3 and 5 were prototyped on a scratch copy of the
tree and re-scanned. All three removed the residue they target (numbers
are in each finding). Protected entry values, kpa's own `Zeroizing`
password copy and `EntrySummary` all clear correctly. See
[What is solid](#what-is-solid).

A caveat that applies to every "0" below: glibc writes free-list pointers
over the first 16 bytes of a freed chunk. A secret of 16 bytes or less
sitting in freed heap is therefore often wiped by accident, and a
full-length search misses a longer one. The scans search for each 32-byte
secret's tail half (`[bytes 16..]`) as well for this reason. A zero for a
short secret is allocator luck, not zeroization.

---

## 1. Master password survives unlock and lock via the prompt's stdout buffer

**Severity:** Medium. It contradicts the Security table's first row, and
the fix is small and entirely in this repo.

**Where:** `src/server.rs:240` (`Command::new(program).args(args).output()?`)
and `:245`. **Contradicts:** `docs/design.md:246` ("Master password: No —
zeroized by kpa immediately after key derivation") and the footnote at
`:251-257`.

`Command::output()` collects the child's stdout into a plain `Vec<u8>`,
and std's `read_to_end` grows that `Vec` as it reads. The password is
copied into `Zeroizing` at `:245`, but the `Vec` and any predecessor left
behind by growth are freed unwiped. The doc comment at `:225-231` treats
this as equivalent to the old third-party `rpassword` caveat. It is not
equivalent: this buffer is kpa's own, and kpa can avoid it.

**Verified.** Real `Server`, unlocked through the socket from a separate
client process. The prompt is `cat <file>` with a 48-character passphrase
(the fixture's own password is 11 bytes, too short to survive the
allocator's 16-byte overwrite). The unlock attempt is followed immediately
by `lock`:

```
needle                   before unlock   after unlock   after lock
password                             0              0            0
password [bytes 16..]                0              1            1
sha256(password)                     0              0            0
```

32 bytes of the master password are still in the daemon's heap after the
lock, identical across runs. With a `list` served in between, the chunk
happened to be reused and the count dropped to 0. That is luck, not
clearing.

**Fix (this repo).** Don't use `output()`. Spawn with `Stdio::piped()` and
read into a fixed-capacity zeroizing buffer that never grows:

```rust
let mut child = Command::new(program).args(args)
    .stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::null())
    .spawn()?;
let mut buf = Zeroizing::new(vec![0u8; 4096]);   // never reallocates
let mut n = 0;
// loop { out.read(&mut buf[n..]) ... }  — error out if n == buf.len()
if !child.wait()?.success() { return Ok(PromptOutcome::Cancelled); }
let text = std::str::from_utf8(&buf[..n])?;     // no lossy Cow copy
let mut password = Zeroizing::new(String::from(text));
```

With that change (prototyped on a scratch copy of the tree) the same scan
reads `0 / 0 / 0` in every column.

**Fix (doc).** Rewrite footnote ¹ (`docs/design.md:252-257`). The password
now arrives from the prompt command's stdout, not `rpassword`. kpa holds it
only in `Zeroizing` buffers. The copies kpa cannot reach are inside the
prompt program itself and inside `keepass` (finding 4).

**How to verify the fix.** Re-run the scan above: `password [bytes 16..]`
should read 0 after unlock and after lock. This belongs in this audit, not
in the test suite. A unit test can pin the non-growth property instead:
feed `prompt_password` a command that prints more than 4096 bytes and
assert that it errors instead of reallocating.

---

## 2. Keyfile key material is fully recoverable after lock

**Severity:** Medium. A keyfile is usually a long-lived credential reused
across databases, and the design makes an explicit "No" claim about it.

**Where:** `keepass` 0.15.0 `key/mod.rs:19-89` (`parse_xml_keyfile`),
reached from `src/vault.rs:168`. **Contradicts:** `docs/design.md:248`
("Keyfile contents: No — read at unlock, zeroize after") and `:206-209`
("key material … actually gone after the drop").

`DatabaseKey` zeroizes the raw file buffer it holds. Parsing makes plain
copies that nothing zeroizes. A v2 XML keyfile is processed as
`into_owned()` text, then `key_value`, then `key_bytes`, then
`trim().replace(" ").replace("\n").replace("\t").replace("\r")` (four
whole-string copies, three of them byte-identical), then `hex::decode`.

**Verified.** `tests/fixtures/fixture-kf.kdbx` with its `.keyx`, unlocked
through the real `Server` (prompt prints nothing), then locked:

```
needle                                      before unlock  after unlock  after lock
keyfile XML text (first 35 chars)                       0             1           1
keyfile XML text (first 35 chars) [bytes 16..]          0             3           2
keyfile hex, whitespace-stripped [bytes 16..]           0             3           3
keyfile key element (32 B) [bytes 16..]                 0             1           0
```

After lock, the first 35 characters of the `<Data>` text (key bytes 0–15)
survive intact, and so do three copies of hex characters 16–63 (key bytes
8–31) of the stripped string. Together they cover all 32 bytes of the key
element. The counts are the same when `vault::open` is called directly,
with no daemon.

**Fix (upstream).** In `parse_xml_keyfile`, hold `key_value`, `key_bytes`,
the stripped string and the event buffer in `Zeroizing`, and strip
whitespace in one pass rather than four `replace` calls. Return
`KeyElement` as `Zeroizing<Vec<u8>>`. This is a small, self-contained
patch and worth filing.

**Fix (this repo), partial and optional.** kpa could read the keyfile into
a `Zeroizing` buffer itself and pre-parse it to the 32-byte element before
handing it to `keepass`. That removes the XML copies. It does not remove
`keepass`'s own `buffer.to_vec()` of the 32 raw bytes (`key/mod.rs:117`),
and it duplicates `keepass`'s keyfile-format detection. Not recommended
unless upstream declines.

**Fix (doc).** Change row `:248` to say what is true: the raw keyfile
buffer is zeroized, but `keepass` parses it into unzeroized intermediates,
and those can survive a lock.

---

## 3. The daemon is dumpable: `PR_SET_DUMPABLE=0` is claimed but not done

**Severity:** Medium. This is the one channel on the list that crosses
from memory to disk. A core dump contains the decrypted database plus
every residue in this report. Aborts that would produce one are reachable
from ordinary file corruption (`review-2026-09.md` finding 7: Argon2
allocation failure → SIGABRT).

**Where:** `src/main.rs:89` (`run_serve`). There is no `prctl` anywhere in
`src/`. **Contradicts:** `docs/design.md:271-272`, which says in the
present tense: "`PR_SET_DUMPABLE=0` at startup prevents core dumps". It is
actually scheduled for step 6 (`docs/plan.md:83`), but step 2 already
holds decrypted vaults.

**Verified.** `kpa serve` built from this tree, one `unlock` served. The
kernel makes `/proc/<pid>/*` root-owned for a non-dumpable process. Here
they are user-owned, and the environment used for this audit had an
unlimited core size limit:

```
$ stat -c '%U %n' /proc/$PID/mem /proc/$PID/environ
<user> /proc/<pid>/mem
<user> /proc/<pid>/environ
```

**Fix (this repo).** Pull that one line of step 6 forward now. Put it at
the top of `run_serve`, before the config is read or anything is
unlocked:

```rust
// libc = "0.2" (already in the lockfile transitively)
if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } != 0 {
    eprintln!("error: PR_SET_DUMPABLE failed");
    return ExitCode::FAILURE;
}
```

The same check after this change (prototyped on a scratch copy of the
tree) reports `root /proc/<pid>/mem`. As a side effect this also blocks
same-uid ptrace and `/proc/<pid>/mem` reads regardless of the host's Yama
setting.

**Fix (doc).** Until it lands, either move the sentence at `:271` under
"planned (step 6)" or state it as a requirement rather than a fact. Also
say that it is kpa's claim only up to the host's `fs.suid_dumpable`: with
`2`, the kernel still writes a root-owned dump. That part is a host
property, like the ptrace and zram bullets above it.

**How to verify the fix.** An in-process test can call the hardening
function and assert `prctl(PR_GET_DUMPABLE) == 0`. The `/proc/<pid>/mem`
owner check above works end to end.

---

## 4. Key-derivation intermediates are not zeroized

**Severity:** Low–Medium. **Fix lives:** upstream, plus the doc.

**Where:** `keepass` `key/mod.rs:204-228` (`get_key_elements` returns plain
`Vec<Vec<u8>>`, including `sha256(password)` at `:208`),
`format/kdbx3.rs:228-244` / `format/kdbx4/parse.rs:83-117` (composite,
transformed and master keys as stack arrays), and `crypt/ciphers.rs:36-44`
(`AES256Cipher` copies the master key into a plain `Vec<u8>`; Twofish
likewise at `:93`). **Contradicts:** `docs/design.md:206-209` ("key
material … handled by `zeroize`/`secrecy` types and are actually gone after
the drop") and `:251` ("the credential side is handled by the library").
Only `DatabaseKey`'s own fields are handled.

`sha256(password)` is the password-derived key element. It is
password-equivalent for this database, because it can be fed into the KDF
without knowing the password.

**Verified for `sha256(password)`**, fixture password, unlock then lock
through the `Server`:

```
needle                          before unlock   after unlock   after lock
sha256(password)                            0              0            0
sha256(password) [bytes 16..]               0              1            1
```

Half of it survives the lock. The first half is overwritten by allocator
metadata, not by zeroization. The same result appears when calling
`vault::open` directly.

**Reasoned only** for the composite, transformed and master keys. The
harness computes each one independently and self-checks the master key by
decrypting the fixture's first payload block against `StreamStartBytes`.
All three read 0 at every stage in every run. They are 32-byte values in
freed or reused memory, so this is the same allocator luck as above, not
evidence that they are cleared.

**Fix (upstream).** Return `KeyElements` as `Zeroizing`, and derive
`Zeroize, ZeroizeOnDrop` on the cipher structs (or hold `Zeroizing<Vec<u8>>`
keys). The stack arrays need explicit `zeroize()` before return. File this
together with finding 2 and `review-2026-09.md` finding 3's plaintext-buffer
patch.

**Fix (doc).** Narrow `:206-209` and `:251`: `DatabaseKey`'s own password
and keyfile copies and protected values are zeroized. Derived key material
inside `keepass` is not.

---

## 5. The serialized `list` response survives lock

**Severity:** Low. Nothing crosses a boundary it shouldn't. This is residue
in freed heap, readable only by something that could already read the
process. It is squarely this repo's own residue, though.

**Where:** `src/server.rs:357` (`serde_json::to_string(&response)`).
**Contradicts:** `docs/design.md:212-213` ("Lock … clears what it can").

This re-checks the `review-2026-09.md` addendum with a sharper needle: the
fragment `"username":"alice"` exists only in serialized JSON, never in a
`String` field.

**Verified:**

```
needle                  before unlock  unlocked  after 1 list  after 3 lists  after lock
"username":"alice"                  0         0             2              2           2
alice                               0         3             5              5           4
```

Both surviving extra copies of `alice` are JSON. `serde_json::to_string`
starts with a 128-byte buffer and grows to fit the 173-byte response, which
leaves the unwiped predecessor plus the final `String`. This corrects the
addendum's attribution, which was reasoned by elimination: in these runs
the `WireEntry` clones were not the survivors. Their fields are shorter
than 16 bytes, so free-list metadata overwrote them. Any field longer than
16 bytes would leave its tail behind, so `WireEntry` still deserves
`ZeroizeOnDrop`. Three identical `list`s did not add further copies. The
same-sized chunks were reused.

**Fix (this repo).** Measure with a counting writer, then serialize into a
`Zeroizing<Vec<u8>>` of exactly that capacity and `write_all` it. Also
derive `Zeroize, ZeroizeOnDrop` on `WireEntry`, with `#[zeroize(skip)]` on
`uuid`. That lets `wire_entries` drop its "costs nothing security-wise"
comment (`src/server.rs:178-182`), which is true of the socket and false of
the heap. Prototyped (buffer change only):

```
"username":"alice"                  0         0             0              0           0
alice                               0         3             3              3           2
```

That is back to `keepass`'s floor of 2 (`review-2026-09.md` finding 3,
upstream).

**Small related cleanup.** `Status::status` (`src/server.rs:68`) builds a
full `Vec<EntrySummary>` of every title, username and URL just to call
`.len()`. Those copies zeroize on drop, so this is not a leak, but a
counting walk would avoid making them at all.

---

## 6. Stale security comments and an unused `rpassword` dependency

**Severity:** Nit. **Reasoned.**

- `Cargo.toml:16`: `rpassword = "7"` is no longer used by any code (`grep`
  finds it only in comments). Drop it. A password-prompt crate with no
  zeroization (7.5.4 has none) should not sit in the dependency tree
  looking like it's in use.
- `src/vault.rs:135-141`: describes `rpassword`'s internal buffer as the
  residual copy. The password now comes from `src/server.rs`'s prompt
  command.
- `src/server.rs:225-231`: calls the unzeroized `output.stdout` an
  "already-accepted residual-copy caveat". Finding 1 removes it, so this
  comment should go with it.
- `docs/design.md:252-257`: the footnote describes the `rpassword` path
  (see finding 1).
- `docs/design.md:24`: "`proto.rs`'s `Request` enum". The protocol is now
  `src/proto/`, and the op enum is `Op` in `src/proto/request.rs`. The
  read-only-is-structural claim still holds: `Op` has no write variant, and
  `keepass` is built without `save_kdbx4`.

---

## What is solid

- **Protected fields stay protected in `list`.** `vault::unprotected_field`
  checks `is_protected()` before calling `Value::get()`. No `get_title` /
  `get_username` / `get_url` / `expose_secret` call exists in `src/`.
  **Verified** by `vault::tests::list_omits_protected_fields` (passes), which
  builds protected Title/UserName/URL in memory.
- **`SecretBox` does its job.** The protected entry password reads 1 copy
  while unlocked and 0 after lock, in every run, for both KDBX3 and KDBX4
  (**verified**).
- **kpa's own `Zeroizing` copies clear.** Reading the password into
  `Zeroizing<String>` and dropping it takes its count from 1 to 0
  (**verified**, direct `vault::open`). `EntrySummary` zeroizes on drop.
- **Parser text never crosses the boundary.** `server::unlock_error` drops
  `VaultError::Corrupt`'s string, `UnlockError::Corrupt` has no `detail`,
  and `log_response` logs `UnlockError` (which never held the text), not
  `VaultError`. `proto::tests::a_corrupt_database_reports_no_parser_text`
  pins the wire side. The rule is written down on `VaultError::Corrupt` and
  on `ErrorFields::detail`.
- **The operation log is disciplined.** Reads are silent, only op and
  database name are logged, and client-supplied names go through `{:?}`, so
  a client cannot inject lines into the log.
- **The protocol never carries a password.** The prompt command gets a null
  stdin, and its argv comes from config, never from the request.
- **The socket is `0600`, and its parent directory is set to `0700` before
  `bind`**, so there is no window where the socket is reachable with looser
  permissions.
- **The host-dependent claims are framed honestly.** The ptrace-scope and
  zram bullets in `docs/design.md` § Security now say they are machine
  properties, not kpa guarantees. `PR_SET_DUMPABLE` (finding 3) is the one
  claim still written as if it were already true.

Out of scope for this review but noticed: `bind_socket` does `chmod 0700`
on *whatever* directory contains `--socket` (`src/server.rs:261-264`). With
`--socket ~/kpa.sock`, that silently changes the user's home directory's
permissions. Not a leak. It belongs on the robustness side.

---

## Method

- **Out-of-tree harness.** A scratch crate depends on `kpa` by path. It
  drives the real `kpa::server::Server` via `bind_socket` + `serve` on a
  background thread, and sends each request from a *separate client
  process*, so the only copies in the scanned process are the daemon's
  own. A second binary calls `vault::open` directly on the main thread.
- **Scanner.** It reads `/proc/self/maps`, then each `rw` mapping via
  `/proc/self/mem`, in fixed-size chunks with overlap. The chunk buffer and
  the maps `String` are allocated once, before the vault is opened, and a
  warm-up scan runs first. The scanner's own buffer is excluded from the
  scan.
- **Masked needles.** Needles are derived in a separate process and passed
  in XOR-masked, and matching is done under the mask. The scanning process
  never holds an unmasked copy of anything it searches for. Labels are
  generic for the same reason. (A first run with the plaintext in the
  labels showed a spurious "1 before unlock". Worth knowing for anyone
  re-running this.) That process computes the composite, transformed and
  master keys independently (AES-KDF for the KDBX3 fixtures) and checks the
  master key by decrypting the first payload block against
  `StreamStartBytes`.
- **Tail-half needles.** Every secret of 32 bytes or more is also searched
  for as `[bytes 16..]`, because glibc overwrites the first 16 bytes of a
  freed chunk with free-list pointers.
- **Fix prototypes.** Findings 1, 3 and 5 were prototyped on a scratch copy
  of the tree. The existing test suite passed there unchanged (34 tests),
  and the scans above were re-run against it.

Heap-residue scans depend on allocator behaviour. They belong in this
audit, not in `cargo test`.
