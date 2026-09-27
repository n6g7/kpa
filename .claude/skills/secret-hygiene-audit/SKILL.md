---
name: secret-hygiene-audit
description: Trace every secret through this codebase and find where it leaks — unzeroized copies left in freed heap, protected fields silently de-protected by convenience getters, vault plaintext embedded in error strings, and secrets crossing a boundary (stderr, socket, clipboard, logs) that the design says they never cross. Use when asked to audit for password exfiltration or leaks, review what a lock actually clears, check zeroization, or verify the security claims in docs/design.md against the code. Pairs with robustness-audit, which covers crashes rather than leaks.
---

# Secret hygiene audit

Follow the secrets. Every password, keyfile byte and decrypted field, from
where it enters the process to every place a copy of it comes to rest.

## The rule that makes this worth doing

**A zeroization claim is not real until a heap scan confirms it.** Deriving
`ZeroizeOnDrop` proves one struct clears itself; it says nothing about the
copies made on the way in, the intermediate buffers upstream, or the
allocations your own code made from the result. Those copies are the finding.

Label every claim **verified** (reproduced) or **reasoned** (read). Do not
blur them.

## Setup

Same out-of-tree harness as `robustness-audit` — see that skill's Setup
section. Briefly: redirect `CARGO_TARGET_DIR` to the scratchpad, and create a
scratch crate depending on `kpa` by path with `src/bin/<check>.rs` per
experiment. Confirm `git status --porcelain` is clean when finished.

## Checks

### 1. Map the secret lifecycle before touching anything

Write the map down first; it decides what the rest of the audit looks at.

- **Entry points.** Where does secret material enter? Today: the password
  prompt (`src/main.rs`), keyfile bytes, and the decrypted database itself.
- **Copies.** Every `to_owned()`, `clone()`, `to_string()`, `String::from`
  and struct field on that path. Type signatures are the tell: a function
  taking `&str` for a password *forces* its caller to hold an unzeroizable
  `String`. Flag the signature, not just the call site.
- **Sinks.** Where can it exit the process? `println!`/`eprintln!`, the
  socket, the clipboard, logs, error `Display` impls, and anything with a
  `detail` field in the protocol.

### 2. Verify zeroization empirically

Scan the process's own writable mappings before, during, and after the secret
should have been cleared.

```rust
// Pre-allocate EVERYTHING the scanner needs before the secret is ever loaded.
struct Scanner { buf: Vec<u8>, maps: String }
// scan(): read /proc/self/maps into the pre-allocated String, then for each
// " rw" mapping, seek /proc/self/mem and read_exact into the pre-allocated
// buf, counting buf.windows(needle.len()) matches.
```

**The pitfall that produces a false negative:** if the scanner allocates
while scanning, its own allocations reuse the freed chunks you are looking
for, and the secret appears to have been cleared when it was merely
overwritten by luck. Allocate the buffer and the maps string once, up front,
before the vault is opened, and do a warm-up scan to force any lazy
allocation. A scan that allocates is worthless.

Use three probes: a value stored *protected* in the vault, a value stored
unprotected, and the master password. Scan at three points: before unlock,
while unlocked, and after the `Database` is dropped. The interesting row is
the last one — dropping the database is what `lock` will do, so anything
still present there survives a lock.

Expect asymmetry. In this codebase the `secrecy::SecretBox` path clears
protected values correctly, while unprotected fields and the upstream
plaintext XML buffer do not. That asymmetry *is* the finding.

### 3. Convenience getters that de-protect

Any accessor that reaches through a protection wrapper silently is a leak
waiting to be called:

```sh
grep -rn --include='*.rs' 'expose_secret\|ExposeSecret' "<dep src>"
```

Trace which public getters bottom out there. In `keepass`, `Entry::get()` —
and therefore `get_title`, `get_username`, `get_url` — calls
`Value::get()`, which calls `expose_secret()` on `Value::Protected`. Any
code in this repo using those getters de-protects whatever the user chose to
protect, with no signal that it happened.

Test it by building a `Database` in the harness with `Value::protected` on
non-password fields and calling this repo's own function against it. No
fixture file needed.

### 4. Secrets in error strings

Error text derived from decrypted content is a leak channel that grows
quietly as a project adds logging and protocol `detail` fields.

```sh
grep -rn --include='*.rs' 'Error::custom(format!\|format!(".*{}' "<dep src>" | grep -i 'invalid\|unexpected\|parse'
```

Then check what this repo does with the text: a `VaultError::Corrupt(err.to_string())`
that gets printed or returned to a client forwards whatever the library
embedded. Establish the boundary rule early — library parser text never
crosses a process boundary — while there is still only one call site.

### 5. Boundary inventory

For each sink from step 1, ask what actually crosses it and whether that
matches what the design promises. Specifically:

- Does the index response carry anything the user marked protected?
- Does an error path print vault content to stderr?
- Does anything secret reach stdout, where it lands in scrollback?

### 6. Design claims versus code

`docs/design.md` makes precise, falsifiable security claims — a Security
table of what is and is not held, a lock policy, and assertions about the
host environment. Check each one:

```sh
grep -n 'zeroize\|never\|No —\|cannot\|mlock\|ptrace\|dumpable' docs/design.md
```

For each row, find the code that implements it and the scan that confirms
it. A claim that is true of a library's internal copy but false of the
caller's copy is the common failure — as is a claim about the machine
(swap configuration, ptrace scope) dressed up as a claim about the program.
Distinguish "kpa guarantees this" from "this is true if the host is
configured a certain way", and say which the doc is doing.

When code and doc disagree, the fix is sometimes the doc. Say so explicitly
rather than defaulting to a code change — an accurate doc is a real
deliverable.

### 7. Dependency secret-handling posture

Read, do not assume:

```sh
grep -rn --include='*.rs' 'zeroize\|Zeroize\|SecretBox' "<dep src>"
```

Count the places it appears. If a crate that handles passwords references
`zeroize` in only a handful of spots, enumerate which types are covered and,
more importantly, which decrypted buffers are not. Check the prompt crate
too — `rpassword` 7.x has no zeroization at all, which makes any "the
password is wiped" claim false at the entry point regardless of what happens
downstream.

## Reporting

Write findings to `docs/review-<YYYY-MM>.md`, following the existing one's
structure. Per finding:

- **Severity.** Weight leaks by what crosses a boundary and who can see it.
  A leak into a field served to every client outranks one confined to a
  developer's stderr.
- **Location** as `path:line`, plus the design-doc line it contradicts.
- **Fix lives:** this repo / upstream / the doc. Be precise when a leak is
  split across the three — say which share is actually fixable here, and do
  not let the in-repo share imply the whole problem is solved.
- **Verified or reasoned**, with real output pasted in.
- **How to verify the fix.** Prefer an in-process test with no fixture file.
  Heap-residue scans belong in this skill, not the test suite — they depend
  on allocator behaviour and would be flaky as tests.

Note what is solid, too. The point of an adversarial read is an accurate
picture, and a report that only lists faults gives a false one.
