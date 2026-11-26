---
name: robustness-audit
description: Adversarial hunt for crashes, hangs, aborts and unsound assumptions in this Rust codebase — stack overflows, unbounded loops and allocations driven by file input, panics reachable from untrusted data, and comments or docs that claim a property the code does not have. Use when asked to audit stability, look for crashes or memory-corruption risk, check what a malformed or corrupt .kdbx can do, or review robustness as the codebase grows. security-audit runs the full threat-model audit and uses this skill's method for file input.
---

# Robustness audit

Hunt for ways this process can die, wedge, or silently misbehave on input it
does not control. Leaks, and everything else in the threat model, belong to
`security-audit`.

## The rule that makes this worth doing

**Prove it, don't read it.** A finding that was reasoned from source is worth
a fraction of one that was reproduced. Every claim in the final report is
labelled **verified** (you ran it and watched it happen) or **reasoned** (you
read the code and believe it). Never let the second wear the first's clothes.

The corollary matters just as much: when a check comes back clean, report
what you actually observed, not what you set out to observe. See
"Fuzzing" below for how this goes wrong.

## Setup: never modify the repo to test it

Build and experiment entirely out of tree. Two moves:

```sh
# 1. Repo builds go to the scratchpad, leaving ./target and the tree untouched.
CARGO_TARGET_DIR=<scratchpad>/target cargo build --release

# 2. A scratch crate that depends on this one by path, for exercising internals.
mkdir -p <scratchpad>/harness/src/bin
cat > <scratchpad>/harness/Cargo.toml <<'EOF'
[package]
name = "harness"
version = "0.0.0"
edition = "2021"
[dependencies]
kpa = { path = "<repo>" }
keepass = { version = "0.15.0", default-features = false }
[profile.release]
debug = true
EOF
```

Copy the repo's `Cargo.lock` into the harness before its first build, and
give `keepass` the version that lock pins: a fresh resolve picks newer
versions than the ones kpa ships, and the harness would test those.

Each check becomes a `src/bin/<check>.rs`. Build with
`CARGO_TARGET_DIR=<scratchpad>/harnesstarget cargo build --release --bin <check>`.

This crate is where every PoC lives. It can call library internals, build
`Database` values in memory without fixture files, and abort freely. When the
audit is done, confirm the repo is untouched with `git status --porcelain`.

Two practical notes for this repo: the toolchain comes from the flake, so
prefix commands with `nix develop -c` when not already in the dev shell; and
the daemon asks for the master password through its prompt program, or on
a terminal the request passes, so driving the `kpa` binary takes a config
whose `prompt` prints the fixture's password, or a pty for
`kpa unlock --tty`. Calling `kpa::databases` from the harness
(`Databases::begin_unlock`, then `finish` with the password, as
`tests/common/mod.rs` does) avoids the problem entirely and is usually the
better move.

## Checks

Work through these in order. Each one ends in either a finding or a recorded
negative result — a clean check is a reportable result, not a non-event.

### 1. Unsafe inventory

```sh
grep -rn unsafe src tests
```

Then the dependencies that actually touch untrusted bytes — read their
vendored source, not their README:

```sh
grep -rn --include='*.rs' unsafe "$(ls -d ~/.cargo/registry/src/*/<crate>-<version>)/src"
```

If this comes back empty for the repo and for the parsing dependencies, say
so plainly in the report. It rules out the entire use-after-free /
memory-corruption class and is the single most useful sentence you can give
someone worried about it.

### 2. Panic and abort inventory

```sh
grep -rn 'unwrap()\|\.expect(\|panic!\|unreachable!\|todo!' src
grep -rn --include='*.rs' 'unwrap()\|\.expect(\|panic!' "<dep src>" | grep -v '/bin/'
```

For dependency hits, check whether the `expect` is genuinely guarded by a
preceding check (many are, and say so in a comment) or whether malformed
input can reach it. Guarded ones are not findings.

Remember the hierarchy: a panic can be caught and is survivable; **a stack
overflow or an allocation failure is an abort** — `SIGABRT`, no unwinding,
`catch_unwind` does not help, and in a daemon it takes every other session
down with it. Rank aborts above panics.

### 3. Recursion audit

For every recursive function that walks a structure built from file input:

- Find it (`grep -n 'fn .*(' -A3` over the traversal code, or look for a
  function calling itself).
- Measure the actual threshold in the harness by building the structure
  in memory, not via a file — it isolates your code from any limit the
  parser imposes.
- **Measure it on a 2 MiB stack, not just the main thread's 8 MiB.**
  `std::thread` defaults to 2 MiB, so a daemon's connection handlers get
  roughly a quarter of the depth the main thread survives. Test both:

```rust
std::thread::Builder::new().stack_size(2 * 1024 * 1024)
    .spawn(move || { /* the traversal */ }).unwrap().join().unwrap();
```

Then ask the reachability question separately: is there a bound upstream
that prevents a *file* from reaching that depth? If yes — **that is still a
finding** when the bound is undocumented and lives in a transitive
dependency. "Safe because quick-xml happens to cap nesting at 128" is a
property that can vanish in a patch release. Recommend converting the
recursion to an explicit worklist regardless; it is usually four lines.

### 4. Values from input that drive loops or allocations

Grep the parsing dependency for iteration counts and sizes read out of the
file:

```sh
grep -rn --include='*.rs' 'for _ in 0\.\.\|with_capacity\|vec!\[0' "<dep src>"
```

For each, trace where the bound comes from. A `u64` loop counter or a
memory-size parameter read from a header with no ceiling is a hang or an
OOM abort. Check **when** it is validated relative to when it is used — a
parameter authenticated *after* it has already been applied is not
authenticated at all.

To exercise these, patch the header of a real fixture directly. Headers are
usually plaintext TLV; a short Python script that walks the fields, edits
one, and fixes up any keyless checksum is enough. Confirm the effect with
`timeout N` (a hang shows as exit 124) and with `ulimit -v` (an allocation
abort shows as exit 134).

### 5. Mutation fuzzing of every file-parsing entry point

Random byte flips over a valid fixture, through the repo's own public API.

**Build a per-iteration timeout in from the start.** A mutation that hits a
KDF cost parameter turns one iteration into an unbounded one, and a fuzzer
without a watchdog silently wedges and then reports a completed run it never
performed. Either print progress *every* iteration, or run each iteration in
a subprocess under `timeout`. A wedge is itself a finding — investigate
which mutated byte caused it rather than just skipping it.

Watch for three outcomes, not one: a panic, a hang, and a mutated file that
*opens successfully* (which would mean integrity checking is not working).

Report the iteration count you observed reaching. If the run was killed at
iteration 58, the finding is "58 iterations, then a hang" — not "a clean
run".

### 6. Claims versus behaviour

Comments and design docs in this repo are unusually specific, which makes
them checkable. Treat every confident assertion as a test case:

```sh
grep -rn 'never\|always\|cannot\|guaranteed\|no code path\|impossible' src docs
```

For each, construct the case it forbids. Findings from this check are often
the most valuable in the report, because they are the places where someone
is relying on a property that is not there. The shape to look for is a
claim that is plausible, specific, and wrong: a `Once` said to guard
against races between processes, when it only dedupes calls within one.

## Reporting

Run by `security-audit`, the findings go in its workstream file as finding
records. Run on its own, write them to
`docs/audits/<YYYY-MM-DD>-robustness.md` (git-ignored). Per finding:

- **Severity**, and be honest about it — deprioritise anything whose threat
  model does not hold. Input the user fully controls is not an attack
  surface; it is still a robustness surface, so reframe rather than drop.
- **Location** as `path:line`.
- **Fix lives:** this repo / upstream / the doc. Say explicitly when a fix is
  not reachable from this codebase, and what the in-repo alternative would
  cost — a second partial parser to keep in step with an upstream one is a
  real maintenance burden and should be priced, not waved through.
- **Verified or reasoned**, with the actual command output pasted in.
- **How to verify the fix**, ideally a test that needs no fixture file.

Lead the report with the memory-safety verdict. It is the question people
actually have.
