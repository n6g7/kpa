---
name: security-audit
description: Full security audit of kpa against docs/threat-model.md — fans out parallel subagents, one per group of threat-model goals (socket and uid isolation, secret flow and persistence, file input and vault integrity, lock lifecycle, clipboard and entry content, claims and model gaps), verifies each finding independently, and writes one report in a fixed structure that humans can read and remediation agents can act on finding by finding. Use when asked for a security audit, a security review, a pentest-style pass, or to check the code against the threat model. Supersedes secret-hygiene-audit; robustness-audit remains the deep method for file-input crashes and hangs.
---

# Security audit

Test every claim in `docs/threat-model.md` against the code, and report in a
structure that a person can skim and a remediation agent can pick up one
finding at a time.

The threat model is the spec. A finding is only as good as its mapping to
it: which goal (`G-n`) breaks, for which actor (`ACT-n`), across which
boundary (`TB-n`), and which bucket of §9 it falls in. Read the whole of
`docs/threat-model.md` before anything else, and have every subagent read
it too.

## Rules

- **Prove it, don't read it.** Every finding is labelled **verified** (you
  ran it and watched it happen) or **reasoned** (you read the code). Never
  let the second pass as the first. A clean check is a result too: record
  what was observed, not what was meant to be observed.
- **Never modify the repo to test it.** All builds, harnesses, fixtures,
  sockets and daemons live in the scratchpad. `git status --porcelain` must
  be unchanged at the end (the report is git-ignored).
- **Never touch the user's real setup.** Always pass `--socket` and
  `--config` pointing into the scratchpad. Never connect to the default
  socket, read the default config, or open a real vault.
- **Leave no processes behind.** Start every daemon under `timeout`, and
  record its PID under your work directory. Kill everything you started,
  including anything inside user namespaces you created, before you
  reply. A run that skipped this left about 170 daemons running. The
  orchestrator checks `pgrep -a kpa` before finishing.
- **Write the report as if it will be shared.** Reports are git-ignored
  (`docs/audits/`) while their findings are open, but they get passed to
  other agents and people. Mask absolute paths outside the repo (write
  `<scratch>/…`), hostnames, and usernames in pasted output. Use only
  fixture passwords.
- **Triage against the model, not against intuition.** An out-of-scope
  finding stays out of scope however alarming it looks (NG-1 especially).
  When the model itself seems wrong, that is a *model gap* finding, not a
  reason to re-rate.

## Phase 0: setup (orchestrator, before fanning out)

1. Record `git rev-parse --short HEAD` and
   `git hash-object docs/threat-model.md | cut -c1-12`. The second is the
   threat model's content hash, which works even when the file is
   uncommitted. Both go in the report.
   If `git status --porcelain` shows changes to `src/`, `Cargo.*` or
   `docs/threat-model.md`, the audit covers the working tree, not the
   commit; say so in the report.
2. **Resume, don't redo.** If `<scratch>/audit/RUN` exists and its `commit`
   and `threat_model` lines match the values from step 1, a previous run was
   interrupted. Keep its setup and skip every workstream whose `w<n>.md`
   exists and has a "Checked, clean" section. Skip every finding that
   already has a verdict file in phase 2. Otherwise move any old
   `<scratch>/audit/` aside and start fresh, writing `RUN` with two lines:
   `commit: <sha>` and `threat_model: <hash>`. Audits are long enough to
   hit usage limits, so resuming is the normal case, not an edge case.
3. Create `<scratch>/audit/`. Inside it:
   - `target/`: the shared `CARGO_TARGET_DIR`. Cargo serializes concurrent
     builds on its lock, so sharing is safe and saves recompiling `keepass`
     and the KDFs once per workstream.
   - `harness/`: a scratch crate depending on `kpa` by path, with
     `[profile.release] debug = true` (see `robustness-audit`'s Setup).
     Each workstream adds only its own `src/bin/w<n>_*.rs`. A workstream
     that needs another dependency creates its own crate, `harness-w<n>/`,
     rather than editing the shared `Cargo.toml`.
   - `fixtures/`: run `tests/fixture.sh <scratch>/audit/fixtures`. If you
     need a crafted vault the script can't make, generate it from a
     *separate* crate with `keepass`'s `save_kdbx4` feature on. Turning that
     feature on in the harness would unify it into the audited `kpa` build
     and change the thing under test.
4. Build once to warm the target dir:
   `CARGO_TARGET_DIR=<scratch>/audit/target cargo build --release`
   (prefix `nix develop -c` outside the dev shell).
5. Re-read §6 and §7 of the threat model. Assign every `G-` and `T-` to a
   workstream using the table below. Anything new since this skill was
   written goes to W6. Don't drop it.

## Phase 1: fan out

Launch all six workstreams **in one message**, as parallel `general-purpose`
subagents. Give each this prompt, filled in:

> You are workstream W<n> (<name>) of a security audit of the kpa repo at
> <repo>. Read `docs/threat-model.md` in full, then
> `.claude/skills/security-audit/SKILL.md`: its Rules, the "Finding record"
> section, and your workstream's section. Your scope: <IDs>. The shared
> setup is ready: `CARGO_TARGET_DIR=<scratch>/audit/target`, harness crate
> at `<scratch>/audit/harness`, fixtures at `<scratch>/audit/fixtures`.
> Work under `<scratch>/audit/w<n>/`. Write your findings, as finding
> records numbered `W<n>-01`, `W<n>-02`, …, to `<scratch>/audit/w<n>.md`.
> Follow them with a "Goal status" section, one line per goal clause in
> your scope (`G-n (clause): holds | broken | partial | not implemented |
> not checked — verified/reasoned — evidence`), then a "Not tested"
> section, and a "Checked, clean" list written last (its presence marks
> the file complete). Reply with at most ten lines: counts by bucket and
> severity, plus anything you couldn't test and why. Do not edit the repo.
> Do not write the final report.

| WS | Name | Goals | Threats | Boundaries |
| -- | ---- | ----- | ------- | ---------- |
| W1 | Socket and uid isolation | G-2, G-11 | T-1, T-2, T-14, T-15 | TB-1 |
| W2 | Secret flow and persistence | G-3, G-4, G-6 | T-4, T-5, T-9 | TB-5, TB-7 |
| W3 | File input and vault integrity | G-1, G-8, G-9 | T-3, T-11, T-12 | TB-2 |
| W4 | Lock lifecycle | G-5 | T-8, T-10 | TB-6 |
| W5 | Clipboard and entry content | G-7, G-10 | T-6, T-7, T-13 | TB-3, TB-4 |
| W6 | Claims and model gaps | all (cross-check) | T-16, anything unassigned | all |

## Workstreams

Each section lists where to look and the methods that have found real bugs
here before. They are starting points, not the limit of scope: test every
"in scope" clause of your threats.

### W1: Socket and uid isolation

- Socket creation path in `src/socket.rs` (`bind_socket`) and default-path
  resolution in `src/main.rs`. Test with `$XDG_RUNTIME_DIR` unset, empty,
  relative, pointing at a world-writable dir, and at a dir owned by
  another uid you can simulate. Test a pre-existing path that is a
  symlink, a regular file, a live socket, or a dead one. Test the parent
  directory's mode and creation.
- The bind-then-chmod window: check the umask around `bind`, and whether
  the socket is ever briefly connectable with wider permissions
  (`strace -f -e trace=bind,chmod,fchmod,umask`).
- Network surface: run the daemon on a fixture, then
  `ss -xlp; ss -tunap | grep <pid>`, and `strace -f -e trace=network` across
  unlock/list/lock. Also look for any abstract-namespace (`@`) address.
- Protocol abuse: a line of exactly 64 KiB and one byte over, no newline,
  a slow drip under the 5 s deadline, more than the connection cap at
  once (does the next client get refused or hang?), invalid UTF-8, deeply
  nested JSON, unknown `v`, duplicate keys, and a client that never
  reads its response. Measure whether one abusive client starves a
  well-behaved one.

### W2: Secret flow and persistence

Follow every password, keyfile byte and protected field from entry to rest.

1. **Map the lifecycle first**, before any test. Entry points: the prompt
   program's stdout pipe (`src/prompt/program.rs`), keyfile bytes, and the
   decrypted database. List every copy (`clone`, `to_owned`, `to_string`,
   `String::from`, `format!`, serde) and every sink (stdout, stderr,
   socket, logs, error `Display`, protocol `detail` fields, panic
   messages, a child's argv and env). A signature that takes `&str` for a
   secret forces its caller to hold an unzeroizable `String`, so flag the
   signature as well as the call.
2. **Heap-residue scan** for G-6. Scan the process's own writable mappings
   (`/proc/self/maps` rw regions via `/proc/self/mem`) before unlock, while
   unlocked, and after lock. Use three needles: a protected field, an
   unprotected field, and the master password. **Pre-allocate the scan
   buffer and the maps string before the vault is loaded, and do a warm-up
   scan.** A scanner that allocates while scanning reuses the very chunks
   it's looking for, which produces false "cleared" results. Classify each
   surviving copy as kpa-owned (G-6, in scope) or inside `keepass` (NG-4,
   hardening at most).
3. **De-protecting getters.** In `keepass`, `Entry::get` and therefore
   `get_title`/`get_username`/`get_url` call `expose_secret()` on
   protected values. `Value`'s `Clone` re-exposes the value, its
   `Serialize` writes plaintext, and `DatabaseKey` derives `Debug`. Build a
   `Database` in memory with `Value::protected` on non-password fields and
   run kpa's own `list` path against it. No fixture file is needed.
4. **Error text.** Check whether library parser text (which can embed
   decrypted content) ever reaches a client, stderr, or a log. Grep the
   dependency for `format!` inside error constructors.
5. **Persistence.** Confirm `PR_SET_DUMPABLE=0` takes effect before the
   config is read or any unlock (`grep Dumpable`-equivalent: call
   `prctl(PR_GET_DUMPABLE)` from the harness, or check that `/proc/<pid>`
   files become root-owned). Check that nothing writes secrets to a file,
   and look at what the prompt child inherits (env, fds, argv).

### W3: File input and vault integrity

- **G-1.** Run unlock, list and lock under
  `strace -f -e trace=openat,open,creat,rename,unlink,truncate,ftruncate,flock,fcntl,chmod,utimensat,write`
  against fixtures in a directory you snapshot before and after
  (`find -printf '%p %m %T@ %s\n'`). Any open with write intent, any new
  file, any changed timestamp, and any fd on the vault that outlives the
  read is a finding. Confirm in `Cargo.lock`/`cargo tree -e features` that
  `keepass` is built without save support.
- **G-9.** Follow `robustness-audit` checks 1–5: unsafe inventory
  including the dependency tree (`rust-argon2` has `unsafe` driven by KDF
  parameters), panic inventory, recursion depth on a 2 MiB thread stack,
  header and KDF values that drive loops or allocations (are they
  authenticated *before* use?), and mutation fuzzing with a per-iteration
  timeout. Also test that one database's crafted file cannot affect
  another database's state in the same daemon.
- **G-8.** Change the file between unlock and the next request in every
  way a sync tool might: atomic rename, in-place rewrite at the same size,
  a rewrite followed by `touch -d` to restore the mtime, a same-second
  write against filesystem mtime granularity, a hardlink swap, and a
  delete. Note the order of `stat` versus read at unlock time: a change
  that lands between the two is a TOCTOU.

### W4: Lock lifecycle

- **Races.** Lock during an in-flight unlock (while the prompt is open,
  and during the KDF), a double unlock, and lock-all against a concurrent
  `list`. A request served after lock, or an unlock installing after a
  lock, breaks G-5. Use a fake prompt program that sleeps, so the timing
  is deterministic.
- **Idle timer.** What resets it? Only a request should. Check whether a
  failed, malformed or `status` request counts as activity, and whether
  the timer is per-database.
- **D-Bus and logind.** If implemented: introspect what kpa exports
  (`busctl --user introspect`), test whether any method or signal can
  unlock, read, or *suppress* a lock, test re-subscription after the bus
  reconnects, and test `PrepareForSleep(true)` handling. A spoofed signal
  that only locks is out of scope (NG-7).
- **Not yet implemented** is a goal status, not a finding, unless the
  README or `design.md` presents the feature as existing. Check
  `TODO.md` to tell planned from forgotten.

### W5: Clipboard and entry content

- **Clipboard** (if implemented): check the offered MIME types for the
  `x-kde-passwordManagerHint: secret` tag on every copy path, expiry
  timing, expiry after another client replaced the selection (must be a
  no-op), and an offer outliving its database's lock. Without a Wayland
  session, mark the result reasoned and say so.
- **Entry content as data.** Build entries in memory containing ESC/CSI/OSC
  sequences, BEL, `\r`, `\n`, NUL, bidi overrides, invalid surrogates, a
  JSON-looking string, and 1 MiB titles. Run them through `list` and
  through the CLI's actual terminal output. Raw control bytes reaching a
  terminal break G-10. Check whether framing can be broken and whether
  `copy` addressing can be confused by duplicate titles or UUIDs across two
  databases.

### W6: Claims and model gaps

W6 covers what falls *between* the other workstreams, not their ground
again. A claim or gap that belongs to a goal W1–W5 owns is theirs. Note it
in one line under "Handed off", and don't test it or write a record. A
first run that skipped this rule produced eight duplicates with conflicting
triage.

- **Claims versus code.** Grep `README.md`, `docs/design.md`,
  `config.example.toml` and source comments for
  `never|always|cannot|guaranteed|zeroiz|only|no code path`. Test the
  assertions no goal covers, and the ones that span several goals. When
  code and doc disagree, decide which one is wrong and say so. An accurate
  doc is a valid fix.
- **Configuration.** Check settings that are accepted but ignored, and
  conflicting or duplicate entries.
- **Dependency posture.** List `unsafe` in the full dependency tree's
  crates that touch untrusted bytes or secrets. Check zeroization coverage
  in `keepass`. If `cargo audit` is available offline, run it. Pinned
  versions that are out of upstream support are a finding (see ASM-5).
- **Model gaps.** Do one STRIDE pass per trust boundary looking for threats
  that §7 lacks, and for any entry that is wrong, too broad, or rated at
  the wrong severity. Each becomes a *Model gap* finding with the exact
  proposed text for `docs/threat-model.md`.
- **T-16.** Record its current state. Findings here are hardening.

## Phase 2: verify

First merge duplicates across workstreams (phase 3's rule) so that each
root cause is verified once. Then, for every finding in the
**Vulnerability** or **Model gap** bucket at Medium or above, launch a
fresh `general-purpose` subagent, all in one message:

> Try to refute one security-audit finding on the kpa repo at <repo>.
> Read `docs/threat-model.md` in full, then the Rules section of
> `.claude/skills/security-audit/SKILL.md`. The finding is in
> `<scratch>/audit/verify/<id>.finding.md`. Reproduce it independently
> under `<scratch>/audit/verify/<id>/`, or show why it fails, or show that
> it reduces to an assumption violation, a non-goal, or an existing entry.
> Write `<scratch>/audit/verify/<id>.verdict.md` in exactly this shape:
> a `Verdict:` line (Confirmed | Confirmed with changes | Refuted), an
> `Evidence:` line (Verified | Reasoned), a `Bucket:` line and a
> `Severity:` line (what you would assign), then `## Corrections` (each
> claim in the record that is wrong, and the correct text) and
> `## Reproduction` (the commands and trimmed output, at most 40 lines).
> Reply with the four header lines only.

Apply the verdicts: drop refuted findings to Appendix B with the reason,
fold corrections into the record, and take the verifier's bucket and
severity unless you can say in one sentence why the original triage was
right. Raise "reasoned" to "verified" only when the verifier reproduced
it.

## Phase 3: consolidate and report

Merge the workstream files. Deduplicate findings that share a root cause:
keep one finding, list every goal it breaks, keep the strongest evidence,
and list the source IDs in one line at the top of Appendix A
(`W1-1→F-03, W1-2→F-02, …`). Re-check each bucket and severity against §9
yourself rather than trusting the workstream. When workstreams triaged the
same root cause differently, decide and say why in the record. Order by
severity, then bucket. Number the findings `F-01`, `F-02` and so on. Write
`docs/audits/<YYYY-MM-DD>.md`, adding `-2`, `-3`, … if that file exists.

### Report structure

The layout follows the OWASP Web Security Testing Guide's reporting
chapter (v4.2 §5: Introduction, Executive Summary, Findings, Appendices).
Its per-finding *Likelihood / Impact / Risk* fields map onto the threat
model: likelihood is the actor's reach (`ACT-n`), impact is the asset and
goal (`A-n`, `G-n`), and risk is the §9 severity. Keep the headings and
field names exactly as below so the report parses mechanically.

```markdown
---
date: <YYYY-MM-DD>
commit: <short sha>
threat_model: <content hash of docs/threat-model.md from phase 0>
findings: { critical: N, high: N, medium: N, low: N, informational: N }
---

# Security audit — <YYYY-MM-DD>

## 1. Introduction

Scope (commit, what was and wasn't exercised), method (the workstreams;
verified versus reasoned), and limitations (what couldn't be tested here
and why: no Wayland session, no system bus access, and so on).

## 2. Executive summary

Three to six sentences: the overall verdict, the worst finding, and the
memory-safety verdict.

| Goal | Status | Evidence | Findings |
| ---- | ------ | -------- | -------- |
| G-1 Read-only | holds / broken / partial / not implemented / not checked | verified / reasoned | F-nn, … |
| G-5 (idle timeout) | …one row per goal; split a goal into one row per clause when its clauses differ in status… |

## 3. Findings summary

| ID | Title | Bucket | Severity | Goal | Fix lives | Status |
| -- | ----- | ------ | -------- | ---- | --------- | ------ |

## 4. Findings

<one finding record per finding, in table order>

## 5. Proposed threat-model changes

Exact replacement or insertion text for each model-gap finding, keyed by
finding ID, ready to apply.

## Appendix A. Checked and clean

Per workstream: what was tested and came back clean, with the command or
harness name. This is what stops the next audit redoing the work.

## Appendix B. Out of scope and refuted

One line each: the claim, its bucket (assumption violation, out of scope,
or refuted), and the ASM-, NG- or verifier reason.
```

### Finding record

Each finding is self-contained, so a remediation agent can be handed one
record plus the threat model and nothing else. Two consequences:

- **The reproduction runs from the record alone.** The scratchpad is gone
  by the time anyone reads the report, so inline the commands, config and
  harness source. Never refer to a script by its file name only
  (`drive.py idle`). Cut harness code down to the lines that matter.
- **Keep it short: about 60 lines per record, 20 for Informational.**
  Trim output to the lines that show the defect. Exhaustive data, such as
  fuzzing tables and race counts, goes in Appendix A, with one line in the
  record pointing to it. An Informational record keeps the field table,
  Description and Remediation. It needs Reproduction only if the defect
  isn't obvious from the code, and it drops Impact, since Informational
  means no goal breaks.

```markdown
### F-nn · <title: the defect, not the fix>

| Field | Value |
| ----- | ----- |
| Bucket | Vulnerability / Model gap / Hardening |
| Severity | Critical / High / Medium / Low / Informational |
| Threat model | G-n · ACT-n · TB-n · T-n (· A-n) |
| Location | `path:line` (one per line if several) |
| Evidence | Verified / Reasoned |
| Fix lives | this repo / upstream (`crate`) / doc / split — see Remediation |
| Status | Open |

**Description.** What is wrong and why it breaks the cited goal.

**Reproduction.** Exact steps or harness source, and the real output
pasted. For reasoned findings, the code path, step by step.

**Impact.** Who gains what, in threat-model terms: actor, asset, and the
conditions it needs.

**Remediation.** The change, with enough precision to implement directly.
When the fix is split across this repo, upstream and the doc, say which
part is fixable here and don't imply that part solves the whole problem.
If the fix costs something (a second parser to maintain, a dependency),
price it.

**Acceptance criteria.**
- [ ] A test, preferably in-process and needing no fixture file, that fails
      before the fix and passes after. Heap-residue scans are too dependent
      on the allocator to be tests, so name the audit check to re-run
      instead.
- [ ] Any doc or threat-model text that has to change with it.
```

Severity follows threat model §9. Hardening, assumption violations and
out-of-scope items are **Informational**. A model gap takes the severity it
would have once the proposed entry is adopted.

`Status` is for remediation. Fixers change it to `Fixed in <sha>` or
`Won't fix: <reason>`, and cite findings in commits as
`docs/audits/<date>.md F-nn`.

## Finishing

- Confirm `git status --porcelain` is unchanged.
- Lead your reply with the executive summary's verdict and the findings
  summary table, then the path of the report.
- Don't commit unless asked. Don't apply the threat-model changes from §5
  unless asked: they're proposals.
