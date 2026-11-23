---
name: security-audit
description: Full security audit of kpa against docs/threat-model.md — fans out parallel subagents, one per group of threat-model goals (sockets and uid isolation, secret flow and persistence, file input and vault integrity, lock lifecycle and prompt routing, clipboard and entry content, claims and model gaps, SSH agent policy), verifies each finding independently, and writes one report in a fixed structure that humans can read and remediation agents can act on finding by finding. Use when asked for a security audit, a security review, a pentest-style pass, or to check the code against the threat model. Supersedes secret-hygiene-audit; robustness-audit remains the deep method for file-input crashes and hangs.
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

Two parts of §6 shape the work. The table at its head says where each
asset may go: an asset anywhere else is a finding. And the goals that make
several claims are lists of clauses: test them, and report on them, one
clause at a time.

## Rules

- **Prove it, don't read it.** Every finding is labelled **verified** (you
  ran it and watched it happen) or **reasoned** (you read the code). Never
  let the second pass as the first. A clean check is a result too: record
  what was observed, not what was meant to be observed.
- **Never modify the repo to test it.** All builds, harnesses, fixtures,
  sockets and daemons live in the scratchpad. `git status --porcelain` must
  be unchanged at the end (the report is git-ignored).
- **Never touch the user's real setup.** Always pass `--socket` and
  `--config` pointing into the scratchpad, and set `ssh_agent.socket` in
  that config. Never connect to the default sockets, read the default
  config, or open a real vault. More of the user's setup is within a
  daemon's reach than its sockets:
  - A spawned `kpa serve` writes its key cache under `$XDG_CACHE_HOME`, and
    reads the `known_hosts` files `ssh_agent.known_hosts` lists, by default
    the user's and the system's: start it with `XDG_CACHE_HOME` set into
    the scratchpad, and list files of your own in that setting.
  - It also talks to the real logind and session bus: it shows a tray icon
    and holds a sleep inhibitor while something is unlocked. Where the
    test isn't about `kpa serve` itself, build the daemon in-process
    instead, as `tests/common/mod.rs` does: the harness hands it its file
    locations, the display session and each requester's cgroup, and a
    private bus if it wants lock triggers.
  - `ssh` reads the user's own config, which can send it to their real
    agent: give it `SSH_AUTH_SOCK` on the scratch socket, `-F` with a
    config of your own and a `UserKnownHostsFile` in the scratchpad, and
    log in only to an `sshd` you started on localhost.
    `tests/ssh_forwarding.rs` does all of that for forwarded use.
  - The live clipboard tests take the user's real clipboard: run them only
    if the user agreed to it.
  - `kpa pick` runs the `fzf` on `PATH` under the user's own `fzf` options,
    which can name a history file and bind keys to programs, and ends in a
    `copy`. Run it with `FZF_DEFAULT_OPTS` and `FZF_DEFAULT_OPTS_FILE` set
    by you, on a terminal of your own (a pty), against the in-process
    daemon and its fake clipboard, as
    `src/frontends/control/client/pick/tests.rs` does. Where the test
    isn't about the real `fzf`, put a script of yours first on `PATH`.
- **Leave no processes behind.** Start every daemon under `timeout`, and
  record its PID under your work directory. Kill everything you started,
  including anything inside user namespaces you created, before you
  reply. A run that skipped this left about 170 daemons running. The
  orchestrator checks `pgrep -a kpa` before finishing, against the list it
  took in phase 0: the user's own `kpa serve` may be running, and is never
  to be stopped, signalled or connected to.
- **Write the report as if it will be shared.** Reports are git-ignored
  (`docs/audits/`) while their findings are open, but they get passed to
  other agents and people. Mask absolute paths outside the repo (write
  `<scratch>/…`), hostnames, and usernames in pasted output. Use only
  fixture passwords.
- **Triage against the model, not against intuition.** An out-of-scope
  finding stays out of scope however alarming it looks (NG-1 especially).
  When the model itself seems wrong, that is a *model gap* finding, not a
  reason to re-rate.
- **A known gap or an unbuilt design is not a finding.** The model records
  the gaps it knows of (under G-3), and a doc says at the spot when what
  it describes isn't built yet. Check that the gap still stands and that
  what the doc says happens instead does happen, give the clause its
  status, and move on. A gap that has closed, or a "not built yet" that
  has been built, is a model gap: the doc is out of date.

## Phase 0: setup (orchestrator, before fanning out)

1. Record `git rev-parse --short HEAD` and
   `git hash-object docs/threat-model.md | cut -c1-12`. The second is the
   threat model's content hash, which works even when the file is
   uncommitted. Both go in the report.
   If `git status --porcelain` shows changes to `src/`, `Cargo.*` or
   `docs/threat-model.md`, the audit covers the working tree, not the
   commit; say so in the report.
   Record `pgrep -a kpa` too: whatever it lists before the audit starts is
   the user's, and stays as it is.
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
     rather than editing the shared `Cargo.toml`. `tests/common/mod.rs`
     has the in-process daemon to copy from: `daemon::build` with its own
     `Paths`, a `DisplayWriter` to set the display session,
     `authn::assume_cgroup` to place requesters on or outside the desktop,
     and `auto_lock::Source::at` for a private bus.
   - `fixtures/`: run `tests/fixture.sh <scratch>/audit/fixtures`. It
     builds a vault per concern, among them one with hostile entry text,
     one with custom fields and TOTP, and one with SSH keys. If you
     need a crafted vault the script can't make, generate it from a
     *separate* crate with `keepass`'s `save_kdbx4` feature on. Turning that
     feature on in the harness would unify it into the audited `kpa` build
     and change the thing under test.
4. Build once to warm the target dir:
   `CARGO_TARGET_DIR=<scratch>/audit/target cargo build --release`
   (prefix `nix develop -c` outside the dev shell).
5. Re-read §6 and §7 of the threat model. Assign every `G-` and `T-` to a
   workstream using the table below. Anything the table doesn't list goes
   to W6. Don't drop it.

## Phase 1: fan out

Launch all seven workstreams **in one message**, as parallel
`general-purpose` subagents. Give each this prompt, filled in:

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
| W1 | Sockets and uid isolation | G-2, G-11 | T-1, T-2, T-14, T-15, T-21 | TB-1, TB-8 |
| W2 | Secret flow and persistence | G-3, G-4, G-6 | T-4, T-5, T-9, T-22, T-24 | TB-5, TB-7 |
| W3 | File input and vault integrity | G-1, G-8, G-9 | T-3, T-11, T-12, T-17 | TB-2 |
| W4 | Lock lifecycle and prompt routing | G-5, G-12 | T-8, T-10, T-19 | TB-6 |
| W5 | Clipboard and entry content | G-7, G-10 | T-6, T-7, T-13 | TB-3, TB-4 |
| W6 | Claims and model gaps | all (cross-check) | T-16, T-18, anything unassigned | all |
| W7 | SSH agent policy | G-13, G-14, G-15 | T-20, T-23, T-25 | TB-8 |

Both sockets are W1's as transports: who may connect, and what malformed
traffic does. What the agent signs, for whom and after which prompt, is
W7's.

## Workstreams

Each section lists where to look and the methods that have found real bugs
here before. They are starting points, not the limit of scope: test every
"in scope" clause of your threats.

### W1: Sockets and uid isolation

- Both sockets are bound by `bind_socket` in `src/socket.rs`. The control
  socket's default path is resolved in `src/main.rs`, the agent's in
  `config::SshAgentConfig::socket_path`. Test each with
  `$XDG_RUNTIME_DIR` unset, empty, relative, pointing at a world-writable
  dir, and at a dir owned by another uid you can simulate. Test a
  pre-existing path that is a symlink, a regular file, a live socket, or a
  dead one. Test the parent directory's mode and creation, and a
  user-supplied `--socket` and `ssh_agent.socket`.
- The bind-then-chmod window: check the umask around `bind`, and whether
  either socket is ever briefly connectable with wider permissions
  (`strace -f -e trace=bind,chmod,fchmod,umask`).
- Peer checks: the daemon's on both sockets (`src/authn.rs`,
  `authz::may_connect`), and the CLI's on whoever answers at its path.
- Network surface: run the daemon on a fixture, then
  `ss -xlp; ss -tunap | grep <pid>`, and `strace -f -e trace=network` across
  unlock/list/lock and a signature. Also look for any abstract-namespace
  (`@`) address.
- Control protocol abuse (`src/frontends/control/serve.rs`): a line of
  exactly 64 KiB and one byte over, no newline, a slow drip under the 5 s
  deadline, more than the connection cap at once (does the next client get
  refused or hang?), invalid UTF-8, deeply nested JSON, unknown `v`,
  duplicate keys, and a client that never reads its response. A request
  can pass a descriptor: send one that isn't a terminal, two, and more
  than the control buffer holds. Measure whether one abusive client
  starves a well-behaved one.
- Agent protocol abuse (`src/frontends/ssh_agent/`: `serve.rs`, `wire.rs`,
  `bind.rs`, `classify.rs`): a frame of exactly 256 KiB and one byte over,
  a frame that stalls after its first byte, a connection that sits idle,
  a client that never reads, more connections than the cap, more forwarded
  ones than theirs, more bindings than a connection may hold, unknown
  messages and extensions. A session-bind's host key or host certificate
  and its signature are an SSH server's to choose (ACT-12), and a
  forwarding host sends binds of its own (ACT-11): send malformed,
  oversized and mismatched ones, a certificate larger than the daemon
  keeps, and time the verification, a certificate's CA signature
  included. Fill what requests leave behind: pending requests, forwarded
  approvals, forwarding sessions. Time a signature on a bound connection
  against a large `known_hosts`, which is read for each, and check that
  the read holds up neither other clients nor a lock. Run the fuzz
  targets in `fuzz/` for a bounded time (`nix develop .#fuzz`).
- T-15 is split: what a process holding only the agent socket gets is
  W7's, and what the tray shows a session-bus peer is W4's. Here, check
  that nothing else reaches either socket.

### W2: Secret flow and persistence

Follow every password, keyfile byte, protected field, TOTP seed and private
key from entry to rest, and check where each ends up against the table at
the head of §6.

1. **Map the lifecycle first**, before any test. Entry points: the unlock
   prompt program's stdout pipe (`src/prompt/program.rs`), a terminal a
   request passed (`src/prompt/terminal.rs`), keyfile bytes, the decrypted
   database, and the private keys the agent parses out of attachments
   (`src/ssh/keys.rs`, `src/frontends/ssh_agent/agent/`). Vault content is
   read only through `Open`'s and `Entry`'s methods in
   `src/databases/mod.rs`, and nothing outside `src/databases/` names
   `keepass`: start from those call sites, and treat an exception as a
   finding. List every copy (`clone`, `to_owned`, `to_string`,
   `String::from`, `format!`, serde) and every sink (stdout, stderr, both
   sockets, identity comments, the log, error `Display`, protocol `detail`
   fields, panic messages, a prompt's message, a child's argv and env, the
   key cache). A signature that takes `&str` for a secret forces its
   caller to hold an unzeroizable `String`, so flag the signature as well
   as the call.
2. **Heap-residue scan** for G-6. Scan the process's own writable mappings
   (`/proc/self/maps` rw regions via `/proc/self/mem`) before unlock, while
   unlocked, and after lock. Use four needles: a protected field, an
   unprotected field, the master password, and a private key's bytes once
   it has signed. **Pre-allocate the scan buffer and the maps string
   before the vault is loaded, and do a warm-up scan.** A scanner that
   allocates while scanning reuses the very chunks it's looking for, which
   produces false "cleared" results. Classify each surviving copy as
   kpa-owned (G-6, in scope) or inside `keepass` or `ssh-key` (NG-4,
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
   config is read or any unlock, in the daemon and in a CLI process
   (`grep Dumpable`-equivalent: call `prctl(PR_GET_DUMPABLE)` from the
   harness, or check that `/proc/<pid>` files become root-owned). Check
   that nothing writes secrets to a file. The one file kpa creates besides
   its sockets is the key cache: read what an unlock wrote there, and its
   mode.
6. **What the prompt children get** (T-24). Look at the environment, fds
   and argv of the unlock prompt and of the confirm prompt. The message is
   in `KPA_PROMPT_MESSAGE`, the data behind it in `KPA_PROMPT_DATA`, and
   neither in an argv that kpa builds; a wrapper that copies one onto a
   command line is the residual T-24 accepts, not a finding. Check that
   the data holds nothing of A-2. A terminal a request passed is not
   inherited.
7. **The log** (G-4). Run every operation, signatures included, at `debug`
   against a vault whose titles, usernames, URLs and field values are
   recognizable strings, then search the log for them. G-4 names the few
   things a line may carry. A signature's line names its hosts, which are
   not assets.
8. **`kpa pick`** (G-4, T-5, T-24;
   `src/frontends/control/client/pick/`). It runs `fzf` twice when the
   user asks for a field by name: record both runs. With a recording
   `fzf` and under `strace -f -e trace=execve,openat,creat`, look at what
   each `fzf` gets on its argv, in its environment and on its stdin, and
   at every file the run creates: nothing from a vault on a command line,
   no file from kpa. Then with the real `fzf`, set a `--history` file and
   a `--preview` that leaves a mark, through `FZF_DEFAULT_OPTS` and
   through `FZF_DEFAULT_OPTS_FILE`: the history stays empty and the
   preview never runs. Read the line it prints and its errors for
   anything beyond the entry's title and database.
9. **Where a `copy` lands** (G-3). With the in-process daemon, place the
   requester on and outside the desktop, against a display session that
   is absent, locked, unlocked and inactive. `copy` offers only on the
   desktop of an active, unlocked session, and fails with `no_display`
   before the clipboard is touched anywhere else. `status`'s `can_copy`
   says the same for the requester that asked. Change the display session
   after reading it: `copy` follows the session, not the hint.

### W3: File input and vault integrity

- **G-1.** Run unlock, list, lock and a signature under
  `strace -f -e trace=openat,open,creat,rename,unlink,truncate,ftruncate,flock,fcntl,chmod,utimensat,write`
  against fixtures in a directory you snapshot before and after
  (`find -printf '%p %m %T@ %s\n'`). Any open with write intent, any new
  file, any changed timestamp, and any fd on the vault that outlives the
  read is a finding. The key cache is the one file kpa creates: check that
  it lands under the cache directory, wherever the vault is. Confirm in
  `Cargo.lock`/`cargo tree -e features` that `keepass` is built without
  save support.
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
  delete. Follow each with a `list`, a `status` and a signature. Note the
  order of `stat` versus read at unlock time: a change that lands between
  the two is a TOCTOU.
- **T-17.** Nothing addresses it: record its current state.

### W4: Lock lifecycle and prompt routing

- **Races.** Lock during an in-flight unlock (while the prompt is open,
  and during the KDF), a double unlock, and lock-all against a concurrent
  `list`, `copy` and signature. A request served or a signature made after
  lock, or an unlock installing after a lock, breaks G-5. Use a fake
  prompt program that sleeps, so the timing is deterministic.
- **What a lock ends.** Clipboard offers, approvals, pending requests, the
  agent's private keys and any prompt in flight, for every kind of lock:
  explicit, idle, screen lock, suspend, a lost watch, a file found
  changed. On suspend, check that they are gone before the sleep inhibitor
  is released.
- **Idle timer.** G-5 names the activity that resets it. Check that
  nothing else does (a failed, malformed or `status` request,
  `ssh_pending`, `ssh_approve`, `ssh_grants`, listing identities, a
  refused signature, a forwarded one), and that the timer is per
  database.
- **D-Bus and logind** (`src/frontends/auto_lock/`). On a private bus with
  a mock logind, as `tests/logind.rs` runs one: signals from a peer that
  doesn't own logind's name, sent straight to kpa's connection; a
  subscription that drops and comes back, and a database unlocked while
  there was none; `PrepareForSleep(true)`; a display session that changes.
  A spoofed signal that only locks is out of scope (NG-7).
- **The tray** (`src/frontends/tray.rs`). Introspect what it exports
  (`busctl --user introspect`, on a session bus of your own), and test
  whether any method can unlock without a prompt, read entry data, or
  *suppress* a lock. T-15's residual says what it may show.
- **Prompt routing** (G-12, T-19; `src/authz.rs` and each front end's own
  `authz`). Four prompts can be raised: the unlock prompt from the control
  socket, from the tray and from the agent, and the agent's confirm
  prompt. Try each with a requester on and outside the desktop, against a
  display session that is absent, locked, unlocked and inactive, and with
  a screen lock landing just before and just after the prompt goes up. For
  the terminal prompt (`src/prompt/terminal.rs`): a descriptor that isn't
  a terminal, the requester leaving, a hang-up, and the terminal's modes
  after each way out.
- **Not built yet** is a goal status, not a finding, where the docs say so
  at that spot (see Rules). A feature the docs present as built and the
  code lacks is a finding.

### W5: Clipboard and entry content

- **Clipboard** (`src/clipboard/`): check the offered MIME types for the
  `x-kde-passwordManagerHint: secret` tag on every copy path, expiry
  timing, expiry after another client replaced the selection (must be a
  no-op), an offer outliving its database's lock, and what the compositor
  check refuses: a socket outside the runtime directory, served by another
  uid, or from outside the desktop. The live tests
  (`cargo test --test clipboard -- --ignored`) need a Wayland session and
  take its clipboard. Without a session, or without the user's agreement,
  mark the result reasoned and say so.
- **Entry content as data.** Build entries in memory containing ESC/CSI/OSC
  sequences, BEL, `\r`, `\n`, NUL, bidi overrides, invalid surrogates, a
  JSON-looking string, and 1 MiB titles. Run them through every place
  entry content is shown: `list` and the CLI's actual terminal output,
  the lines and the header `kpa pick` gives `fzf` and the line it prints,
  `kpa ssh keys`, `kpa ssh pending` and `kpa ssh grants`, an SSH identity
  comment (`ssh-add -l`), a prompt's message and its data (a scripted
  prompt that records `KPA_PROMPT_MESSAGE` and `KPA_PROMPT_DATA`), and the
  log. Raw control bytes reaching a terminal or a prompt break G-10. Check
  whether framing can be broken and whether `copy` addressing can be
  confused by duplicate titles or UUIDs across two databases.
- **What `kpa pick` copies** (T-13). The entry and field are those of the
  line the user chose. Try titles, usernames and field names that hold a
  tab, a newline, an index of their own or a whole look-alike line, two
  entries that show the same, and an `fzf` that answers with a line it
  wasn't given, an index out of range, or a key `pick` didn't ask for.
  T-13's residual says what a title may still imitate.
- **Attachments as keys** (T-13). An attachment that starts like an
  OpenSSH private key is parsed when a database that serves keys unlocks,
  and on `ssh_keys`. Feed the scan truncated, oversized and malformed
  ones, and watch the unlock they run in.
- **Request text and host names as data.** A database name, a login's
  user, an `SSHSIG` namespace and the requester's command name are shown
  too, and so is the name a host goes by, from a `known_hosts` line or a
  host certificate's principal: put the same hostile strings in each.

### W6: Claims and model gaps

W6 covers what falls *between* the other workstreams, not their ground
again. A claim or gap that belongs to a goal another workstream owns is
theirs. Note it in one line under "Handed off", and don't test it or write
a record. A first run that skipped this rule produced eight duplicates with
conflicting triage.

- **Claims versus code.** Grep `README.md`, every doc in `docs/`,
  `config.example.toml`, `nix/hm-module.nix` and source comments for
  `never|always|cannot|guaranteed|zeroiz|only|no code path`. Test the
  assertions no goal covers, and the ones that span several goals. When
  code and doc disagree, decide which one is wrong and say so. An accurate
  doc is a valid fix.
- **Built or not.** The docs say at the spot what isn't built yet. Check
  that each such mark is still true, and that nothing else is described
  as built that isn't.
- **Configuration.** Check settings that are accepted but ignored, and
  conflicting or duplicate entries.
- **Dependency posture.** List `unsafe` in the full dependency tree's
  crates that touch untrusted bytes or secrets. Check zeroization coverage
  in `keepass` and `ssh-key`. If `cargo audit` is available offline, run
  it. Pinned versions that are out of upstream support, or not yet in it,
  are a finding (see ASM-5).
- **The unit's sandbox** (`nix/hm-module.nix`). No goal rests on it (§5),
  so a weakness there is hardening. Check each directive against what the
  daemon and its prompt children do.
- **Model gaps.** Do one STRIDE pass per trust boundary looking for threats
  that §7 lacks, and for any entry that is wrong, too broad, or rated at
  the wrong severity. Each becomes a *Model gap* finding with the exact
  proposed text for `docs/threat-model.md`.
- **T-16, T-18.** Record T-16's current state; findings there are
  hardening. T-18 is an accepted risk with an in-scope list: test each
  item on it, the daemon's memory read by the same uid among them.

### W7: SSH agent policy

Which signatures the agent makes, for whom, and after which prompt
(`docs/ssh-agent.md` has the design). The socket as a transport is W1's,
key material in memory is W2's, and how a hostile title looks in a prompt
is W5's.

Drive the agent the way `tests/ssh_agent_serve.rs` does, with the real
OpenSSH tools (`ssh-add -l`, `ssh-keygen -Y sign`, `ssh` to an `sshd` of
your own on localhost) and with raw frames where a tool can't say what you
need, such as a session-bind signed by a throwaway host key.
`tests/ssh_forwarding.rs` forwards the agent with the real `ssh -A`
through a private `sshd`. A scripted confirm prompt that records
`KPA_PROMPT_MESSAGE` and `KPA_PROMPT_DATA` and answers `Allow`, `Deny`,
something else or nothing gives every outcome on demand.

- **G-13.** A database that doesn't opt in, and a `serve = false` key:
  neither listed nor signed with. A locked database: listed from the key
  cache, nothing signed. Unlock on demand: the unlock prompt, then the
  confirm prompt, and no signature if the second is refused. Each
  `confirm` setting. What an approval covers: try another key, another
  destination, bound against unbound, another purpose, and the same
  request after a lock. `ssh_approve` with an unknown id, an expired one,
  one from before a lock, and the one-signature window of a
  `confirm = "always"` key. A login whose session isn't the one its
  connection is bound to. A SHA-1 RSA request.
- **Policy is config's.** Vault content that might steer it: per-entry
  agent settings a KeePass client stores, a key present in two databases,
  a key in the recycle bin or in an entry's history.
- **G-14.** Mark a connection forwarded with a first session-bind that
  claims it: one that verifies, and one that doesn't, whether it was
  forged or is an honest one the daemon can't verify. Then try to unmark
  it with later binds. On a forwarded connection: which keys are listed;
  that only a login signs, only for the session its destination bound,
  and never without a destination; that `confirm = "never"` still asks,
  and `"always"` asks each time; that the idle timer doesn't move; and
  that nothing sent on the agent socket approves, locks, or unlocks
  without the unlock prompt.
- **What a forwarded approval covers** (T-20). After one `Allow`, try the
  same key and destination from a second forwarding session through the
  same host, through another forwarding host, for another destination,
  and from a local connection; and try a local approval against
  forwarded use. Check what `kpa ssh grants` and `kpa ssh pending` say of
  each, and that a lock drops them all.
- **G-15.** Add, remove, remove-all, smartcard, lock, unlock and unknown
  extensions: each fails, and changes nothing.
- **T-23.** Count prompts. Several signers at once for one key raise one
  confirm prompt. A cancelled or timed-out prompt holds the database's
  prompts back, a `Deny` doesn't. Unlock and confirm prompts never share
  the screen. A confirm prompt that fails, is killed, times out or prints
  anything but `Allow` approves nothing.
- **T-25.** Read what each prompt says, in its message and in its data,
  and what `kpa ssh pending` lists, for a login, an `SSHSIG` and anything
  else, bound, unbound and forwarded, against what is then signed. Name
  the hosts every way `known_hosts` can: a plain line, a hashed one, a
  revoked one, a wildcard and a negated pattern, the same key in two
  files. For a host that presents a certificate: a CA line that matches a
  principal, one that doesn't, a revoked CA, and a certificate that is
  expired, a user certificate, carries a critical option, or that its CA
  didn't sign. For a forwarding chain: one host, several, and more than
  the message has room for.
- **T-15.** From a process that holds the agent socket and nothing else:
  what it lists, and what it can get signed without the control socket.

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
