# kpa — module structure

kpa is one library crate and a CLI binary, divided into **subsystems**.
Rust has no term for this, so this doc defines it: a subsystem is a
top-level module (one declared in `src/lib.rs`) together with everything
below it, such as `ssh/`, `clipboard/`, `databases/` or `prompt/`.
Each module under `src/frontends/` (`control/`, `ssh_agent/`, `tray`,
`auto_lock/`) is a subsystem too: a front end is one way in to kpa. A
subsystem is kpa's unit of encapsulation, much like a Go package: its files
work together freely, and the rest of the crate sees only the API it
exports.

## The subsystems

Each row lists what the subsystem uses from the rest of kpa, besides `log`,
`output` and `cancel` (logging, terminal-safe text, cancel tokens), which
any subsystem may use and which use nothing in kpa. Read together, the rows
are the dependency graph; there is no arrow between two front ends.

| Subsystem | Is | Uses |
|---|---|---|
| `paths` | the per-user base directories, read from the environment once | nothing |
| `config` | the config file's types and parser | nothing |
| `display_session` | `DisplaySession`, its one writer (`DisplayWriter`) and read-only `DisplayHandle`s | nothing |
| `prompt` | the prompt queue, backends, outcomes, `PromptOn` | nothing |
| `authn` | `Requester`: who is on the other end of a socket, and where it asked to be prompted | `prompt` |
| `authz` | the checks every front end shares: `may_connect`, `on_desktop`, `display_allows_prompt`, `may_prompt_on_screen` | `authn`, `display_session` |
| `socket` | the owner-only bind, the socket directory check, a request with a file descriptor attached | `authn` |
| `clipboard` | the clipboard, with its Wayland backend inside | `authn`, `authz`, `display_session` |
| `databases` | the databases and their lifecycle, `Observer`; `vault` (reading a `.kdbx`) inside | `config` |
| `ssh` | what `control` and `ssh_agent` share about SSH: `keys` (finding keys in a database, their config, the public-key cache) and `approvals` (approvals and pending requests, per database and per unlock) | `databases` (reads only), `config`, `paths` |
| `frontends::control` | kpa's own socket: transport, handlers, `CopyState`, the wire types (`proto`) and the CLI's client | `databases`, `ssh`, `authz`, `authn`, `prompt`, `clipboard`, `display_session`, `socket`, `config` |
| `frontends::ssh_agent` | the SSH agent's socket: protocol, policy, the sign flow, `SshState` | `databases`, `ssh`, `authz`, `authn`, `prompt`, `display_session`, `config` |
| `frontends::tray` | the status icon and its menu | `databases`, `authz`, `prompt`, `display_session` |
| `frontends::auto_lock` | what locks without a request: the logind watcher, the sleep inhibitor, the idle tick, `SleepHold` | `databases`, `authn`, `display_session` |
| `daemon` | wiring: builds the core, registers its observers in order, starts the threads | everything above it |
| `main` (the binary) | arguments, hardening, dispatch | `daemon`, `config`, `paths`, `socket`, `frontends::control` (its client and wire types), `frontends::auto_lock` (`Source`) |

## Between subsystems

- **Dependencies form a DAG.** A subsystem never uses anything from a
  subsystem that, directly or through others, uses it. Cargo forbids
  cycles only between crates, so within kpa's single crate only review
  enforces this.
- **Front ends don't use each other.** `control/`, `ssh_agent/`, `tray` and
  `auto_lock/` share what they need through the subsystems below them, such
  as `ssh/` for what `control/` and `ssh_agent/` both know about SSH keys
  and approvals. Only `main` and the daemon's wiring import `frontends::`.
- **Only front ends drive the core.** Only a front end unlocks or locks a
  `databases` database. `ssh/` may read it through a guard a front end hands
  it and hear of a lock, and the daemon's wiring builds it. `authz`,
  `clipboard`, `prompt` and the rest never see it.
- **A type's behaviour stays in its subsystem.** No `impl` blocks for
  another subsystem's types. No blanket impl whose only real implementor
  is one concrete type from another subsystem; wrap that type in one of
  your own and implement the trait on the wrapper.
- **Export a small API.** A subsystem's `mod.rs` (or its single file)
  re-exports what other subsystems may use; everything else stays private.
  Making a field or method `pub(crate)` so another subsystem can reach
  into a type is a smell: that subsystem usually wants a method, a value
  passed in, or a trait.
- **Keep decisions pure; use a trait only for a real callback.** When a
  lower subsystem needs something from a higher one, first try to make it
  pure: data in, a decision out, and the caller does the I/O, as
  `frontends::ssh_agent::authz::authorize_sign` and
  `frontends::control::authz::authorize_copy` do.
  When a callback can't be avoided, or a test needs a fake, the lower
  subsystem defines a trait for exactly what it needs, and the higher one
  implements it (`databases::Observer`). Don't add a trait with one
  implementation and no test using a second.

## Within a subsystem

- **Files use each other and their parent freely.** Rust makes a private
  item visible to its module and all of that module's descendants, so a
  directory and its files share their internals and nothing else does.
  `mod.rs` can hold what its files share; `use super::*` in tests is fine.
- **A type's inherent `impl` blocks may span the subsystem's files**,
  splitting a large type by responsibility.
- **One responsibility per file, and a directory once a responsibility has
  parts.** Split by responsibility, not by line count.

Apply these to code a task already touches, like the
[portability rules](./portability.md). Don't restructure other code only
to follow them. The graph above has no cycles.

## Layout

kpa is one Cargo package with two crates: the library (`src/lib.rs`), which
holds every module above but `main`, and the binary (`src/main.rs`), which
parses arguments, hardens the process and dispatches: `kpa serve` goes to
`daemon::serve`, and every client subcommand goes to `control`'s client.

```
src/
  main.rs               arguments, hardening, dispatch
  lib.rs
  daemon.rs             wiring: builds everything, starts the threads
  databases/            the core
    mod.rs              Databases and its slots; Open, the guard with the read methods
    unlock.rs           begin_unlock, Unlocking, finish
    observer.rs         Observer, and telling observers in their order
    freshness.rs        the freshness guard: a changed file locks the database
    vault.rs            reading a .kdbx (private to databases)
    testing.rs          in-memory databases, and files to unlock, for other subsystems' tests
  frontends/
    mod.rs
    control/            kpa's own socket
      mod.rs            Api (what the handlers share) and the small handlers:
                        status, lock, list, ssh keys / pending / approve
      serve.rs          listener, connection cap, read one request, write one response
      unlock.rs         the unlock handler: begin, choose where to ask, ask, finish
      copy.rs           the copy handler, and CopyState (ends offers on lock)
      authz.rs          authorize_copy, choose_unlock_prompt
      proto/            the wire types
      client/           the CLI's side: mod.rs, tty.rs, ssh_keys_report.rs,
                        ssh_requests_report.rs
    ssh_agent/          the agent socket: wire, bind, classify, authz, serve
      agent/            the agent's logic: SshState (state.rs), Hold (hold.rs),
                        identities, the sign flow, prompts, signing
    tray.rs             the status icon: Tray, and Changed, its observer
    auto_lock/
      mod.rs            react, watch_idle, SleepHold (OS-neutral)
      logind.rs         the logind watcher and the sleep inhibitor
  ssh/                  what control and ssh_agent share about SSH
    keys.rs             finding keys, their config, the public-key cache
    approvals/          approvals and pending requests, and their state per unlock
      mod.rs            Approvals (the state and its observer), Scope,
                        SignatureApproval, RequestDetails, PendingRequest
      granted.rs        GrantedApprovals: what is approved
      pending.rs        PendingRequests: what was refused
  display_session.rs    DisplaySession, DisplayWriter, DisplayHandle
  clipboard/            mod.rs (Backend, Offer), and wayland/
  authn.rs  authz.rs  prompt/  config.rs  paths.rs  socket.rs
  cancel.rs  log.rs  output/
tests/                  integration tests, each named for what it drives
                        (control.rs, databases.rs, logind.rs, ssh_agent_serve.rs, ...)
fuzz/                   the fuzz targets, their own package
```

There is no `states/`, `util/` or `os/` directory. It is one package rather
than a workspace: the dependency rules between subsystems are kept by review
rather than by crate boundaries, and the test fakes (`prompt::Scripted`,
`clipboard::RecordingBackend`, `Databases::for_test`) stay usable from every
subsystem's unit tests, which separate crates would put behind a feature or a
test-support crate.

## Testing

- **`databases` is tested alone**: the state machine (a lock beats an unlock, a
  token is cancelled when its unlock's lock happens, idle expiry per database,
  the freshness guard, `InProgress`), with in-memory databases installed through
  `install_for_test`, a real KDBX4 file written by `write_for_test` where a test
  unlocks, and observers that record what they are told and call back into the
  core.
- **No front-end test uses a mock of `Databases`.** A mock needs a trait in
  front of the core and a second implementation of its lock and token
  semantics, which can drift from the real one. The stand-in sits at the
  lowest seam, the file: the real core holding an in-memory database, or reading
  a real file the test wrote.
  Likewise the prompts are `prompt::Scripted`, the clipboard is
  `clipboard::RecordingBackend`, and the display session is a writer the test
  sets.
- **`ssh::approvals`, `ssh_agent`, `control` and `tray`** are tested against a
  real `Databases` with their own state registered as observers. The races each
  has to survive are tests: a lock while a prompt is up, a lock and a fresh
  unlock after the answer, a file that changes between two reads, two concurrent
  signers, two overlapping copies. The tray's menu callback is tested behind a
  mutex standing in for the service's lock, since a unit test has no session bus.
- **`auto_lock`** is tested by unit tests of `react`, `watch_idle` and
  `SleepHold` on a `Databases` with an `Event` channel the test reads; the logind
  watcher and `auto_lock::start` by `tests/logind.rs` against a private bus,
  under the system bus's stock default policy.
- **Integration tests** build the daemon with `daemon::build` and put the real
  CLI and the OpenSSH tools in front of it.
