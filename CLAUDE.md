# kpa — notes for agents

## Design for Linux and macOS

kpa runs on Linux, and macOS support is planned. Every interface you add
or change must be one a macOS implementation could sit behind without its
callers changing. Read [`docs/portability.md`](docs/portability.md) before
working on any OS seam it lists: socket peer identity, request origin, file
locations, lock triggers and D-Bus, the clipboard, the tray, prompts,
process hardening and the service manager.

- Shape each API around what kpa needs, not the Linux mechanism behind it,
  and keep Linux types inside the module that uses them.
- Apply this to the code your task touches. Don't rewrite other code just
  to make it portable.
- Don't write macOS code: no `#[cfg(target_os = "macos")]`, no macOS-only
  dependencies, no stub modules. Windows is out of scope.

## Keep subsystem dependencies a DAG

A subsystem is a top-level module (declared in `src/lib.rs`) with
everything below it; each module under `src/frontends/` is one too.
Subsystems depend on each other in one direction only, even though Rust
compiles cycles. Read
[`docs/module-structure.md`](docs/module-structure.md) before adding a
subsystem or a dependency between two.

- No cycles between subsystems. Inside one, files and their `mod.rs` use
  each other freely.
- Front ends (`src/frontends/*`) don't use each other: what two of them
  share lives in a subsystem below them (`src/ssh/`).
- Only front ends drive `databases` (unlock, lock). `src/ssh/` may read it
  through a guard it is handed; `src/daemon.rs` builds and wires it.
- No `impl` blocks for another subsystem's types, and no blanket impl whose
  only real implementor is one of them.
- Export a small API. `pub(crate)` added to reach into another
  subsystem's type is a smell.
- Keep decisions pure (data in, decision out). Add a trait only for a
  callback that can't be avoided or a test fake, defined by the subsystem
  that calls it.
- One responsibility per file, and a directory once it has parts.
- Apply this to the code your task touches, as above.
