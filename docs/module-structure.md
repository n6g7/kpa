# kpa — module structure

kpa is one library crate and a CLI binary, divided into **subsystems**.
Rust has no term for this, so this doc defines it: a subsystem is a
top-level module (one declared in `src/lib.rs`) together with everything
below it, such as `ssh/`, `clipboard/`, `databases/`, `server` or `prompt/`.
Each module under `src/frontends/` (`control/`, `ssh_agent/`, `tray`) is a
subsystem too: a front end is one way in to kpa. A subsystem is kpa's unit
of encapsulation, much like a Go package: its files work together freely,
and the rest of the crate sees only the API it exports.

## Between subsystems

- **Dependencies form a DAG.** A subsystem never uses anything from a
  subsystem that, directly or through others, uses it. Cargo forbids
  cycles only between crates, so within kpa's single crate only review
  enforces this.
- **Front ends don't use each other.** `control/`, `ssh_agent/` and `tray`
  share what they need through the subsystems below them, such as `ssh/`
  for what `control/` and `ssh_agent/` both know about SSH keys and
  approvals. Only `main` and the daemon's wiring import `frontends::`.
- **Only front ends drive the core.** Only a front end unlocks or locks a
  `databases` database. `ssh/` may read it through a guard a front end hands
  it and hear of a lock, and the daemon's wiring builds it.
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
  `frontends::ssh_agent::authz::authorize_sign` and `clipboard::Clipboard` do.
  When a callback can't be avoided, or a test needs a fake, the lower
  subsystem defines a trait for exactly what it needs, and the higher one
  implements it (`frontends::ssh_agent::agent::SshHost`). Don't add a trait with one implementation
  and no test using a second.

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
to follow them. `main` follows them today: its subsystem graph has no
cycles.
