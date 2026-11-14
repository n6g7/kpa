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

## Keep the module graph a DAG

Modules depend on each other in one direction only, even though Rust
compiles cycles. Read [`docs/module-structure.md`](docs/module-structure.md)
before adding a module or a cross-module dependency.

- No cycles, and no child using its parent's items: `mod.rs` declares,
  re-exports and documents, and shared items live in a child of their own.
- A type's `impl` blocks stay in its module. No blanket impls that give
  another module's types new behaviour.
- When a lower module needs something from a higher one, it defines a
  trait and the higher module implements it.
- One responsibility per module, and a directory once it has parts.
- Apply this to the code your task touches, as above.
