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
