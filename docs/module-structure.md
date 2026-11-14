# kpa — module structure

kpa's modules depend on each other in one direction only: the module graph
is a DAG. Rust compiles cycles between modules of one crate, and lets a
child module use its parent's items or add `impl` blocks to another
module's types, so nothing enforces this but review. It's kept because a
one-way graph forces each module to state what it needs as an interface,
and lets each one be read and tested without the modules above it.

## The rules

- **No cycles.** A module never uses anything from a module that, directly
  or through others, uses it.
- **A child never depends on its parent.** A directory's `mod.rs` declares
  its submodules, re-exports the public API and carries the module docs.
  It defines nothing a child uses. An item several children share, such
  as an error type or a constant, lives in a child of its own (`error.rs`)
  that its siblings import. `super::sibling::Item` names a sibling, which
  is fine; `super::Item` for something defined in `mod.rs` is not.
- **A type's behaviour lives with the type.** Inherent `impl` blocks stay
  in the module that defines the type. A trait impl sits next to the type
  or next to the trait, whichever module already depends on the other.
  Don't give another module's types behaviour through a blanket impl; wrap
  them in a type of your own and implement the trait on that.
- **The caller defines the interface.** When a lower module needs
  something from a higher one, it declares a trait for exactly that, and
  the higher module implements it, as `policy::Locks`,
  `origin::PeerOrigin`, `ssh_agent::serve::SshSign` and
  `ssh_agent::agent::SshHost` do. This is how a callback runs up the graph
  without an import running up it.
- **Widening visibility to reach in is a design smell.** Making a field or
  method `pub(crate)` so another module can use a type's internals usually
  means that module wants a method or a trait instead.
- **One responsibility per module, and a directory once it has parts.**
  Split by responsibility, not by line count. `proto/`, `ssh_agent/` and
  `wayland/` are the pattern: one concern each, one file per part of it.

Apply these to code a task already touches, like the
[portability rules](./portability.md). Don't restructure other code only
to follow them.

## Known exceptions

These predate the rules. Fix each when work next changes that code:

- `wayland::copy` and `wayland::data_control` use each other.
- `wayland::compositor` and `wayland::copy` use `wayland::Error`, defined
  in `wayland/mod.rs`.
- `proto::request` uses `proto::VERSION`, defined in `proto/mod.rs`.
