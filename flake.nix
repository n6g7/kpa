{
  description = "kpa — read-only KeePass agent";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs =
    { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = import nixpkgs { inherit system; };
      in
      {
        # Just a devShell for now. `packages.default` (rustPlatform.buildRustPackage)
        # comes in a later PR once there's something worth packaging — see
        # docs/design.md's "Packaging" section and docs/plan.md.
        devShells.default = pkgs.mkShell {
          packages = with pkgs; [
            cargo
            rustc
            clippy
            rustfmt
            rust-analyzer
            # Neither of these is a Rust dependency — tests/fixture.sh shells
            # out to both to build throwaway .kdbx fixtures rather than
            # hand-rolling the KDBX format in a test helper. keepassxc-cli
            # only ever produces KDBX3 (no CLI flag controls this — verified
            # against 2.7.12's --help); pykeepass is here specifically to
            # produce a KDBX4 fixture too, so both formats keepass claims to
            # support are actually exercised by the test suite.
            keepassxc
            (python3.withPackages (ps: [ ps.pykeepass ]))
          ];

          # rust-analyzer and clippy both want to find the sysroot's source;
          # RUST_SRC_PATH keeps that working without a separate rustup install.
          RUST_SRC_PATH = "${pkgs.rustPlatform.rustLibSrc}";
        };
      }
    );
}
