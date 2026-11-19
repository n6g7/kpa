{
  description = "kpa — read-only KeePass agent";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    # Pinned nightly rustc for fuzz/ (docs/plan.md step 6): cargo-fuzz's
    # instrumentation flags (`-Cinstrument-coverage`, `-Zsanitizer=...`) are
    # nightly-only, and nixpkgs itself only packages stable. Only
    # `devShells.fuzz` below pulls this in.
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    { self, nixpkgs, flake-utils, rust-overlay }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = import nixpkgs { inherit system; };
        fuzzPkgs = import nixpkgs {
          inherit system;
          overlays = [ rust-overlay.overlays.default ];
        };
      in
      {
        packages.default = pkgs.callPackage ./nix/package.nix {
          rev = self.dirtyShortRev or self.shortRev or null;
        };

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
            # tests/logind.rs starts a private dbus-daemon for its mock logind.
            dbus
            # ssh-keygen and ssh-add: tests/fixture.sh generates the SSH
            # agent fixture's keys with ssh-keygen, and the SSH agent's
            # integration tests drive kpa with ssh-add and ssh-keygen -Y.
            openssh
            # wl-copy/wl-paste, for driving docs/plan.md step 3's manual
            # clipboard test by hand — kpa itself doesn't use them (its own
            # client is src/clipboard/wayland/).
            wl-clipboard
            # A StatusNotifierItem host, for driving docs/plan.md step 4's
            # tray test by hand — not a Rust dependency (that's ksni, in
            # Cargo.toml). Any host that advertises
            # org.kde.StatusNotifierWatcher on the session bus works; this
            # is just a small, scriptable one to run for that.
            waybar
            # Rasterizes assets/tray/*.svg to the PNGs src/frontends/tray.rs embeds —
            # see assets/tray/render.sh. Not a Rust dependency, and not
            # needed for a normal build: the PNGs it produces are committed.
            resvg
          ];

          # rust-analyzer and clippy both want to find the sysroot's source;
          # RUST_SRC_PATH keeps that working without a separate rustup install.
          RUST_SRC_PATH = "${pkgs.rustPlatform.rustLibSrc}";
        };

        # fuzz/ (docs/plan.md step 6): `nix develop .#fuzz -c cargo fuzz run
        # decode_request -- -max_total_time=180`, from the repo root. Kept
        # separate from `devShells.default` so the nightly toolchain and
        # `cargo-fuzz` never show up in, or affect, a normal `cargo
        # build`/`cargo test`/`cargo clippy`.
        devShells.fuzz = pkgs.mkShell {
          packages = [
            (fuzzPkgs.rust-bin.nightly.latest.default)
            pkgs.cargo-fuzz
          ];
        };
      }
    )
    // {
      # Not per-system: home-manager evaluates this against whichever
      # system the caller's own `pkgs` already is.
      homeManagerModules.default = import ./nix/hm-module.nix self;
    };
}
