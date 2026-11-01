{ lib, rustPlatform }:

rustPlatform.buildRustPackage {
  pname = "kpa";
  version = (lib.importTOML ../Cargo.toml).package.version;

  src = lib.cleanSource ../.;

  cargoLock.lockFile = ../Cargo.lock;

  # The test suite needs keepassxc-cli, pykeepass and a dbus session to
  # build and drive fixtures (see flake.nix's devShell) — not something to
  # bring into this derivation's build sandbox. `nix develop -c cargo
  # test` runs the real suite; CI runs the same command.
  doCheck = false;

  meta = {
    description = "A small read-only KeePass agent";
    homepage = "https://github.com/n6g7/kpa";
    license = with lib.licenses; [
      mit
      asl20
    ];
    mainProgram = "kpa";
  };
}
