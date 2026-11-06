# A home-manager module, curried over the flake's own `self` so it can
# default `package` to this flake's own build rather than making every
# caller pass it in. `flake.nix` exposes the result as
# `homeManagerModules.default`.
self:
{
  config,
  lib,
  pkgs,
  ...
}:
let
  cfg = config.services.kpa;
  settingsFormat = pkgs.formats.toml { };
in
{
  options.services.kpa = {
    enable = lib.mkEnableOption "kpa, a read-only KeePass agent";

    package = lib.mkOption {
      type = lib.types.package;
      default = self.packages.${pkgs.system}.default;
      defaultText = lib.literalExpression "kpa.packages.<system>.default";
      description = "The kpa package to run.";
    };

    settings = lib.mkOption {
      type = settingsFormat.type;
      default = { };
      description = ''
        Settings written to kpa's config file, in the shape documented by
        `config.example.toml` in the kpa repository (`idle_timeout`,
        `clipboard_timeout`, `prompt`, and one `[[database]]` table per
        vault).
      '';
      example = lib.literalExpression ''
        {
          idle_timeout = "30m";
          clipboard_timeout = "30s";
          prompt = [ "fuzzel" "--dmenu" "--password" "--prompt" ];
          database = [
            { name = "personal"; path = "/home/you/passwords.kdbx"; }
          ];
        }
      '';
    };
  };

  config = lib.mkIf cfg.enable {
    xdg.configFile."kpa/config.toml".source = settingsFormat.generate "kpa-config.toml" cfg.settings;

    systemd.user.services.kpa = {
      Unit = {
        Description = "kpa, a read-only KeePass agent";
      };
      Service = {
        ExecStart = "${lib.getExe cfg.package} serve";
        Restart = "on-failure";

        # Sandboxing. Every directive here is `lib.mkDefault`, so a caller
        # who needs something looser can still set
        # `systemd.user.services.kpa.Service.<name> = lib.mkForce ...`.
        #
        # kpa's own daemon loop touches only AF_UNIX sockets (its client
        # socket, the D-Bus session and system buses for the tray and the
        # logind watcher, and — through `wl-clipboard-rs` — the Wayland
        # socket), never execs another program itself, and needs no
        # writable+executable memory. The one path that breaks that
        # pattern is `unlock`, which execs the configured `prompt` command
        # (`config.example.toml`'s `prompt`, e.g. a dmenu-style picker) as
        # a child that inherits every directive below — each one here was
        # checked against that child, not just against kpa itself:
        #
        # - `MemoryDenyWriteExecute = true` blocks any prompt program that
        #   JITs at runtime (an embedded JS/Lua engine, PyPy, a browser
        #   view). A prompt like that needs
        #   `systemd.user.services.kpa.Service.MemoryDenyWriteExecute = lib.mkForce false;`.
        # - `RestrictNamespaces = true` blocks a prompt program that
        #   creates its own namespaces (e.g. one that re-sandboxes itself
        #   with bwrap, or a Flatpak-packaged picker). Override with
        #   `systemd.user.services.kpa.Service.RestrictNamespaces = lib.mkForce false;`.
        # - `PrivateTmp = true` gives the unit (and the prompt command) a
        #   private `/tmp`; a prompt command or script that specifically
        #   expects to share the host's `/tmp` with other processes needs
        #   `systemd.user.services.kpa.Service.PrivateTmp = lib.mkForce false;`.
        #
        # `ProtectHome` is deliberately left unset: `read-only` also makes
        # the per-user `/run/user/<uid>` read-only, which breaks kpa's own
        # socket (`$XDG_RUNTIME_DIR/kpa/sock`) and any prompt program that
        # keeps a lock file or cache there — not a safe default even
        # though the vault itself is only ever read.
        LimitCORE = lib.mkDefault 0;
        NoNewPrivileges = lib.mkDefault true;
        RestrictAddressFamilies = lib.mkDefault "AF_UNIX";
        MemoryDenyWriteExecute = lib.mkDefault true;
        SystemCallFilter = lib.mkDefault "@system-service";
        SystemCallArchitectures = lib.mkDefault "native";
        ProtectSystem = lib.mkDefault "strict";
        PrivateTmp = lib.mkDefault true;
        RestrictNamespaces = lib.mkDefault true;
        LockPersonality = lib.mkDefault true;
        ProtectKernelTunables = lib.mkDefault true;
        ProtectKernelModules = lib.mkDefault true;
        ProtectKernelLogs = lib.mkDefault true;
        ProtectClock = lib.mkDefault true;
        ProtectControlGroups = lib.mkDefault true;
        ProtectHostname = lib.mkDefault true;
      };
      Install = {
        WantedBy = [ "default.target" ];
      };
    };
  };
}
