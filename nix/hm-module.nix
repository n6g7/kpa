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
        `clipboard_timeout`, `prompt`, `prompt_timeout`, and one
        `[[database]]` table per vault).
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

    sshAgent.enable = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = ''
        Wire kpa's SSH agent (`$XDG_RUNTIME_DIR/kpa/ssh-agent`) into the
        session, as `docs/ssh-agent.md` § 8 describes: `SSH_AUTH_SOCK` for
        the graphical session, an `ssh_config` fallback for sessions
        outside it, and a login-shell default for tools that read neither.

        This option only adds kpa's own wiring. It does not turn off
        `services.gnome.gcr-ssh-agent` or a KeePass client's SSH agent
        integration, and it does not narrow `ForwardAgent`; turning those
        off, where they exist, is yours to do.
      '';
    };
  };

  config = lib.mkMerge [
    {
      assertions = [
        {
          assertion = cfg.sshAgent.enable -> cfg.enable;
          message = "services.kpa.sshAgent.enable requires services.kpa.enable.";
        }
      ];
    }

    (lib.mkIf cfg.enable {
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
          # socket, the D-Bus session and system buses for the tray, the
          # logind watcher and the service manager's environment, and the
          # Wayland socket for the clipboard), never execs another program
          # itself, and needs no writable+executable memory. The one path
          # that breaks that pattern is `unlock`, which execs the configured
          # `prompt` command (`config.example.toml`'s `prompt`, e.g. a
          # dmenu-style picker) as a child that inherits every directive
          # below — each one here was checked against that child, not just
          # against kpa itself:
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
    })

    # docs/ssh-agent.md § 8, steps 3-4: point the session, and sessions
    # outside it, at kpa's agent socket. This only adds kpa's own wiring
    # (§ 8 step 2, narrowing `ForwardAgent`, and turning off another
    # agent are left to the caller, as the option above says).
    (lib.mkIf (cfg.enable && cfg.sshAgent.enable) {
      # Reaches the graphical session and everything it starts
      # (environment.d), including tools that read `SSH_AUTH_SOCK`
      # directly rather than `ssh_config`.
      systemd.user.sessionVariables.SSH_AUTH_SOCK = lib.mkDefault "\${XDG_RUNTIME_DIR}/kpa/ssh-agent";

      # A fallback for sessions environment.d doesn't reach (an SSH
      # login, a terminal-server shell): a forwarded agent that lists
      # keys wins, kpa answers otherwise. `programs.ssh.enable` is left
      # alone — a caller who manages `~/.ssh/config` some other way gets
      # no block, rather than having home-manager start managing that
      # file for them. Keyed by something other than the literal `"*"`
      # attribute, this block always renders before a catch-all set the
      # usual way, at `programs.ssh.settings."*"`: that one setting alone
      # is always written last, regardless of this block's position.
      programs.ssh.settings.kpa-ssh-agent = {
        header = ''Match host * exec "test -z '$SSH_AUTH_SOCK' || ! ssh-add -l >/dev/null 2>&1"'';
        IdentityAgent = "/run/user/%i/kpa/ssh-agent";
      };

      # A second fallback, for tools that read neither environment.d nor
      # `ssh_config`: default `SSH_AUTH_SOCK` in login shells, leaving a
      # forwarded agent's socket (set by sshd) alone. Only the shells
      # already managed by home-manager gain this; others are untouched.
      programs.bash.profileExtra = lib.mkIf config.programs.bash.enable ''
        if [ -z "$SSH_AUTH_SOCK" ]; then
          export SSH_AUTH_SOCK="''${XDG_RUNTIME_DIR}/kpa/ssh-agent"
        fi
      '';
      programs.zsh.profileExtra = lib.mkIf config.programs.zsh.enable ''
        if [ -z "$SSH_AUTH_SOCK" ]; then
          export SSH_AUTH_SOCK="''${XDG_RUNTIME_DIR}/kpa/ssh-agent"
        fi
      '';
      programs.fish.loginShellInit = lib.mkIf config.programs.fish.enable ''
        if not set -q SSH_AUTH_SOCK
            set -gx SSH_AUTH_SOCK "''${XDG_RUNTIME_DIR}/kpa/ssh-agent"
        end
      '';
    })
  ];
}
