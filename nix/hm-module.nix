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

  # The agent's socket: `settings.ssh_agent.socket` if set, else kpa's
  # default under the runtime directory (docs/ssh-agent.md § 7). Spelled
  # once for the environment and the shells, where `$XDG_RUNTIME_DIR` and
  # `$HOME` expand, and once for `ssh_config`, where `%i` and `~` do. The
  # variables are unbraced: environment.d, bash and zsh read `$VAR` as
  # well as `${VAR}`, and fish reads only `$VAR`.
  agentSocket = (cfg.settings.ssh_agent or { }).socket or null;
  envAgentSocket =
    if agentSocket == null then
      "$XDG_RUNTIME_DIR/kpa/ssh-agent"
    else if lib.hasPrefix "~/" agentSocket then
      "$HOME/" + lib.removePrefix "~/" agentSocket
    else
      agentSocket;
  sshConfigAgentSocket = if agentSocket == null then "/run/user/%i/kpa/ssh-agent" else agentSocket;

  # `pick.keyBinding` (`ctrl-s`, `alt-s`) in each shell's own spelling.
  # The option's type admits only those two shapes, so the match holds
  # whenever the key is set; nothing reads this while it is null.
  pickKey =
    let
      parts = builtins.match "(ctrl|alt)-([a-z])" cfg.pick.keyBinding;
      modifier = builtins.elemAt parts 0;
      letter = builtins.elemAt parts 1;
    in
    if modifier == "ctrl" then
      {
        zsh = "^${letter}";
        bash = "\\C-${letter}";
        fish = "\\c${letter}";
      }
    else
      {
        zsh = "\\e${letter}";
        bash = "\\e${letter}";
        fish = "\\e${letter}";
      };

  # Terminal flow control swallows these two keys before a shell reads them.
  pickKeyIsFlowControl = builtins.elem cfg.pick.keyBinding [
    "ctrl-s"
    "ctrl-q"
  ];
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
          prompt = [ "sh" "-c" "exec fuzzel --dmenu --password --prompt \"$KPA_PROMPT_MESSAGE\"" ];
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
        Wire kpa's SSH agent (`settings.ssh_agent.socket`, by default
        `$XDG_RUNTIME_DIR/kpa/ssh-agent`) into the session, as `docs/ssh-agent.md` § 8 describes: `SSH_AUTH_SOCK` for
        the graphical session, an `ssh_config` fallback for sessions
        outside it, and a login-shell default for tools that read neither.

        This option only adds kpa's own wiring. It does not turn off
        `services.gnome.gcr-ssh-agent` or a KeePass client's SSH agent
        integration, and it does not narrow `ForwardAgent`; turning those
        off, where they exist, is yours to do.
      '';
    };

    pick.keyBinding = lib.mkOption {
      type = lib.types.nullOr (lib.types.strMatching "ctrl-[a-wyz]|alt-[a-z]");
      default = null;
      example = "ctrl-s";
      description = ''
        A key that runs `kpa pick` in your interactive zsh, bash and fish
        shells, in each one home-manager manages (`programs.<shell>.enable`).
        Null binds nothing. A key is `ctrl-` or `alt-` and a letter, such as
        `ctrl-s` or `alt-s`. `ctrl-x` is left out because the shells use it
        as the prefix of other bindings.

        The key types `kpa pick` as a command line and runs it, so `kpa pick`
        can read a master password from the terminal when it unlocks a
        database. The line you were typing comes back at the next prompt,
        and `kpa pick` lands in your shell history.

        `ctrl-s` and `ctrl-q` are the terminal's flow-control keys. When the
        key is one of them, the binding also turns flow control off in zsh
        and bash (fish has it off already). No other key changes it.
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
        {
          assertion = cfg.pick.keyBinding != null -> cfg.enable;
          message = "services.kpa.pick.keyBinding requires services.kpa.enable.";
        }
      ];
    }

    (lib.mkIf cfg.enable {
      # `kpa` on PATH, for `kpa pick` and every other subcommand.
      home.packages = [ cfg.package ];

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
      systemd.user.sessionVariables.SSH_AUTH_SOCK = lib.mkDefault envAgentSocket;

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
        IdentityAgent = sshConfigAgentSocket;
      };

      # A second fallback, for tools that read neither environment.d nor
      # `ssh_config`: default `SSH_AUTH_SOCK` in login shells, leaving a
      # forwarded agent's socket (set by sshd) alone. Only the shells
      # already managed by home-manager gain this; others are untouched.
      programs.bash.profileExtra = lib.mkIf config.programs.bash.enable ''
        if [ -z "$SSH_AUTH_SOCK" ]; then
          export SSH_AUTH_SOCK="${envAgentSocket}"
        fi
      '';
      programs.zsh.profileExtra = lib.mkIf config.programs.zsh.enable ''
        if [ -z "$SSH_AUTH_SOCK" ]; then
          export SSH_AUTH_SOCK="${envAgentSocket}"
        fi
      '';
      programs.fish.loginShellInit = lib.mkIf config.programs.fish.enable ''
        if not set -q SSH_AUTH_SOCK
            set -gx SSH_AUTH_SOCK "${envAgentSocket}"
        end
      '';
    })

    # The `pick.keyBinding` key, in the shells home-manager manages. Each
    # binding replaces the line being typed with `kpa pick`, runs it as an
    # ordinary command line, and puts the typed line back at the next prompt.
    # `kpa pick` can ask the terminal for a master password, which needs the
    # terminal's normal modes (echo off by `stty`, Enter ending the read).
    # A command run from inside the line editor gets the editor's raw modes
    # in bash and fish, so each shell hands the line over to its own
    # command-line execution instead.
    (lib.mkIf (cfg.enable && cfg.pick.keyBinding != null) {
      programs.zsh.initContent = lib.mkIf config.programs.zsh.enable ''
        ${lib.optionalString pickKeyIsFlowControl "unsetopt flow_control\n"}
        kpa-pick-widget() {
          zle push-line
          BUFFER='kpa pick'
          zle accept-line
        }
        zle -N kpa-pick-widget
        bindkey '${pickKey.zsh}' kpa-pick-widget
      '';

      # `bind -x` is the only way to read or set the line (`READLINE_LINE`),
      # but a command it runs is inside the editor, so two of them only
      # stash and restore the line, and a macro around them accepts the
      # line in between. The keys after the accept stay queued and run at
      # the next prompt, before anything is typed.
      programs.bash.initExtra = lib.mkIf config.programs.bash.enable ''
        ${lib.optionalString pickKeyIsFlowControl "if [[ -t 0 ]]; then stty -ixon; fi\n"}
        __kpa_pick_stash() {
          __kpa_pick_line=$READLINE_LINE
          __kpa_pick_point=$READLINE_POINT
          READLINE_LINE='kpa pick'
          READLINE_POINT=8
        }
        __kpa_pick_restore() {
          READLINE_LINE=$__kpa_pick_line
          READLINE_POINT=$__kpa_pick_point
        }
        for __kpa_pick_keymap in emacs vi-insert; do
          bind -m $__kpa_pick_keymap -x '"\C-x\C-k1": __kpa_pick_stash'
          bind -m $__kpa_pick_keymap -x '"\C-x\C-k2": __kpa_pick_restore'
          bind -m $__kpa_pick_keymap '"${pickKey.bash}": "\C-x\C-k1\C-m\C-x\C-k2"'
        done
        unset __kpa_pick_keymap
      '';

      # `fish_postexec` puts the stashed line back after the command. fish
      # turns flow control off itself.
      programs.fish.interactiveShellInit = lib.mkIf config.programs.fish.enable ''
        function __kpa_pick_run
            set -g __kpa_pick_line (commandline | string collect)
            set -g __kpa_pick_cursor (commandline --cursor)
            commandline --replace 'kpa pick'
            commandline --function execute
        end
        function __kpa_pick_restore --on-event fish_postexec
            if set -q __kpa_pick_line
                commandline --replace -- $__kpa_pick_line
                commandline --cursor $__kpa_pick_cursor
                set -e __kpa_pick_line __kpa_pick_cursor
            end
        end
        bind ${pickKey.fish} __kpa_pick_run
        bind -M insert ${pickKey.fish} __kpa_pick_run
      '';
    })
  ];
}
