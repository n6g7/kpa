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
      };
      Install = {
        WantedBy = [ "default.target" ];
      };
    };
  };
}
