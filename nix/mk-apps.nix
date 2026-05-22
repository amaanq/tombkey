{
  lib,
  tombkeyPackages,
  nixpkgs,
}:
# The configurations are only kept for API stability since the binary discovers plans itself now.
{
  nixosConfigurations ? { },
  darwinConfigurations ? { },
}:
let
  inherit (lib) genAttrs mapAttrs;

  appsForSystem =
    system:
    let
      pkgs = nixpkgs.legacyPackages.${system};
      tombkey = tombkeyPackages.${system}.tombkey;

      # The binary walks up from $PWD to find `flake.nix`, or honors the
      # flag or environment variable.
      subcommandApp =
        subcommand:
        pkgs.writeShellScriptBin "tombkey-${subcommand}" ''
          set -euo pipefail
          exec ${tombkey}/bin/tombkey ${subcommand} "$@"
        '';

      drvs = {
        rekey = subcommandApp "rekey";
        reseal = subcommandApp "reseal";
        gc = subcommandApp "gc";
        edit = subcommandApp "edit";
        view = subcommandApp "view";
      };
    in
    mapAttrs (name: drv: {
      type = "app";
      program = "${drv}/bin/tombkey-${name}";
    }) drvs;
in
genAttrs (builtins.attrNames tombkeyPackages) appsForSystem
