# Building the apps must never force host configs, or every `nix run` pays a fleet eval again.
{ pkgs, lib }:
let
  testLib = import ./lib.nix { inherit pkgs lib; };
  inherit (testLib) eq ok;

  mkApps = import ../mk-apps.nix {
    inherit lib;
    nixpkgs.legacyPackages = {
      "x86_64-linux" = pkgs;
      "aarch64-linux" = pkgs;
    };
    tombkeyPackages = {
      "x86_64-linux".tombkey = pkgs.hello;
      "aarch64-linux".tombkey = pkgs.hello;
    };
  };

  poisonedHost = {
    pkgs = throw "mkApps must not force host pkgs";
    config = throw "mkApps must not force host config";
  };

  apps = mkApps {
    nixosConfigurations.alpha = poisonedHost;
    darwinConfigurations.bravo = poisonedHost;
  };
in
[
  (eq "apps cover every tombkey package system" (builtins.attrNames apps) [
    "aarch64-linux"
    "x86_64-linux"
  ])

  (eq "all subcommands are exposed" (builtins.attrNames apps.x86_64-linux) [
    "edit"
    "gc"
    "rekey"
    "reseal"
    "view"
  ])

  (ok "host configurations are never forced" (
    let
      app = apps.x86_64-linux.rekey;
    in
    app.type == "app" && lib.hasSuffix "/bin/tombkey-rekey" app.program
  ))
]
