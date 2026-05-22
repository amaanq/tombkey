{
  lib,
  tombkeyPackages,
  nixpkgs,
}:
{
  nixosConfigurations ? { },
  darwinConfigurations ? { },
}:
let
  inherit (lib) genAttrs mapAttrs mapAttrsToList;

  allHosts = nixosConfigurations // darwinConfigurations;
  enabledHosts = lib.filterAttrs (_: cfg: cfg.config.age.tombkey.enable or false) allHosts;

  hostSystem = cfg: cfg.pkgs.stdenv.hostPlatform.system;

  # Cross-host invariants.
  enabledPlanData = mapAttrsToList (_: cfg: cfg.config.age.tombkey.planData) enabledHosts;

  # Unordered pairs (i < j)
  unorderedPairs =
    list:
    let
      indexed = lib.imap0 (i: x: { inherit i x; }) list;
    in
    lib.concatMap (
      a:
      lib.concatMap (
        b:
        lib.optional (b.i > a.i) {
          a = a.x;
          b = b.x;
        }
      ) indexed
    ) indexed;

  storageOverlapsBetween =
    a: b:
    lib.hasPrefix (a.local_storage_dir + "/") (b.local_storage_dir + "/")
    || lib.hasPrefix (b.local_storage_dir + "/") (a.local_storage_dir + "/");

  reportCrossHostError =
    let
      overlapping = lib.filter ({ a, b }: storageOverlapsBetween a b) (unorderedPairs enabledPlanData);
      manifests = lib.unique (map (entry: entry.manifest_file) enabledPlanData);
    in
    if overlapping != [ ] then
      let
        first = builtins.head overlapping;
      in
      throw ''
        tombkey.lib.mkApps: hosts ${first.a.host_label} (${first.a.local_storage_dir}) and ${first.b.host_label} (${first.b.local_storage_dir}) globally have overlapping `localStorageDir`. All enabled hosts share the same on-disk repo, so the orphan sweep from either host would delete the other's outputs once that rekey app runs.
      ''
    else if lib.length manifests > 1 then
      throw ''
        tombkey.lib.mkApps: enabled hosts disagree on `manifestFile`: ${lib.concatStringsSep ", " manifests}. All hosts must share a single manifest (one per repo).
      ''
    else
      null;

  appsForSystem =
    system:
    let
      pkgs = nixpkgs.legacyPackages.${system};
      tombkey = tombkeyPackages.${system}.tombkey;

      systemPluginDirs = lib.unique (
        lib.concatLists (
          mapAttrsToList (_: cfg: cfg.config.age.tombkey.planData.age_plugins) (
            lib.filterAttrs (_: cfg: hostSystem cfg == system) enabledHosts
          )
        )
      );

      planFlags = builtins.concatStringsSep " " (
        mapAttrsToList (
          _: cfg:
          let
            planData = cfg.config.age.tombkey.planData // {
              age_plugins = systemPluginDirs;
            };
          in
          "--plan ${pkgs.writeText "tombkey-plan-${planData.host_label}.json" (builtins.toJSON planData)}"
        ) enabledHosts
      );

      # The binary walks up from $PWD to find `flake.nix`, or honors the flag or environment variable.
      multiPlanApp =
        subcommand:
        pkgs.writeShellScriptBin "tombkey-${subcommand}" ''
          set -euo pipefail
          exec ${tombkey}/bin/tombkey ${planFlags} ${subcommand} "$@"
        '';

      drvs = {
        rekey = multiPlanApp "rekey";
        reseal = multiPlanApp "reseal";
        gc = multiPlanApp "gc";
        edit = multiPlanApp "edit";
        view = multiPlanApp "view";
      };
    in
    mapAttrs (name: drv: {
      type = "app";
      program = "${drv}/bin/tombkey-${name}";
    }) drvs;

  systemsInUse = lib.unique (lib.mapAttrsToList (_: hostSystem) enabledHosts);
in
if enabledHosts == { } then
  throw "tombkey.lib.mkApps: no host has age.tombkey.enable = true"
else
  builtins.seq reportCrossHostError (genAttrs systemsInUse appsForSystem)
