{
  config,
  lib,
  ...
}:
let
  inherit (lib)
    assertMsg
    hasPrefix
    literalExpression
    mkIf
    mkOption
    removePrefix
    types
    filterAttrs
    ;

  cfg = config.age.tombkey;
  hostName = config.networking.hostName or "host";

  userFlakeDir =
    if cfg.userFlake == null then null else toString (cfg.userFlake.outPath or cfg.userFlake);

  effectiveStorageDir =
    if cfg.localStorageDir != null then
      cfg.localStorageDir
    else if cfg.userFlake != null then
      cfg.userFlake + "/hosts/${hostName}/secrets"
    else
      null;

  effectiveManifestFile =
    if cfg.manifestFile != null then
      cfg.manifestFile
    else if cfg.userFlake != null then
      cfg.userFlake + "/.tombkey/manifest.json"
    else
      null;

  relativeToFlake =
    path:
    let
      fileStr = toString path;
    in
    assert assertMsg (hasPrefix (userFlakeDir + "/") fileStr || fileStr == userFlakeDir) ''
      age.tombkey: ${fileStr} is not under userFlake (${userFlakeDir}).
      All output/manifest paths must be subpaths of the flake so the runtime
      wrapper can resolve them after cd'ing into the on-disk flake root.
    '';
    if fileStr == userFlakeDir then "." else removePrefix (userFlakeDir + "/") fileStr;

  outputFile =
    name:
    let
      rekeyedPath = builtins.path { path = effectiveStorageDir; } + "/${name}.age";
    in
    assert assertMsg (builtins.pathExists rekeyedPath) ''
      host ${hostName}: rekeyed secret for ${name} not found at ${toString rekeyedPath}.
      Run `nix run .#rekey` and commit the result.
    '';
    rekeyedPath;

  recipient = import ./recipient.nix { inherit lib; };

  rekeyFileSecrets = filterAttrs (_: secret: secret.rekeyFile != null) config.age.secrets;
in
{
  options.age.secrets = mkOption {
    type = types.attrsOf (
      types.submodule (
        { name, config, ... }:
        {
          options.rekeyFile = mkOption {
            type = types.nullOr types.path;
            default = null;
            description = ''
              Path to the master-encrypted source `.age` file. Tombkey
              re-encrypts this to the host's pubkey on each rekey run.
            '';
          };
          config.file = mkIf (cfg.enable && config.rekeyFile != null) (outputFile name);
        }
      )
    );
  };

  options.age.tombkey = {
    enable = mkOption {
      description = ''
        Whether `tombkey` manages this host's rekeyed secrets.
      '';
      type = types.bool;
      default = false;
    };

    userFlake = mkOption {
      description = ''
        The consumer's flake source, typically `self`. Tombkey anchors all
        output/manifest paths under this so the committed plan stays
        portable. The runtime wrapper walks up from `$PWD` until it finds
        `flake.nix` to recover the on-disk location at rekey time.
      '';
      type = types.nullOr types.unspecified;
      default = null;
    };

    masterIdentities = mkOption {
      description = ''
        List of age identities able to decrypt the source `.age` files.
      '';
      type = types.listOf (
        types.submodule {
          options = {
            identity = mkOption {
              type = types.either types.path types.str;
            };
            pubkey = mkOption {
              type = types.nullOr types.str;
              default = null;
            };
          };
        }
      );
      default = [ ];
    };

    hostPubkey = mkOption {
      description = "Age recipient (string) that this host's rekeyed outputs are encrypted to.";
      type = types.nullOr (types.either types.path types.str);
      default = null;
    };

    localStorageDir = mkOption {
      description = ''
        Directory under `userFlake` that holds the rekeyed outputs.
        Default: `''${userFlake}/hosts/''${hostName}/secrets`.
      '';
      type = types.nullOr types.path;
      default = null;
      defaultText = literalExpression ''userFlake + "/hosts/''${hostName}/secrets"'';
    };

    manifestFile = mkOption {
      description = ''
        Committed JSON manifest tracking per-secret rekey state.
        Default: `''${userFlake}/.tombkey/manifest.json`.
      '';
      type = types.nullOr types.path;
      default = null;
      defaultText = literalExpression ''userFlake + "/.tombkey/manifest.json"'';
    };

    agePlugins = mkOption {
      description = "Packages providing `age-plugin-X` binaries used during encrypt/decrypt.";
      type = types.listOf types.package;
      default = [ ];
    };

    planData = mkOption {
      description = ''
        Plan content as a plain Nix attrset. `mkApps` reads this directly and
        serializes per-host plan JSONs with the aggregator's pkgs, so
        one machine can drive every host regardless of platform.
      '';
      type = types.attrs;
      readOnly = true;
    };
  };

  config = mkIf cfg.enable {
    assertions = [
      {
        assertion = cfg.userFlake != null;
        message = "age.tombkey.userFlake must be set when age.tombkey.enable is true (typically `self`).";
      }
      {
        assertion =
          cfg.userFlake == null
          || builtins.isPath cfg.userFlake
          || builtins.isString cfg.userFlake
          || (builtins.isAttrs cfg.userFlake && cfg.userFlake ? outPath);
        message = "age.tombkey.userFlake must be a path, a string, or a flake (attrs with `.outPath`).";
      }
      {
        assertion = cfg.masterIdentities != [ ];
        message = "age.tombkey.masterIdentities must be non-empty when age.tombkey.enable is true.";
      }
      {
        assertion = cfg.hostPubkey != null;
        message = "age.tombkey.hostPubkey must be set when age.tombkey.enable is true.";
      }
    ];

    age.tombkey.planData = {
      host_pubkey = recipient.validateRecipient "age.tombkey.hostPubkey" (toString cfg.hostPubkey);
      host_label = hostName;
      master_identities = map (entry: {
        identity = toString entry.identity;
        pubkey = recipient.resolvedPubkey entry;
      }) cfg.masterIdentities;
      secrets = lib.mapAttrsToList (name: secret: {
        inherit name;
        rekey_file = relativeToFlake secret.rekeyFile;
        output_file = relativeToFlake (effectiveStorageDir + "/${name}.age");
      }) rekeyFileSecrets;
      local_storage_dir = relativeToFlake effectiveStorageDir;
      manifest_file = relativeToFlake effectiveManifestFile;
      age_plugins = map (pkg: "${pkg}/bin") cfg.agePlugins;
    };
  };
}
