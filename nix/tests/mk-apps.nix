# Tests for `../mk-apps.nix`'s cross-host validator. The validator runs
# during flake output construction and is fully eval-time, so we can
# exercise it without spinning up a NixOS test driver.
#
# We build a tiny stand-in for an evaluated NixOS config: just enough
# shape that `cfg.config.age.tombkey.planData` exists. mkApps reads
# nothing else from the config.
{ pkgs, lib }:
let
  testLib = import ./lib.nix { inherit pkgs lib; };
  inherit (testLib)
    eq
    ok
    throws
    sampleRecipients
    ;

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

  fakeHost =
    {
      label,
      system ? pkgs.stdenv.hostPlatform.system,
      storage ? "hosts/${label}/secrets",
      manifest ? ".tombkey/manifest.json",
    }:
    {
      pkgs = pkgs // {
        stdenv = pkgs.stdenv // {
          hostPlatform = pkgs.stdenv.hostPlatform // {
            inherit system;
          };
        };
      };
      config.age.tombkey = {
        enable = true;
        planData = {
          host_pubkey = sampleRecipients.x25519;
          host_label = label;
          master_identities = [ ];
          secrets = [ ];
          local_storage_dir = storage;
          manifest_file = manifest;
          age_plugins = [ ];
        };
      };
    };

  callMkApps =
    hosts:
    mkApps {
      nixosConfigurations = hosts;
      darwinConfigurations = { };
    };
in
[
  (ok "disjoint hosts: apps generate without throwing" (
    let
      result = builtins.tryEval (callMkApps {
        alpha = fakeHost { label = "alpha"; };
        beta = fakeHost { label = "beta"; };
      });
    in
    result.success
  ))

  (throws "overlapping localStorageDir is rejected" (callMkApps {
    alpha = fakeHost {
      label = "alpha";
      storage = "shared/secrets";
    };
    beta = fakeHost {
      label = "beta";
      storage = "shared/secrets";
    };
  }))

  (throws "nested localStorageDir is rejected" (callMkApps {
    alpha = fakeHost {
      label = "alpha";
      storage = "hosts/alpha/secrets";
    };
    beta = fakeHost {
      label = "beta";
      storage = "hosts/alpha/secrets/nested";
    };
  }))

  (throws "divergent manifestFile is rejected" (callMkApps {
    alpha = fakeHost {
      label = "alpha";
      manifest = ".tombkey/manifest.json";
    };
    beta = fakeHost {
      label = "beta";
      manifest = ".tombkey/other.json";
    };
  }))

  (throws "no enabled hosts is rejected" (callMkApps { }))

  (ok "cross-system disjoint hosts evaluate (per-host storage)" (
    let
      result = builtins.tryEval (callMkApps {
        alpha = fakeHost {
          label = "alpha";
          system = "x86_64-linux";
        };
        beta = fakeHost {
          label = "beta";
          system = "aarch64-linux";
        };
      });
    in
    result.success
  ))

  (throws "cross-system overlap is still rejected (one shared on-disk repo)" (callMkApps {
    alpha = fakeHost {
      label = "alpha";
      system = "x86_64-linux";
      storage = "shared/secrets";
    };
    beta = fakeHost {
      label = "beta";
      system = "aarch64-linux";
      storage = "shared/secrets";
    };
  }))
]
