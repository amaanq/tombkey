{
  description = "Re-encrypt age secrets to per-host pubkeys, driven by a Nix-emitted plan.";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixpkgs-unstable";
    fenix = {
      url = "github:nix-community/fenix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    inputs:
    let
      inherit (inputs.nixpkgs) lib;
      inherit (inputs) self;
      inherit (lib) genAttrs optionals;

      eachSystem =
        f: genAttrs lib.systems.flakeExposed (system: f inputs.nixpkgs.legacyPackages.${system});

      hasFenix = system: inputs.fenix.packages ? ${system};
      hasMold = plat: plat.isLinux && (plat.isx86_64 || plat.isAarch64);
    in
    {
      packages = eachSystem (
        pkgs:
        let
          packageName = "tombkey";
          inherit (pkgs.stdenv.hostPlatform) system;
          rustPlatform =
            if hasFenix system then
              let
                fenixPkgs = inputs.fenix.packages.${system};
              in
              pkgs.makeRustPlatform {
                cargo = fenixPkgs.latest.cargo;
                rustc = fenixPkgs.latest.rustc;
              }
            else
              pkgs.rustPlatform;
        in
        {
          tombkey = rustPlatform.buildRustPackage {
            pname = packageName;
            src = ./.;
            version = "0.1.0";

            cargoLock.lockFile = ./Cargo.lock;

            nativeBuildInputs = [
              pkgs.pkg-config
            ]
            ++ optionals (hasMold pkgs.stdenv.hostPlatform) [
              pkgs.clang
              pkgs.mold
            ];

            meta = {
              description = "Re-encrypt age secrets to per-host pubkeys, driven by a Nix plan";
              homepage = "https://github.com/amaanq/tombkey";
              license = lib.licenses.mit;
              maintainers = [ lib.maintainers.amaanq ];
              mainProgram = packageName;
            };
          };

          default = self.packages.${system}.tombkey;

          regenerate-test-fixtures = pkgs.writeScriptBin "regenerate-test-fixtures" /* nu */ ''
            #!${lib.getExe pkgs.nushell}

            const HOSTNAME = "tombkey-vm"
            const PLAINTEXT = "hello tombkey"
            const FIXTURES = "nix/tests/fixtures"

            def extract-recipient [pubkey_file: path]: nothing -> string {
              open --raw $pubkey_file
              | parse --regex '(?<pub>age1[0-9a-z]+)'
              | get pub.0
            }

            def main [] {
              cd $FIXTURES

              rm -rf identities secrets hosts host-pubkey
              mkdir identities secrets $"hosts/($HOSTNAME)/secrets"

              ^${lib.getExe pkgs.rage}-keygen out> identities/master.txt err> identities/master.pubkey
              $"(open --raw identities/master.pubkey)(open --raw identities/master.txt)"
                | save --force identities/master.pub
              chmod 400 identities/master.pub identities/master.txt

              ^${lib.getExe pkgs.rage}-keygen out> identities/host.txt err> identities/host.pubkey
              chmod 400 identities/host.txt

              let master_pub = extract-recipient identities/master.pubkey
              let host_pub = extract-recipient identities/host.pubkey

              $PLAINTEXT | ^${lib.getExe pkgs.rage} --encrypt -r $master_pub -o secrets/hello.age

              ^${lib.getExe pkgs.rage} --decrypt -i identities/master.txt secrets/hello.age
                | ^${lib.getExe pkgs.rage} --encrypt -r $host_pub -o $"hosts/($HOSTNAME)/secrets/hello.age"

              $host_pub | save --force host-pubkey

              print $"regenerated fixtures with master=($master_pub) host=($host_pub)"
            }
          '';
        }
      );

      nixosModules.default = import ./nix/module.nix;
      darwinModules.default = import ./nix/module.nix;

      lib.mkApps = import ./nix/mk-apps.nix {
        inherit lib;
        inherit (inputs) nixpkgs;
        tombkeyPackages = self.packages;
      };

      checks = eachSystem (
        pkgs:
        let
          inherit (pkgs.stdenv.hostPlatform) system;
        in
        {
          eval = (import ./nix/tests { inherit pkgs lib; }).check;
        }
        // lib.optionalAttrs pkgs.stdenv.hostPlatform.isLinux {
          integration = import ./nix/tests/integration.nix {
            inherit pkgs;
            tombkeyPackage = self.packages.${system}.default;
            tombkeyModule = self.nixosModules.default;
          };
        }
      );

      devShells = eachSystem (
        pkgs:
        let
          inherit (pkgs.stdenv.hostPlatform) system;
          toolchain =
            if hasFenix system then
              (inputs.fenix.packages.${system}.complete.withComponents [
                "cargo"
                "clippy"
                "rust-src"
                "rustc"
                "rustfmt"
                "rust-analyzer"
              ])
            else
              pkgs.rustc;
        in
        {
          default = pkgs.mkShell {
            packages = [
              pkgs.nixfmt
              pkgs.pkg-config
              pkgs.taplo
              toolchain
            ]
            ++ optionals (hasMold pkgs.stdenv.hostPlatform) [
              pkgs.clang
              pkgs.mold
            ];
          };
        }
      );
    };
}
