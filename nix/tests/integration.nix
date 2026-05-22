# This test proves that the tombkey module produces a closure that's self-contained on the target machine.
{
  pkgs,
  tombkeyPackage,
  tombkeyModule,
}:
let
  hostName = "tombkey-vm";
  expectedPlaintext = "hello tombkey";
  fixture = ./fixtures;
in
pkgs.testers.runNixOSTest {
  name = "tombkey-integration";

  containers.machine =
    {
      config,
      lib,
      pkgs,
      modulesPath,
      ...
    }:
    let
      # Workaround for NixOS/nixpkgs#40367. Upstream refuses to boot a rootfs without /usr
      # despite there being no use case for it. run-nspawn only mkdir's an empty rootDir before
      # launch, so we reconstruct the upstream wrapper with a mkdir prepended.
      runNspawn = pkgs.callPackage (modulesPath + "/virtualisation/nspawn-container/run-nspawn") { };
      cfg = config.virtualisation;
      cliOpts = lib.cli.toCommandLineShellGNU { } {
        container-name = config.system.name;
        root-dir = cfg.rootDir;
        interfaces-json = builtins.toJSON (lib.attrValues cfg.allInterfaces);
        init = "${config.system.build.toplevel}/init";
        cmdline-json = builtins.toJSON cfg.cmdline;
      };
    in
    {
      imports = [
        tombkeyModule
        ./agenix-stub.nix
      ];

      networking.hostName = hostName;

      system.build.nspawn = lib.mkForce (
        pkgs.writeScriptBin "run-${config.system.name}-nspawn" # nu
          ''
            #!${lib.getExe pkgs.nushell}
            def main [...rest: string] {
              # nushell's `exec` reads `$env.PATH` internally even when given an
              # absolute path, so define an empty one to placate it.
              $env.PATH = ""

              # Pre-create /usr in the rootDir so systemd-nspawn's OS-tree check accepts it.
              mkdir $"($env.RUN_NSPAWN_ROOT_DIR)/usr"
              exec ${lib.getExe runNspawn} ${cliOpts} ${lib.escapeShellArgs cfg.systemd-nspawn.options} ...$rest
            }
          ''
      );

      environment.systemPackages = [
        tombkeyPackage
        pkgs.rage
      ];

      age.tombkey = {
        enable = true;
        userFlake = fixture;
        hostPubkey = builtins.readFile "${fixture}/host-pubkey";
        masterIdentities = [
          { identity = "${fixture}/identities/master.pub"; }
        ];
      };

      age.secrets.hello = {
        rekeyFile = "${fixture}/secrets/hello.age";
      };
    };

  testScript =
    { containers, ... }:
    let
      secretFile = containers.machine.age.secrets.hello.file;
    in
    ''
      machine.start()
      machine.wait_for_unit("multi-user.target")

      # The closure must contain the rekeyed ciphertext at a /nix/store path.
      assert "${secretFile}".startswith("/nix/store/"), \
        "age.secrets.hello.file must be a /nix/store path, got ${secretFile}"
      machine.succeed("test -f ${secretFile}")

      # Round-trip: the stored ciphertext must decrypt to the original plaintext.
      machine.copy_from_host("${fixture}/identities/host.txt", "/run/host.txt")
      result = machine.succeed("rage --decrypt -i /run/host.txt ${secretFile}")
      assert result == "${expectedPlaintext}", \
        f"plaintext round-trip failed: got {result!r}"
    '';
}
