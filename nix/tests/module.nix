# Tests for `../module.nix`: assertions fire on missing required fields,
# the module is inert when disabled, and host secret `.file` paths default
# correctly.
{ pkgs, lib }:
let
  testLib = import ./lib.nix { inherit pkgs lib; };
  inherit (testLib)
    eq
    ok
    evalConfig
    sampleRecipients
    ;
  inherit (builtins) head toFile;
  inherit (lib) any filter hasInfix;

  disabled = evalConfig { };

  disabledWithSecrets = evalConfig {
    age.secrets.foo.rekeyFile = toFile "x" "y";
  };

  enabledMissingFields = evalConfig {
    age.tombkey = {
      enable = true;
      masterIdentities = [
        {
          identity = "/etc/ssh/m";
          pubkey = sampleRecipients.x25519;
        }
      ];
    };
  };

  failingAssertions = filter (a: !a.assertion) enabledMissingFields.assertions;
  failingMsgs = map (a: a.message) failingAssertions;

  # An enabled config with a stub userFlake should
  # emit a plan attrset whose paths are all relative. Locks in the
  # relative-path contract without going through the VM.
  fakeFlake = toFile "tombkey-test-flake-marker" "";
  fakeFlakeDir = dirOf fakeFlake;
  enabledHappy = evalConfig {
    networking.hostName = "happyhost";
    age.secrets.foo.rekeyFile = "${fakeFlakeDir}/secrets/foo.age";
    age.tombkey = {
      enable = true;
      userFlake = fakeFlakeDir;
      hostPubkey = sampleRecipients.x25519;
      masterIdentities = [
        {
          identity = "/etc/ssh/id";
          pubkey = sampleRecipients.x25519;
        }
      ];
    };
  };
  enabledPlan = enabledHappy.age.tombkey.planData;
  fooSecret = head enabledPlan.secrets;
in
[
  (eq "disabled: assertions empty" disabled.assertions [ ])
  (eq "disabled: age.secrets empty" disabled.age.secrets { })
  (eq "disabled w/secrets: assertions empty" disabledWithSecrets.assertions [ ])
  (eq "disabled w/secrets: foo.file untouched" disabledWithSecrets.age.secrets.foo.file
    "/run/agenix/foo"
  )
  (ok "enabled w/o required fields: at least one assertion fires" (failingAssertions != [ ]))
  (ok "enabled w/o required fields: hostPubkey assertion present" (
    any (m: hasInfix "hostPubkey" m) failingMsgs
  ))
  (ok "enabled w/o required fields: userFlake assertion present" (
    any (m: hasInfix "userFlake" m) failingMsgs
  ))

  # Enabled-config plan shape.
  (eq "enabled: planData.host_label matches hostName" enabledPlan.host_label "happyhost")
  (eq "enabled: planData.host_pubkey is the configured recipient" enabledPlan.host_pubkey
    sampleRecipients.x25519
  )
  (eq "enabled: planData.local_storage_dir is relative (default)" enabledPlan.local_storage_dir
    "hosts/happyhost/secrets"
  )
  (eq "enabled: planData.manifest_file is relative (default)" enabledPlan.manifest_file
    ".tombkey/manifest.json"
  )
  (eq "enabled: secret.rekey_file is relative" fooSecret.rekey_file "secrets/foo.age")
  (eq "enabled: secret.output_file lands under local_storage_dir" fooSecret.output_file
    "hosts/happyhost/secrets/foo.age"
  )
  (ok "enabled: planData has no absolute output paths" (
    !lib.hasPrefix "/" enabledPlan.local_storage_dir
    && !lib.hasPrefix "/" enabledPlan.manifest_file
    && lib.all (
      s: !lib.hasPrefix "/" s.output_file && !lib.hasPrefix "/" s.rekey_file
    ) enabledPlan.secrets
  ))
]
