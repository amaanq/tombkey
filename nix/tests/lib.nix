# Shared helpers for the eval-only test groups.
#
# Each test in a group returns `null` on pass or a labelled string on fail.
{ pkgs, lib }:
let
  inherit (lib) evalModules;

  # The eval tests evaluate `../module.nix` outside a real NixOS module tree,
  # so they also need stubs for `networking.hostName` and `assertions`.
  # `agenix-stub.nix` is shared with the integration test, which gets those
  # options from the real NixOS module set, so we extend it here.
  agenixStub =
    { lib, ... }:
    {
      imports = [ ./agenix-stub.nix ];
      options.networking.hostName = lib.mkOption {
        type = lib.types.str;
        default = "test-host";
      };
      options.assertions = lib.mkOption {
        type = lib.types.listOf lib.types.unspecified;
        default = [ ];
      };
    };
in
{
  sampleRecipients = {
    x25519 = "age1lggyhqrw2nlhcxprm67z43rta597azn8gknawjehu9d9dl0jq3yqqvfafg";
    fido2 = "age1fido2-hmac1qqpzvf37n8852hn88xmgcxzlnp93vmdqnk7l5s6nadfcgtdxhd4fc6cqx9zqdpnr4tduxc8e0gfudtrt4qxh4et3dgx2vruv5u3lfjy8jj0gw4tpm5zfpd27f0rye707n74j4674yzm27uwqv2m7kfzfp6vnf36us45jpj904gsmgfef98shleyqtttt4c43hrjt8rr2s5twyx7dqye765qr";
    sshEd25519 = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAID+36H8eD4p4waEpgPejhPCNGymi+OSN9fZ5LRUBcOnP contact@amaanq.com";
    sshRsa = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCq7VqJ4cIJpqW user@host";
  };

  # Assertion primitives.

  ok = label: cond: if cond then null else "${label}: expected true";

  eq =
    label: actual: expected:
    if actual == expected then
      null
    else
      "${label}: expected ${builtins.toJSON expected}, got ${builtins.toJSON actual}";

  throws =
    label: expr:
    let
      attempt = builtins.tryEval expr;
    in
    if attempt.success then
      "${label}: expected a throw, got ${builtins.toJSON attempt.value}"
    else
      null;

  # Minimal agenix-shaped module.

  evalConfig =
    extraModule:
    (evalModules {
      specialArgs = { inherit pkgs; };
      modules = [
        agenixStub
        ../module.nix
        extraModule
      ];
    }).config;

  recipient = import ../recipient.nix { inherit lib; };
}
