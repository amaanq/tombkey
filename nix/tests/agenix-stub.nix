# Minimal agenix-shaped module so the tombkey module can wire
# `age.secrets.<name>.file` in test configurations without pulling in real
# agenix. Only declares the option surface agenix itself owns (`file` +
# the attrset); `rekeyFile` is declared by `../module.nix` as its own
# submodule extension. Shared by the eval tests in `lib.nix` and the NixOS
# integration test in `integration.nix`.
{ lib, ... }:
{
  options.age.secrets = lib.mkOption {
    type = lib.types.attrsOf (
      lib.types.submodule (
        { name, ... }:
        {
          options.file = lib.mkOption {
            type = lib.types.str;
            default = "/run/agenix/${name}";
          };
        }
      )
    );
    default = { };
  };
}
