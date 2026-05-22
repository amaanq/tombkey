# Eval-only test entry. Imports each group, filters failures, builds a
# stub derivation that succeeds when the failure list is empty.
{ pkgs, lib }:
let
  inherit (lib) concatMapStringsSep filter length;

  groups = [
    (import ./module.nix { inherit pkgs lib; })
    (import ./recipient.nix { inherit pkgs lib; })
    (import ./mk-apps.nix { inherit pkgs lib; })
  ];
  allResults = builtins.concatLists groups;
  failures = filter (x: x != null) allResults;
in
{
  inherit failures;

  check = pkgs.runCommand "tombkey-module-eval-check" { } (
    if failures == [ ] then
      ''
        echo "module eval: ${toString (length allResults)} checks passed"
        touch "$out"
      ''
    else
      ''
        echo "module eval FAILED:" >&2
        ${concatMapStringsSep "\n" (msg: "echo '  - ${msg}' >&2") failures}
        exit 1
      ''
  );
}
