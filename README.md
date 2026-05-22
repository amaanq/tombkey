# tombkey

Re-encrypt [age](https://github.com/FiloSottile/age) secrets from master
identities to per-host pubkeys, driven by a Nix-emitted plan.

## Status

Experimental and personal-use. API is unstable; treat each release as a
fresh contract.

## Layout

Nix compiles the `age.tombkey.*` config into a JSON plan at evaluation time.
The CLI reads the plan and does all the work, that is, decrypting with
masters, re-encrypting to the host pubkey, and writing atomically. Per-secret
rekey state lives in a committed `.tombkey/manifest.json` sidecar that anchors
the skip-decision against source/output sha256 fingerprints.

All output, source, and manifest paths in the plan are stored RELATIVE to your
flake root. At runtime the binary itself walks up from `$PWD` until it finds
`flake.nix` to anchor those paths (override with `--repo-root <path>` or the
`TOMBKEY_REPO_ROOT` env var). The plan stays portable across clones and across
users; user-typed paths for `edit`/`view` are always interpreted
repo-root-relative, not invocation-CWD-relative.

## Install

In `flake.nix`:

```nix
inputs.tombkey.url = "github:amaanq/tombkey";

imports = [ inputs.tombkey.nixosModules.default ];

age.tombkey = {
  enable = true;
  userFlake = self;                          # required: anchors all relative paths
  hostPubkey = "age1...";
  masterIdentities = [
    { identity = ./secrets/iray.pub; }       # pubkey extracted from `# public key:` comment
    { identity = ./secrets/yardang-ssh.pub; pubkey = "age1..."; }
  ];
  # localStorageDir + manifestFile default to:
  #   ${userFlake}/hosts/${networking.hostName}/secrets
  #   ${userFlake}/.tombkey/manifest.json
  # Override only if you want a non-default layout.
  agePlugins = [ pkgs.age-plugin-fido2-hmac ];
};

# age.secrets.<name>.rekeyFile points at the master-encrypted source. Tombkey
# re-encrypts it to hostPubkey and wires `age.secrets.<name>.file` to a
# content-addressed /nix/store copy of the rekeyed output, so the closure is
# self-contained at deploy time.
age.secrets.atuin-key.rekeyFile = ./secrets/atuin-key.age;

apps = inputs.tombkey.lib.mkApps {
  inherit nixosConfigurations;
};
```

## Usage

```bash
nix run .#rekey             # re-encrypt sources to every host's pubkey
nix run .#reseal            # reseal sources to current master set
nix run .#edit -- <secret>  # decrypt → $EDITOR → re-encrypt
nix run .#view -- <secret>  # decrypt → stdout
nix run .#gc                # prune dead manifest entries + orphan outputs
```

`rekey` builds a work graph keyed by source file. For each source it
collects every host output that's stale relative to the manifest; if the
set is empty the source is skipped entirely with no identity loading and no
hardware tap. Otherwise the source is decrypted once and the plaintext fans
out to every stale host. Failed secrets are dropped from the manifest and
their stale outputs deleted, so agenix activation fails loud rather than
consuming stale ciphertext.

`reseal` dedupes sources across hosts and re-encrypts each unique source
exactly once to the current `masterIdentities`. Run it after adding,
removing, or rotating a master so the new master set can decrypt your sources.

`edit` decrypts the source, opens it in `$EDITOR`, re-encrypts to the
masters, AND automatically reruns the rekey work graph so every consuming
host's output reflects the new plaintext in the same invocation. Unlike
agenix-rekey, you don't need a separate `rekey` step after editing.

The edit-then-rekey flow is two-phase: the source is written back first,
then host outputs are refreshed. If the source write succeeds but a host
rekey fails partway, the command exits non-zero and the next `rekey` run
converges (source's new fingerprint mismatches the manifest, so every
consuming host re-encrypts). Editing a source that's not yet in any host's
plan also works for bootstrap: the source is encrypted to the first host's
masters and no host outputs change.

`tombkey` enforces "same source = same master set" across plans: two hosts
that consume the same `rekey_file` must declare equivalent `masterIdentities`.
Silent unioning would widen who can decrypt the source on the next
`reseal`; tombkey rejects the plan upfront and tells you which hosts to
align.

## Workflows

**Edit a secret.** `nix run .#edit -- secrets/foo.age`. Source is rewritten
and every consuming host's output is refreshed in the same invocation.

**Add a new host.** Declare the host's `age.tombkey.*` config, rebuild,
then `nix run .#rekey`. The new host's outputs are produced; other hosts
are cache hits.

**Add or rotate a master.** Update `masterIdentities`, rebuild, then
`nix run .#reseal` (sources accept the new master) followed by
`nix run .#rekey` (host outputs are re-encrypted under the new master-set
fingerprint). Skipping `reseal` leaves sources encrypted to the old master
set, so any newly added master can't decrypt them.

**Remove a secret.** Drop the `age.secrets.<name>` declaration, rebuild,
then `nix run .#gc`. The manifest entry and orphan output file are pruned.

## Manifest

`.tombkey/manifest.json` at your flake root is a committed sidecar (like
`Cargo.lock` or `flake.lock`). Each host has its own section with a
`host_pubkey_sha256`, `master_set_sha256`, and per-secret `source_sha256` /
`output_file` / `output_sha256`. Diffing the manifest in a PR shows exactly
which secrets got rewritten. Steady-state runs that change nothing leave the
manifest's mtime untouched.

## Differences from agenix-rekey

- Cache key includes the master pubkey set, so adding or rotating a master
  invalidates the cache. Upstream agenix-rekey hashes only `host_pubkey` and
  the source, so a master-set change without a `reseal` was silent.
- Skip-decision lives in a single committed JSON manifest instead of an
  XDG-cache directory.
- Source-keyed work graph: a source consumed by N hosts decrypts once.
- `edit` propagates: editing a source automatically rekeys every consuming
  host's output. agenix-rekey makes you do that as a separate step.
- "Same source = same master set" is validated upfront, not silently
  unioned, so adding host A's masters never widens decrypt access to
  host B's secrets.
- Recipient extraction uses a regex robust to `#` and indent prefixes, so
  both `age-plugin-fido2-hmac`'s `# public key:` and `age-plugin-yubikey`'s
  `#    Recipient:` line shapes work.
- No `derivation` storage mode, no secret generators, no home-manager
  auto-discovery. Local storage only.

## License

`tombkey` is licensed under the MIT license.
