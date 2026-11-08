#![expect(
   unused_imports,
   reason = "pound 0.6.1 derives an unused `ViaFromStr` import per field"
)]

use std::path::PathBuf;

use pound::Parse;

/// Re-encrypt age secrets to per-host pubkeys, driven by a Nix-emitted plan.
#[derive(Debug, Parse)]
#[pound(name = "tombkey")]
pub struct Cli {
   /// Path to a JSON plan emitted by the Nix module. Repeatable; pass one
   /// `--plan` per host and tombkey processes them together. With no
   /// `--plan`, plans are discovered by evaluating each host of the flake
   /// at the repo root.
   #[pound(long = "plan", env = "TOMBKEY_PLAN", value_name = "PATH")]
   pub plans: Vec<PathBuf>,

   /// Concurrent `nix eval` subprocesses during plan discovery. Defaults
   /// to the available cores.
   #[pound(long, value_name = "N")]
   pub jobs: Option<usize>,

   /// Pass `--impure` to the discovery evaluations. Needed when a flake
   /// input resolves to an absolute path outside the store, which pure
   /// evaluation refuses to read.
   #[pound(long, env = "TOMBKEY_IMPURE", global)]
   pub impure: bool,

   /// Flake root that the plan's relative paths resolve against. If
   /// omitted, tombkey walks up from `$PWD` looking for `flake.nix`. Pass
   /// this explicitly (or set `TOMBKEY_REPO_ROOT`) when invoking outside
   /// a checkout.
   #[pound(long, env = "TOMBKEY_REPO_ROOT", value_name = "PATH")]
   pub repo_root: Option<PathBuf>,

   /// Override the manifest path. Defaults to the plan's `manifest_file`
   /// resolved against `--repo-root`.
   #[pound(long, value_name = "PATH")]
   pub manifest: Option<PathBuf>,

   #[pound(subcommand)]
   pub command: Command,
}

#[derive(Debug, Parse)]
pub enum Command {
   /// Re-encrypt source secrets to the per-host pubkey.
   Rekey,

   /// Reseal every source secret to the current master set, writing back in
   /// place. Skips sources whose ciphertext and master set haven't changed
   /// since the last reseal.
   Reseal {
      /// Reseal every source unconditionally, ignoring the manifest cache.
      #[pound(long, short)]
      force: bool,
   },

   /// Open a secret in `$EDITOR`, re-encrypt to masters on save.
   Edit {
      /// Path to the source `.age` file. Relative paths resolve against
      /// the repo root (`--repo-root`), not the current directory.
      secret: PathBuf,
   },

   /// Decrypt a secret to stdout.
   View {
      /// Path to the source `.age` file. Relative paths resolve against
      /// the repo root (`--repo-root`), not the current directory.
      secret: PathBuf,
   },

   /// Prune manifest entries and orphan output files no longer
   /// referenced by the plan.
   Gc,
}
