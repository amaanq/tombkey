use std::path::PathBuf;

use clap::{
   Parser,
   Subcommand,
};

#[derive(Debug, Parser)]
#[command(
   name = "tombkey",
   version,
   about = "Re-encrypt age secrets to per-host pubkeys, driven by a Nix-emitted plan"
)]
pub struct Cli {
   /// Path to a JSON plan emitted by the Nix module. Repeatable; pass one
   /// `--plan` per host and tombkey processes them together.
   #[arg(long = "plan", env = "TOMBKEY_PLAN", value_name = "PATH")]
   pub plans: Vec<PathBuf>,

   /// Flake root that the plan's relative paths resolve against. If
   /// omitted, tombkey walks up from `$PWD` looking for `flake.nix`. Pass
   /// this explicitly (or set `TOMBKEY_REPO_ROOT`) when invoking outside
   /// a checkout.
   #[arg(long = "repo-root", env = "TOMBKEY_REPO_ROOT", value_name = "PATH")]
   pub repo_root: Option<PathBuf>,

   /// Override the manifest path. Defaults to the plan's `manifest_file`
   /// resolved against `--repo-root`.
   #[arg(long, value_name = "PATH")]
   pub manifest: Option<PathBuf>,

   #[command(subcommand)]
   pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
   /// Re-encrypt source secrets to the per-host pubkey.
   Rekey,

   /// Reseal every source secret to the current master set, writing back in
   /// place. Skips sources whose ciphertext and master set haven't changed
   /// since the last reseal.
   Reseal {
      /// Reseal every source unconditionally, ignoring the manifest cache.
      #[arg(long, short)]
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
