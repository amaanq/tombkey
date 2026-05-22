use std::{
   env,
   fs,
   io,
   path::{
      Path,
      PathBuf,
   },
   process,
};

use clap::Parser as _;
use tombkey::{
   cli::{
      Cli,
      Command,
   },
   error::{
      Error,
      Result,
   },
   ops,
   plan::Plan,
};
use tracing::error;
use tracing_subscriber::EnvFilter;

fn main() {
   init_tracing();
   let cli = Cli::parse();
   match dispatch(&cli) {
      Ok(exit_code) => process::exit(exit_code),
      Err(err) => {
         error!(error = %err, "tombkey failed");
         process::exit(1);
      },
   }
}

fn init_tracing() {
   let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
   tracing_subscriber::fmt()
      .with_env_filter(filter)
      .with_target(false)
      .with_writer(io::stderr)
      .init();
}

fn dispatch(cli: &Cli) -> Result<i32> {
   if cli.plans.is_empty() {
      return Err(Error::InvalidPlan(
         "at least one --plan is required (TOMBKEY_PLAN also accepts one)".into(),
      ));
   }
   let plans = cli
      .plans
      .iter()
      .map(|path| load_plan(path))
      .collect::<Result<Vec<_>>>()?;
   Plan::validate_set(&plans)?;

   let repo_root = resolve_repo_root(cli.repo_root.as_deref())?;
   let manifest_path = manifest_path(cli.manifest.as_deref(), &plans[0], &repo_root);

   match cli.command {
      Command::Rekey => exit_code_from(ops::rekey::run(&plans, &repo_root, &manifest_path)?),
      Command::Reseal { force } => {
         exit_code_from(ops::reseal::run(&plans, &repo_root, &manifest_path, force)?)
      },
      Command::Gc => {
         ops::gc::run(&plans, &repo_root, &manifest_path)?;
         Ok(0)
      },
      Command::Edit { ref secret } => {
         ops::edit::run(&plans, &repo_root, &manifest_path, secret)?;
         Ok(0)
      },
      Command::View { ref secret } => {
         ops::view::run(&plans, &repo_root, secret)?;
         Ok(0)
      },
   }
}

fn load_plan(path: &Path) -> Result<Plan> {
   let bytes = fs::read(path)
      .map_err(|err| Error::InvalidPlan(format!("read {}: {err}", path.display())))?;
   Plan::from_json(&bytes)
}

/// Resolve the flake root.
///
/// Lookup order:
///
/// 1. `--repo-root <path>`
/// 2. `$TOMBKEY_REPO_ROOT`
/// 3. Walk up from `$PWD` until a `flake.nix` shows up.
fn resolve_repo_root(override_path: Option<&Path>) -> Result<PathBuf> {
   if let Some(path) = override_path {
      let canonical = fs::canonicalize(path).map_err(|err| {
         Error::Storage(format!(
            "canonicalize --repo-root {}: {err}",
            path.display()
         ))
      })?;
      return Ok(canonical);
   }
   let start = env::current_dir().map_err(|err| Error::Storage(format!("current_dir: {err}")))?;
   let mut cursor = start.clone();
   loop {
      if cursor.join("flake.nix").is_file() {
         return Ok(cursor);
      }
      if !cursor.pop() {
         return Err(Error::InvalidPlan(format!(
            "no flake.nix in any parent of {}: run tombkey from inside your flake checkout, or \
             pass --repo-root <path> (or set TOMBKEY_REPO_ROOT)",
            start.display(),
         )));
      }
   }
}

fn manifest_path(override_path: Option<&Path>, plan: &Plan, repo_root: &Path) -> PathBuf {
   override_path.map_or_else(|| repo_root.join(&plan.manifest_file), Path::to_path_buf)
}

const fn exit_code_from(failures: usize) -> Result<i32> {
   if failures == 0 {
      Ok(0)
   } else {
      Err(Error::Aggregated(failures))
   }
}
