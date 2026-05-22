//! Discover plans at runtime with one parallel `nix eval` per host instead of
//! baking them into the app.

use std::{
   collections::BTreeSet,
   env::{
      self,
      consts,
   },
   path::{
      Path,
      PathBuf,
   },
   process::Command,
   sync::{
      Arc,
      Mutex,
      PoisonError,
      mpsc,
   },
   thread,
};

use serde::Deserialize;
use tracing::{
   info,
   warn,
};

use crate::{
   error::{
      Error,
      Result,
   },
   plan::Plan,
};

const CONFIG_ATTRS: [&str; 2] = ["nixosConfigurations", "darwinConfigurations"];

/// Disabled hosts evaluate to `null` rather than an error.
const HOST_APPLY: &str = "cfg: if cfg.config.age.tombkey.enable or false then { plan = \
                          cfg.config.age.tombkey.planData; system = \
                          cfg.pkgs.stdenv.hostPlatform.system; } else null";

#[derive(Deserialize)]
struct HostEval {
   plan:   serde_json::Value,
   system: String,
}

pub fn discover(repo_root: &Path, jobs: Option<usize>, impure: bool) -> Result<Vec<Plan>> {
   let flake = repo_root.to_string_lossy().into_owned();
   let hosts = enumerate_hosts(&flake, impure)?;
   if hosts.is_empty() {
      return Err(Error::Discover(format!(
         "flake {flake} has no nixosConfigurations or darwinConfigurations"
      )));
   }

   let worker_count = jobs
      .filter(|&n| n > 0)
      .unwrap_or_else(|| thread::available_parallelism().map_or(4, usize::from))
      .min(hosts.len());
   info!(
      "evaluating {} host plans ({worker_count} in parallel)",
      hosts.len()
   );

   let queue = Arc::new(Mutex::new(hosts));
   let (tx, rx) = mpsc::channel();
   let mut workers = Vec::new();
   for _ in 0..worker_count {
      let worker_queue = Arc::clone(&queue);
      let worker_tx = tx.clone();
      let worker_flake = flake.clone();
      workers.push(thread::spawn(move || {
         loop {
            let entry = worker_queue
               .lock()
               .unwrap_or_else(PoisonError::into_inner)
               .pop();
            let Some((attr, host)) = entry else {
               break;
            };
            let result = eval_host(&worker_flake, &attr, &host, impure);
            if worker_tx.send((host, result)).is_err() {
               break;
            }
         }
      }));
   }
   drop(tx);

   let mut evals = Vec::new();
   for (host, result) in rx {
      if let Some(eval) = result? {
         info!("plan for {host}");
         evals.push(eval);
      } else {
         info!("skipping {host} (tombkey disabled)");
      }
   }
   for worker in workers {
      worker
         .join()
         .map_err(|_| Error::Discover("eval worker panicked".into()))?;
   }

   if evals.is_empty() {
      return Err(Error::Discover(
         "no host has age.tombkey.enable = true".into(),
      ));
   }

   let mut plans = Vec::with_capacity(evals.len());
   let plugin_dirs = plugin_union(&evals);
   for eval in evals {
      let bytes = serde_json::to_vec(&eval.plan)?;
      let mut plan = Plan::from_json(&bytes)?;
      plan.age_plugins = plugin_dirs.iter().cloned().collect();
      plans.push(plan);
   }
   realise_missing(&plugin_dirs)?;
   Ok(plans)
}

fn enumerate_hosts(flake: &str, impure: bool) -> Result<Vec<(String, String)>> {
   let mut hosts = Vec::new();
   for attr in CONFIG_ATTRS {
      let mut command = Command::new("nix");
      command.args([
         "eval",
         "--json",
         &format!("{flake}#{attr}"),
         "--apply",
         "builtins.attrNames",
      ]);
      if impure {
         command.arg("--impure");
      }
      let output = command
         .output()
         .map_err(|err| Error::Discover(format!("spawn nix eval: {err}")))?;
      if !output.status.success() {
         let stderr = String::from_utf8_lossy(&output.stderr);
         if stderr.contains("does not provide attribute") {
            continue;
         }
         return Err(Error::Discover(format!(
            "nix eval {flake}#{attr} failed:\n{}",
            tail(&stderr)
         )));
      }
      let names: Vec<String> = serde_json::from_slice(&output.stdout)?;
      hosts.extend(names.into_iter().map(|name| (attr.to_owned(), name)));
   }
   Ok(hosts)
}

fn eval_host(flake: &str, attr: &str, host: &str, impure: bool) -> Result<Option<HostEval>> {
   let mut command = Command::new("nix");
   command.args([
      "eval",
      "--json",
      &format!("{flake}#{attr}.{host}"),
      "--apply",
      HOST_APPLY,
   ]);
   if impure {
      command.arg("--impure");
   }
   // Shaves the evaluator's GC growth phase. Callers can still override it.
   if env::var_os("GC_INITIAL_HEAP_SIZE").is_none() {
      command.env("GC_INITIAL_HEAP_SIZE", "2G");
   }
   let output = command
      .output()
      .map_err(|err| Error::Discover(format!("spawn nix eval: {err}")))?;
   if !output.status.success() {
      return Err(Error::Discover(format!(
         "nix eval of {host} failed:\n{}",
         tail(&String::from_utf8_lossy(&output.stderr))
      )));
   }
   Ok(serde_json::from_slice(&output.stdout)?)
}

/// Plugins run on this machine, so every plan gets the local system's union of
/// plugin dirs.
fn plugin_union(evals: &[HostEval]) -> BTreeSet<PathBuf> {
   let system = current_system();
   let dirs: BTreeSet<PathBuf> = evals
      .iter()
      .filter(|eval| eval.system == system)
      .filter_map(|eval| eval.plan.get("age_plugins"))
      .filter_map(|dirs| dirs.as_array())
      .flatten()
      .filter_map(|dir| dir.as_str())
      .map(PathBuf::from)
      .collect();
   if dirs.is_empty() {
      warn!("no {system} host contributes age plugin dirs; plugin recipients may fail");
   }
   dirs
}

fn current_system() -> String {
   let os = if consts::OS == "macos" {
      "darwin"
   } else {
      consts::OS
   };
   format!("{}-{os}", consts::ARCH)
}

/// `nix eval` hands back plugin paths as bare strings, so substitute any that
/// aren't in the store.
fn realise_missing(dirs: &BTreeSet<PathBuf>) -> Result<()> {
   let missing: Vec<&Path> = dirs
      .iter()
      .map(PathBuf::as_path)
      .filter(|dir| !dir.exists())
      .collect();
   if missing.is_empty() {
      return Ok(());
   }
   let status = Command::new("nix-store")
      .arg("--realise")
      .args(&missing)
      .status()
      .map_err(|err| Error::Discover(format!("spawn nix-store: {err}")))?;
   if !status.success() {
      return Err(Error::Discover(format!(
         "age plugin dirs are not in the store and could not be substituted: {}; build or switch \
          to the current configuration first",
         missing
            .iter()
            .map(|dir| dir.display().to_string())
            .collect::<Vec<_>>()
            .join(", "),
      )));
   }
   Ok(())
}

fn tail(text: &str) -> String {
   let trimmed = text.trim_end();
   trimmed.char_indices().nth_back(2000).map_or_else(
      || trimmed.to_owned(),
      |(idx, _)| format!("…{}", trimmed.get(idx..).unwrap_or(trimmed)),
   )
}

#[cfg(test)]
mod tests {
   use super::*;

   fn eval(system: &str, plugins: &[&str]) -> HostEval {
      HostEval {
         plan:   serde_json::json!({ "age_plugins": plugins }),
         system: system.into(),
      }
   }

   #[test]
   fn plugin_union_filters_by_local_system() {
      let system = current_system();
      let evals = [
         eval(&system, &["/nix/store/a", "/nix/store/b"]),
         eval(&system, &["/nix/store/b", "/nix/store/c"]),
         eval("other-system", &["/nix/store/foreign"]),
      ];
      let dirs = plugin_union(&evals);
      let expected: BTreeSet<PathBuf> = ["/nix/store/a", "/nix/store/b", "/nix/store/c"]
         .iter()
         .map(PathBuf::from)
         .collect();
      assert_eq!(dirs, expected);
   }

   #[test]
   fn current_system_is_a_nix_double() {
      let system = current_system();
      let (arch, os) = system.split_once('-').unwrap();
      assert!(!arch.is_empty());
      assert!(matches!(os, "linux" | "darwin"));
   }
}
