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
   process::{
      Command,
      Stdio,
   },
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

/// Disabled hosts evaluate to `null`. A dynamic derivation's `drvPath` is a
/// placeholder, so it builds through the derivation producing its `.drv`.
const HOST_APPLY: &str = "cfg: let tk = cfg.config.age.tombkey; \
                          installable = pkg: let drv = pkg.drvPath; \
                          out = pkg.outputName or \"out\"; ctx = builtins.getContext drv; \
                          producer = builtins.head (builtins.attrNames ctx); in \
                          if builtins.dirOf drv == builtins.storeDir \
                          then \"${builtins.unsafeDiscardStringContext drv}^${out}\" \
                          else \"${producer}^${builtins.head ctx.${producer}.outputs}^${out}\"; \
                          in if tk.enable or false then { \
                          plan = tk.planData; system = cfg.pkgs.stdenv.hostPlatform.system; \
                          plugins = map installable tk.agePlugins; } else null";

#[derive(Deserialize)]
struct HostEval {
   plan:    serde_json::Value,
   system:  String,
   plugins: Vec<String>,
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
   let plugin_dirs = realise(&plugin_union(&evals))?;
   for eval in evals {
      let mut plan = Plan::from_value(eval.plan)?;
      plan.age_plugins.clone_from(&plugin_dirs);
      plans.push(plan);
   }
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
      let target = format!("{flake}#{attr}");
      let output = command.output().map_err(|cause| {
         Error::Spawn {
            program: "nix eval".to_owned(),
            cause,
         }
      })?;
      if !output.status.success() {
         let stderr = String::from_utf8_lossy(&output.stderr);
         if stderr.contains("does not provide attribute") {
            continue;
         }
         return Err(Error::NixEval {
            target,
            stderr: tail(&stderr),
         });
      }
      let names: Vec<String> = serde_json::from_slice(&output.stdout)
         .map_err(|cause| Error::ParseEval { target, cause })?;
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
   let target = format!("{flake}#{attr}.{host}");
   let output = command.output().map_err(|cause| {
      Error::Spawn {
         program: "nix eval".to_owned(),
         cause,
      }
   })?;
   if !output.status.success() {
      return Err(Error::NixEval {
         target,
         stderr: tail(&String::from_utf8_lossy(&output.stderr)),
      });
   }
   serde_json::from_slice(&output.stdout).map_err(|cause| Error::ParseEval { target, cause })
}

/// Plugins run on this machine, so every plan gets the local system's union of
/// plugin dirs.
fn plugin_union(evals: &[HostEval]) -> BTreeSet<String> {
   let system = current_system();
   let plugins = evals
      .iter()
      .filter(|eval| eval.system == system)
      .flat_map(|eval| eval.plugins.iter().cloned())
      .collect::<BTreeSet<String>>();
   if plugins.is_empty() {
      warn!("no {system} host contributes age plugins; plugin recipients may fail");
   }
   plugins
}

fn current_system() -> String {
   let os = if consts::OS == "macos" {
      "darwin"
   } else {
      consts::OS
   };
   format!("{}-{os}", consts::ARCH)
}

/// Substitutes missing plugins, or builds them when no cache has them.
fn realise(installables: &BTreeSet<String>) -> Result<Vec<PathBuf>> {
   if installables.is_empty() {
      return Ok(Vec::new());
   }
   let output = Command::new("nix")
      .args(["build", "--no-link", "--print-out-paths"])
      .args(installables)
      .stderr(Stdio::inherit())
      .output()
      .map_err(|cause| {
         Error::Spawn {
            program: "nix build".to_owned(),
            cause,
         }
      })?;
   if !output.status.success() {
      return Err(Error::Discover(format!(
         "failed to realise age plugins: {}",
         installables.iter().cloned().collect::<Vec<_>>().join(", ")
      )));
   }
   Ok(String::from_utf8_lossy(&output.stdout)
      .lines()
      .map(|out| Path::new(out).join("bin"))
      .collect())
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

   fn eval(system: &str, installables: &[&str]) -> HostEval {
      HostEval {
         plan:    serde_json::Value::Null,
         system:  system.into(),
         plugins: installables.iter().map(|&installable| installable.into()).collect(),
      }
   }

   #[test]
   fn plugin_union_filters_by_local_system() {
      let system = current_system();
      let evals = [
         eval(&system, &["/nix/store/a.drv^out", "/nix/store/b.drv^out"]),
         eval(&system, &["/nix/store/b.drv^out", "/nix/store/c.drv.drv^out^out"]),
         eval("other-system", &["/nix/store/foreign.drv^out"]),
      ];
      let expected: BTreeSet<String> = [
         "/nix/store/a.drv^out",
         "/nix/store/b.drv^out",
         "/nix/store/c.drv.drv^out^out",
      ]
      .iter()
      .map(|&installable| installable.into())
      .collect();
      assert_eq!(plugin_union(&evals), expected);
   }

   #[test]
   fn current_system_is_a_nix_double() {
      let system = current_system();
      let (arch, os) = system.split_once('-').unwrap();
      assert_ne!(arch, "");
      assert!(matches!(os, "linux" | "darwin"));
   }
}
