use std::{
   collections::{
      BTreeSet,
      HashSet,
   },
   fs,
   io,
   iter,
   path::{
      Path,
      PathBuf,
   },
};

use age_core::format::FileKey;
use tracing::{
   info,
   warn,
};

use crate::{
   age::{
      batch_unwrap,
      decrypt,
      plugin::PluginPath,
   },
   error::{
      Error,
      Result,
   },
   plan::Plan,
};

pub mod edit;
pub mod gc;
pub mod rekey;
pub mod reseal;
pub mod view;

/// A ciphertext and its candidate identity files for the batch decrypt.
struct BatchDecryptInput<'a> {
   ciphertext:     &'a [u8],
   identity_paths: Vec<&'a Path>,
}

/// Batch unwrap, or all-`None` so callers fall back to per-file decrypt.
fn batch_unwrap_file_keys(
   plans: &[Plan],
   inputs: &[BatchDecryptInput<'_>],
) -> Vec<Option<FileKey>> {
   if inputs.is_empty() {
      return Vec::new();
   }

   let plugin_dirs = plans
      .iter()
      .flat_map(|plan| plan.age_plugins.iter().cloned())
      .collect::<Vec<PathBuf>>();
   let Some(binary) = batch_unwrap::find_plugin_binary(&plugin_dirs) else {
      return empty_file_keys(inputs.len());
   };

   let identity_files = inputs
      .iter()
      .flat_map(|input| input.identity_paths.iter().copied())
      .collect::<BTreeSet<&Path>>()
      .into_iter()
      .collect::<Vec<&Path>>();
   let ciphertexts = inputs
      .iter()
      .map(|input| input.ciphertext)
      .collect::<Vec<&[u8]>>();

   batch_unwrap::unwrap_file_keys(&ciphertexts, &identity_files, &binary).unwrap_or_else(|err| {
      warn!(error = %err, "batch unwrap failed; falling back to per-source decrypt");
      empty_file_keys(inputs.len())
   })
}

fn empty_file_keys(count: usize) -> Vec<Option<FileKey>> {
   iter::repeat_with(|| None).take(count).collect()
}

/// Remove `*.age` files in `plan.local_storage_dir` that aren't plan outputs.
pub fn sweep_orphans(plan: &Plan, repo_root: &Path) -> Result<usize> {
   let dir = repo_root.join(&plan.local_storage_dir);
   if !dir.is_dir() {
      return Ok(0);
   }
   let owned = plan
      .secrets
      .iter()
      .map(|secret| repo_root.join(&secret.output_file))
      .collect::<HashSet<PathBuf>>();

   let removed = sweep_orphans_in(&dir, &owned)?;

   Ok(removed)
}

fn sweep_orphans_in(dir: &Path, owned: &HashSet<PathBuf>) -> Result<usize> {
   let entries = fs::read_dir(dir)
      .map_err(|err| Error::Storage(format!("read local_storage_dir {}: {err}", dir.display())))?;
   let mut removed = 0;
   for entry_result in entries {
      let entry = entry_result.map_err(|err| Error::Storage(format!("read_dir entry: {err}")))?;
      let path = entry.path();
      let file_type = entry
         .file_type()
         .map_err(|err| Error::Storage(format!("file type {}: {err}", path.display())))?;
      if file_type.is_dir() {
         removed += sweep_orphans_in(&path, owned)?;
         continue;
      }
      if !path.is_file()
         || path.extension().and_then(|ext| ext.to_str()) != Some("age")
         || owned.contains(&path)
      {
         continue;
      }
      fs::remove_file(&path)
         .map_err(|err| Error::Storage(format!("remove orphan {}: {err}", path.display())))?;
      removed += 1;
   }
   Ok(removed)
}

/// Enforce the "same source = same master set" invariant. Silent unioning
/// would widen who can decrypt the source on the next `reseal`.
pub fn validate_source_master_consistency(plans: &[Plan]) -> Result<()> {
   use std::collections::BTreeMap;

   struct Anchor<'a> {
      host_label: &'a str,
      pubkeys:    BTreeSet<&'a str>,
   }

   let mut anchored = BTreeMap::<&Path, Anchor<'_>>::new();
   for plan in plans {
      let pubkeys = plan
         .master_identities
         .iter()
         .map(|master| master.pubkey.as_str())
         .collect::<BTreeSet<_>>();
      for secret in &plan.secrets {
         match anchored.get(secret.rekey_file.as_path()) {
            None => {
               anchored.insert(secret.rekey_file.as_path(), Anchor {
                  host_label: plan.host_label.as_str(),
                  pubkeys:    pubkeys.clone(),
               });
            },
            Some(prev) => {
               if prev.pubkeys != pubkeys {
                  return Err(Error::InvalidPlan(format!(
                     "source {} is consumed by hosts {:?} and {:?} with different master sets; \
                      align their masterIdentities or split the source into per-host copies",
                     secret.rekey_file.display(),
                     prev.host_label,
                     plan.host_label,
                  )));
               }
            },
         }
      }
   }
   Ok(())
}

/// Install every plan's `age_plugins` directories onto `$PATH`, deduped, and
/// return a guard that restores the previous `$PATH` on drop.
#[must_use]
pub fn install_plugin_paths(plans: &[Plan]) -> PluginPath {
   let plugin_dirs = plans
      .iter()
      .flat_map(|plan| plan.age_plugins.iter().map(PathBuf::as_path))
      .collect::<BTreeSet<&Path>>()
      .into_iter()
      .collect::<Vec<_>>();
   PluginPath::install(&plugin_dirs)
}

/// Normalize a user-provided secret path for plan lookup.
pub fn normalize_secret_path(repo_root: &Path, secret_path: &Path) -> Result<PathBuf> {
   let canonical_root = fs::canonicalize(repo_root).unwrap_or_else(|_| repo_root.to_path_buf());
   let absolute = if secret_path.is_absolute() {
      secret_path.to_path_buf()
   } else {
      canonical_root.join(secret_path)
   };
   let canonical = fs::canonicalize(&absolute).unwrap_or(absolute);
   canonical
      .strip_prefix(&canonical_root)
      .map(Path::to_path_buf)
      .map_err(|_| {
         Error::InvalidPlan(format!(
            "secret path {} is not under repo root {}",
            secret_path.display(),
            repo_root.display(),
         ))
      })
}

#[must_use]
pub fn plan_consuming<'a>(plans: &'a [Plan], rekey_file_rel: &Path) -> Option<&'a Plan> {
   plans.iter().find(|plan| {
      plan
         .secrets
         .iter()
         .any(|secret| secret.rekey_file == rekey_file_rel)
   })
}

/// Shared preamble for `edit` / `view`. When `create_if_missing` is true and
/// the source file does not exist, returns empty plaintext so the caller can
/// treat the absence as an "uninitialized secret".
pub fn load_canonical_plaintext<'a>(
   plans: &'a [Plan],
   repo_root: &Path,
   secret_path: &Path,
   create_if_missing: bool,
) -> Result<(&'a Plan, PathBuf, PluginPath, Vec<u8>)> {
   validate_source_master_consistency(plans)?;

   let rekey_file_rel = normalize_secret_path(repo_root, secret_path)?;
   let source_abs = repo_root.join(&rekey_file_rel);

   let canonical = plan_consuming(plans, &rekey_file_rel).unwrap_or_else(|| {
      info!(
         path = %rekey_file_rel.display(),
         host = plans[0].host_label.as_str(),
         "source not referenced by any host; using first host's masters as canonical",
      );
      &plans[0]
   });
   let guard = PluginPath::install(&canonical.age_plugins);

   let source = match fs::read(&source_abs) {
      Ok(bytes) => bytes,
      Err(err) if err.kind() == io::ErrorKind::NotFound && create_if_missing => {
         info!(path = %source_abs.display(), "source not present; staging new secret");
         return Ok((canonical, source_abs, guard, Vec::new()));
      },
      Err(err) => {
         return Err(Error::Decrypt {
            path:    source_abs,
            message: format!("read source: {err}"),
         });
      },
   };
   let identities = decrypt::identities_from_files(
      canonical
         .master_identities
         .iter()
         .map(|master| &master.identity),
   )?;
   let plaintext = decrypt::decrypt(&source, &identities).map_err(|message| {
      Error::Decrypt {
         path: source_abs.clone(),
         message,
      }
   })?;
   Ok((canonical, source_abs, guard, plaintext))
}
