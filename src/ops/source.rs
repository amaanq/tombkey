use std::{
   collections::{
      BTreeMap,
      BTreeSet,
   },
   fs,
   io,
   path::{
      Path,
      PathBuf,
   },
};

use tracing::info;

use crate::{
   age::{
      decrypt,
      plugin::PluginPath,
   },
   error::{
      Error,
      Result,
   },
   plan::Plan,
};

/// Enforce the "same source = same master set" invariant. Silent unioning
/// would widen who can decrypt the source on the next `reseal`.
pub fn validate_source_master_consistency(plans: &[Plan]) -> Result<()> {
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
#[must_use = "dropping the guard restores the previous $PATH"]
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

#[must_use = "the lookup has no effect"]
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
      Err(cause) => {
         return Err(Error::File {
            action: "read source",
            path: source_abs,
            cause,
         });
      },
   };
   let identities = decrypt::identities_from_files(
      canonical
         .master_identities
         .iter()
         .map(|master| &master.identity),
   )?;
   let plaintext = decrypt::decrypt(&source, &identities).map_err(|cause| {
      Error::Decrypt {
         path: source_abs.clone(),
         cause,
      }
   })?;
   Ok((canonical, source_abs, guard, plaintext))
}
