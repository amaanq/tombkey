//! Reseal source secrets to the current master set.

use std::{
   collections::{
      BTreeMap,
      BTreeSet,
   },
   fs,
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
      decrypt,
      encrypt,
   },
   error::{
      Error,
      Result,
   },
   fs::write_atomic,
   manifest::{
      Manifest,
      SourceSealState,
      master_set_sha256_hex,
      sha256_hex,
   },
   ops,
   plan::Plan,
};

pub fn run(plans: &[Plan], repo_root: &Path, manifest_path: &Path, force: bool) -> Result<usize> {
   ops::validate_source_master_consistency(plans)?;
   let _plugin_guard = ops::install_plugin_paths(plans);

   let mut sources = BTreeMap::<PathBuf, SourceTargets<'_>>::new();
   for plan in plans {
      for secret in &plan.secrets {
         let entry = sources.entry(secret.rekey_file.clone()).or_default();
         for master in &plan.master_identities {
            entry.master_pubkeys.insert(master.pubkey.as_str());
            entry.identity_paths.insert(master.identity.as_path());
         }
      }
   }

   let mut manifest = Manifest::load(manifest_path)?;
   let manifest_initial = manifest.clone();

   // Read failures are per-source failures.
   let mut failures = 0_usize;
   let mut prepared = Vec::<(PathBuf, &SourceTargets<'_>, Vec<u8>, String)>::new();
   for (rel_path, targets) in &sources {
      let abs_path = repo_root.join(rel_path);
      let ciphertext = match fs::read(&abs_path) {
         Ok(bytes) => bytes,
         Err(err) => {
            warn!(source = %abs_path.display(), error = %err, "reseal failed");
            failures += 1;
            continue;
         },
      };
      let master_set_sha = master_set_sha256_hex(targets.master_pubkeys.iter().copied());

      // Skip when both the on-disk ciphertext and the master set match the last
      // recorded reseal — a freshly-resealed source is wasted work otherwise.
      if !force
         && let Some(prev) = manifest.sources.get(rel_path)
         && prev.ciphertext_sha256 == sha256_hex(&ciphertext)
         && prev.master_set_sha256 == master_set_sha
      {
         continue;
      }

      prepared.push((rel_path.clone(), targets, ciphertext, master_set_sha));
   }

   // One plugin session for the batch; `None` falls back per source.
   let inputs = prepared
      .iter()
      .map(|entry| {
         ops::BatchDecryptInput {
            ciphertext:     entry.2.as_slice(),
            identity_paths: entry.1.identity_paths.iter().copied().collect(),
         }
      })
      .collect::<Vec<_>>();
   let file_keys = ops::batch_unwrap_file_keys(plans, &inputs);

   for ((rel_path, targets, ciphertext, master_set_sha), file_key) in
      prepared.into_iter().zip(file_keys)
   {
      let abs_path = repo_root.join(&rel_path);
      match reseal_source(&abs_path, targets, &ciphertext, file_key) {
         Ok(updated_bytes) => {
            info!(source = %abs_path.display(), "resealed");
            manifest.sources.insert(rel_path, SourceSealState {
               ciphertext_sha256: sha256_hex(&updated_bytes),
               master_set_sha256: master_set_sha,
            });
         },
         Err(err) => {
            warn!(source = %abs_path.display(), error = %err, "reseal failed");
            failures += 1;
         },
      }
   }

   if manifest != manifest_initial {
      manifest.write_atomic(manifest_path)?;
   }
   Ok(failures)
}

#[derive(Default)]
struct SourceTargets<'a> {
   master_pubkeys: BTreeSet<&'a str>,
   identity_paths: BTreeSet<&'a Path>,
}

/// Decrypt one source (batched file key, else the per-source path for
/// non-fido2-hmac masters), re-encrypt to its masters, write atomically.
///
/// Returns the bytes written so the caller can hash them for the manifest.
fn reseal_source(
   source_path: &Path,
   targets: &SourceTargets<'_>,
   ciphertext: &[u8],
   file_key: Option<FileKey>,
) -> Result<Vec<u8>> {
   let plaintext = if let Some(key) = file_key {
      decrypt::decrypt_with_file_key(ciphertext, key)
   } else {
      let identities = decrypt::identities_from_files(targets.identity_paths.iter().copied())?;
      decrypt::decrypt(ciphertext, &identities)
   }
   .map_err(|message| {
      Error::Decrypt {
         path: source_path.to_path_buf(),
         message,
      }
   })?;
   let master_pubkeys = targets.master_pubkeys.iter().copied().collect::<Vec<_>>();
   let updated = encrypt::encrypt(&plaintext, &master_pubkeys)?;
   write_atomic(source_path, &updated)
      .map_err(|err| Error::Encrypt(format!("write {}: {err}", source_path.display())))?;
   Ok(updated)
}
