//! Edit a source secret and propagate it to host outputs.

use std::path::Path;

use tracing::info;

use crate::{
   age::encrypt,
   editor::{
      EditOutcome,
      LoadedSecret,
   },
   error::{
      Error,
      Result,
   },
   fs::write_atomic,
   ops,
   plan::Plan,
};

pub fn run(
   plans: &[Plan],
   repo_root: &Path,
   manifest_path: &Path,
   secret_path: &Path,
) -> Result<()> {
   let (canonical, source_abs, plugin_guard, plaintext) =
      ops::load_canonical_plaintext(plans, repo_root, secret_path, true)?;

   let basename = source_abs.file_name().map_or_else(
      || "secret".into(),
      |name| name.to_string_lossy().into_owned(),
   );
   let mut secret = LoadedSecret::stage(plaintext, &basename)?;
   match secret.edit_in_editor()? {
      EditOutcome::Unchanged => {
         info!(path = %source_abs.display(), "no changes, leaving file untouched");
         return Ok(());
      },
      EditOutcome::Modified => {},
   }

   let master_pubkeys = canonical
      .master_identities
      .iter()
      .map(|master| master.pubkey.as_str())
      .collect::<Vec<_>>();
   let ciphertext = encrypt::encrypt(secret.bytes(), &master_pubkeys)?;
   write_atomic(&source_abs, &ciphertext)
      .map_err(|err| Error::Encrypt(format!("write {}: {err}", source_abs.display())))?;
   info!(path = %source_abs.display(), "source saved");

   // Reinstall the full plugin union inside rekey.
   drop(plugin_guard);

   let failures = ops::rekey::run(plans, repo_root, manifest_path)?;
   if failures > 0 {
      return Err(Error::Aggregated(failures));
   }
   Ok(())
}
