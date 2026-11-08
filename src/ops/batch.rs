use std::{
   collections::BTreeSet,
   iter,
   path::{
      Path,
      PathBuf,
   },
};

use age_core::format::FileKey;
use tracing::warn;

use crate::{
   age::batch_unwrap,
   error::Chain,
   plan::Plan,
};

/// A ciphertext and its candidate identity files for the batch decrypt.
pub struct BatchDecryptInput<'a> {
   pub ciphertext:     &'a [u8],
   pub identity_paths: Vec<&'a Path>,
}

/// Batch unwrap, or all-`None` so callers fall back to per-file decrypt.
pub fn batch_unwrap_file_keys(
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
      warn!(error = %Chain(&err), "batch unwrap failed; falling back to per-source decrypt");
      empty_file_keys(inputs.len())
   })
}

fn empty_file_keys(count: usize) -> Vec<Option<FileKey>> {
   iter::repeat_with(|| None).take(count).collect()
}
