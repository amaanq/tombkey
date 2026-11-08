use std::{
   collections::HashSet,
   fs,
   path::{
      Path,
      PathBuf,
   },
};

use crate::{
   error::{
      Error,
      Result,
   },
   plan::Plan,
};

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
   let entries = fs::read_dir(dir).map_err(|cause| {
      Error::File {
         action: "read local_storage_dir",
         path: dir.to_path_buf(),
         cause,
      }
   })?;
   let mut removed = 0;
   for entry_result in entries {
      let entry = entry_result.map_err(|cause| {
         Error::File {
            action: "read entry of",
            path: dir.to_path_buf(),
            cause,
         }
      })?;
      let path = entry.path();
      let file_type = entry.file_type().map_err(|cause| {
         Error::File {
            action: "read file type of",
            path: path.clone(),
            cause,
         }
      })?;
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
      fs::remove_file(&path).map_err(|cause| {
         Error::File {
            action: "remove orphan",
            path: path.clone(),
            cause,
         }
      })?;
      removed += 1;
   }
   Ok(removed)
}
