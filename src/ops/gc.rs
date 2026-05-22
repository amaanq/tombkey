//! Prune manifest entries and orphan `*.age` outputs to match the plans.
//! Other hosts' sections are authoritative on their own state and pass
//! through untouched.

use std::{
   collections::{
      BTreeMap,
      HashSet,
   },
   mem,
   path::Path,
};

use tracing::info;

use crate::{
   error::Result,
   manifest::Manifest,
   ops,
   plan::Plan,
};

pub fn run(plans: &[Plan], repo_root: &Path, manifest_path: &Path) -> Result<usize> {
   let mut manifest = Manifest::load(manifest_path)?;
   let manifest_initial = manifest.clone();

   let mut removed_manifest = 0;
   for plan in plans {
      let live_names = plan
         .secrets
         .iter()
         .map(|secret| secret.name.as_str())
         .collect::<HashSet<&str>>();
      if let Some(host_section) = manifest.hosts.get_mut(&plan.host_label) {
         let before = host_section.secrets.len();
         host_section.secrets = mem::take(&mut host_section.secrets)
            .into_iter()
            .filter(|&(ref name, _)| live_names.contains(name.as_str()))
            .collect::<BTreeMap<_, _>>();
         removed_manifest += before - host_section.secrets.len();
      }
   }

   let live_sources = plans
      .iter()
      .flat_map(|plan| plan.secrets.iter().map(|secret| secret.rekey_file.as_path()))
      .collect::<HashSet<&Path>>();
   let before = manifest.sources.len();
   manifest.sources = mem::take(&mut manifest.sources)
      .into_iter()
      .filter(|entry| live_sources.contains(entry.0.as_path()))
      .collect::<BTreeMap<_, _>>();
   removed_manifest += before - manifest.sources.len();

   // Sweep filesystems first so a failure leaves the manifest untouched.
   let mut removed_files = 0;
   for plan in plans {
      removed_files += ops::sweep_orphans(plan, repo_root)?;
   }

   if manifest != manifest_initial {
      manifest.write_atomic(manifest_path)?;
   }

   info!(
      removed_manifest_entries = removed_manifest,
      removed_orphan_files = removed_files,
      "gc complete"
   );
   Ok(removed_manifest + removed_files)
}
