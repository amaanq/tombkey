//! Rekey host outputs from source secrets.

use std::{
   collections::{
      BTreeMap,
      BTreeSet,
      btree_map::Entry,
   },
   fs,
   io,
   io::ErrorKind,
   path::{
      Path,
      PathBuf,
   },
   slice,
};

use age_core::format::FileKey;
use secrecy::{
   ExposeSecret as _,
   SecretBox,
};
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
      HostSection,
      Manifest,
      SecretFingerprint,
      master_set_sha256_hex,
      sha256_hex,
   },
   ops,
   plan::{
      Plan,
      SecretEntry,
   },
};

#[derive(Default)]
struct RunReport<'a> {
   failures:          usize,
   stale_left_behind: Vec<&'a SecretEntry>,
}

struct PlanCtx<'a> {
   plan:               &'a Plan,
   host_pubkey_sha256: String,
   master_set_sha256:  String,
   prev_section:       Option<HostSection>,
   new_section:        HostSection,
}

struct StaleTarget<'a> {
   plan_idx:   usize,
   secret:     &'a SecretEntry,
   output_abs: PathBuf,
}

type IdentityCache<'a> = BTreeMap<Vec<&'a Path>, Vec<Box<dyn age::Identity>>>;

pub fn run(plans: &[Plan], repo_root: &Path, manifest_path: &Path) -> Result<usize> {
   ops::validate_source_master_consistency(plans)?;
   let _plugin_guard = ops::install_plugin_paths(plans);

   let mut manifest = Manifest::load(manifest_path)?;
   let manifest_initial = manifest.clone();
   let mut plan_ctxs = build_plan_ctxs(plans, repo_root, &mut manifest)?;

   let mut by_source = BTreeMap::<PathBuf, Vec<(usize, &SecretEntry)>>::new();
   for (plan_idx, plan) in plans.iter().enumerate() {
      for secret in &plan.secrets {
         by_source
            .entry(repo_root.join(&secret.rekey_file))
            .or_default()
            .push((plan_idx, secret));
      }
   }

   // Phase 1: classify sources; unchanged ones skip decrypt/touch.
   let mut report = RunReport::default();
   let mut pending = Vec::<PendingSource<'_>>::new();
   for (source_path, consumers) in &by_source {
      let source_bytes = match fs::read(source_path) {
         Ok(bytes) => bytes,
         Err(err) => {
            warn!(source = %source_path.display(), error = %err, "read source failed");
            for &(_, secret) in consumers {
               record_secret_failure(secret, repo_root, &mut report);
            }
            continue;
         },
      };
      let source_sha = sha256_hex(&source_bytes);
      let stale = classify_consumers(consumers, &source_sha, repo_root, &mut plan_ctxs);
      if stale.is_empty() {
         continue;
      }
      pending.push(PendingSource {
         source_path: source_path.clone(),
         consumers: consumers.clone(),
         source_bytes,
         source_sha,
         stale,
      });
   }

   // Phase 2: one plugin session, with per-source fallback.
   let file_keys = batch_unwrap_sources(plans, &pending);

   // Phase 3: decrypt once, fan out to host outputs.
   let mut identities = IdentityCache::new();
   for (source, file_key) in pending.iter().zip(file_keys) {
      let Some(plaintext) = decrypt_pending(source, file_key, &plan_ctxs, &mut identities) else {
         for target in &source.stale {
            record_secret_failure(target.secret, repo_root, &mut report);
         }
         continue;
      };
      for target in &source.stale {
         fan_out_to_target(
            target,
            &plaintext,
            &source.source_sha,
            &mut plan_ctxs,
            repo_root,
            &mut report,
         );
      }
   }

   if !report.stale_left_behind.is_empty() {
      let names = report
         .stale_left_behind
         .iter()
         .map(|secret| secret.name.as_str())
         .collect::<Vec<_>>()
         .join(", ");
      return Err(Error::Storage(format!(
         "stale outputs could not be removed for failed secrets ({names}); refusing to commit \
          manifest"
      )));
   }

   for plan in plans {
      let removed = ops::sweep_orphans(plan, repo_root)?;
      if removed > 0 {
         info!(
            removed,
            host = plan.host_label.as_str(),
            "pruned orphan outputs from local_storage_dir",
         );
      }
   }

   for ctx in plan_ctxs {
      manifest
         .hosts
         .insert(ctx.plan.host_label.clone(), ctx.new_section);
   }

   if manifest == manifest_initial {
      info!("manifest unchanged; skipping write");
   } else {
      manifest.write_atomic(manifest_path)?;
   }

   Ok(report.failures)
}

fn build_plan_ctxs<'a>(
   plans: &'a [Plan],
   repo_root: &Path,
   manifest: &mut Manifest,
) -> Result<Vec<PlanCtx<'a>>> {
   plans
      .iter()
      .map(|plan| {
         let host_pubkey_sha256 = sha256_hex(plan.host_pubkey.as_bytes());
         let master_set_sha256 = master_set_sha256_hex(
            plan
               .master_identities
               .iter()
               .map(|master| master.pubkey.as_str()),
         );
         let prev_section = manifest.hosts.remove(&plan.host_label);
         let new_section = HostSection {
            host_pubkey_sha256: host_pubkey_sha256.clone(),
            master_set_sha256:  master_set_sha256.clone(),
            secrets:            BTreeMap::new(),
         };
         let storage_abs = repo_root.join(&plan.local_storage_dir);
         fs::create_dir_all(&storage_abs).map_err(|err| {
            Error::Storage(format!(
               "create local_storage_dir {}: {err}",
               storage_abs.display()
            ))
         })?;
         Ok(PlanCtx {
            plan,
            host_pubkey_sha256,
            master_set_sha256,
            prev_section,
            new_section,
         })
      })
      .collect()
}

/// A source that has at least one stale consumer and so must be decrypted.
struct PendingSource<'a> {
   source_path:  PathBuf,
   consumers:    Vec<(usize, &'a SecretEntry)>,
   source_bytes: Vec<u8>,
   source_sha:   String,
   stale:        Vec<StaleTarget<'a>>,
}

/// Recover every pending source's file key in one plugin session.
fn batch_unwrap_sources(plans: &[Plan], pending: &[PendingSource<'_>]) -> Vec<Option<FileKey>> {
   let inputs = pending
      .iter()
      .map(|source| {
         let identity_paths = source
            .consumers
            .iter()
            .flat_map(|&(plan_idx, _)| {
               plans[plan_idx]
                  .master_identities
                  .iter()
                  .map(|master| master.identity.as_path())
            })
            .collect();
         ops::BatchDecryptInput {
            ciphertext: source.source_bytes.as_slice(),
            identity_paths,
         }
      })
      .collect::<Vec<_>>();
   ops::batch_unwrap_file_keys(plans, &inputs)
}

fn load_identities<'a, 'cache>(
   consumers: &[(usize, &'a SecretEntry)],
   plan_ctxs: &[PlanCtx<'a>],
   identity_cache: &'cache mut IdentityCache<'a>,
) -> Result<&'cache [Box<dyn age::Identity>]> {
   let identity_paths = consumers
      .iter()
      .flat_map(|&(plan_idx, _)| {
         plan_ctxs[plan_idx]
            .plan
            .master_identities
            .iter()
            .map(|master| master.identity.as_path())
      })
      .collect::<BTreeSet<&Path>>()
      .into_iter()
      .collect::<Vec<_>>();
   if let Entry::Vacant(slot) = identity_cache.entry(identity_paths.clone()) {
      slot.insert(decrypt::identities_from_files(
         identity_paths.iter().copied(),
      )?);
   }
   Ok(identity_cache
      .get(&identity_paths)
      .expect("just-inserted entry must exist")
      .as_slice())
}

/// Decrypt one pending source. Warns and returns [`None`] on failure.
fn decrypt_pending<'a>(
   source: &PendingSource<'a>,
   file_key: Option<FileKey>,
   plan_ctxs: &[PlanCtx<'a>],
   identity_cache: &mut IdentityCache<'a>,
) -> Option<SecretBox<Vec<u8>>> {
   let result = if let Some(key) = file_key {
      decrypt::decrypt_with_file_key(&source.source_bytes, key)
   } else {
      let identities = match load_identities(&source.consumers, plan_ctxs, identity_cache) {
         Ok(ids) => ids,
         Err(err) => {
            warn!(source = %source.source_path.display(), error = %err, "identity load failed");
            return None;
         },
      };
      decrypt::decrypt(&source.source_bytes, identities)
   };
   match result {
      Ok(bytes) => Some(SecretBox::new(Box::new(bytes))),
      Err(message) => {
         warn!(source = %source.source_path.display(), error = message.as_str(), "decrypt failed");
         None
      },
   }
}

fn classify_consumers<'a>(
   consumers: &[(usize, &'a SecretEntry)],
   source_sha: &str,
   repo_root: &Path,
   plan_ctxs: &mut [PlanCtx<'a>],
) -> Vec<StaleTarget<'a>> {
   let mut stale = Vec::<StaleTarget<'_>>::new();
   for &(plan_idx, secret) in consumers {
      let ctx = &mut plan_ctxs[plan_idx];
      let output_abs = repo_root.join(&secret.output_file);
      if matches_prev(ctx, secret, source_sha, &output_abs) {
         let prev_entry = ctx
            .prev_section
            .as_ref()
            .and_then(|section| section.secrets.get(&secret.name))
            .expect("matches_prev only returns true when prev_entry exists")
            .clone();
         ctx.new_section
            .secrets
            .insert(secret.name.clone(), prev_entry);
      } else {
         stale.push(StaleTarget {
            plan_idx,
            secret,
            output_abs,
         });
      }
   }
   stale
}

fn fan_out_to_target<'a>(
   target: &StaleTarget<'a>,
   plaintext: &SecretBox<Vec<u8>>,
   source_sha: &str,
   plan_ctxs: &mut [PlanCtx<'a>],
   repo_root: &Path,
   report: &mut RunReport<'a>,
) {
   let ctx = &mut plan_ctxs[target.plan_idx];
   let host_pubkey = ctx.plan.host_pubkey.as_str();
   let recipients = slice::from_ref(&host_pubkey);
   let ciphertext = match encrypt::encrypt(plaintext.expose_secret(), recipients) {
      Ok(bytes) => bytes,
      Err(err) => {
         warn!(
            secret = target.secret.name.as_str(),
            host = ctx.plan.host_label.as_str(),
            error = %err,
            "encrypt to host pubkey failed",
         );
         record_secret_failure(target.secret, repo_root, report);
         return;
      },
   };
   if let Err(err) = write_atomic(&target.output_abs, &ciphertext) {
      warn!(
         secret = target.secret.name.as_str(),
         output = %target.output_abs.display(),
         error = %err,
         "write output failed",
      );
      record_secret_failure(target.secret, repo_root, report);
      return;
   }
   ctx.new_section
      .secrets
      .insert(target.secret.name.clone(), SecretFingerprint {
         source_sha256: source_sha.to_owned(),
         output_file:   target.secret.output_file.clone(),
         output_sha256: sha256_hex(&ciphertext),
      });
   info!(
      secret = target.secret.name.as_str(),
      host = ctx.plan.host_label.as_str(),
      output = %target.output_abs.display(),
      "rekeyed",
   );
}

fn matches_prev(
   ctx: &PlanCtx<'_>,
   secret: &SecretEntry,
   source_sha: &str,
   output_abs: &Path,
) -> bool {
   let Some(prev) = ctx.prev_section.as_ref() else {
      return false;
   };
   if prev.host_pubkey_sha256 != ctx.host_pubkey_sha256
      || prev.master_set_sha256 != ctx.master_set_sha256
   {
      return false;
   }
   let Some(prev_entry) = prev.secrets.get(&secret.name) else {
      return false;
   };
   if prev_entry.source_sha256 != source_sha || prev_entry.output_file != secret.output_file {
      return false;
   }
   fs::read(output_abs).is_ok_and(|existing| prev_entry.output_sha256 == sha256_hex(&existing))
}

/// Delete failures block the manifest commit.
fn record_secret_failure<'a>(
   secret: &'a SecretEntry,
   repo_root: &Path,
   report: &mut RunReport<'a>,
) {
   report.failures += 1;
   let output_abs = repo_root.join(&secret.output_file);
   if let Err(purge_err) = purge_stale_output(&output_abs) {
      warn!(
         secret = secret.name.as_str(),
         output = %output_abs.display(),
         error = %purge_err,
         "FAILED to remove stale output; activation may consume stale ciphertext",
      );
      report.stale_left_behind.push(secret);
   }
}

fn purge_stale_output(output_abs: &Path) -> io::Result<()> {
   match fs::remove_file(output_abs) {
      Ok(()) => Ok(()),
      Err(err) if err.kind() == ErrorKind::NotFound => Ok(()),
      Err(err) => Err(err),
   }
}
