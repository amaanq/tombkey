//! Per-host JSON plan emitted by the Nix module.

use std::{
   collections::HashSet,
   path::{
      Component,
      Path,
      PathBuf,
   },
   str::FromStr as _,
};

use age::{
   plugin,
   ssh,
   x25519,
};
use serde::{
   Deserialize,
   Serialize,
};

use crate::error::{
   Error,
   Result,
};

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct Plan {
   pub host_pubkey: String,

   /// Hostname; the key into the manifest's `hosts` map.
   pub host_label: String,

   pub master_identities: Vec<MasterIdentity>,

   pub secrets: Vec<SecretEntry>,

   /// Output directory, relative to the repo root. Scope of the orphan sweep.
   pub local_storage_dir: PathBuf,

   /// Manifest path, relative to the repo root.
   pub manifest_file: PathBuf,

   /// Directories prepended to `$PATH` so age can spawn plugin binaries.
   pub age_plugins: Vec<PathBuf>,
}

/// One master identity.
///
/// `pubkey` is resolved at Nix-eval time, so the binary never reads identity
/// files just to learn the recipient.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct MasterIdentity {
   pub identity: PathBuf,
   pub pubkey:   String,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct SecretEntry {
   pub name: String,

   /// Source ciphertext path, relative to the repo root.
   pub rekey_file: PathBuf,

   /// Output path, relative to the repo root.
   pub output_file: PathBuf,
}

impl Plan {
   pub fn from_json(bytes: &[u8]) -> Result<Self> {
      let plan = serde_json::from_slice::<Self>(bytes)?;
      plan.validate()?;
      Ok(plan)
   }

   /// Cross-plan invariants.
   pub fn validate_set(plans: &[Self]) -> Result<()> {
      let mut labels = HashSet::<&str>::new();
      let mut outputs = HashSet::<&Path>::new();
      for plan in plans {
         if !labels.insert(plan.host_label.as_str()) {
            return Err(Error::InvalidPlan(format!(
               "duplicate host_label {:?}; manifest host sections would overwrite each other",
               plan.host_label,
            )));
         }
         for secret in &plan.secrets {
            if !outputs.insert(secret.output_file.as_path()) {
               return Err(Error::InvalidPlan(format!(
                  "two plans claim the same output_file {} (one is host {:?})",
                  secret.output_file.display(),
                  plan.host_label,
               )));
            }
         }
      }
      if let Some(first) = plans.first() {
         for plan in &plans[1..] {
            if plan.manifest_file != first.manifest_file {
               return Err(Error::InvalidPlan(format!(
                  "plans disagree on manifest_file: {} vs {}",
                  first.manifest_file.display(),
                  plan.manifest_file.display(),
               )));
            }
         }
      }
      for (idx, plan) in plans.iter().enumerate() {
         for other in &plans[idx + 1..] {
            if plan.local_storage_dir.starts_with(&other.local_storage_dir)
               || other.local_storage_dir.starts_with(&plan.local_storage_dir)
            {
               return Err(Error::InvalidPlan(format!(
                  "local_storage_dir overlap between hosts {:?} ({}) and {:?} ({}): each host \
                   must own a disjoint output directory or the orphan sweep will delete the other \
                   host's outputs",
                  plan.host_label,
                  plan.local_storage_dir.display(),
                  other.host_label,
                  other.local_storage_dir.display(),
               )));
            }
         }
      }
      Ok(())
   }

   pub fn validate(&self) -> Result<()> {
      validate_recipient(&self.host_pubkey, "host_pubkey")?;
      if self.master_identities.is_empty() {
         return Err(Error::InvalidPlan("master_identities is empty".into()));
      }
      for master in &self.master_identities {
         validate_recipient(
            &master.pubkey,
            &format!("master_identities[{}].pubkey", master.identity.display()),
         )?;
      }
      reject_traversal(&self.local_storage_dir, "local_storage_dir")?;
      reject_traversal(&self.manifest_file, "manifest_file")?;
      let mut names = HashSet::<&str>::new();
      let mut outputs = HashSet::<&Path>::new();
      for secret in &self.secrets {
         if !names.insert(&secret.name) {
            return Err(Error::InvalidPlan(format!(
               "duplicate secret name {:?}",
               secret.name
            )));
         }
         if !outputs.insert(secret.output_file.as_path()) {
            return Err(Error::InvalidPlan(format!(
               "duplicate secret output_file {}",
               secret.output_file.display()
            )));
         }
         if secret.output_file == secret.rekey_file {
            return Err(Error::InvalidPlan(format!(
               "secret {:?}: output_file equals rekey_file ({})",
               secret.name,
               secret.output_file.display()
            )));
         }
         reject_traversal(
            &secret.rekey_file,
            &format!("secret {:?}.rekey_file", secret.name),
         )?;
         reject_traversal(
            &secret.output_file,
            &format!("secret {:?}.output_file", secret.name),
         )?;
         // Keep the orphan sweep scoped to tombkey-owned outputs.
         if !secret.output_file.starts_with(&self.local_storage_dir) {
            return Err(Error::InvalidPlan(format!(
               "secret {:?}.output_file ({}) must live under local_storage_dir ({})",
               secret.name,
               secret.output_file.display(),
               self.local_storage_dir.display(),
            )));
         }
      }
      Ok(())
   }
}

/// Reject non-normal relative paths before they become equality keys.
fn reject_traversal(path: &Path, label: &str) -> Result<()> {
   if path.is_absolute() {
      return Err(Error::InvalidPlan(format!(
         "{label} ({}) must be a relative path",
         path.display()
      )));
   }
   for component in path.components() {
      match component {
         Component::Normal(_) => {},
         Component::ParentDir => {
            return Err(Error::InvalidPlan(format!(
               "{label} ({}) contains `..` component",
               path.display()
            )));
         },
         Component::CurDir => {
            return Err(Error::InvalidPlan(format!(
               "{label} ({}) contains `.` component; emit a normalized path",
               path.display()
            )));
         },
         Component::Prefix(_) | Component::RootDir => {
            return Err(Error::InvalidPlan(format!(
               "{label} ({}) must be a relative path",
               path.display()
            )));
         },
      }
   }
   // Raw path equality depends on normalized spelling.
   let normalized = path.components().collect::<PathBuf>();
   if normalized.as_os_str() != path.as_os_str() {
      return Err(Error::InvalidPlan(format!(
         "{label} ({}) is not normalized; emit {} instead",
         path.display(),
         normalized.display()
      )));
   }
   Ok(())
}

fn validate_recipient(value: &str, label: &str) -> Result<()> {
   if value.is_empty() {
      return Err(Error::InvalidPlan(format!("{label} is empty")));
   }
   if x25519::Recipient::from_str(value).is_ok()
      || plugin::Recipient::from_str(value).is_ok()
      || ssh::Recipient::from_str(value).is_ok()
   {
      return Ok(());
   }
   Err(Error::InvalidPlan(format!(
      "{label} is not a valid age recipient: {value:?}"
   )))
}

#[cfg(test)]
mod tests {
   use super::*;

   fn sample() -> Plan {
      Plan {
         host_pubkey:       "age1lggyhqrw2nlhcxprm67z43rta597azn8gknawjehu9d9dl0jq3yqqvfafg".into(),
         host_label:        "yardang".into(),
         master_identities: vec![
            MasterIdentity {
               identity: "/home/u/.ssh/id".into(),
               pubkey:   "age1lggyhqrw2nlhcxprm67z43rta597azn8gknawjehu9d9dl0jq3yqqvfafg".into(),
            },
            MasterIdentity {
               identity: "/home/u/dotfiles/secrets/iray-37504518.pub".into(),
               pubkey:   "age1fido2-hmac1qqpzvf37n8852hn88xmgcxzlnp93vmdqnk7l5s6nadfcgtdxhd4fc6cqx9zqdpnr4tduxc8e0gfudtrt4qxh4et3dgx2vruv5u3lfjy8jj0gw4tpm5zfpd27f0rye707n74j4674yzm27uwqv2m7kfzfp6vnf36us45jpj904gsmgfef98shleyqtttt4c43hrjt8rr2s5twyx7dqye765qr".into(),
            },
         ],
         secrets: vec![SecretEntry {
            name:        "atuin-key".into(),
            rekey_file:  "secrets/atuin-key.age".into(),
            output_file: "hosts/yardang/secrets/atuin-key.age".into(),
         }],
         local_storage_dir: "hosts/yardang/secrets".into(),
         manifest_file: ".tombkey/manifest.json".into(),
         age_plugins: vec!["/nix/store/...-age-plugin-fido2-hmac".into()],
      }
   }

   #[test]
   fn json_roundtrip() {
      let plan = sample();
      let bytes = serde_json::to_vec(&plan).unwrap();
      let parsed = Plan::from_json(&bytes).unwrap();
      assert_eq!(parsed, plan);
   }

   #[test]
   fn rejects_empty_host_pubkey() {
      let mut plan = sample();
      plan.host_pubkey.clear();
      plan.validate().unwrap_err();
   }

   #[test]
   fn rejects_empty_masters() {
      let mut plan = sample();
      plan.master_identities.clear();
      plan.validate().unwrap_err();
   }

   #[test]
   fn rejects_duplicate_secret_names() {
      let mut plan = sample();
      plan.secrets.push(plan.secrets[0].clone());
      plan.validate().unwrap_err();
   }

   #[test]
   fn rejects_malformed_host_pubkey() {
      let mut plan = sample();
      plan.host_pubkey = "not-an-age-recipient".into();
      plan.validate().unwrap_err();
   }

   #[test]
   fn rejects_malformed_master_pubkey() {
      let mut plan = sample();
      plan.master_identities[0].pubkey = "totally-bogus".into();
      plan.validate().unwrap_err();
   }

   #[test]
   fn rejects_duplicate_output_files() {
      let mut plan = sample();
      let mut extra = plan.secrets[0].clone();
      extra.name = "different-name".into();
      plan.secrets.push(extra);
      plan.validate().unwrap_err();
   }

   #[test]
   fn rejects_output_file_equal_to_rekey_file() {
      let mut plan = sample();
      plan.secrets[0].output_file = plan.secrets[0].rekey_file.clone();
      plan.validate().unwrap_err();
   }

   #[test]
   fn rejects_absolute_output_file() {
      let mut plan = sample();
      plan.secrets[0].output_file = "/etc/age/atuin-key.age".into();
      plan.validate().unwrap_err();
   }

   #[test]
   fn rejects_output_file_with_parent_dir_traversal() {
      let mut plan = sample();
      plan.secrets[0].output_file = "hosts/yardang/../escape/atuin-key.age".into();
      plan.validate().unwrap_err();
   }

   #[test]
   fn rejects_absolute_manifest_file() {
      let mut plan = sample();
      plan.manifest_file = "/etc/age/manifest.json".into();
      plan.validate().unwrap_err();
   }

   #[test]
   fn rejects_absolute_rekey_file() {
      let mut plan = sample();
      plan.secrets[0].rekey_file = "/nix/store/abc/secrets/atuin-key.age".into();
      plan.validate().unwrap_err();
   }

   #[test]
   fn rejects_rekey_file_with_parent_dir_traversal() {
      let mut plan = sample();
      plan.secrets[0].rekey_file = "secrets/../escape/atuin-key.age".into();
      plan.validate().unwrap_err();
   }

   #[test]
   fn rejects_paths_with_embedded_dot_component() {
      let mut plan = sample();
      plan.secrets[0].rekey_file = "secrets/./atuin-key.age".into();
      plan.validate().unwrap_err();

      let mut storage_plan = sample();
      storage_plan.local_storage_dir = "hosts/yardang/./secrets".into();
      storage_plan.secrets[0].output_file = "hosts/yardang/./secrets/atuin-key.age".into();
      storage_plan.validate().unwrap_err();
   }

   #[test]
   fn rejects_paths_with_repeated_separators() {
      let mut plan = sample();
      plan.secrets[0].rekey_file = "secrets//atuin-key.age".into();
      plan.validate().unwrap_err();
   }

   #[test]
   fn rejects_paths_with_leading_cur_dir() {
      let mut plan = sample();
      plan.secrets[0].rekey_file = "./secrets/atuin-key.age".into();
      plan.validate().unwrap_err();
   }

   #[test]
   fn rejects_output_file_outside_local_storage_dir() {
      let mut plan = sample();
      plan.secrets[0].output_file = "hosts/yardang/elsewhere/atuin-key.age".into();
      plan.validate().unwrap_err();
   }

   #[test]
   fn validate_set_rejects_duplicate_host_labels() {
      let plan_a = sample();
      let plan_b = sample();
      Plan::validate_set(&[plan_a, plan_b]).unwrap_err();
   }

   #[test]
   fn validate_set_rejects_divergent_manifest_files() {
      let plan_a = sample();
      let mut plan_b = sample();
      plan_b.host_label = "other-host".into();
      plan_b.local_storage_dir = "hosts/other-host/secrets".into();
      plan_b.secrets[0].output_file = "hosts/other-host/secrets/atuin-key.age".into();
      plan_b.manifest_file = ".tombkey/other-manifest.json".into();
      Plan::validate_set(&[plan_a, plan_b]).unwrap_err();
   }

   #[test]
   fn validate_set_rejects_duplicate_output_files_across_plans() {
      let plan_a = sample();
      let mut plan_b = sample();
      plan_b.host_label = "other-host".into();
      plan_b.local_storage_dir = "hosts/other-host/secrets".into();
      // Same output_file path as `plan_a` — would clobber if rekey ran both.
      Plan::validate_set(&[plan_a, plan_b]).unwrap_err();
   }

   #[test]
   fn validate_set_rejects_overlapping_local_storage_dirs() {
      let plan_a = sample();
      let mut plan_b = sample();
      plan_b.host_label = "other-host".into();
      // `plan_b.local_storage_dir` is a child of `plan_a.local_storage_dir`.
      // The per-host orphan sweep on `plan_a` would treat `plan_b`'s outputs
      // as orphans.
      plan_b.local_storage_dir = "hosts/yardang/secrets/nested".into();
      plan_b.secrets[0].output_file = "hosts/yardang/secrets/nested/atuin-key.age".into();
      Plan::validate_set(&[plan_a, plan_b]).unwrap_err();
   }

   #[test]
   fn validate_set_accepts_disjoint_plans() {
      let plan_a = sample();
      let mut plan_b = sample();
      plan_b.host_label = "other-host".into();
      plan_b.local_storage_dir = "hosts/other-host/secrets".into();
      plan_b.secrets[0].output_file = "hosts/other-host/secrets/atuin-key.age".into();
      Plan::validate_set(&[plan_a, plan_b]).unwrap();
   }

   #[test]
   fn accepts_ssh_recipient_host_pubkey() {
      let mut plan = sample();
      plan.host_pubkey = "ssh-ed25519 \
                          AAAAC3NzaC1lZDI1NTE5AAAAIPQQBN06V58ll+e2+t4X9qq/foFY+Hsx9DVQtEoGKz+R \
                          root@yardang"
         .into();
      plan.validate().unwrap();
   }
}
