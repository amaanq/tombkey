//! Committed JSON manifest tracking per-secret rekey state.

use std::{
   collections::BTreeMap,
   fs,
   io,
   path::{
      Path,
      PathBuf,
   },
};

use serde::{
   Deserialize,
   Serialize,
};
use sha2::{
   Digest as _,
   Sha256,
};

use crate::{
   error::{
      Error,
      Result,
   },
   fs::write_atomic,
};

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct Manifest {
   pub version: u32,
   pub hosts:   BTreeMap<String, HostSection>,
   /// Per-source reseal cache, keyed by repo-relative source path. Lets reseal
   /// skip when the on-disk ciphertext and master set are both unchanged.
   pub sources: BTreeMap<PathBuf, SourceSealState>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct SourceSealState {
   /// sha256 of the source's ciphertext on disk after the last reseal. An
   /// external edit invalidates the skip.
   pub ciphertext_sha256: String,
   /// sha256 of the master pubkey set the source was last sealed to. A
   /// `masterIdentities` change invalidates the skip.
   pub master_set_sha256: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct HostSection {
   /// sha256 of the host's age recipient. Hashed (not raw) so the committed
   /// manifest doesn't repeat the pubkey for every secret.
   pub host_pubkey_sha256: String,

   /// sha256 of the sorted master pubkey set. Invalidates this host's cache
   /// when any master rotates.
   pub master_set_sha256: String,
   pub secrets:           BTreeMap<String, SecretFingerprint>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct SecretFingerprint {
   pub source_sha256: String,

   /// Repo-relative path of the rekeyed output ciphertext.
   pub output_file: PathBuf,

   pub output_sha256: String,
}

pub const CURRENT_VERSION: u32 = 1;

impl Manifest {
   pub fn load(path: &Path) -> Result<Self> {
      match fs::read(path) {
         Ok(bytes) => {
            let manifest = serde_json::from_slice::<Self>(&bytes).map_err(|err| {
               Error::Storage(format!("parse manifest {}: {err}", path.display()))
            })?;
            if manifest.version != CURRENT_VERSION {
               return Err(Error::Storage(format!(
                  "manifest {} version {} not supported (expected {})",
                  path.display(),
                  manifest.version,
                  CURRENT_VERSION
               )));
            }
            Ok(manifest)
         },
         Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(Self::empty()),
         Err(err) => {
            Err(Error::Storage(format!(
               "read manifest {}: {err}",
               path.display()
            )))
         },
      }
   }

   #[must_use]
   pub const fn empty() -> Self {
      Self {
         version: CURRENT_VERSION,
         hosts:   BTreeMap::new(),
         sources: BTreeMap::new(),
      }
   }

   pub fn write_atomic(&self, path: &Path) -> Result<()> {
      let mut bytes = serde_json::to_vec_pretty(self)
         .map_err(|err| Error::Storage(format!("serialize manifest {}: {err}", path.display())))?;
      bytes.push(b'\n');
      write_atomic(path, &bytes)
         .map_err(|err| Error::Storage(format!("write manifest {}: {err}", path.display())))
   }
}

#[must_use]
pub fn sha256_hex(bytes: &[u8]) -> String {
   let mut hasher = Sha256::new();
   hasher.update(bytes);
   hex::encode(hasher.finalize())
}

/// Fingerprint of a master pubkey set: sorted, `|`-joined, sha256-hex.
/// Order-independent so master-rotation alone invalidates downstream caches.
#[must_use]
pub fn master_set_sha256_hex<'a, I>(pubkeys: I) -> String
where
   I: IntoIterator<Item = &'a str>,
{
   use std::collections::BTreeSet;
   let sorted = pubkeys.into_iter().collect::<BTreeSet<&str>>();
   let joined = sorted.into_iter().collect::<Vec<_>>().join("|");
   sha256_hex(joined.as_bytes())
}

#[cfg(test)]
mod tests {
   use tempfile::TempDir;

   use super::*;

   fn fixture() -> Manifest {
      let mut hosts = BTreeMap::new();
      hosts.insert("karst".into(), HostSection {
         host_pubkey_sha256: "aa".into(),
         master_set_sha256:  "bb".into(),
         secrets:            BTreeMap::from([("atuin-key".into(), SecretFingerprint {
            source_sha256: "cc".into(),
            output_file:   "hosts/karst/secrets/atuin-key.age".into(),
            output_sha256: "dd".into(),
         })]),
      });
      Manifest {
         version: CURRENT_VERSION,
         hosts,
         sources: BTreeMap::new(),
      }
   }

   #[test]
   fn load_returns_empty_when_file_missing() {
      let tmp = TempDir::new().unwrap();
      let path = tmp.path().join(".tombkey/manifest.json");
      let manifest = Manifest::load(&path).unwrap();
      assert_eq!(manifest, Manifest::empty());
   }

   #[test]
   fn write_then_load_roundtrip() {
      let tmp = TempDir::new().unwrap();
      let path = tmp.path().join(".tombkey/manifest.json");
      let manifest = fixture();
      manifest.write_atomic(&path).unwrap();
      let loaded = Manifest::load(&path).unwrap();
      assert_eq!(loaded, manifest);
   }

   #[test]
   fn load_rejects_unknown_version() {
      let tmp = TempDir::new().unwrap();
      let path = tmp.path().join("manifest.json");
      fs::write(&path, br#"{"version":42,"hosts":{}}"#).unwrap();
      Manifest::load(&path).unwrap_err();
   }

   #[test]
   fn master_set_hash_stable_under_reordering() {
      let age_a = master_set_sha256_hex(["age1a", "age1b"]);
      let age_b = master_set_sha256_hex(["age1b", "age1a"]);
      assert_eq!(age_a, age_b);
   }

   #[test]
   fn master_set_hash_changes_on_new_master() {
      let age_a = master_set_sha256_hex(["age1a"]);
      let age_b = master_set_sha256_hex(["age1a", "age1c"]);
      assert_ne!(age_a, age_b);
   }

   #[test]
   fn source_seal_state_roundtrips() {
      let tmp = TempDir::new().unwrap();
      let path = tmp.path().join("manifest.json");
      let mut manifest = Manifest::empty();
      manifest.sources.insert(
         "modules/common/atuin/key.age".into(),
         SourceSealState {
            ciphertext_sha256: "aa".into(),
            master_set_sha256: "bb".into(),
         },
      );
      manifest.write_atomic(&path).unwrap();
      let loaded = Manifest::load(&path).unwrap();
      assert_eq!(loaded, manifest);
   }
}
