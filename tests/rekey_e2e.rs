//! End-to-end manifest-driven rekey op against real age ciphertext.

use std::{
   collections::BTreeMap,
   fs::{
      self,
      File,
   },
   io::{
      Read as _,
      Write as _,
   },
   iter,
   path::{
      Path,
      PathBuf,
   },
   slice,
   thread,
   time::Duration,
};

use age::{
   Decryptor,
   Encryptor,
   Identity,
   secrecy::ExposeSecret as _,
   x25519,
};
use tempfile::TempDir;
use tombkey::{
   manifest::{
      HostSection,
      Manifest,
      SecretFingerprint,
   },
   ops,
   plan::{
      MasterIdentity,
      Plan,
      SecretEntry,
   },
};

struct AgeKey {
   identity:  x25519::Identity,
   recipient: x25519::Recipient,
}

fn fresh_age_key() -> AgeKey {
   let identity = x25519::Identity::generate();
   let recipient = identity.to_public();
   AgeKey {
      identity,
      recipient,
   }
}

fn write_identity_file(dir: &Path, name: &str, key: &AgeKey) -> PathBuf {
   let path = dir.join(name);
   let mut file = File::create(&path).unwrap();
   writeln!(file, "# public key: {}", key.recipient).unwrap();
   writeln!(file, "{}", key.identity.to_string().expose_secret()).unwrap();
   path
}

fn encrypt_with(recipients: &[&x25519::Recipient], plaintext: &[u8]) -> Vec<u8> {
   let encryptor = Encryptor::with_recipients(
      recipients
         .iter()
         .map(|recipient| *recipient as &dyn age::Recipient),
   )
   .expect("encryptor init");
   let mut ciphertext = Vec::<u8>::new();
   let mut writer = encryptor.wrap_output(&mut ciphertext).unwrap();
   writer.write_all(plaintext).unwrap();
   writer.finish().unwrap();
   ciphertext
}

fn decrypt_with(identity: &x25519::Identity, ciphertext: &[u8]) -> Vec<u8> {
   let decryptor = Decryptor::new(ciphertext).unwrap();
   let mut reader = decryptor
      .decrypt(iter::once(identity as &dyn Identity))
      .unwrap();
   let mut plaintext = Vec::<u8>::new();
   reader.read_to_end(&mut plaintext).unwrap();
   plaintext
}

const STORAGE_REL: &str = "hosts/testhost/secrets";
const MANIFEST_REL: &str = ".tombkey/manifest.json";

struct Source {
   name:      String,
   abs:       PathBuf,
   rel:       PathBuf,
   plaintext: Vec<u8>,
}

struct Fixture {
   #[expect(dead_code, reason = "holds the TempDir alive for the test's lifetime")]
   workdir:       TempDir,
   repo_root:     PathBuf,
   manifest:      PathBuf,
   master_a:      AgeKey,
   master_id:     PathBuf,
   host:          AgeKey,
   sources:       Vec<Source>,
   local_storage: PathBuf,
}

fn fixture(secret_names: &[&str]) -> Fixture {
   let workdir = TempDir::new().unwrap();
   let repo_root = workdir.path().to_path_buf();
   let manifest = repo_root.join(MANIFEST_REL);
   let local_storage = repo_root.join(STORAGE_REL);
   fs::create_dir_all(&local_storage).unwrap();
   let master_a = fresh_age_key();
   let host = fresh_age_key();
   let master_id = write_identity_file(&repo_root, "master-a.txt", &master_a);

   let sources_dir = repo_root.join("secrets");
   fs::create_dir_all(&sources_dir).unwrap();
   let mut sources = Vec::new();
   for name in secret_names {
      let plaintext = format!("plaintext-of-{name}").into_bytes();
      let rel = PathBuf::from(format!("secrets/{name}.age"));
      let abs = repo_root.join(&rel);
      fs::write(&abs, encrypt_with(&[&master_a.recipient], &plaintext)).unwrap();
      sources.push(Source {
         name: (*name).to_owned(),
         abs,
         rel,
         plaintext,
      });
   }

   Fixture {
      workdir,
      repo_root,
      manifest,
      master_a,
      master_id,
      host,
      sources,
      local_storage,
   }
}

impl Fixture {
   fn plan(&self) -> Plan {
      Plan {
         host_pubkey:       self.host.recipient.to_string(),
         host_label:        "testhost".into(),
         master_identities: vec![MasterIdentity {
            identity: self.master_id.clone(),
            pubkey:   self.master_a.recipient.to_string(),
         }],
         secrets:           self
            .sources
            .iter()
            .map(|source| {
               SecretEntry {
                  name:        source.name.clone(),
                  rekey_file:  source.rel.clone(),
                  output_file: PathBuf::from(format!("{STORAGE_REL}/{}.age", source.name)),
               }
            })
            .collect(),
         local_storage_dir: PathBuf::from(STORAGE_REL),
         manifest_file:     PathBuf::from(MANIFEST_REL),
         age_plugins:       vec![],
      }
   }
}

#[test]
fn skip_on_current_inputs_avoids_re_encrypt() {
   let fixture = fixture(&["alpha", "beta"]);
   let plan = fixture.plan();

   assert_eq!(
      ops::rekey::run(
         slice::from_ref(&plan),
         &fixture.repo_root,
         &fixture.manifest
      )
      .unwrap(),
      0
   );

   let out_a = fixture.local_storage.join("alpha.age");
   let out_b = fixture.local_storage.join("beta.age");
   let mtime_a = fs::metadata(&out_a).unwrap().modified().unwrap();
   let mtime_b = fs::metadata(&out_b).unwrap().modified().unwrap();

   assert_eq!(
      ops::rekey::run(
         slice::from_ref(&plan),
         &fixture.repo_root,
         &fixture.manifest
      )
      .unwrap(),
      0
   );
   assert_eq!(fs::metadata(&out_a).unwrap().modified().unwrap(), mtime_a);
   assert_eq!(fs::metadata(&out_b).unwrap().modified().unwrap(), mtime_b);
}

#[test]
fn source_change_forces_rekey() {
   let fixture = fixture(&["alpha"]);
   let plan = fixture.plan();
   assert_eq!(
      ops::rekey::run(
         slice::from_ref(&plan),
         &fixture.repo_root,
         &fixture.manifest
      )
      .unwrap(),
      0
   );
   let out = fixture.local_storage.join("alpha.age");
   let mtime_before = fs::metadata(&out).unwrap().modified().unwrap();

   let new_plaintext = b"different plaintext".as_slice();
   fs::write(
      &fixture.sources[0].abs,
      encrypt_with(&[&fixture.master_a.recipient], new_plaintext),
   )
   .unwrap();
   // mtime granularity is coarse on some filesystems.
   thread::sleep(Duration::from_millis(10));

   assert_eq!(
      ops::rekey::run(
         slice::from_ref(&plan),
         &fixture.repo_root,
         &fixture.manifest
      )
      .unwrap(),
      0
   );
   let mtime_after = fs::metadata(&out).unwrap().modified().unwrap();
   assert_ne!(
      mtime_before, mtime_after,
      "source change should force re-encrypt"
   );
   let bytes = fs::read(&out).unwrap();
   assert_eq!(decrypt_with(&fixture.host.identity, &bytes), new_plaintext);
}

#[test]
fn master_set_change_forces_rekey() {
   let fixture = fixture(&["alpha"]);
   let plan = fixture.plan();
   assert_eq!(
      ops::rekey::run(
         slice::from_ref(&plan),
         &fixture.repo_root,
         &fixture.manifest
      )
      .unwrap(),
      0
   );
   let out = fixture.local_storage.join("alpha.age");
   let mtime_before = fs::metadata(&out).unwrap().modified().unwrap();
   let master_set_before = Manifest::load(&fixture.manifest).unwrap().hosts["testhost"]
      .master_set_sha256
      .clone();

   let master_b = fresh_age_key();
   let master_b_path = write_identity_file(&fixture.repo_root, "master-b.txt", &master_b);
   fs::write(
      &fixture.sources[0].abs,
      encrypt_with(
         &[&fixture.master_a.recipient, &master_b.recipient],
         &fixture.sources[0].plaintext,
      ),
   )
   .unwrap();
   let mut plan2 = plan;
   plan2.master_identities.push(MasterIdentity {
      identity: master_b_path,
      pubkey:   master_b.recipient.to_string(),
   });
   thread::sleep(Duration::from_millis(10));

   assert_eq!(
      ops::rekey::run(
         slice::from_ref(&plan2),
         &fixture.repo_root,
         &fixture.manifest
      )
      .unwrap(),
      0
   );
   let mtime_after = fs::metadata(&out).unwrap().modified().unwrap();
   assert_ne!(
      mtime_before, mtime_after,
      "master set change should force re-encrypt"
   );
   let master_set_after = Manifest::load(&fixture.manifest).unwrap().hosts["testhost"]
      .master_set_sha256
      .clone();
   assert_ne!(
      master_set_before, master_set_after,
      "master_set_sha256 should change when masters rotate",
   );
}

#[test]
fn failed_secret_purges_output_and_manifest_entry() {
   let fixture = fixture(&["alpha", "beta"]);
   let plan = fixture.plan();
   assert_eq!(
      ops::rekey::run(
         slice::from_ref(&plan),
         &fixture.repo_root,
         &fixture.manifest
      )
      .unwrap(),
      0
   );
   let out_alpha = fixture.local_storage.join("alpha.age");
   assert!(out_alpha.is_file());

   fs::write(&fixture.sources[0].abs, b"not-age-ciphertext").unwrap();

   let failures = ops::rekey::run(
      slice::from_ref(&plan),
      &fixture.repo_root,
      &fixture.manifest,
   )
   .unwrap();
   assert!(failures >= 1, "alpha rekey should fail");

   assert!(
      !out_alpha.exists(),
      "failed secret's output should be removed"
   );
   let manifest = Manifest::load(&fixture.manifest).unwrap();
   let host = &manifest.hosts["testhost"];
   assert!(
      !host.secrets.contains_key("alpha"),
      "failed entry should be purged"
   );
   assert!(fixture.local_storage.join("beta.age").is_file());
   assert!(host.secrets.contains_key("beta"));
}

#[test]
fn delete_failure_blocks_manifest_commit() {
   let fixture = fixture(&["alpha", "beta"]);
   let plan = fixture.plan();
   assert_eq!(
      ops::rekey::run(
         slice::from_ref(&plan),
         &fixture.repo_root,
         &fixture.manifest
      )
      .unwrap(),
      0
   );

   let manifest_before = Manifest::load(&fixture.manifest).unwrap();

   fs::write(&fixture.sources[0].abs, b"not-age-ciphertext").unwrap();
   let out_alpha = fixture.local_storage.join("alpha.age");
   fs::remove_file(&out_alpha).unwrap();
   fs::create_dir_all(&out_alpha).unwrap();

   let result = ops::rekey::run(
      slice::from_ref(&plan),
      &fixture.repo_root,
      &fixture.manifest,
   );
   assert!(
      result.is_err(),
      "delete-failure must propagate as hard error, got {result:?}"
   );

   let manifest_after = Manifest::load(&fixture.manifest).unwrap();
   assert_eq!(manifest_before, manifest_after);
}

#[test]
fn removed_secret_prunes_output_and_manifest_entry() {
   let fixture = fixture(&["alpha", "beta"]);
   let plan = fixture.plan();
   assert_eq!(
      ops::rekey::run(
         slice::from_ref(&plan),
         &fixture.repo_root,
         &fixture.manifest
      )
      .unwrap(),
      0
   );
   assert!(fixture.local_storage.join("alpha.age").is_file());
   assert!(fixture.local_storage.join("beta.age").is_file());

   let mut plan2 = plan;
   plan2.secrets.retain(|secret| secret.name != "beta");

   assert_eq!(
      ops::rekey::run(
         slice::from_ref(&plan2),
         &fixture.repo_root,
         &fixture.manifest
      )
      .unwrap(),
      0
   );
   assert!(fixture.local_storage.join("alpha.age").is_file());
   assert!(!fixture.local_storage.join("beta.age").exists());
   let manifest = Manifest::load(&fixture.manifest).unwrap();
   let host = &manifest.hosts["testhost"];
   assert!(host.secrets.contains_key("alpha"));
   assert!(!host.secrets.contains_key("beta"));
}

#[test]
fn orphan_sweep_recurses_into_nested_storage_dirs() {
   let fixture = fixture(&["alpha"]);
   let mut plan = fixture.plan();
   plan.secrets[0].output_file = PathBuf::from(format!("{STORAGE_REL}/nested/alpha.age"));

   let owned = fixture.repo_root.join(&plan.secrets[0].output_file);
   let orphan = fixture
      .repo_root
      .join(format!("{STORAGE_REL}/nested/stale.age"));
   fs::create_dir_all(owned.parent().unwrap()).unwrap();
   fs::write(&owned, b"owned ciphertext").unwrap();
   fs::write(&orphan, b"stale ciphertext").unwrap();

   assert_eq!(ops::sweep_orphans(&plan, &fixture.repo_root).unwrap(), 1);
   assert!(owned.is_file(), "owned nested output should remain");
   assert!(!orphan.exists(), "nested orphan output should be removed");
}

#[test]
fn multi_host_manifest_preserves_other_host_sections() {
   let fixture = fixture(&["alpha"]);
   let plan = fixture.plan();
   assert_eq!(
      ops::rekey::run(
         slice::from_ref(&plan),
         &fixture.repo_root,
         &fixture.manifest
      )
      .unwrap(),
      0
   );

   let mut manifest = Manifest::load(&fixture.manifest).unwrap();
   manifest.hosts.insert("other-host".into(), HostSection {
      host_pubkey_sha256: "deadbeef".into(),
      master_set_sha256:  "cafebabe".into(),
      secrets:            BTreeMap::from([("k".into(), SecretFingerprint {
         source_sha256: "11".into(),
         output_file:   "hosts/other-host/secrets/k.age".into(),
         output_sha256: "22".into(),
      })]),
   });
   manifest.write_atomic(&fixture.manifest).unwrap();
   assert_eq!(
      ops::rekey::run(
         slice::from_ref(&plan),
         &fixture.repo_root,
         &fixture.manifest
      )
      .unwrap(),
      0
   );

   let updated_manifest = Manifest::load(&fixture.manifest).unwrap();
   let other = updated_manifest
      .hosts
      .get("other-host")
      .expect("other-host section preserved");
   assert_eq!(other.host_pubkey_sha256, "deadbeef");
   assert_eq!(
      other.secrets["k"].output_file,
      PathBuf::from("hosts/other-host/secrets/k.age")
   );
}

#[test]
fn two_hosts_sharing_one_source_each_get_their_own_output() {
   let workdir = TempDir::new().unwrap();
   let repo_root = workdir.path().to_path_buf();
   let manifest = repo_root.join(MANIFEST_REL);

   let master = fresh_age_key();
   let master_id = write_identity_file(&repo_root, "master.txt", &master);
   let host_a = fresh_age_key();
   let host_b = fresh_age_key();

   let secret_plaintext = b"shared-secret-plaintext".as_slice();
   let source_rel = PathBuf::from("secrets/shared.age");
   let source_abs = repo_root.join(&source_rel);
   fs::create_dir_all(source_abs.parent().unwrap()).unwrap();
   fs::write(
      &source_abs,
      encrypt_with(&[&master.recipient], secret_plaintext),
   )
   .unwrap();

   let storage_host_a = "hosts/host-a/secrets";
   let storage_host_b = "hosts/host-b/secrets";
   fs::create_dir_all(repo_root.join(storage_host_a)).unwrap();
   fs::create_dir_all(repo_root.join(storage_host_b)).unwrap();

   let make_plan = |host: &AgeKey, label: &str, storage_rel: &str| {
      Plan {
         host_pubkey:       host.recipient.to_string(),
         host_label:        label.into(),
         master_identities: vec![MasterIdentity {
            identity: master_id.clone(),
            pubkey:   master.recipient.to_string(),
         }],
         secrets:           vec![SecretEntry {
            name:        "shared".into(),
            rekey_file:  source_rel.clone(),
            output_file: PathBuf::from(format!("{storage_rel}/shared.age")),
         }],
         local_storage_dir: PathBuf::from(storage_rel),
         manifest_file:     PathBuf::from(MANIFEST_REL),
         age_plugins:       vec![],
      }
   };
   let plan_a = make_plan(&host_a, "host-a", storage_host_a);
   let plan_b = make_plan(&host_b, "host-b", storage_host_b);

   assert_eq!(
      ops::rekey::run(&[plan_a, plan_b], &repo_root, &manifest).unwrap(),
      0
   );

   let out_a = repo_root.join(storage_host_a).join("shared.age");
   let out_b = repo_root.join(storage_host_b).join("shared.age");
   assert!(out_a.is_file());
   assert!(out_b.is_file());
   assert_eq!(
      decrypt_with(&host_a.identity, &fs::read(&out_a).unwrap()),
      secret_plaintext
   );
   assert_eq!(
      decrypt_with(&host_b.identity, &fs::read(&out_b).unwrap()),
      secret_plaintext
   );
   let loaded = Manifest::load(&manifest).unwrap();
   assert!(loaded.hosts.contains_key("host-a"));
   assert!(loaded.hosts.contains_key("host-b"));
}

#[test]
fn skip_run_does_not_rewrite_manifest() {
   let fixture = fixture(&["alpha"]);
   let plan = fixture.plan();
   assert_eq!(
      ops::rekey::run(
         slice::from_ref(&plan),
         &fixture.repo_root,
         &fixture.manifest
      )
      .unwrap(),
      0
   );
   let mtime_before = fs::metadata(&fixture.manifest).unwrap().modified().unwrap();
   thread::sleep(Duration::from_millis(10));
   assert_eq!(
      ops::rekey::run(
         slice::from_ref(&plan),
         &fixture.repo_root,
         &fixture.manifest
      )
      .unwrap(),
      0
   );
   let mtime_after = fs::metadata(&fixture.manifest).unwrap().modified().unwrap();
   assert_eq!(
      mtime_before, mtime_after,
      "manifest should not be rewritten when nothing changed"
   );
}

#[test]
fn divergent_master_sets_for_shared_source_are_rejected() {
   let workdir = TempDir::new().unwrap();
   let repo_root = workdir.path().to_path_buf();
   let manifest = repo_root.join(MANIFEST_REL);

   let master_alpha = fresh_age_key();
   let master_beta = fresh_age_key();
   let master_alpha_path = write_identity_file(&repo_root, "master-alpha.txt", &master_alpha);
   let master_beta_path = write_identity_file(&repo_root, "master-beta.txt", &master_beta);
   let host_alpha = fresh_age_key();
   let host_beta = fresh_age_key();

   let source_rel = PathBuf::from("secrets/shared.age");
   let source_abs = repo_root.join(&source_rel);
   fs::create_dir_all(source_abs.parent().unwrap()).unwrap();
   fs::write(
      &source_abs,
      encrypt_with(
         &[&master_alpha.recipient, &master_beta.recipient],
         b"plaintext",
      ),
   )
   .unwrap();

   let storage_alpha_rel = "hosts/alpha/secrets";
   let storage_beta_rel = "hosts/beta/secrets";
   fs::create_dir_all(repo_root.join(storage_alpha_rel)).unwrap();
   fs::create_dir_all(repo_root.join(storage_beta_rel)).unwrap();

   let make_plan = |host: &AgeKey,
                    label: &str,
                    master_path: &Path,
                    master: &AgeKey,
                    storage_rel: &str|
    -> Plan {
      Plan {
         host_pubkey:       host.recipient.to_string(),
         host_label:        label.into(),
         master_identities: vec![MasterIdentity {
            identity: master_path.to_path_buf(),
            pubkey:   master.recipient.to_string(),
         }],
         secrets:           vec![SecretEntry {
            name:        "shared".into(),
            rekey_file:  source_rel.clone(),
            output_file: PathBuf::from(format!("{storage_rel}/shared.age")),
         }],
         local_storage_dir: PathBuf::from(storage_rel),
         manifest_file:     PathBuf::from(MANIFEST_REL),
         age_plugins:       vec![],
      }
   };
   let plan_alpha = make_plan(
      &host_alpha,
      "host-alpha",
      &master_alpha_path,
      &master_alpha,
      storage_alpha_rel,
   );
   let plan_beta = make_plan(
      &host_beta,
      "host-beta",
      &master_beta_path,
      &master_beta,
      storage_beta_rel,
   );

   let err = ops::rekey::run(&[plan_alpha, plan_beta], &repo_root, &manifest).unwrap_err();
   let msg = err.to_string();
   assert!(
      msg.contains("different master sets"),
      "expected master-set divergence error, got: {msg}"
   );
}

#[test]
fn cache_hit_run_does_not_require_identity_files() {
   let fixture = fixture(&["alpha"]);
   let plan = fixture.plan();
   assert_eq!(
      ops::rekey::run(
         slice::from_ref(&plan),
         &fixture.repo_root,
         &fixture.manifest
      )
      .unwrap(),
      0
   );

   fs::remove_file(&fixture.master_id).unwrap();

   assert_eq!(
      ops::rekey::run(
         slice::from_ref(&plan),
         &fixture.repo_root,
         &fixture.manifest
      )
      .unwrap(),
      0,
      "cache-hit run should not require identity files"
   );
}

#[test]
fn unreadable_source_purges_outputs_and_fails_loud() {
   let fixture = fixture(&["alpha", "beta"]);
   let plan = fixture.plan();
   assert_eq!(
      ops::rekey::run(
         slice::from_ref(&plan),
         &fixture.repo_root,
         &fixture.manifest
      )
      .unwrap(),
      0
   );

   let manifest_before = Manifest::load(&fixture.manifest).unwrap();
   let out_alpha = fixture.local_storage.join("alpha.age");
   assert!(out_alpha.is_file());

   fs::remove_file(&fixture.sources[0].abs).unwrap();

   let result = ops::rekey::run(
      slice::from_ref(&plan),
      &fixture.repo_root,
      &fixture.manifest,
   );
   assert!(
      !out_alpha.exists(),
      "stale output should be purged on classify failure"
   );
   if let Ok(failures) = result {
      assert!(failures >= 1, "unreadable source should count as a failure");
      let manifest_after = Manifest::load(&fixture.manifest).unwrap();
      let host = &manifest_after.hosts["testhost"];
      assert!(!host.secrets.contains_key("alpha"));
      assert!(host.secrets.contains_key("beta"));
   } else {
      let manifest_after = Manifest::load(&fixture.manifest).unwrap();
      assert_eq!(manifest_after, manifest_before);
   }
}
