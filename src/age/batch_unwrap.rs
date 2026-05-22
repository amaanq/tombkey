//! Unwrap many sources' file keys in one age-plugin session.
//!
//! Bypasses `age::Decryptor`'s per-file plugin spawn while still letting age
//! handle payload decryption from the recovered file keys.

use std::{
   fs,
   io,
   iter,
   path::{
      Path,
      PathBuf,
   },
};

use age_core::{
   format::{
      FILE_KEY_BYTES,
      FileKey,
      Stanza,
      read::age_stanza,
   },
   plugin::{
      Connection,
      IDENTITY_V1,
   },
};
use tracing::{
   info,
   warn,
};

// Mirrored from age-plugin-fido2-hmac to avoid linking CTAP/HID deps here.

/// Stanza tag; filters out native X25519 stanzas.
const PLUGIN_TAG: &str = "fido2-hmac";
/// Identity HRP prefix for this plugin.
const IDENTITY_PREFIX: &str = "AGE-PLUGIN-FIDO2-HMAC-";
/// Binary name the plugin installs as.
const PLUGIN_BINARY: &str = "age-plugin-fido2-hmac";

// age identity-v1 command tags; not exported by age.
const CMD_ADD_IDENTITY: &str = "add-identity";
const CMD_RECIPIENT_STANZA: &str = "recipient-stanza";
const CMD_MSG: &str = "msg";
const CMD_CONFIRM: &str = "confirm";
const CMD_REQUEST_PUBLIC: &str = "request-public";
const CMD_REQUEST_SECRET: &str = "request-secret";
const CMD_FILE_KEY: &str = "file-key";
const CMD_ERROR: &str = "error";

const AGE_V1_PREFIX: &[u8] = b"age-encryption.org/v1\n";

/// Locate the plugin binary in one of the plan's `age_plugins` dirs.
pub fn find_plugin_binary(plugin_dirs: &[PathBuf]) -> Option<PathBuf> {
   plugin_dirs
      .iter()
      .map(|dir| dir.join(PLUGIN_BINARY))
      .find(|path| path.is_file())
}

/// Parse a source's age header into its `fido2-hmac` stanzas (others ignored).
fn plugin_stanzas(ciphertext: &[u8]) -> Vec<Stanza> {
   let Some(mut input) = ciphertext.strip_prefix(AGE_V1_PREFIX) else {
      return Vec::new();
   };
   let mut stanzas = Vec::new();
   while !input.starts_with(b"---") {
      match age_stanza(input) {
         Ok((rest, parsed)) => {
            let stanza = Stanza::from(parsed);
            if stanza.tag == PLUGIN_TAG {
               stanzas.push(stanza);
            }
            input = rest;
         },
         Err(_) => break,
      }
   }
   stanzas
}

/// Read the fido2-hmac plugin identity strings from the master identity files
/// (the non-comment lines whose HRP targets this plugin).
fn plugin_identities(identity_files: &[&Path]) -> io::Result<Vec<String>> {
   let mut out = Vec::new();
   for path in identity_files {
      let contents = fs::read_to_string(path)?;
      for line in contents.lines() {
         let trimmed = line.trim();
         if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
         }
         if trimmed.to_ascii_uppercase().starts_with(IDENTITY_PREFIX) {
            out.push(trimmed.to_owned());
         }
      }
   }
   Ok(out)
}

/// One identity-v1 session over the whole batch.
fn unwrap_once(
   ciphertexts: &[&[u8]],
   identity_files: &[&Path],
   plugin_binary: &Path,
) -> io::Result<Vec<Option<FileKey>>> {
   // Skip sources with no fido2-hmac stanzas: age-plugin's wire validator rejects
   // any gap in file indices, so an x25519/ssh-only source between fido2 ones
   // would abort the whole session. Send only eligible sources at contiguous
   // batch indices and remap on receive; skipped sources stay `None` so the
   // caller's per-file fallback handles them.
   let mut eligible_stanzas = Vec::<Vec<Stanza>>::new();
   let mut orig_indices = Vec::<usize>::new();
   for (i, ct) in ciphertexts.iter().enumerate() {
      let stanzas = plugin_stanzas(ct);
      if !stanzas.is_empty() {
         orig_indices.push(i);
         eligible_stanzas.push(stanzas);
      }
   }
   let identities = plugin_identities(identity_files)?;

   let mut conn = Connection::open(plugin_binary, IDENTITY_V1)?;

   conn.unidir_send(|mut phase| {
      for identity in &identities {
         phase.send(CMD_ADD_IDENTITY, &[identity.as_str()], &[])?;
      }
      for (batch_idx, stanzas) in eligible_stanzas.iter().enumerate() {
         let index_arg = batch_idx.to_string();
         for stanza in stanzas {
            phase.send_stanza(CMD_RECIPIENT_STANZA, &[index_arg.as_str()], stanza)?;
         }
      }
      Ok(())
   })?;

   let mut results = iter::repeat_with(|| None)
      .take(ciphertexts.len())
      .collect::<Vec<Option<FileKey>>>();
   conn.bidir_receive(
      &[
         CMD_MSG,
         CMD_CONFIRM,
         CMD_REQUEST_PUBLIC,
         CMD_REQUEST_SECRET,
         CMD_FILE_KEY,
         CMD_ERROR,
      ],
      |command, reply| match command.tag.as_str() {
         CMD_MSG => {
            info!("{}", String::from_utf8_lossy(&command.body));
            reply.ok(None)
         },
         // `fail` aborts the session; ACK and leave this slot empty.
         CMD_ERROR => {
            warn!(error = %String::from_utf8_lossy(&command.body), "plugin reported a source failure");
            reply.ok(None)
         },
         CMD_FILE_KEY => {
            let batch_idx = command
               .args
               .first()
               .filter(|_| command.args.len() == 1)
               .and_then(|arg| arg.parse::<usize>().ok());
            if let Some(idx) = batch_idx
               && command.body.len() == FILE_KEY_BYTES
               && let Some(&orig) = orig_indices.get(idx)
               && let Some(slot) = results.get_mut(orig)
               && slot.is_none()
            {
               *slot = Some(FileKey::init_with_mut(|out| out.copy_from_slice(&command.body)));
            } else {
               warn!(
                  args = ?command.args,
                  body_len = command.body.len(),
                  "plugin returned an unusable file-key command"
               );
            }
            reply.ok(None)
         },
         // confirm / request-public / request-secret: no TTY in batch mode.
         _ => reply.fail(),
      },
   )?;

   Ok(results)
}

/// Unwrap file keys in one plugin session; retry only whole-session failures.
pub fn unwrap_file_keys(
   ciphertexts: &[&[u8]],
   identity_files: &[&Path],
   plugin_binary: &Path,
) -> io::Result<Vec<Option<FileKey>>> {
   const ATTEMPTS: u32 = 3;
   let mut last_err = None;
   for attempt in 1..=ATTEMPTS {
      match unwrap_once(ciphertexts, identity_files, plugin_binary) {
         Ok(results) => return Ok(results),
         Err(err) => {
            warn!(attempt, error = %err, "plugin session failed; retrying");
            last_err = Some(err);
         },
      }
   }
   Err(last_err.unwrap_or_else(|| io::Error::other("plugin session failed")))
}

#[cfg(test)]
mod tests {
   use super::*;

   #[test]
   fn extracts_only_fido2_hmac_stanzas_across_the_header() {
      // Two stanzas (one X25519, one fido2-hmac) then the MAC line. The
      // parser must walk past the foreign stanza, keep the plugin one with
      // its args intact, and stop at `---`.
      let header = b"age-encryption.org/v1\n\
         -> X25519 c29tZS1lcGhlbWVyYWwtc2hhcmU\n\
         QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo\n\
         -> fido2-hmac AAI c2hhcmU AA c2FsdA Y3JlZGlk\n\
         d3JhcHBlZC1maWxlLWtleQ\n\
         --- TUFD\n\
         \x00\x01\x02binary payload";

      let stanzas = plugin_stanzas(header);
      assert_eq!(stanzas.len(), 1, "exactly one fido2-hmac stanza");
      assert_eq!(stanzas[0].tag, PLUGIN_TAG);
      assert_eq!(stanzas[0].args, [
         "AAI", "c2hhcmU", "AA", "c2FsdA", "Y3JlZGlk"
      ]);
   }

   #[test]
   fn ignores_non_age_input() {
      assert!(plugin_stanzas(b"not an age file").is_empty());
      assert!(plugin_stanzas(b"").is_empty());
   }

   #[test]
   fn x25519_only_source_produces_no_plugin_stanzas() {
      // Sources keyed only to non-fido2 recipients (x25519 / ssh) must yield
      // empty `plugin_stanzas` so `unwrap_once` can filter them out of the wire
      // batch.
      let header = b"age-encryption.org/v1\n\
         -> X25519 c29tZS1lcGhlbWVyYWwtc2hhcmU\n\
         QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo\n\
         --- TUFD\n\
         \x00";
      assert!(plugin_stanzas(header).is_empty());
   }
}
