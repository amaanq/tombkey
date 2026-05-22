use std::{
   io::Read as _,
   path::{
      Path,
      PathBuf,
   },
   result,
};

use age::{
   DecryptError,
   Decryptor,
   Identity,
   IdentityFile,
   armor::ArmoredReader,
};
use age_core::{
   format::{
      FileKey,
      Stanza,
   },
   secrecy::ExposeSecret as _,
};

use crate::{
   age::callbacks::TracingCallbacks,
   error::{
      Error,
      Result,
   },
};

pub fn identities_from_files<I, P>(paths: I) -> Result<Vec<Box<dyn age::Identity>>>
where
   I: IntoIterator<Item = P>,
   P: AsRef<Path>,
{
   let mut identities = Vec::<Box<dyn age::Identity>>::new();
   let mut first_path = None::<PathBuf>;
   for entry in paths {
      let path = entry.as_ref();
      let owned = path.to_path_buf();
      if first_path.is_none() {
         first_path = Some(owned.clone());
      }
      let filename = path
         .to_str()
         .ok_or_else(|| {
            Error::Identity {
               path:    owned.clone(),
               message: "non-UTF-8 path".into(),
            }
         })?
         .to_owned();
      let file = IdentityFile::from_file(filename)
         .map_err(|err| {
            Error::Identity {
               path:    owned.clone(),
               message: format!("parse failed: {err}"),
            }
         })?
         .with_callbacks(TracingCallbacks);
      let mut loaded = file.into_identities().map_err(|err| {
         Error::Identity {
            path:    owned.clone(),
            message: format!("load failed: {err}"),
         }
      })?;
      identities.append(&mut loaded);
   }

   if identities.is_empty() {
      return Err(Error::Identity {
         path:    first_path.unwrap_or_default(),
         message: "no identities parsed".into(),
      });
   }
   Ok(identities)
}

/// Decrypt `ciphertext`. Returns a bare message on failure so callers can
/// attach the source path they know about.
pub fn decrypt(
   ciphertext: &[u8],
   identities: &[Box<dyn age::Identity>],
) -> result::Result<Vec<u8>, String> {
   // Wrap in ArmoredReader so ASCII-armored and raw-binary sources both work,
   // since the wrapper passes binary through.
   let decryptor = Decryptor::new(ArmoredReader::new(ciphertext))
      .map_err(|err| format!("decryptor init: {err}"))?;
   let mut reader = decryptor
      .decrypt(identities.iter().map(|i| i.as_ref() as &dyn age::Identity))
      .map_err(|err| format!("decrypt: {err}"))?;
   let mut plaintext = Vec::<u8>::new();
   reader
      .read_to_end(&mut plaintext)
      .map_err(|err| format!("read plaintext: {err}"))?;
   Ok(plaintext)
}

/// An [`age::Identity`] that yields an already-recovered file key, so the
/// payload decrypts without re-spawning the plugin.
struct PrecomputedKey(FileKey);

impl Identity for PrecomputedKey {
   fn unwrap_stanza(&self, _stanza: &Stanza) -> Option<result::Result<FileKey, DecryptError>> {
      Some(Ok(clone_file_key(&self.0)))
   }
}

fn clone_file_key(key: &FileKey) -> FileKey {
   FileKey::init_with_mut(|slot| slot.copy_from_slice(key.expose_secret()))
}

/// Decrypt a payload with a file key already recovered out-of-band. Bare
/// message on failure so the caller can attach the source path.
pub fn decrypt_with_file_key(
   ciphertext: &[u8],
   file_key: FileKey,
) -> result::Result<Vec<u8>, String> {
   let identities: [Box<dyn Identity>; 1] = [Box::new(PrecomputedKey(file_key))];
   decrypt(ciphertext, &identities)
}
