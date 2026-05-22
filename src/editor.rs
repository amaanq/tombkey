//! Tempfile + `$EDITOR` flow for secret editing.

#[cfg(test)] use std::path::Path;
use std::{
   env,
   fs,
   io::Write as _,
   path::PathBuf,
   process::Command,
   sync::atomic::{
      AtomicBool,
      Ordering,
   },
};

use secrecy::{
   ExposeSecret as _,
   SecretBox,
};
use tempfile::TempDir;
use zeroize::Zeroize as _;

use crate::{
   error::{
      Error,
      Result,
   },
   manifest::sha256_hex,
};

static ABORTED: AtomicBool = AtomicBool::new(false);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EditOutcome {
   Unchanged,
   Modified,
}

pub struct LoadedSecret {
   bytes:       SecretBox<Vec<u8>>,
   #[expect(dead_code, reason = "kept for Drop to unlink the tempdir")]
   tmpdir:      TempDir,
   path:        PathBuf,
   mlock_guard: MlockGuard,
}

/// A best-effort `mlock`. Failure only weakens swap-leak defence, so we
/// continue rather than abort.
struct MlockGuard {
   active: Option<(*const u8, usize)>,
}

/// SAFETY: The raw pointer is only passed back to [`region::unlock`].
unsafe impl Send for MlockGuard {}

impl MlockGuard {
   fn lock(bytes: &[u8]) -> Self {
      if bytes.is_empty() {
         return Self { active: None };
      }
      // `LoadedSecret` keeps this buffer alive while the guard exists.
      let locked = region::lock(bytes.as_ptr(), bytes.len()).is_ok();
      Self {
         active: locked.then_some((bytes.as_ptr(), bytes.len())),
      }
   }
}

impl Drop for MlockGuard {
   fn drop(&mut self) {
      if let Some((ptr, len)) = self.active.take() {
         let _ = region::unlock(ptr, len);
      }
   }
}

impl LoadedSecret {
   pub fn stage(plaintext: Vec<u8>, basename: &str) -> Result<Self> {
      let tmpdir = TempDir::new().map_err(|err| Error::Editor(format!("tempdir: {err}")))?;
      let path = tmpdir.path().join(basename);
      let mut file = fs::OpenOptions::new()
         .create(true)
         .write(true)
         .truncate(true)
         .mode_if_supported(0o600)
         .open(&path)
         .map_err(|err| Error::Editor(format!("open tempfile {}: {err}", path.display())))?;
      file
         .write_all(&plaintext)
         .map_err(|err| Error::Editor(format!("write tempfile: {err}")))?;
      file
         .sync_all()
         .map_err(|err| Error::Editor(format!("sync tempfile: {err}")))?;
      drop(file);

      let mlock_guard = MlockGuard::lock(&plaintext);
      let bytes = SecretBox::new(Box::new(plaintext));
      Ok(Self {
         bytes,
         tmpdir,
         path,
         mlock_guard,
      })
   }

   #[cfg(test)]
   fn path(&self) -> &Path {
      &self.path
   }

   #[must_use]
   pub fn bytes(&self) -> &[u8] {
      self.bytes.expose_secret()
   }

   /// Launch `$EDITOR` (or `vi`) and report whether contents changed.
   pub fn edit_in_editor(&mut self) -> Result<EditOutcome> {
      install_signal_handlers();
      ABORTED.store(false, Ordering::SeqCst);

      let editor = env::var_os("EDITOR").unwrap_or_else(|| "vi".into());
      let status = Command::new(&editor)
         .arg(&self.path)
         .status()
         .map_err(|err| Error::Editor(format!("spawn {}: {err}", editor.to_string_lossy())))?;
      if !status.success() {
         return Err(Error::Editor(format!(
            "{} exited with status {status}",
            editor.to_string_lossy()
         )));
      }
      if ABORTED.load(Ordering::SeqCst) {
         return Err(Error::Editor("edit aborted by signal".into()));
      }

      let before = sha256_hex(self.bytes.expose_secret());
      let mut after_bytes =
         fs::read(&self.path).map_err(|err| Error::Editor(format!("re-read tempfile: {err}")))?;
      let after = sha256_hex(&after_bytes);

      if before == after {
         after_bytes.zeroize();
         return Ok(EditOutcome::Unchanged);
      }

      self.mlock_guard = MlockGuard::lock(&after_bytes);
      self.bytes = SecretBox::new(Box::new(after_bytes));
      Ok(EditOutcome::Modified)
   }
}

impl Drop for LoadedSecret {
   fn drop(&mut self) {
      // Wipe on-disk plaintext before TempDir unlinks the file.
      if let Ok(metadata) = fs::metadata(&self.path)
         && let Ok(len) = usize::try_from(metadata.len())
         && len > 0
         && let Ok(mut file) = fs::OpenOptions::new().write(true).open(&self.path)
      {
         let zeros = vec![0_u8; len];
         let _ = file.write_all(&zeros);
         let _ = file.sync_all();
      }
   }
}

fn install_signal_handlers() {
   #[cfg(unix)]
   {
      use std::sync::Once;

      use nix::sys::signal::{
         SaFlags,
         SigAction,
         SigHandler,
         SigSet,
         Signal,
         sigaction,
      };

      static INIT: Once = Once::new();
      INIT.call_once(|| {
         extern "C" fn handler(_: libc::c_int) {
            ABORTED.store(true, Ordering::SeqCst);
         }
         let action = SigAction::new(
            SigHandler::Handler(handler),
            SaFlags::empty(),
            SigSet::empty(),
         );
         for sig in &[Signal::SIGINT, Signal::SIGTERM, Signal::SIGHUP] {
            // SAFETY: handler is async-signal-safe (just an atomic store).
            unsafe {
               let _ = sigaction(*sig, &action);
            }
         }
      });
   }
}

#[cfg(unix)]
trait OpenOptionsExt {
   fn mode_if_supported(&mut self, mode: u32) -> &mut Self;
}

#[cfg(unix)]
impl OpenOptionsExt for fs::OpenOptions {
   fn mode_if_supported(&mut self, mode: u32) -> &mut Self {
      use std::os::unix::fs::OpenOptionsExt as _;
      self.mode(mode)
   }
}

#[cfg(not(unix))]
trait OpenOptionsExt {
   fn mode_if_supported(&mut self, mode: u32) -> &mut Self;
}

#[cfg(not(unix))]
impl OpenOptionsExt for fs::OpenOptions {
   fn mode_if_supported(&mut self, _mode: u32) -> &mut Self {
      self
   }
}

#[cfg(test)]
mod tests {
   use super::*;

   #[test]
   fn stage_creates_tempfile_with_contents() {
      let secret = LoadedSecret::stage(b"hello".to_vec(), "secret.txt").unwrap();
      assert!(secret.path().is_file());
      assert_eq!(fs::read(secret.path()).unwrap(), b"hello");
      assert_eq!(secret.bytes(), b"hello");
   }

   #[test]
   fn drop_removes_tempfile() {
      let path = {
         let secret = LoadedSecret::stage(b"hello".to_vec(), "x.txt").unwrap();
         secret.path().to_path_buf()
      };
      assert!(
         !path.exists(),
         "tempfile {} still exists after drop",
         path.display()
      );
   }
}
