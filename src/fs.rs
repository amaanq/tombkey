use std::{
   fs,
   io::{
      self,
      Write as _,
   },
   path::Path,
};

/// Atomically write `bytes` to `dst`. Creates the parent dir if missing.
pub fn write_atomic(dst: &Path, bytes: &[u8]) -> io::Result<()> {
   let parent = dst
      .parent()
      .ok_or_else(|| io::Error::other(format!("{} has no parent directory", dst.display())))?;
   fs::create_dir_all(parent)?;
   let mut tmp = tempfile::NamedTempFile::new_in(parent)?;
   tmp.write_all(bytes)?;
   tmp.as_file().sync_all()?;
   tmp.persist(dst).map_err(|err| err.error)?;
   sync_parent_dir(parent)?;
   Ok(())
}

#[cfg(unix)]
fn sync_parent_dir(parent: &Path) -> io::Result<()> {
   fs::File::open(parent)?.sync_all()
}

#[cfg(not(unix))]
const fn sync_parent_dir(_parent: &Path) -> io::Result<()> {
   Ok(())
}
