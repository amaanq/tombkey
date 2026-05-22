//! Decrypt a source secret to stdout.

use std::{
   io::{
      self,
      Write as _,
   },
   path::Path,
};

use crate::{
   error::{
      Error,
      Result,
   },
   ops,
   plan::Plan,
};

pub fn run(plans: &[Plan], repo_root: &Path, secret_path: &Path) -> Result<()> {
   let (_, _, _, plaintext) = ops::load_canonical_plaintext(plans, repo_root, secret_path, false)?;
   io::stdout()
      .write_all(&plaintext)
      .map_err(|err| Error::Storage(format!("write stdout: {err}")))?;
   Ok(())
}
