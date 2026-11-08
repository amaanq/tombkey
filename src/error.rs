use std::{
   error,
   fmt,
   io,
   path::PathBuf,
   process::ExitStatus,
   result,
};

use age::plugin::ResolveError;
use flub::Error;

use crate::{
   age::decrypt::DecryptFailure,
   manifest::CURRENT_VERSION,
};

pub type Result<T> = result::Result<T, Error>;

#[derive(Debug, Error)]
pub enum Error {
   #[error("{action}")]
   Io {
      action: &'static str,
      #[source]
      cause:  io::Error,
   },

   #[error("{action} {path}")]
   File {
      action: &'static str,
      path:   PathBuf,
      #[source]
      cause:  io::Error,
   },

   #[error("spawn {program}")]
   Spawn {
      program: String,
      #[source]
      cause:   io::Error,
   },

   #[error("parse plan")]
   ParsePlan(#[source] serde_json::Error),

   #[error("invalid plan: {0}")]
   InvalidPlan(String),

   #[error(
      "no flake.nix in any parent of {start}: run tombkey from inside your flake checkout, or \
       pass --repo-root <path> (or set TOMBKEY_REPO_ROOT)"
   )]
   NoFlake { start: PathBuf },

   #[error("plan discovery: {0}")]
   Discover(String),

   #[error("nix eval {target} failed:\n{stderr}")]
   NixEval { target: String, stderr: String },

   #[error("parse nix eval output of {target}")]
   ParseEval {
      target: String,
      #[source]
      cause:  serde_json::Error,
   },

   #[error("{action} manifest {path}")]
   Manifest {
      action: &'static str,
      path:   PathBuf,
      #[source]
      cause:  serde_json::Error,
   },

   #[error(
      "manifest {path} version {found} not supported (expected {})",
      CURRENT_VERSION
   )]
   ManifestVersion { path: PathBuf, found: u32 },

   #[error("identity path {path} is not UTF-8")]
   IdentityPath { path: PathBuf },

   #[error("load identity {path}")]
   Identity {
      path:  PathBuf,
      #[source]
      cause: age::DecryptError,
   },

   #[error("no identities in {path}")]
   NoIdentities { path: PathBuf },

   #[error("age decrypt failed for {path}")]
   Decrypt {
      path:  PathBuf,
      #[source]
      cause: DecryptFailure,
   },

   #[error("at least one recipient is required")]
   NoRecipients,

   #[error("not a valid recipient: {0:?}")]
   InvalidRecipient(String),

   #[error("init plugin {plugin:?}")]
   Plugin {
      plugin: String,
      #[source]
      cause:  ResolveError,
   },

   #[error("init encryptor")]
   Encryptor(#[source] age::EncryptError),

   #[error("write ciphertext")]
   WriteCiphertext(#[source] io::Error),

   #[error("{editor} exited with {status}")]
   EditorExit { editor: String, status: ExitStatus },

   #[error("edit aborted by signal")]
   EditAborted,

   #[error(
      "stale outputs could not be removed for failed secrets ({0}); refusing to commit manifest"
   )]
   StaleOutputs(String),

   #[error("{0} tombkey operations failed")]
   Aggregated(usize),
}

/// Formats an error and every source below it, joined by `: `.
pub struct Chain<'err>(pub &'err (dyn error::Error + 'static));

impl fmt::Display for Chain<'_> {
   fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
      write!(f, "{}", self.0)?;
      let mut cause = self.0.source();
      while let Some(inner) = cause {
         write!(f, ": {inner}")?;
         cause = inner.source();
      }
      Ok(())
   }
}
