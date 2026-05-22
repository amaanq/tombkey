use std::{
   path::PathBuf,
   result,
};

pub type Result<T> = result::Result<T, Error>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
   #[error("plan parse: {0}")]
   PlanParse(#[from] serde_json::Error),

   #[error("invalid plan: {0}")]
   InvalidPlan(String),

   #[error("identity {path}: {message}")]
   Identity { path: PathBuf, message: String },

   #[error("age decrypt failed for {path}: {message}")]
   Decrypt { path: PathBuf, message: String },

   #[error("age encrypt failed: {0}")]
   Encrypt(String),

   #[error("storage: {0}")]
   Storage(String),

   #[error("editor: {0}")]
   Editor(String),

   #[error("{0} tombkey operations failed")]
   Aggregated(usize),
}
