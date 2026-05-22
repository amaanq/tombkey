//! Route age plugin `display_message` frames through tracing.

use age::{
   Callbacks,
   cli_common::UiCallbacks,
   secrecy::SecretString,
};
use tracing::info;

#[derive(Clone, Copy)]
pub struct TracingCallbacks;

impl Callbacks for TracingCallbacks {
   fn display_message(&self, message: &str) {
      info!("{message}");
   }

   fn confirm(&self, message: &str, yes_string: &str, no_string: Option<&str>) -> Option<bool> {
      UiCallbacks.confirm(message, yes_string, no_string)
   }

   fn request_public_string(&self, description: &str) -> Option<String> {
      UiCallbacks.request_public_string(description)
   }

   fn request_passphrase(&self, description: &str) -> Option<SecretString> {
      UiCallbacks.request_passphrase(description)
   }
}
