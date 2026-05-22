//! Encrypt to one or more age recipients. Plugin recipients are grouped by
//! plugin name so each plugin binary spawns exactly once per encrypt call.

use std::{
   collections::BTreeMap,
   io::Write as _,
   str::FromStr as _,
};

use age::{
   Encryptor,
   Recipient,
   plugin,
   ssh,
   x25519,
};

use crate::{
   age::callbacks::TracingCallbacks,
   error::{
      Error,
      Result,
   },
};

pub fn encrypt(plaintext: &[u8], recipient_strs: &[&str]) -> Result<Vec<u8>> {
   if recipient_strs.is_empty() {
      return Err(Error::Encrypt("at least one recipient is required".into()));
   }

   let mut recipients = Vec::<Box<dyn Recipient>>::new();
   let mut plugin_by_name = BTreeMap::<String, Vec<plugin::Recipient>>::new();
   for value in recipient_strs {
      if let Ok(recipient) = x25519::Recipient::from_str(value) {
         recipients.push(Box::new(recipient));
         continue;
      }
      if let Ok(recipient) = ssh::Recipient::from_str(value) {
         recipients.push(Box::new(recipient));
         continue;
      }
      if let Ok(recipient) = plugin::Recipient::from_str(value) {
         plugin_by_name
            .entry(recipient.plugin().to_owned())
            .or_default()
            .push(recipient);
         continue;
      }
      return Err(Error::Encrypt(format!("not a valid recipient: {value:?}")));
   }

   for (plugin_name, recipients_for_plugin) in plugin_by_name {
      let bundle = plugin::RecipientPluginV1::new(
         &plugin_name,
         &recipients_for_plugin,
         &[],
         TracingCallbacks,
      )
      .map_err(|err| Error::Encrypt(format!("plugin {plugin_name:?} init: {err}")))?;
      recipients.push(Box::new(bundle));
   }

   let encryptor = Encryptor::with_recipients(
      recipients
         .iter()
         .map(|recipient| recipient.as_ref() as &dyn age::Recipient),
   )
   .map_err(|err| Error::Encrypt(format!("encryptor init: {err}")))?;
   let mut out = Vec::<u8>::new();
   let mut writer = encryptor
      .wrap_output(&mut out)
      .map_err(|err| Error::Encrypt(format!("wrap_output: {err}")))?;
   writer
      .write_all(plaintext)
      .map_err(|err| Error::Encrypt(format!("write: {err}")))?;
   writer
      .finish()
      .map_err(|err| Error::Encrypt(format!("finish: {err}")))?;
   Ok(out)
}
