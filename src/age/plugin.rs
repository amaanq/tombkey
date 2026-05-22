//! Prepend the plan's plugin dirs to `$PATH` so age can spawn `age-plugin-*`
//! binaries.

use std::{
   env,
   ffi::OsString,
   path::Path,
};

/// RAII handle that restores the previous `$PATH` on drop.
pub struct PluginPath {
   previous: Option<OsString>,
}

impl PluginPath {
   /// Prepend plugin dirs to `$PATH` until the guard drops.
   ///
   /// # Panics
   ///
   /// Panics if any plugin path contains the platform path separator.
   #[must_use]
   pub fn install<P>(plugins: &[P]) -> Self
   where
      P: AsRef<Path>,
   {
      let previous = env::var_os("PATH");
      if plugins.is_empty() {
         return Self { previous };
      }

      let mut parts = plugins
         .iter()
         .map(|plugin_path| plugin_path.as_ref().into())
         .collect::<Vec<OsString>>();
      if let Some(current) = previous.as_ref() {
         for existing in env::split_paths(current) {
            parts.push(existing.into_os_string());
         }
      }
      let joined = env::join_paths(parts)
         .expect("PATH entries should not contain the platform path separator");

      // SAFETY: the CLI is single-threaded while this guard is active.
      unsafe {
         env::set_var("PATH", joined);
      }

      Self { previous }
   }
}

impl Drop for PluginPath {
   fn drop(&mut self) {
      match self.previous.take() {
         // SAFETY: see `Self::install`.
         Some(path) => unsafe { env::set_var("PATH", path) },
         // SAFETY: see `Self::install`.
         None => unsafe { env::remove_var("PATH") },
      }
   }
}

#[cfg(test)]
mod tests {
   use std::{
      path::PathBuf,
      slice,
   };

   use super::*;

   // Both cases share global $PATH state; one serial test avoids the race.
   #[test]
   fn install_and_drop_lifecycle() {
      let before = env::var_os("PATH");

      let empty: &[PathBuf] = &[];
      {
         let _guard = PluginPath::install(empty);
         assert_eq!(env::var_os("PATH"), before);
      }
      assert_eq!(env::var_os("PATH"), before);

      let plugin_dir = PathBuf::from("/tmp/tombkey-test-plugins");
      {
         let _guard = PluginPath::install(slice::from_ref(&plugin_dir));
         let now = env::var("PATH").unwrap();
         assert!(
            now.starts_with("/tmp/tombkey-test-plugins"),
            "expected prepended PATH, got {now:?}"
         );
      }
      assert_eq!(env::var_os("PATH"), before);
   }
}
