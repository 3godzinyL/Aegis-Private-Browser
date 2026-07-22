//! Daemon configuration loading.
//!
//! The daemon reads an [`aegis_core::config::AppConfig`] from a TOML file passed
//! with `--config`. If the path is absent or unreadable the daemon falls back to
//! [`AppConfig::default`] so it always starts (spec §3: the daemon is the
//! integration linchpin and must come up even before an operator has written a
//! config). A file that *exists* but is malformed is a hard
//! [`aegis_core::Error::Config`] — we never guess past corrupt configuration.

use aegis_core::config::AppConfig;
use aegis_core::{Error, Result};
use std::path::Path;

/// Load an [`AppConfig`] from a TOML file, falling back to the default when the
/// file does not exist.
///
/// # Errors
/// Returns [`Error::Config`] if the file exists but cannot be read or parsed.
pub fn load_config(path: &Path) -> Result<AppConfig> {
    match std::fs::read_to_string(path) {
        Ok(text) => toml::from_str(&text)
            .map_err(|e| Error::Config(format!("invalid config {}: {e}", path.display()))),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            tracing::warn!(
                path = %path.display(),
                "config file not found; using built-in defaults"
            );
            Ok(AppConfig::default())
        }
        Err(e) => Err(Error::Config(format!(
            "cannot read config {}: {e}",
            path.display()
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_file_falls_back_to_default() {
        let cfg = load_config(Path::new("/nonexistent/aegis/does-not-exist.toml")).unwrap();
        assert_eq!(cfg, AppConfig::default());
    }

    #[test]
    fn default_config_roundtrips_through_toml() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        let text = toml::to_string(&AppConfig::default()).unwrap();
        std::fs::write(&path, text).unwrap();
        let cfg = load_config(&path).unwrap();
        assert_eq!(cfg, AppConfig::default());
    }

    #[test]
    fn malformed_file_is_config_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bad.toml");
        std::fs::write(&path, "this is = = not valid toml {{").unwrap();
        let err = load_config(&path).unwrap_err();
        assert!(matches!(err, Error::Config(_)));
    }
}
