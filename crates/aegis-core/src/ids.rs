//! Strongly-typed identifiers.
//!
//! Every identifier is a newtype over a UUID so the type system prevents, for
//! example, passing a [`ProfileId`] where a [`VmId`] is expected. Instance IDs
//! are generated locally and are deliberately unrelated to any host identifier
//! (spec §4: "losowy identyfikator instancji VM generowany lokalnie").

use std::fmt;
use uuid::Uuid;

macro_rules! typed_id {
    ($(#[$meta:meta])* $name:ident, $prefix:literal) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
        #[serde(transparent)]
        pub struct $name(Uuid);

        impl $name {
            /// Generate a fresh, random identifier (UUIDv4).
            #[must_use]
            pub fn new() -> Self {
                Self(Uuid::new_v4())
            }

            /// Wrap an existing UUID.
            #[must_use]
            pub const fn from_uuid(id: Uuid) -> Self {
                Self(id)
            }

            /// The underlying UUID.
            #[must_use]
            pub const fn as_uuid(&self) -> &Uuid {
                &self.0
            }

            /// A short, stable, human-facing slug (prefix + first 8 hex chars).
            /// Used in logs and libvirt domain names. Contains no host data.
            #[must_use]
            pub fn slug(&self) -> String {
                let hex = self.0.simple().to_string();
                format!("{}-{}", $prefix, &hex[..8])
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}", self.0)
            }
        }

        impl std::str::FromStr for $name {
            type Err = crate::Error;
            fn from_str(s: &str) -> crate::Result<Self> {
                Uuid::parse_str(s)
                    .map(Self)
                    .map_err(|e| crate::Error::Config(format!(concat!("invalid ", stringify!($name), ": {}"), e)))
            }
        }
    };
}

typed_id!(
    /// Identifies a browsing profile (ephemeral or persistent).
    ProfileId, "prof"
);
typed_id!(
    /// Identifies a virtual machine instance (gateway or browser).
    VmId, "vm"
);
typed_id!(
    /// Identifies a single private-browsing session (one gateway + one browser VM).
    SessionId, "sess"
);
typed_id!(
    /// A per-boot random instance identifier, never derived from host state.
    InstanceId, "inst"
);

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn roundtrip_display_parse() {
        let id = ProfileId::new();
        let parsed = ProfileId::from_str(&id.to_string()).unwrap();
        assert_eq!(id, parsed);
    }

    #[test]
    fn slug_is_prefixed_and_short() {
        let id = VmId::new();
        let slug = id.slug();
        assert!(slug.starts_with("vm-"));
        assert_eq!(slug.len(), "vm-".len() + 8);
    }

    #[test]
    fn ids_are_unique() {
        assert_ne!(SessionId::new(), SessionId::new());
    }
}
