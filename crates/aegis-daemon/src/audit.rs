//! Append-only, secret-free audit sinks (spec §3, §11
//! "bezpieczne logowanie zdarzeń").
//!
//! An [`aegis_core::traits::AuditSink`] appends one JSON line per
//! [`AuditRecord`]. Records are secret-free by construction (see
//! [`aegis_core::events`]); these sinks never add anything of their own, and
//! never log key material, credentials, full URLs, or host-identifying paths.
//!
//! Two implementations:
//!
//! * [`FileAuditSink`] — appends to the configured audit-log path on disk. Used
//!   in production. Opening/serialization failures fail closed (they are surfaced
//!   as an [`aegis_core::Error`]) rather than silently dropping the record.
//! * [`MemoryAuditSink`] — keeps the records in memory. Used by the integration
//!   tests to assert exactly which events (e.g. a `FailClosed` critical) were
//!   emitted, without touching the filesystem.

use aegis_core::events::AuditRecord;
use aegis_core::traits::AuditSink;
use aegis_core::{Error, Result};
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

/// A [`AuditSink`] that appends secret-free JSON lines to a file.
///
/// The parent directory is created on first write. Each record is serialized to
/// a single line (`AuditRecord::to_json_line`) and appended with a trailing
/// newline. Writes are serialized by an internal mutex so concurrent sessions
/// cannot interleave partial lines.
#[derive(Debug)]
pub struct FileAuditSink {
    path: PathBuf,
    guard: Mutex<()>,
}

impl FileAuditSink {
    /// Create a sink that appends to `path`. No I/O happens until the first
    /// [`AuditSink::record`] call.
    #[must_use]
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            guard: Mutex::new(()),
        }
    }

    /// The audit-log path this sink writes to.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl AuditSink for FileAuditSink {
    fn record(&self, record: &AuditRecord) -> Result<()> {
        // Serialize first: a serialization fault must not leave a half-written
        // line, and it is surfaced (fail-closed) rather than swallowed.
        let line = record.to_json_line()?;

        let _guard = self
            .guard
            .lock()
            .map_err(|_| Error::Internal("audit sink lock poisoned".into()))?;

        if let Some(parent) = self.path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)
                    .map_err(|e| Error::System(format!("audit: create log dir: {e}")))?;
            }
        }

        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .map_err(|e| Error::System(format!("audit: open log: {e}")))?;
        // One record per line.
        file.write_all(line.as_bytes())
            .and_then(|()| file.write_all(b"\n"))
            .map_err(|e| Error::System(format!("audit: append: {e}")))?;
        Ok(())
    }
}

/// An in-memory [`AuditSink`] for tests: keeps every record so a test can assert
/// exactly which events (and severities) were emitted.
#[derive(Debug, Default)]
pub struct MemoryAuditSink {
    records: Mutex<Vec<AuditRecord>>,
}

impl MemoryAuditSink {
    /// A fresh, empty sink.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// A snapshot of every recorded event, in order.
    #[must_use]
    pub fn records(&self) -> Vec<AuditRecord> {
        self.records.lock().expect("audit lock").clone()
    }

    /// The number of recorded events.
    #[must_use]
    pub fn len(&self) -> usize {
        self.records.lock().expect("audit lock").len()
    }

    /// Whether no events have been recorded.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl AuditSink for MemoryAuditSink {
    fn record(&self, record: &AuditRecord) -> Result<()> {
        // Prove the record serializes cleanly (and is secret-free by type) even
        // in memory, so a test sink has the same contract as the file one.
        let _ = record.to_json_line()?;
        self.records
            .lock()
            .map_err(|_| Error::Internal("audit sink lock poisoned".into()))?
            .push(record.clone());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_core::error::FailureClass;
    use aegis_core::events::{EventKind, Severity};
    use chrono::Utc;

    fn fail_closed_record() -> AuditRecord {
        AuditRecord::new(
            Utc::now(),
            Severity::Critical,
            EventKind::FailClosed {
                class: FailureClass::NetworkContainment,
                reason: "preflight blocked".into(),
            },
        )
    }

    #[test]
    fn memory_sink_records_in_order() {
        let sink = MemoryAuditSink::new();
        assert!(sink.is_empty());
        sink.record(&fail_closed_record()).unwrap();
        assert_eq!(sink.len(), 1);
        let rec = &sink.records()[0];
        assert_eq!(rec.severity, Severity::Critical);
    }

    #[test]
    fn file_sink_appends_json_lines() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested").join("audit.jsonl");
        let sink = FileAuditSink::new(&path);
        sink.record(&fail_closed_record()).unwrap();
        sink.record(&fail_closed_record()).unwrap();

        let contents = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = contents.lines().collect();
        assert_eq!(lines.len(), 2, "one JSON line per record");
        for line in lines {
            // Each line parses back as a record and mentions the event kind.
            let back: AuditRecord = serde_json::from_str(line).unwrap();
            assert_eq!(back.severity, Severity::Critical);
            assert!(line.contains("fail_closed"));
            // No secret material.
            assert!(!line.to_lowercase().contains("password"));
        }
    }
}
