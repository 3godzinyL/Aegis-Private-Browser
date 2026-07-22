//! The command-execution abstraction used to drive external tools
//! (`virsh`, `qemu-img`) without hard-wiring `tokio::process` into the control
//! logic.
//!
//! [`LibvirtController`](crate::LibvirtController) is generic over a
//! [`CommandRunner`], so the isolation and lifecycle logic can be unit-tested
//! against a [`MockRunner`] that records calls and returns canned output —
//! no hypervisor, no VMs, and no `virsh` binary required.

use aegis_core::{Error, Result};
use async_trait::async_trait;
use std::sync::Mutex;

/// The captured result of running an external command.
///
/// This mirrors the useful subset of [`std::process::Output`] but is
/// constructible in tests and carries decoded, lossy UTF-8 strings so callers
/// do not have to re-decode raw bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandOutput {
    /// The process exit code, or `None` if the process was killed by a signal.
    pub status: Option<i32>,
    /// Captured standard output, lossily decoded as UTF-8.
    pub stdout: String,
    /// Captured standard error, lossily decoded as UTF-8.
    pub stderr: String,
}

impl CommandOutput {
    /// Construct a successful (exit code `0`) output with the given stdout.
    #[must_use]
    pub fn ok(stdout: impl Into<String>) -> Self {
        Self {
            status: Some(0),
            stdout: stdout.into(),
            stderr: String::new(),
        }
    }

    /// Construct a failed output with the given exit code and stderr.
    #[must_use]
    pub fn err(code: i32, stderr: impl Into<String>) -> Self {
        Self {
            status: Some(code),
            stdout: String::new(),
            stderr: stderr.into(),
        }
    }

    /// Whether the process exited successfully (exit code `0`).
    #[must_use]
    pub fn success(&self) -> bool {
        self.status == Some(0)
    }

    /// Trimmed stdout, convenient for parsing single-line tool output.
    #[must_use]
    pub fn stdout_trimmed(&self) -> &str {
        self.stdout.trim()
    }
}

/// An abstraction over "run an external program and capture its output".
///
/// Implementations must never panic on tool failure; a non-zero exit is
/// reported through the returned [`CommandOutput::status`], while an inability
/// to *spawn* the program at all is an [`Err`].
#[async_trait]
pub trait CommandRunner: Send + Sync {
    /// Run `program` with `args`, capturing stdout/stderr.
    ///
    /// # Errors
    /// Returns an error if the process could not be spawned (e.g. the binary is
    /// missing) or the platform does not support privileged system actions.
    async fn run(&self, program: &str, args: &[String]) -> Result<CommandOutput>;
}

/// The production runner: spawns real processes via `tokio::process`.
///
/// Because the privileged actions Aegis performs (`virsh`, `qemu-img` against a
/// system libvirt/KVM stack) only work on Linux, this runner returns
/// [`Error::Unsupported`] on non-Linux targets *at runtime* rather than failing
/// to compile. This keeps the whole workspace buildable on Windows/macOS while
/// making it impossible to silently "succeed" without the real toolchain.
#[derive(Debug, Default, Clone)]
pub struct SystemRunner {
    _private: (),
}

impl SystemRunner {
    /// Create a new system runner.
    #[must_use]
    pub fn new() -> Self {
        Self { _private: () }
    }
}

#[async_trait]
impl CommandRunner for SystemRunner {
    async fn run(&self, program: &str, args: &[String]) -> Result<CommandOutput> {
        #[cfg(target_os = "linux")]
        {
            use tokio::process::Command;
            // Note: we deliberately do NOT log `args`; a caller could pass paths
            // and the isolation model treats tool invocations as sensitive.
            let output = Command::new(program)
                .args(args)
                .output()
                .await
                .map_err(|e| Error::System(format!("failed to spawn {program}: {e}")))?;
            Ok(CommandOutput {
                status: output.status.code(),
                stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
                stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
            })
        }
        #[cfg(not(target_os = "linux"))]
        {
            // Keep the parameters "used" so the signature is identical on all
            // platforms without dead-code warnings.
            let _ = (program, args);
            Err(Error::Unsupported(
                "libvirt/QEMU control is only supported on Linux hosts".to_string(),
            ))
        }
    }
}

/// A single recorded invocation made against a [`MockRunner`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordedCall {
    /// The program that was invoked.
    pub program: String,
    /// The arguments passed to it.
    pub args: Vec<String>,
}

impl RecordedCall {
    /// Whether this call was `program` with exactly `args`.
    #[must_use]
    pub fn matches(&self, program: &str, args: &[&str]) -> bool {
        self.program == program
            && self
                .args
                .iter()
                .map(String::as_str)
                .eq(args.iter().copied())
    }

    /// Whether the joined command line contains `needle` (handy for assertions
    /// that don't care about exact argument boundaries).
    #[must_use]
    pub fn contains(&self, needle: &str) -> bool {
        self.args.iter().any(|a| a.contains(needle))
    }
}

/// How a [`MockRunner`] should respond to a given invocation.
type Responder = Box<dyn Fn(&str, &[String]) -> Result<CommandOutput> + Send + Sync>;

/// A test double that records every call and returns canned responses.
///
/// By default every call succeeds with empty output. Use [`MockRunner::with_responder`]
/// to install program-specific logic (for example, to make `virsh domstate`
/// return `running`, or to make one command fail so failure paths can be
/// exercised).
pub struct MockRunner {
    calls: Mutex<Vec<RecordedCall>>,
    responder: Responder,
}

impl std::fmt::Debug for MockRunner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MockRunner")
            .field("calls", &self.calls.lock().map(|c| c.len()).unwrap_or(0))
            .finish_non_exhaustive()
    }
}

impl Default for MockRunner {
    fn default() -> Self {
        Self::new()
    }
}

impl MockRunner {
    /// A mock runner where every command succeeds with empty output.
    #[must_use]
    pub fn new() -> Self {
        Self {
            calls: Mutex::new(Vec::new()),
            responder: Box::new(|_, _| Ok(CommandOutput::ok(""))),
        }
    }

    /// A mock runner using a custom responder closure that decides the output
    /// (or error) for each `(program, args)` pair.
    #[must_use]
    pub fn with_responder<F>(responder: F) -> Self
    where
        F: Fn(&str, &[String]) -> Result<CommandOutput> + Send + Sync + 'static,
    {
        Self {
            calls: Mutex::new(Vec::new()),
            responder: Box::new(responder),
        }
    }

    /// A snapshot of every recorded call, in order.
    #[must_use]
    pub fn calls(&self) -> Vec<RecordedCall> {
        self.calls.lock().expect("mock lock poisoned").clone()
    }

    /// The number of recorded calls.
    #[must_use]
    pub fn call_count(&self) -> usize {
        self.calls.lock().expect("mock lock poisoned").len()
    }

    /// Whether any recorded call was `program` with exactly `args`.
    #[must_use]
    pub fn was_called_with(&self, program: &str, args: &[&str]) -> bool {
        self.calls().iter().any(|c| c.matches(program, args))
    }

    /// Whether any recorded call to `program` contained `needle` anywhere in
    /// its argument list.
    #[must_use]
    pub fn any_arg_contains(&self, program: &str, needle: &str) -> bool {
        self.calls()
            .iter()
            .any(|c| c.program == program && c.contains(needle))
    }
}

#[async_trait]
impl CommandRunner for MockRunner {
    async fn run(&self, program: &str, args: &[String]) -> Result<CommandOutput> {
        self.calls
            .lock()
            .expect("mock lock poisoned")
            .push(RecordedCall {
                program: program.to_string(),
                args: args.to_vec(),
            });
        (self.responder)(program, args)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn mock_records_calls_and_returns_default_ok() {
        let mock = MockRunner::new();
        let out = mock.run("virsh", &["list".to_string()]).await.unwrap();
        assert!(out.success());
        assert_eq!(mock.call_count(), 1);
        assert!(mock.was_called_with("virsh", &["list"]));
    }

    #[tokio::test]
    async fn mock_responder_can_fail_and_branch_on_program() {
        let mock = MockRunner::with_responder(|program, args| {
            if program == "qemu-img" {
                Ok(CommandOutput::err(1, "boom"))
            } else if args.iter().any(|a| a == "domstate") {
                Ok(CommandOutput::ok("running\n"))
            } else {
                Ok(CommandOutput::ok(""))
            }
        });
        let img = mock.run("qemu-img", &["create".to_string()]).await.unwrap();
        assert!(!img.success());
        assert_eq!(img.stderr, "boom");

        let st = mock
            .run("virsh", &["domstate".to_string(), "vm-x".to_string()])
            .await
            .unwrap();
        assert_eq!(st.stdout_trimmed(), "running");
    }

    #[tokio::test]
    async fn recorded_call_matchers() {
        let mock = MockRunner::new();
        mock.run(
            "qemu-img",
            &["create".to_string(), "/tmp/overlay.qcow2".to_string()],
        )
        .await
        .unwrap();
        let call = &mock.calls()[0];
        assert!(call.matches("qemu-img", &["create", "/tmp/overlay.qcow2"]));
        assert!(call.contains("overlay"));
        assert!(mock.any_arg_contains("qemu-img", "overlay"));
    }

    #[cfg(not(target_os = "linux"))]
    #[tokio::test]
    async fn system_runner_is_unsupported_off_linux() {
        let runner = SystemRunner::new();
        let err = runner
            .run("virsh", &["list".to_string()])
            .await
            .unwrap_err();
        assert!(matches!(err, Error::Unsupported(_)));
    }
}
