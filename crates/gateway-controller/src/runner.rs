//! The command-execution abstraction the gateway controller uses to touch the
//! host: loading nftables rulesets, starting/probing the tunnel backend, etc.
//!
//! Every privileged action is funnelled through [`CommandRunner`] so that:
//!
//! * the [`SystemRunner`] can shell out with [`tokio::process::Command`] on
//!   Linux (and refuse, fail-closed, everywhere else); and
//! * tests can inject a [`MockRunner`](crate::MockRunner) and assert on the *exact* commands and
//!   stdin that would have been executed — no VM, no root, no network.
//!
//! Rules of the road:
//!
//! * Runners never log the contents of `stdin` (it may carry a ruleset, and we
//!   keep the network path free of anything that could leak configuration into
//!   logs — see the crate-level fail-closed note).
//! * A non-zero exit status is surfaced as an [`Error`] so the caller can apply
//!   fail-closed handling.

use aegis_core::{Error, Result};

/// A single command invocation: a program plus its arguments, optionally fed a
/// blob of standard input (used for `nft -f -`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Command {
    /// The program to execute (e.g. `nft`, `systemctl`).
    pub program: String,
    /// The arguments, already split (never a shell string).
    pub args: Vec<String>,
    /// Optional standard input piped to the process.
    pub stdin: Option<String>,
}

impl Command {
    /// Build a command from a program and its arguments.
    #[must_use]
    pub fn new(program: impl Into<String>, args: &[&str]) -> Self {
        Self {
            program: program.into(),
            args: args.iter().map(|s| (*s).to_string()).collect(),
            stdin: None,
        }
    }

    /// Attach standard input (consumed by the child on stdin).
    #[must_use]
    pub fn with_stdin(mut self, stdin: impl Into<String>) -> Self {
        self.stdin = Some(stdin.into());
        self
    }
}

/// The captured result of running a [`Command`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandOutput {
    /// The process exit code (`None` if terminated by a signal).
    pub code: Option<i32>,
    /// Captured standard output (UTF-8, lossily decoded).
    pub stdout: String,
    /// Captured standard error (UTF-8, lossily decoded).
    pub stderr: String,
}

impl CommandOutput {
    /// Whether the process exited successfully (status code `0`).
    #[must_use]
    pub const fn success(&self) -> bool {
        matches!(self.code, Some(0))
    }
}

/// Executes external commands on behalf of the gateway controller.
///
/// Implementations must be `Send + Sync` so the controller can be shared across
/// async tasks behind a trait object.
#[async_trait::async_trait]
pub trait CommandRunner: Send + Sync {
    /// Run `command`, returning its captured output.
    ///
    /// Returns [`Error::Unsupported`] on platforms that cannot perform the
    /// privileged action (everything except Linux), and [`Error::System`] if the
    /// process could not be spawned. A non-zero exit is reported *in*
    /// [`CommandOutput::code`] — callers decide whether that is fatal.
    async fn run(&self, command: &Command) -> Result<CommandOutput>;
}

/// The production runner: shells out with [`tokio::process::Command`].
///
/// On non-Linux hosts (including this Windows build machine) every call returns
/// [`Error::Unsupported`]: the privileged gateway actions (`nft`, `systemctl`,
/// Tor control) only exist inside the Linux Gateway VM, and returning an error
/// keeps the fail-closed contract — we never silently pretend a firewall was
/// applied.
#[derive(Debug, Default, Clone)]
pub struct SystemRunner;

impl SystemRunner {
    /// Construct a system runner.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

#[async_trait::async_trait]
impl CommandRunner for SystemRunner {
    #[cfg(target_os = "linux")]
    async fn run(&self, command: &Command) -> Result<CommandOutput> {
        use std::process::Stdio;
        use tokio::io::AsyncWriteExt;

        let mut cmd = tokio::process::Command::new(&command.program);
        cmd.args(&command.args)
            .stdin(if command.stdin.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        let mut child = cmd
            .spawn()
            .map_err(|e| Error::System(format!("spawn {}: {e}", command.program)))?;

        if let Some(input) = &command.stdin {
            let mut stdin = child
                .stdin
                .take()
                .ok_or_else(|| Error::System("child stdin unavailable".into()))?;
            stdin
                .write_all(input.as_bytes())
                .await
                .map_err(|e| Error::System(format!("write stdin: {e}")))?;
            // Drop closes the pipe so the child sees EOF.
            drop(stdin);
        }

        let output = child
            .wait_with_output()
            .await
            .map_err(|e| Error::System(format!("wait {}: {e}", command.program)))?;

        Ok(CommandOutput {
            code: output.status.code(),
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        })
    }

    #[cfg(not(target_os = "linux"))]
    async fn run(&self, command: &Command) -> Result<CommandOutput> {
        Err(Error::Unsupported(format!(
            "privileged gateway command '{}' is only available inside the Linux Gateway VM",
            command.program
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_builder_captures_program_args_and_stdin() {
        let c = Command::new("nft", &["-f", "-"]).with_stdin("table x {}");
        assert_eq!(c.program, "nft");
        assert_eq!(c.args, vec!["-f".to_string(), "-".to_string()]);
        assert_eq!(c.stdin.as_deref(), Some("table x {}"));
    }

    #[test]
    fn output_success_only_on_zero() {
        let ok = CommandOutput {
            code: Some(0),
            stdout: String::new(),
            stderr: String::new(),
        };
        let bad = CommandOutput {
            code: Some(1),
            stdout: String::new(),
            stderr: String::new(),
        };
        let sig = CommandOutput {
            code: None,
            stdout: String::new(),
            stderr: String::new(),
        };
        assert!(ok.success());
        assert!(!bad.success());
        assert!(!sig.success());
    }

    #[tokio::test]
    #[cfg(not(target_os = "linux"))]
    async fn system_runner_is_unsupported_off_linux() {
        let r = SystemRunner::new();
        let err = r.run(&Command::new("nft", &["-f", "-"])).await.unwrap_err();
        assert!(matches!(err, Error::Unsupported(_)));
    }
}
