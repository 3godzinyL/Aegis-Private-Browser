//! A scriptable [`CommandRunner`] mock for tests.
//!
//! [`MockRunner`] records every [`Command`] it is asked to run and replies with
//! a scripted [`CommandOutput`], so controller logic (kill-switch transitions,
//! fail-closed handling, tunnel-status mapping) can be exercised without a VM,
//! root, or real network. Programs can be matched by name so a test can, for
//! example, make `nft` succeed while `systemctl` fails.

use crate::runner::{Command, CommandOutput, CommandRunner};
use aegis_core::{Error, Result};
use std::collections::HashMap;
use std::sync::Mutex;

/// How the mock should respond to a matched command.
#[derive(Debug, Clone)]
pub enum MockResponse {
    /// Return this captured output.
    Output(CommandOutput),
    /// Fail as if the process could not be executed at all.
    Error(String),
}

impl MockResponse {
    /// A successful run with empty output.
    #[must_use]
    pub fn ok() -> Self {
        Self::Output(CommandOutput {
            code: Some(0),
            stdout: String::new(),
            stderr: String::new(),
        })
    }

    /// A successful run whose stdout is `stdout`.
    #[must_use]
    pub fn stdout(stdout: impl Into<String>) -> Self {
        Self::Output(CommandOutput {
            code: Some(0),
            stdout: stdout.into(),
            stderr: String::new(),
        })
    }

    /// A non-zero exit (a command that ran but failed).
    #[must_use]
    pub fn failure(code: i32, stderr: impl Into<String>) -> Self {
        Self::Output(CommandOutput {
            code: Some(code),
            stdout: String::new(),
            stderr: stderr.into(),
        })
    }
}

/// A recording, scriptable command runner.
#[derive(Debug, Default)]
pub struct MockRunner {
    /// Per-program scripted responses (matched on `Command::program`).
    by_program: Mutex<HashMap<String, MockResponse>>,
    /// The default response when no program-specific rule matches.
    default: Mutex<Option<MockResponse>>,
    /// Every command that was run, in order.
    calls: Mutex<Vec<Command>>,
}

impl MockRunner {
    /// A mock where every command succeeds with empty output.
    #[must_use]
    pub fn new() -> Self {
        Self {
            by_program: Mutex::new(HashMap::new()),
            default: Mutex::new(Some(MockResponse::ok())),
            calls: Mutex::new(Vec::new()),
        }
    }

    /// A mock with no default response; unmatched commands panic the test.
    #[must_use]
    pub fn strict() -> Self {
        Self {
            by_program: Mutex::new(HashMap::new()),
            default: Mutex::new(None),
            calls: Mutex::new(Vec::new()),
        }
    }

    /// Script `program` to reply with `resp`. Chainable.
    #[must_use]
    pub fn with(self, program: &str, resp: MockResponse) -> Self {
        self.by_program
            .lock()
            .unwrap()
            .insert(program.to_string(), resp);
        self
    }

    /// Set the fallback response used when no program rule matches. Chainable.
    #[must_use]
    pub fn with_default(self, resp: MockResponse) -> Self {
        *self.default.lock().unwrap() = Some(resp);
        self
    }

    /// Override a program's scripted response after construction.
    pub fn set(&self, program: &str, resp: MockResponse) {
        self.by_program
            .lock()
            .unwrap()
            .insert(program.to_string(), resp);
    }

    /// All commands run so far, in order.
    #[must_use]
    pub fn calls(&self) -> Vec<Command> {
        self.calls.lock().unwrap().clone()
    }

    /// Number of commands run.
    #[must_use]
    pub fn call_count(&self) -> usize {
        self.calls.lock().unwrap().len()
    }

    /// Whether any recorded command targeted `program`.
    #[must_use]
    pub fn ran_program(&self, program: &str) -> bool {
        self.calls
            .lock()
            .unwrap()
            .iter()
            .any(|c| c.program == program)
    }

    /// The stdin of the last command run against `program`, if any.
    #[must_use]
    pub fn last_stdin_for(&self, program: &str) -> Option<String> {
        self.calls
            .lock()
            .unwrap()
            .iter()
            .rev()
            .find(|c| c.program == program)
            .and_then(|c| c.stdin.clone())
    }
}

#[async_trait::async_trait]
impl CommandRunner for MockRunner {
    async fn run(&self, command: &Command) -> Result<CommandOutput> {
        self.calls.lock().unwrap().push(command.clone());

        let resp = {
            let by_program = self.by_program.lock().unwrap();
            match by_program.get(&command.program).cloned() {
                Some(r) => Some(r),
                // No program-specific rule: use the default (which is `None`
                // for a `strict()` mock, so unmatched commands panic).
                None => self.default.lock().unwrap().clone(),
            }
        };

        match resp {
            Some(MockResponse::Output(out)) => Ok(out),
            Some(MockResponse::Error(msg)) => Err(Error::System(msg)),
            None => panic!(
                "MockRunner (strict): no scripted response for '{}'",
                command.program
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn records_calls_and_returns_scripted_output() {
        let r = MockRunner::new().with("nft", MockResponse::stdout("done"));
        let out = r
            .run(&Command::new("nft", &["-f", "-"]).with_stdin("ruleset"))
            .await
            .unwrap();
        assert_eq!(out.stdout, "done");
        assert_eq!(r.call_count(), 1);
        assert!(r.ran_program("nft"));
        assert_eq!(r.last_stdin_for("nft").as_deref(), Some("ruleset"));
    }

    #[tokio::test]
    async fn program_specific_failure_isolated_from_default() {
        let r = MockRunner::new().with("systemctl", MockResponse::Error("no such unit".into()));
        // nft still succeeds via default.
        assert!(r.run(&Command::new("nft", &["-f", "-"])).await.is_ok());
        // systemctl fails.
        let err = r
            .run(&Command::new("systemctl", &["start", "tor"]))
            .await
            .unwrap_err();
        assert!(matches!(err, Error::System(_)));
    }

    #[tokio::test]
    #[should_panic(expected = "no scripted response")]
    async fn strict_panics_on_unscripted_command() {
        let r = MockRunner::strict();
        let _ = r.run(&Command::new("nft", &["-f", "-"])).await;
    }
}
