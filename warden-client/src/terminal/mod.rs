mod backend;
mod hook;
mod shell;

pub use backend::TerminalBackend;
pub use hook::{CommandExecutionEvent, CommandHookBridge};
pub use shell::{ShellKind, ShellSpec};

use std::path::PathBuf;

use crate::errors::Result;
use crate::platform::TerminalSize;
use crate::policy::PolicyDecision;
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver};

pub struct TerminalManager {
    backend: Box<dyn TerminalBackend>,
    hook_bridge: CommandHookBridge,
    event_rx: UnboundedReceiver<TerminalEvent>,
}

impl TerminalManager {
    pub fn new() -> Self {
        let (_tx, rx) = unbounded_channel();
        Self {
            backend: Box::new(backend::PtyBackend::default()),
            hook_bridge: CommandHookBridge::new(),
            event_rx: rx,
        }
    }

    pub fn start(
        &mut self,
        mut shell_spec: ShellSpec,
        cwd: PathBuf,
        env: Vec<(String, String)>,
        size: TerminalSize,
    ) -> Result<()> {
        let (event_tx, event_rx) = unbounded_channel();
        self.event_rx = event_rx;
        self.hook_bridge.install(&mut shell_spec)?;
        self.backend.start(shell_spec, cwd, env, size, event_tx)
    }

    pub async fn next_event(&mut self) -> TerminalEvent {
        tokio::select! {
            event = self.event_rx.recv() => event.unwrap_or(TerminalEvent::Exited(-1)),
            event = self.hook_bridge.next_event() => event,
        }
    }

    pub fn write_input(&mut self, bytes: &[u8]) -> Result<()> {
        self.backend.write_input(bytes)
    }

    pub fn resize(&mut self, cols: u16, rows: u16) -> Result<()> {
        self.backend.resize(cols, rows)
    }

    pub fn resolve_pending_command(&mut self, decision: PolicyDecision) -> Result<()> {
        self.hook_bridge.resolve_command(decision)
    }

    pub fn terminate(&mut self) -> Result<()> {
        self.backend.terminate()
    }
}

#[derive(Debug)]
pub enum TerminalEvent {
    Output(Vec<u8>),
    CommandReady(CommandExecutionEvent),
    Exited(i32),
}
