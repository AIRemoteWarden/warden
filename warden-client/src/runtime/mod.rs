mod event;
mod session;
mod state;

pub use event::{RuntimeEvent, ShutdownReason};
pub use session::{ActiveRedaction, InputOrigin, PendingApproval, SessionContext};
pub use state::RuntimeState;

use crate::ai::AiClient;
use crate::config::AppConfig;
use crate::errors::{AppError, Result};
use crate::platform::{PlatformContext, PlatformEvent, TerminalSize};
use crate::policy::{PolicyDecision, PolicyEngine};
use crate::terminal::{CommandExecutionEvent, HookCommandSet, TerminalEvent, TerminalManager};
use crate::transport::{TransportEvent, TransportManager};
use crate::ui::{ApprovalInputAction, UiRenderer};
use tokio::sync::oneshot;

pub struct AppRuntime {
    config: AppConfig,
    session: SessionContext,
    terminal: TerminalManager,
    transport: TransportManager,
    policy: PolicyEngine,
    ai: AiClient,
    platform: PlatformContext,
    ui: UiRenderer,
    state: RuntimeState,
    ai_assessment_rx: Option<oneshot::Receiver<std::result::Result<String, String>>>,
}

impl AppRuntime {
    pub fn new(
        config: AppConfig,
        platform: PlatformContext,
        terminal: TerminalManager,
        transport: TransportManager,
        policy: PolicyEngine,
        ai: AiClient,
        ui: UiRenderer,
    ) -> Self {
        Self {
            session: SessionContext::default(),
            state: RuntimeState::Booting,
            config,
            terminal,
            transport,
            policy,
            ai,
            platform,
            ui,
            ai_assessment_rx: None,
        }
    }

    pub async fn run(&mut self) -> Result<()> {
        self.bootstrap().await?;

        while self.state != RuntimeState::Closed {
            let event = self.next_event().await?;
            self.handle_event(event).await?;
        }

        Ok(())
    }

    async fn bootstrap(&mut self) -> Result<()> {
        self.transition(RuntimeState::CreatingSession)?;

        let created = self.transport.create_session(&self.config).await?;
        self.session.apply_created(created);

        self.transition(RuntimeState::StartingShell)?;

        let cwd = self.platform.current_dir()?;
        let env = self.platform.capture_env();
        let shell_spec = self
            .platform
            .detect_shell(self.config.options.preferred_shell.clone())?;
        let size = self.platform.terminal_size()?;
        let hook_commands = HookCommandSet::from_policy(&self.config.policy);

        self.session.cwd = cwd.clone();
        self.session.readonly = self.config.options.readonly;

        self.ui.show_session_started(&self.session.guest_url);
        self.platform.enter_raw_mode()?;
        self.terminal
            .start(shell_spec, cwd, env, size, &hook_commands)?;
        self.transport.connect_relay(&self.session).await?;
        self.transition(RuntimeState::AwaitingGuest)?;

        Ok(())
    }

    async fn next_event(&mut self) -> Result<RuntimeEvent> {
        let ai_event = async {
            if let Some(receiver) = self.ai_assessment_rx.as_mut() {
                match receiver.await {
                    Ok(result) => RuntimeEvent::AiAssessmentFinished(result),
                    Err(err) => RuntimeEvent::AiAssessmentFinished(Err(format!(
                        "ai task failed: {err}"
                    ))),
                }
            } else {
                std::future::pending::<RuntimeEvent>().await
            }
        };

        tokio::select! {
            event = ai_event => {
                self.ai_assessment_rx = None;
                Ok(event)
            },
            event = self.platform.next_event() => Ok(event.into()),
            event = self.terminal.next_event() => Ok(event.into()),
            event = self.transport.next_event() => Ok(event.into()),
        }
    }

    async fn handle_event(&mut self, event: RuntimeEvent) -> Result<()> {
        match self.state {
            RuntimeState::AwaitingGuest => self.handle_awaiting_guest(event).await,
            RuntimeState::Interactive => self.handle_interactive(event).await,
            RuntimeState::ApprovalPending => self.handle_approval_pending(event).await,
            RuntimeState::Disconnecting => self.handle_disconnecting(event).await,
            RuntimeState::Booting
            | RuntimeState::CreatingSession
            | RuntimeState::StartingShell
            | RuntimeState::Closed => Err(AppError::Invariant(
                "unexpected event while runtime is not interactive",
            )),
        }
    }

    fn transition(&mut self, next_state: RuntimeState) -> Result<()> {
        if self.state == RuntimeState::Closed {
            return Err(AppError::Invariant("closed runtime cannot transition"));
        }

        self.state = next_state;
        Ok(())
    }

    async fn handle_awaiting_guest(&mut self, event: RuntimeEvent) -> Result<()> {
        match event {
            RuntimeEvent::HostInput(bytes) => {
                self.forward_terminal_input(InputOrigin::Host, &bytes).await
            }
            RuntimeEvent::ShellOutput(bytes) => self.forward_shell_output(bytes).await,
            RuntimeEvent::GuestJoined => {
                self.session.guest_connected = true;
                self.best_effort_refresh_prompt_for_guest();
                self.transition(RuntimeState::Interactive)
            }
            RuntimeEvent::CommandReady(command) => self.handle_command_ready(command).await,
            RuntimeEvent::Resize(size) => self.apply_resize(size),
            RuntimeEvent::ShellExited(code) => self.shutdown(ShutdownReason::ShellExited(code)).await,
            RuntimeEvent::TransportClosed => self.shutdown(ShutdownReason::TransportClosed).await,
            RuntimeEvent::AiAssessmentFinished(_) => Ok(()),
            RuntimeEvent::GuestInput(_) => Ok(()),
            RuntimeEvent::GuestLeft => Ok(()),
        }
    }

    async fn handle_interactive(&mut self, event: RuntimeEvent) -> Result<()> {
        match event {
            RuntimeEvent::HostInput(bytes) => {
                self.forward_terminal_input(InputOrigin::Host, &bytes).await
            }
            RuntimeEvent::GuestInput(bytes) => {
                if self.session.readonly {
                    self.transport
                        .send_guest_feedback("session is read-only")
                        .await
                } else {
                    self.forward_terminal_input(InputOrigin::Guest, &bytes).await
                }
            }
            RuntimeEvent::ShellOutput(bytes) => self.forward_shell_output(bytes).await,
            RuntimeEvent::CommandReady(command) => self.handle_command_ready(command).await,
            RuntimeEvent::GuestJoined => {
                self.session.guest_connected = true;
                Ok(())
            }
            RuntimeEvent::GuestLeft => {
                self.session.guest_connected = false;
                self.transition(RuntimeState::AwaitingGuest)
            }
            RuntimeEvent::Resize(size) => self.apply_resize(size),
            RuntimeEvent::ShellExited(code) => self.shutdown(ShutdownReason::ShellExited(code)).await,
            RuntimeEvent::TransportClosed => self.shutdown(ShutdownReason::TransportClosed).await,
            RuntimeEvent::AiAssessmentFinished(_) => Ok(()),
        }
    }

    fn best_effort_refresh_prompt_for_guest(&mut self) {
        // Best-effort readline redraw for a newly joined guest. This only runs
        // while the shell is idle in AwaitingGuest, so Ctrl+L is a reasonable
        // way to surface the current prompt without waiting for manual input.
        let _ = self.terminal.write_input(&[0x0c]);
    }

    async fn handle_approval_pending(&mut self, event: RuntimeEvent) -> Result<()> {
        match event {
            RuntimeEvent::HostInput(bytes) => match self.collect_approval_input(&bytes) {
                ApprovalInputParse::Pending => {
                    if self.ai_assessment_rx.is_some() {
                        self.ui.show_ai_request_in_progress();
                        return Ok(());
                    }
                    self.ui
                        .render_approval_input(&self.session.approval_input_buffer);
                    Ok(())
                }
                ApprovalInputParse::Resolved(action) => self.handle_approval_action(action).await,
                ApprovalInputParse::Invalid => {
                    self.ui.show_invalid_approval_input();
                    Ok(())
                }
            },
            RuntimeEvent::GuestInput(_) => {
                self.transport.send_guest_feedback("waiting for approval").await
            }
            RuntimeEvent::ShellOutput(bytes) => self.forward_shell_output(bytes).await,
            RuntimeEvent::AiAssessmentFinished(result) => {
                let can_redact = self
                    .session
                    .pending_approval
                    .as_ref()
                    .and_then(|pending| pending.redaction_plan.as_ref())
                    .is_some();
                match result {
                    Ok(assessment) => self.ui.show_ai_assessment(&assessment, can_redact),
                    Err(err) => self.ui.show_ai_error(&err, can_redact),
                }
                Ok(())
            }
            RuntimeEvent::GuestLeft => {
                self.session.guest_connected = false;
                Ok(())
            }
            RuntimeEvent::Resize(size) => self.apply_resize(size),
            RuntimeEvent::ShellExited(code) => self.shutdown(ShutdownReason::ShellExited(code)).await,
            RuntimeEvent::TransportClosed => self.shutdown(ShutdownReason::TransportClosed).await,
            RuntimeEvent::GuestJoined | RuntimeEvent::CommandReady(_) => Ok(()),
        }
    }

    async fn handle_disconnecting(&mut self, event: RuntimeEvent) -> Result<()> {
        match event {
            RuntimeEvent::ShellExited(_) | RuntimeEvent::TransportClosed => {
                self.transition(RuntimeState::Closed)
            }
            _ => Ok(()),
        }
    }

    async fn handle_command_ready(&mut self, command: CommandExecutionEvent) -> Result<()> {
        let command_origin = self.session.pending_command_origin.take();
        self.session.last_input_origin = None;

        self.flush_active_redaction().await?;

        if !matches!(command_origin, Some(InputOrigin::Guest)) {
            return self.terminal.resolve_pending_command(PolicyDecision::Allow);
        }

        match self.policy.evaluate(&command, &self.session) {
            PolicyDecision::Allow => self.terminal.resolve_pending_command(PolicyDecision::Allow),
            PolicyDecision::Deny { reason: _ } => {
                self.terminal
                    .resolve_pending_command(PolicyDecision::Deny {
                        reason: "command denied".to_string(),
                    })?;
                self.transport.send_guest_feedback("command denied").await
            }
            PolicyDecision::RequireApproval { reason, risk } => {
                let redaction_plan = self.policy.redaction_plan_for(&command);
                self.session.approval_pending = true;
                self.session.pending_approval = Some(PendingApproval {
                    command: command.command.clone(),
                    reason: reason.clone(),
                    redaction_plan: redaction_plan.clone(),
                });
                self.ui
                    .show_approval_prompt(&command.command, &reason, redaction_plan.is_some());
                self.transport
                    .send_approval_state(&PolicyDecision::RequireApproval {
                        reason,
                        risk,
                    })
                    .await?;
                self.transition(RuntimeState::ApprovalPending)
            }
        }
    }

    async fn forward_shell_output(&mut self, bytes: Vec<u8>) -> Result<()> {
        self.ui.write_terminal_output(&bytes);

        let (outbound, finish_redaction) = if let Some(active) = self.session.active_redaction.as_mut() {
            active.process_bytes(&bytes)
        } else {
            (bytes, false)
        };

        if finish_redaction {
            self.session.active_redaction = None;
        }

        if outbound.is_empty() {
            return Ok(());
        }

        self.transport.send_terminal_bytes(&outbound).await
    }

    async fn finish_approval(&mut self, decision: PolicyDecision) -> Result<()> {
        self.terminal.resolve_pending_command(decision.clone())?;
        self.transport.send_approval_state(&decision).await?;
        self.session.active_redaction = None;

        self.session.approval_pending = false;
        self.session.approval_input_buffer.clear();
        self.session.pending_approval = None;
        self.ui.clear_approval_prompt();
        self.transition(RuntimeState::Interactive)
    }

    fn apply_resize(&mut self, size: TerminalSize) -> Result<()> {
        self.terminal.resize(size.cols, size.rows)?;
        self.transport.send_resize(size);
        Ok(())
    }

    async fn shutdown(&mut self, reason: ShutdownReason) -> Result<()> {
        if self.state == RuntimeState::Closed || self.state == RuntimeState::Disconnecting {
            return Ok(());
        }

        self.transition(RuntimeState::Disconnecting)?;
        self.platform.restore_terminal()?;
        self.ui.show_disconnect(&reason);
        let _ = self.flush_active_redaction().await;
        let _ = self.transport.close().await;
        let _ = self.terminal.terminate();
        self.transition(RuntimeState::Closed)
    }

    async fn forward_terminal_input(&mut self, origin: InputOrigin, bytes: &[u8]) -> Result<()> {
        self.flush_redaction_buffer().await?;
        self.record_input_origin(origin, bytes);
        self.terminal.write_input(bytes)
    }

    fn record_input_origin(&mut self, origin: InputOrigin, bytes: &[u8]) {
        for byte in bytes {
            match *byte {
                b'\r' | b'\n' => {
                    self.session.pending_command_origin =
                        Some(self.session.last_input_origin.unwrap_or(origin));
                }
                _ => {
                    self.session.last_input_origin = Some(origin);
                }
            }
        }
    }

    fn collect_approval_input(&mut self, bytes: &[u8]) -> ApprovalInputParse {
        for byte in bytes {
            match *byte {
                b'\r' | b'\n' => {
                    let action = self
                        .ui
                        .try_resolve_approval_input(&self.session.approval_input_buffer);
                    self.session.approval_input_buffer.clear();
                    return match action {
                        Some(action) => ApprovalInputParse::Resolved(action),
                        None => ApprovalInputParse::Invalid,
                    };
                }
                0x08 | 0x7f => {
                    self.session.approval_input_buffer.pop();
                }
                _ => self.session.approval_input_buffer.push(*byte),
            }
        }

        ApprovalInputParse::Pending
    }

    async fn handle_approval_action(&mut self, action: ApprovalInputAction) -> Result<()> {
        match action {
            ApprovalInputAction::Approve => self.finish_approval(PolicyDecision::Allow).await,
            ApprovalInputAction::Deny => {
                self.finish_approval(PolicyDecision::Deny {
                    reason: "host denied command".to_string(),
                })
                .await
            }
            ApprovalInputAction::Redact => self.finish_approval_with_redaction().await,
            ApprovalInputAction::AskAi => self.request_ai_assessment().await,
        }
    }

    async fn finish_approval_with_redaction(&mut self) -> Result<()> {
        let plan = self
            .session
            .pending_approval
            .as_ref()
            .and_then(|pending| pending.redaction_plan.clone());

        let Some(plan) = plan else {
            self.ui.show_redaction_unavailable();
            return Ok(());
        };

        self.terminal.resolve_pending_command(PolicyDecision::Allow)?;
        self.transport.send_approval_state(&PolicyDecision::Allow).await?;
        self.session.active_redaction = Some(ActiveRedaction::new(plan.clone()));
        self.session.approval_pending = false;
        self.session.approval_input_buffer.clear();
        self.session.pending_approval = None;
        self.ui.clear_approval_prompt();
        self.ui.show_redaction_enabled(plan.label());
        self.transport
            .send_guest_feedback("command approved with redacted output")
            .await?;
        self.transition(RuntimeState::Interactive)
    }

    async fn request_ai_assessment(&mut self) -> Result<()> {
        let pending = self
            .session
            .pending_approval
            .clone()
            .ok_or(AppError::Invariant("missing pending approval context"))?;

        if self.ai_assessment_rx.is_some() {
            self.ui.show_ai_request_in_progress();
            return Ok(());
        }

        self.ui.show_ai_request_started();
        let ai = self.ai.clone();
        let command = pending.command;
        let reason = pending.reason;
        let (tx, rx) = oneshot::channel();
        tokio::spawn(async move {
            let result = ai
                .assess_command(&command, &reason)
                .await
                .map_err(|err| err.to_string());
            let _ = tx.send(result);
        });
        self.ai_assessment_rx = Some(rx);

        Ok(())
    }

    async fn flush_active_redaction(&mut self) -> Result<()> {
        let Some(mut active) = self.session.active_redaction.take() else {
            return Ok(());
        };

        let flushed = active.flush_all();
        if !flushed.is_empty() {
            self.transport.send_terminal_bytes(&flushed).await?;
        }

        Ok(())
    }

    async fn flush_redaction_buffer(&mut self) -> Result<()> {
        let Some(active) = self.session.active_redaction.as_mut() else {
            return Ok(());
        };

        let flushed = active.flush_all();
        if !flushed.is_empty() {
            self.transport.send_terminal_bytes(&flushed).await?;
        }

        Ok(())
    }
}

enum ApprovalInputParse {
    Pending,
    Resolved(ApprovalInputAction),
    Invalid,
}

impl From<PlatformEvent> for RuntimeEvent {
    fn from(value: PlatformEvent) -> Self {
        match value {
            PlatformEvent::HostInput(bytes) => RuntimeEvent::HostInput(bytes),
            PlatformEvent::Resize(size) => RuntimeEvent::Resize(size),
        }
    }
}

impl From<TerminalEvent> for RuntimeEvent {
    fn from(value: TerminalEvent) -> Self {
        match value {
            TerminalEvent::Output(bytes) => RuntimeEvent::ShellOutput(bytes),
            TerminalEvent::CommandReady(command) => RuntimeEvent::CommandReady(command),
            TerminalEvent::Exited(code) => RuntimeEvent::ShellExited(code),
        }
    }
}

impl From<TransportEvent> for RuntimeEvent {
    fn from(value: TransportEvent) -> Self {
        match value {
            TransportEvent::GuestJoined => RuntimeEvent::GuestJoined,
            TransportEvent::GuestLeft => RuntimeEvent::GuestLeft,
            TransportEvent::GuestInput(bytes) => RuntimeEvent::GuestInput(bytes),
            TransportEvent::RemoteClose | TransportEvent::TransportError => RuntimeEvent::TransportClosed,
        }
    }
}
