use std::io::Write;

use crate::brand::{approval_prompt, APP_BANNER};
use crate::runtime::ShutdownReason;

pub struct UiRenderer;

const MAX_NOTICE_WIDTH: usize = 120;

pub enum ApprovalInputAction {
    Approve,
    Deny,
    AskAi,
    Redact,
}

impl UiRenderer {
    pub fn new() -> Self {
        Self
    }

    pub fn show_session_started(&mut self, guest_url: &str) {
        let mut lines = APP_BANNER
            .lines()
            .filter(|line| !line.is_empty())
            .map(str::to_string)
            .collect::<Vec<_>>();
        lines.push(String::new());
        lines.push(format!("Session started: {guest_url}"));
        lines.push("Disconnect: exit".to_string());
        self.write_block(&lines, true);
    }

    pub fn show_approval_prompt(&mut self, command: &str, reason: &str, can_redact: bool) {
        self.write_notice(&format!(
            "Approval required for `{command}`: {reason}"
        ));
        if can_redact {
            self.write_notice("Type `yes`, `no`, `redact`, or `ask ai`, then press Enter.");
        } else {
            self.write_notice("Type `yes`, `no`, or `ask ai`, then press Enter.");
        }
        self.show_approval_input_prompt();
    }

    pub fn clear_approval_prompt(&mut self) {
        self.write_notice("Approval resolved");
    }

    pub fn show_disconnect(&mut self, reason: &ShutdownReason) {
        self.write_block(&[format!("Session ended: {reason:?}")], true);
    }

    pub fn write_terminal_output(&mut self, bytes: &[u8]) {
        let mut stdout = std::io::stdout().lock();
        let _ = stdout.write_all(bytes);
        let _ = stdout.flush();
    }

    pub fn try_resolve_approval_input(&mut self, bytes: &[u8]) -> Option<ApprovalInputAction> {
        let normalized = String::from_utf8_lossy(bytes).trim().to_ascii_lowercase();
        match normalized.as_str() {
            "y" | "yes" => Some(ApprovalInputAction::Approve),
            "n" | "no" => Some(ApprovalInputAction::Deny),
            "redact" | "mask" | "r" => Some(ApprovalInputAction::Redact),
            "ask ai" | "ask-ai" | "ai" => Some(ApprovalInputAction::AskAi),
            _ => None,
        }
    }

    pub fn show_ai_assessment(&mut self, assessment: &str, can_redact: bool) {
        self.write_notice("AI risk assessment:");
        self.write_notice(assessment);
        if can_redact {
            self.write_notice("Review the assessment, then type `yes`, `no`, or `redact`.");
        } else {
            self.write_notice("Review the assessment, then type `yes` or `no`.");
        }
        self.show_approval_input_prompt();
    }

    pub fn show_ai_error(&mut self, error: &str, can_redact: bool) {
        self.write_notice(&format!("AI assessment failed: {error}"));
        if can_redact {
            self.write_notice("Type `yes`, `no`, `redact`, or `ask ai`, then press Enter.");
        } else {
            self.write_notice("Type `yes`, `no`, or `ask ai`, then press Enter.");
        }
        self.show_approval_input_prompt();
    }

    pub fn show_ai_request_started(&mut self) {
        self.write_notice("Requesting AI risk assessment...");
    }

    pub fn show_ai_request_in_progress(&mut self) {
        self.write_notice("AI risk assessment is still in progress...");
    }

    pub fn show_invalid_approval_input(&mut self) {
        self.write_notice("Invalid approval input. Type `yes`, `no`, `redact`, or `ask ai`.");
        self.show_approval_input_prompt();
    }

    pub fn show_redaction_unavailable(&mut self) {
        self.write_notice("Redacted output is not available for this command.");
        self.write_notice("Type `yes`, `no`, or `ask ai`, then press Enter.");
        self.show_approval_input_prompt();
    }

    pub fn show_redaction_enabled(&mut self, label: &str) {
        self.write_notice(&format!("Redaction enabled: {label}"));
    }

    pub fn render_approval_input(&mut self, bytes: &[u8]) {
        let mut stdout = std::io::stdout().lock();
        let prompt = approval_prompt();
        let _ = stdout.write_all(b"\r\x1b[2K");
        let _ = stdout.write_all(prompt.as_bytes());
        let _ = stdout.write_all(bytes);
        let _ = stdout.flush();
    }

    fn write_notice(&mut self, message: &str) {
        let lines = wrap_notice_lines(message, MAX_NOTICE_WIDTH);
        self.write_block(&lines, true);
    }

    fn show_approval_input_prompt(&mut self) {
        let mut stdout = std::io::stdout().lock();
        let prompt = approval_prompt();
        let _ = stdout.write_all(prompt.as_bytes());
        let _ = stdout.flush();
    }

    fn write_block(&mut self, lines: &[String], leading_blank_line: bool) {
        let mut stdout = std::io::stdout().lock();
        if leading_blank_line {
            let _ = stdout.write_all(b"\r\n");
        }
        for line in lines {
            let _ = stdout.write_all(line.as_bytes());
            let _ = stdout.write_all(b"\r\n");
        }
        let _ = stdout.flush();
    }
}

fn wrap_notice_lines(message: &str, max_width: usize) -> Vec<String> {
    let mut lines = Vec::new();
    for raw_line in message.lines() {
        if raw_line.trim().is_empty() {
            lines.push(String::new());
            continue;
        }

        let mut current = String::new();
        for word in raw_line.split_whitespace() {
            let next_len = if current.is_empty() {
                word.len()
            } else {
                current.len() + 1 + word.len()
            };

            if !current.is_empty() && next_len > max_width {
                lines.push(current);
                current = word.to_string();
            } else {
                if !current.is_empty() {
                    current.push(' ');
                }
                current.push_str(word);
            }
        }

        if !current.is_empty() {
            lines.push(current);
        }
    }

    if lines.is_empty() {
        lines.push(String::new());
    }

    lines
}
