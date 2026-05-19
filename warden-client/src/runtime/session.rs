use std::path::PathBuf;

use crate::config::DbMaskRuleKind;
use crate::policy::{PsqlColumnMask, RedactionPlan};
use crate::terminal::ShellSpec;
use crate::transport::SessionCreated;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputOrigin {
    Host,
    Guest,
}

#[derive(Debug, Clone)]
pub struct PendingApproval {
    pub command: String,
    pub reason: String,
    pub redaction_plan: Option<RedactionPlan>,
}

#[derive(Debug, Clone)]
pub struct ActiveRedaction {
    pub plan: RedactionPlan,
    pub pending_bytes: Vec<u8>,
    shadow_saw_complete_output_line: bool,
    psql_state: PsqlMaskingState,
}

#[derive(Debug, Clone, Default)]
struct PsqlMaskingState {
    mode: PsqlMaskingMode,
}

#[derive(Debug, Clone, Default)]
enum PsqlMaskingMode {
    #[default]
    AwaitHeader,
    AwaitSeparator {
        target_columns: Vec<(usize, DbMaskRuleKind)>,
        column_count: usize,
    },
    InRows {
        target_columns: Vec<(usize, DbMaskRuleKind)>,
        column_count: usize,
    },
}

impl ActiveRedaction {
    pub fn new(plan: RedactionPlan) -> Self {
        Self {
            plan,
            pending_bytes: Vec::new(),
            shadow_saw_complete_output_line: false,
            psql_state: PsqlMaskingState::default(),
        }
    }

    pub fn process_bytes(&mut self, bytes: &[u8]) -> (Vec<u8>, bool) {
        self.pending_bytes.extend_from_slice(bytes);
        match self.plan.clone() {
            RedactionPlan::ShadowSecrets => self.process_shadow_bytes(),
            RedactionPlan::PsqlAlignedTable { columns } => self.process_psql_bytes(&columns),
        }
    }

    pub fn flush_all(&mut self) -> Vec<u8> {
        if self.pending_bytes.is_empty() {
            return Vec::new();
        }

        match &self.plan {
            RedactionPlan::ShadowSecrets => {
                let remaining = std::mem::take(&mut self.pending_bytes);
                apply_shadow_redaction(&remaining)
            }
            RedactionPlan::PsqlAlignedTable { .. } => std::mem::take(&mut self.pending_bytes),
        }
    }

    fn process_shadow_bytes(&mut self) -> (Vec<u8>, bool) {
        let mut out = Vec::new();
        let mut finish_redaction = false;

        while let Some(newline_pos) = self.pending_bytes.iter().position(|byte| *byte == b'\n') {
            self.shadow_saw_complete_output_line = true;
            let mut line = self.pending_bytes.drain(..=newline_pos).collect::<Vec<u8>>();
            let had_newline = matches!(line.last(), Some(b'\n'));
            if had_newline {
                line.pop();
            }

            let had_cr = matches!(line.last(), Some(b'\r'));
            if had_cr {
                line.pop();
            }

            let redacted = apply_shadow_redaction(&line);
            out.extend_from_slice(&redacted);
            if had_cr {
                out.push(b'\r');
            }
            if had_newline {
                out.push(b'\n');
            }
        }

        if !self.pending_bytes.is_empty()
            && self
                .pending_bytes
                .iter()
                .any(|byte| matches!(*byte, b' ' | b'\t' | 0x1b))
        {
            out.extend_from_slice(&self.pending_bytes);
            self.pending_bytes.clear();
            finish_redaction = self.shadow_saw_complete_output_line;
        }

        (out, finish_redaction)
    }

    fn process_psql_bytes(&mut self, configured_columns: &[PsqlColumnMask]) -> (Vec<u8>, bool) {
        let mut out = Vec::new();

        while let Some(newline_pos) = self.pending_bytes.iter().position(|byte| *byte == b'\n') {
            let mut line = self.pending_bytes.drain(..=newline_pos).collect::<Vec<u8>>();
            let had_newline = matches!(line.last(), Some(b'\n'));
            if had_newline {
                line.pop();
            }

            let had_cr = matches!(line.last(), Some(b'\r'));
            if had_cr {
                line.pop();
            }

            let text = String::from_utf8_lossy(&line).to_string();
            let rendered = self.process_psql_line(configured_columns, &text);
            out.extend_from_slice(rendered.as_bytes());
            if had_cr {
                out.push(b'\r');
            }
            if had_newline {
                out.push(b'\n');
            }
        }

        if !self.pending_bytes.is_empty() && !self.pending_bytes.contains(&b'|') {
            out.extend_from_slice(&self.pending_bytes);
            self.pending_bytes.clear();
        }

        (out, false)
    }

    fn process_psql_line(&mut self, configured_columns: &[PsqlColumnMask], line: &str) -> String {
        if line.trim().is_empty() {
            self.psql_state.mode = PsqlMaskingMode::AwaitHeader;
            return line.to_string();
        }

        if is_psql_footer(line) {
            self.psql_state.mode = PsqlMaskingMode::AwaitHeader;
            return line.to_string();
        }

        if looks_like_psql_error(line) {
            self.psql_state.mode = PsqlMaskingMode::AwaitHeader;
            return line.to_string();
        }

        match &mut self.psql_state.mode {
            PsqlMaskingMode::AwaitHeader => {
                if !line.contains('|') {
                    return line.to_string();
                }

                let headers = split_psql_row(line);
                let target_columns = headers
                    .iter()
                    .enumerate()
                    .filter_map(|(index, header)| {
                        let header_name = header.trim();
                        configured_columns
                            .iter()
                            .find(|rule| rule.column_name.eq_ignore_ascii_case(header_name))
                            .map(|rule| (index, rule.rule.clone()))
                    })
                    .collect::<Vec<_>>();

                if target_columns.is_empty() {
                    return line.to_string();
                }

                self.psql_state.mode = PsqlMaskingMode::AwaitSeparator {
                    target_columns,
                    column_count: headers.len(),
                };
                line.to_string()
            }
            PsqlMaskingMode::AwaitSeparator {
                target_columns,
                column_count,
            } => {
                if line.contains("-+-") || line.contains('+') {
                    self.psql_state.mode = PsqlMaskingMode::InRows {
                        target_columns: target_columns.clone(),
                        column_count: *column_count,
                    };
                    return line.to_string();
                }

                self.psql_state.mode = PsqlMaskingMode::AwaitHeader;
                line.to_string()
            }
            PsqlMaskingMode::InRows {
                target_columns,
                column_count,
            } => {
                if !line.contains('|') {
                    self.psql_state.mode = PsqlMaskingMode::AwaitHeader;
                    return line.to_string();
                }

                let mut cells = split_psql_row(line);
                if cells.len() != *column_count {
                    return line.to_string();
                }

                for (index, rule) in target_columns.iter() {
                    if let Some(cell) = cells.get_mut(*index) {
                        *cell = redact_psql_cell(cell, rule);
                    }
                }

                cells.join("|")
            }
        }
    }
}

fn apply_shadow_redaction(bytes: &[u8]) -> Vec<u8> {
    let line = String::from_utf8_lossy(bytes);
    redact_shadow_like_line(&line).into_bytes()
}

fn redact_shadow_like_line(line: &str) -> String {
    let mut fields: Vec<String> = line.split(':').map(ToString::to_string).collect();
    if fields.len() < 8 {
        return line.to_string();
    }

    let secret_index = if fields.len() >= 9 { 1 } else { 2 };
    if let Some(field) = fields.get_mut(secret_index) {
        *field = "********".to_string();
    }

    fields.join(":")
}

fn split_psql_row(line: &str) -> Vec<String> {
    line.split('|').map(ToString::to_string).collect()
}

fn is_psql_footer(line: &str) -> bool {
    let trimmed = line.trim();
    trimmed.starts_with('(') && trimmed.ends_with(')') && trimmed.contains("row")
}

fn looks_like_psql_error(line: &str) -> bool {
    let trimmed = line.trim_start();
    trimmed.starts_with("psql:")
        || trimmed.starts_with("ERROR:")
        || trimmed.starts_with("FATAL:")
        || trimmed.starts_with("Password")
        || trimmed.starts_with("password")
}

fn redact_psql_cell(cell: &str, rule: &DbMaskRuleKind) -> String {
    let leading = cell.len() - cell.trim_start().len();
    let trailing = cell.len() - cell.trim_end().len();
    let trimmed = cell.trim();
    let masked = apply_cell_redaction(trimmed, rule);
    let inner_width = cell.len().saturating_sub(leading + trailing);
    let formatted = if masked.len() >= inner_width {
        masked
    } else {
        format!("{masked:<width$}", width = inner_width)
    };

    format!(
        "{}{}{}",
        " ".repeat(leading),
        formatted,
        " ".repeat(trailing)
    )
}

fn apply_cell_redaction(value: &str, rule: &DbMaskRuleKind) -> String {
    match rule {
        DbMaskRuleKind::FullMask => "********".to_string(),
        DbMaskRuleKind::Last4 => {
            let digits_only: String = value.chars().filter(|ch| ch.is_ascii_digit()).collect();
            if digits_only.len() <= 4 {
                "********".to_string()
            } else {
                format!("********{}", &digits_only[digits_only.len() - 4..])
            }
        }
        DbMaskRuleKind::PartialEmail => {
            if let Some((local, domain)) = value.split_once('@') {
                let prefix = local.chars().next().unwrap_or('*');
                format!("{prefix}***@{domain}")
            } else {
                "********".to_string()
            }
        }
    }
}

#[derive(Debug, Default)]
pub struct SessionContext {
    pub session_id: String,
    pub host_token: String,
    pub guest_url: String,
    pub relay_url: String,
    pub shell_spec: Option<ShellSpec>,
    pub cwd: PathBuf,
    pub readonly: bool,
    pub guest_connected: bool,
    pub approval_pending: bool,
    pub approval_input_buffer: Vec<u8>,
    pub last_input_origin: Option<InputOrigin>,
    pub pending_command_origin: Option<InputOrigin>,
    pub pending_approval: Option<PendingApproval>,
    pub active_redaction: Option<ActiveRedaction>,
}

impl SessionContext {
    pub fn apply_created(&mut self, created: SessionCreated) {
        self.session_id = created.session_id;
        self.host_token = created.host_token;
        self.guest_url = created.guest_url;
        self.relay_url = created.relay_url;
    }
}
