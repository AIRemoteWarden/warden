mod decision;

pub use decision::{PolicyDecision, RiskLevel};

use std::path::{Path, PathBuf};

use crate::config::{
    DbMaskRule, DbMaskRuleKind, FileSensitiveRuleConfig, PolicyConfig, SensitiveFileKind,
};
use crate::runtime::SessionContext;
use crate::terminal::CommandExecutionEvent;

pub struct PolicyEngine {
    dangerous_patterns: Vec<String>,
    approval_commands: Vec<String>,
    db_masking_rules: Vec<DbMaskRule>,
    sensitive_resources: SensitiveResourceCatalog,
}

impl PolicyEngine {
    pub fn new(policy: PolicyConfig) -> Self {
        Self {
            dangerous_patterns: policy.shell.dangerous_commands.clone(),
            approval_commands: policy.shell.approval_commands.clone(),
            db_masking_rules: policy.databases.column_rules.clone(),
            sensitive_resources: SensitiveResourceCatalog::from_config(&policy.files.sensitive_rules),
        }
    }

    pub fn evaluate(
        &self,
        command: &CommandExecutionEvent,
        _session: &SessionContext,
    ) -> PolicyDecision {
        let normalized = command.command.trim_start();
        let sensitive_intent = CommandIntent::from_command(command, &self.sensitive_resources);
        let psql_intent = PsqlIntent::parse(&command.command);

        if let Some(pattern) = self
            .dangerous_patterns
            .iter()
            .find(|pattern| normalized.starts_with(pattern.as_str()))
        {
            let reason = if let Some(intent) = sensitive_intent {
                format!(
                    "matched dangerous pattern: {pattern}; sensitive {} access detected: {} `{}`",
                    intent.resource_kind.label(),
                    intent.action.label(),
                    intent.resource_path.display()
                )
            } else {
                format!("matched dangerous pattern: {pattern}")
            };
            return PolicyDecision::RequireApproval {
                reason,
                risk: RiskLevel::High,
            };
        }

        if let Some(intent) = psql_intent {
            if self
                .approval_commands
                .iter()
                .any(|command| command.eq_ignore_ascii_case("psql"))
            {
                let reason = if let Some(query) = intent.query.as_ref() {
                    format!("PostgreSQL query requested via psql -c: `{query}`")
                } else {
                    "interactive PostgreSQL session requested via psql".to_string()
                };
                return PolicyDecision::RequireApproval {
                    reason,
                    risk: RiskLevel::High,
                };
            }
        }

        if let Some(intent) = sensitive_intent {
            return PolicyDecision::RequireApproval {
                reason: format!(
                    "sensitive {} access detected: {} `{}`",
                    intent.resource_kind.label(),
                    intent.action.label(),
                    intent.resource_path.display()
                ),
                risk: RiskLevel::High,
            };
        }

        PolicyDecision::Allow
    }

    pub fn redaction_plan_for(&self, command: &CommandExecutionEvent) -> Option<RedactionPlan> {
        if let Some(intent) = PsqlIntent::parse(&command.command) {
            let applicable_rules = self
                .db_masking_rules
                .iter()
                .filter(|rule| {
                    rule.engine
                        .as_deref()
                        .map(|engine| matches!(engine.to_ascii_lowercase().as_str(), "postgres" | "postgresql"))
                        .unwrap_or(true)
                })
                .filter(|rule| {
                    intent
                        .primary_table
                        .as_ref()
                        .map(|table| table.eq_ignore_ascii_case(&rule.table))
                        .unwrap_or(true)
                })
                .map(|rule| PsqlColumnMask {
                    column_name: rule.column.clone(),
                    rule: rule.rule.clone(),
                })
                .collect::<Vec<_>>();

            if !applicable_rules.is_empty() {
                return Some(RedactionPlan::PsqlAlignedTable {
                    columns: applicable_rules,
                });
            }
        }

        let intent = CommandIntent::from_command(command, &self.sensitive_resources)?;
        if !intent.allow_redaction {
            return None;
        }

        match (intent.resource_kind, intent.action) {
            (SensitiveResourceKind::ShadowFile, CommandAction::ReadFile)
            | (SensitiveResourceKind::ShadowFile, CommandAction::SearchFile) => {
                Some(RedactionPlan::ShadowSecrets)
            }
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub enum RedactionPlan {
    ShadowSecrets,
    PsqlAlignedTable { columns: Vec<PsqlColumnMask> },
}

impl RedactionPlan {
    pub fn label(&self) -> &'static str {
        match self {
            Self::ShadowSecrets => "redact password/hash fields",
            Self::PsqlAlignedTable { .. } => "redact configured PostgreSQL columns",
        }
    }
}

#[derive(Debug, Clone)]
pub struct PsqlColumnMask {
    pub column_name: String,
    pub rule: DbMaskRuleKind,
}

#[derive(Debug)]
struct PsqlIntent {
    query: Option<String>,
    primary_table: Option<String>,
}

impl PsqlIntent {
    fn parse(command: &str) -> Option<Self> {
        let tokens = tokenize_shell_words(command);
        let effective = effective_command_tokens(&tokens)?;
        let executable = effective.first()?.as_str();
        if executable != "psql" {
            return None;
        }

        let mut query = None;
        let mut index = 1;
        while index < effective.len() {
            let token = effective[index].as_str();
            if token == "-c" || token == "--command" {
                if let Some(value) = effective.get(index + 1) {
                    query = Some(value.clone());
                }
                break;
            }
            index += 1;
        }

        let primary_table = query
            .as_deref()
            .and_then(parse_primary_table_from_query);

        Some(Self {
            query,
            primary_table,
        })
    }
}

struct SensitiveResourceCatalog {
    rules: Vec<SensitiveResourceRule>,
}

impl SensitiveResourceCatalog {
    fn from_config(rules: &[FileSensitiveRuleConfig]) -> Self {
        let rules = rules
            .iter()
            .filter_map(SensitiveResourceRule::from_config)
            .collect();
        Self { rules }
    }

    fn match_path(&self, path: &Path) -> Option<&SensitiveResourceRule> {
        self.rules.iter().find(|rule| rule.matches(path))
    }
}

struct SensitiveResourceRule {
    matcher: PathMatcher,
    kind: SensitiveResourceKind,
    allow_redaction: bool,
}

impl SensitiveResourceRule {
    fn from_config(rule: &FileSensitiveRuleConfig) -> Option<Self> {
        let kind = SensitiveResourceKind::from_config(&rule.kind);
        let matcher = if let Some(path) = rule.path.as_ref() {
            PathMatcher::Exact(PathBuf::from(path))
        } else if let Some(name) = rule.basename.as_ref() {
            PathMatcher::Basename(name.clone())
        } else if let Some(suffix) = rule.suffix.as_ref() {
            PathMatcher::Suffix(suffix.clone())
        } else if let Some(component) = rule.path_component.as_ref() {
            PathMatcher::PathComponent(component.clone())
        } else {
            return None;
        };

        Some(Self {
            matcher,
            kind,
            allow_redaction: rule.allow_redaction,
        })
    }

    fn matches(&self, path: &Path) -> bool {
        self.matcher.matches(path)
    }
}

enum PathMatcher {
    Exact(PathBuf),
    Basename(String),
    Suffix(String),
    PathComponent(String),
}

impl PathMatcher {
    fn matches(&self, path: &Path) -> bool {
        match self {
            PathMatcher::Exact(expected) => path == expected,
            PathMatcher::Basename(name) => {
                path.file_name().is_some_and(|file| file == name.as_str())
            }
            PathMatcher::Suffix(suffix) => path.to_string_lossy().ends_with(suffix),
            PathMatcher::PathComponent(component) => path
                .components()
                .any(|segment| segment.as_os_str() == component.as_str()),
        }
    }
}

#[derive(Clone, Copy)]
enum SensitiveResourceKind {
    ShadowFile,
    SshMaterial,
    EnvFile,
    PemKey,
}

impl SensitiveResourceKind {
    fn from_config(kind: &SensitiveFileKind) -> Self {
        match kind {
            SensitiveFileKind::ShadowFile => SensitiveResourceKind::ShadowFile,
            SensitiveFileKind::SshMaterial => SensitiveResourceKind::SshMaterial,
            SensitiveFileKind::EnvFile => SensitiveResourceKind::EnvFile,
            SensitiveFileKind::PemKey => SensitiveResourceKind::PemKey,
        }
    }

    fn label(&self) -> &'static str {
        match self {
            SensitiveResourceKind::ShadowFile => "shadow file",
            SensitiveResourceKind::SshMaterial => "SSH material",
            SensitiveResourceKind::EnvFile => "environment secret file",
            SensitiveResourceKind::PemKey => "PEM key file",
        }
    }
}

struct CommandIntent {
    action: CommandAction,
    resource_kind: SensitiveResourceKind,
    resource_path: PathBuf,
    allow_redaction: bool,
}

impl CommandIntent {
    fn from_command(
        command: &CommandExecutionEvent,
        catalog: &SensitiveResourceCatalog,
    ) -> Option<Self> {
        let tokens = tokenize_shell_words(&command.command);
        let (command_name, args) = effective_command_view(&tokens)?;
        let action = CommandAction::from_command_name(command_name)?;

        for token in args {
            if token.starts_with('-') {
                continue;
            }

            let candidate = normalize_path(&command.cwd, token);
            if let Some(rule) = catalog.match_path(&candidate) {
                return Some(Self {
                    action,
                    resource_kind: rule.kind,
                    resource_path: candidate,
                    allow_redaction: rule.allow_redaction,
                });
            }
        }

        None
    }
}

fn effective_command_view<'a>(tokens: &'a [String]) -> Option<(&'a str, &'a [String])> {
    let first = tokens.first()?.as_str();
    if first != "sudo" {
        return Some((first, &tokens[1..]));
    }

    let mut index = 1;
    while index < tokens.len() {
        let token = tokens[index].as_str();
        if token == "--" {
            index += 1;
            break;
        }

        if !token.starts_with('-') || token == "-" {
            break;
        }

        index += 1;
        if option_consumes_value(token) && index < tokens.len() {
            index += 1;
        }
    }

    let command_name = tokens.get(index)?.as_str();
    Some((command_name, &tokens[index + 1..]))
}

fn effective_command_tokens<'a>(tokens: &'a [String]) -> Option<&'a [String]> {
    let first = tokens.first()?.as_str();
    if first != "sudo" {
        return Some(tokens);
    }

    let mut index = 1;
    while index < tokens.len() {
        let token = tokens[index].as_str();
        if token == "--" {
            index += 1;
            break;
        }

        if !token.starts_with('-') || token == "-" {
            break;
        }

        index += 1;
        if option_consumes_value(token) && index < tokens.len() {
            index += 1;
        }
    }

    tokens.get(index..)
}

fn option_consumes_value(token: &str) -> bool {
    matches!(token, "-u" | "--user" | "-g" | "--group" | "-h" | "--host" | "-p" | "--prompt" | "-C" | "--close-from" | "-T" | "--command-timeout")
}

fn parse_primary_table_from_query(query: &str) -> Option<String> {
    let normalized = query.replace('\n', " ");
    let lower = normalized.to_ascii_lowercase();
    let from_index = lower.find(" from ")?;
    let tail = normalized[from_index + 6..].trim_start();
    let table_token = tail
        .split_whitespace()
        .next()?
        .trim_end_matches(';')
        .trim_end_matches(',');

    table_token
        .split('.')
        .last()
        .map(|part| part.trim_matches('"').to_string())
}

#[derive(Clone, Copy)]
enum CommandAction {
    ReadFile,
    SearchFile,
    TransformFile,
    EditInteractive,
    CopyFile,
}

impl CommandAction {
    fn from_command_name(command_name: &str) -> Option<Self> {
        match command_name {
            "cat" | "head" | "tail" => Some(Self::ReadFile),
            "grep" => Some(Self::SearchFile),
            "sed" | "awk" | "base64" | "python" | "python3" | "perl" => Some(Self::TransformFile),
            "less" | "vim" | "nano" => Some(Self::EditInteractive),
            "cp" | "scp" => Some(Self::CopyFile),
            _ => None,
        }
    }

    fn label(&self) -> &'static str {
        match self {
            CommandAction::ReadFile => "read",
            CommandAction::SearchFile => "search",
            CommandAction::TransformFile => "transform",
            CommandAction::EditInteractive => "interactive access",
            CommandAction::CopyFile => "copy",
        }
    }
}

fn normalize_path(cwd: &Path, candidate: &str) -> PathBuf {
    let path = Path::new(candidate);
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        cwd.join(path)
    }
}

fn tokenize_shell_words(input: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut chars = input.chars().peekable();
    let mut in_single = false;
    let mut in_double = false;

    while let Some(ch) = chars.next() {
        match ch {
            '\'' if !in_double => in_single = !in_single,
            '"' if !in_single => in_double = !in_double,
            '\\' => {
                if let Some(next) = chars.next() {
                    current.push(next);
                }
            }
            ch if ch.is_whitespace() && !in_single && !in_double => {
                if !current.is_empty() {
                    tokens.push(std::mem::take(&mut current));
                }
            }
            _ => current.push(ch),
        }
    }

    if !current.is_empty() {
        tokens.push(current);
    }

    tokens
}
