use std::collections::BTreeSet;
use std::fs::{self, File, OpenOptions};
use std::future::Future;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver};

use crate::brand::{denied_message, hook_dir_prefix};
use crate::config::PolicyConfig;
use crate::errors::{AppError, Result};
use crate::policy::PolicyDecision;
use crate::terminal::{ShellKind, ShellSpec, TerminalEvent};

#[derive(Debug, Clone)]
pub struct CommandExecutionEvent {
    pub command: String,
    pub cwd: PathBuf,
}

#[derive(Debug, Clone, Default)]
pub struct HookCommandSet {
    commands: Vec<String>,
}

impl HookCommandSet {
    pub fn from_policy(policy: &PolicyConfig) -> Self {
        let mut commands = BTreeSet::new();

        for configured in policy
            .shell
            .dangerous_commands
            .iter()
            .chain(policy.shell.approval_commands.iter())
            .chain(policy.shell.hook_commands.iter())
        {
            if let Some(name) = normalize_hook_command_name(configured) {
                commands.insert(name);
            }
        }

        Self {
            commands: commands.into_iter().collect(),
        }
    }

    pub fn commands(&self) -> &[String] {
        &self.commands
    }
}

pub struct CommandHookBridge {
    provider: Box<dyn HookProvider>,
}

impl CommandHookBridge {
    pub fn new() -> Self {
        Self {
            provider: Box::new(NoopHookProvider),
        }
    }

    pub fn install(&mut self, shell_spec: &mut ShellSpec, commands: &HookCommandSet) -> Result<()> {
        let mut provider = hook_provider_for(shell_spec.kind.clone());
        provider.install(shell_spec, commands)?;
        self.provider = provider;
        Ok(())
    }

    pub async fn next_event(&mut self) -> TerminalEvent {
        self.provider.next_event().await
    }

    pub fn resolve_command(&mut self, decision: PolicyDecision) -> Result<()> {
        self.provider.resolve_command(decision)
    }
}

trait HookProvider: Send {
    fn install(&mut self, shell_spec: &mut ShellSpec, commands: &HookCommandSet) -> Result<()>;
    fn next_event<'a>(&'a mut self) -> Pin<Box<dyn Future<Output = TerminalEvent> + Send + 'a>>;
    fn resolve_command(&mut self, decision: PolicyDecision) -> Result<()>;
}

struct NoopHookProvider;

impl HookProvider for NoopHookProvider {
    fn install(&mut self, _shell_spec: &mut ShellSpec, _commands: &HookCommandSet) -> Result<()> {
        Ok(())
    }

    fn next_event<'a>(&'a mut self) -> Pin<Box<dyn Future<Output = TerminalEvent> + Send + 'a>> {
        Box::pin(std::future::pending())
    }

    fn resolve_command(&mut self, _decision: PolicyDecision) -> Result<()> {
        Ok(())
    }
}

struct BashHookProvider {
    event_rx: Option<UnboundedReceiver<TerminalEvent>>,
    response_writer: Option<Arc<Mutex<File>>>,
    hook_dir: Option<PathBuf>,
}

impl BashHookProvider {
    fn new() -> Self {
        Self {
            event_rx: None,
            response_writer: None,
            hook_dir: None,
        }
    }
}

impl HookProvider for BashHookProvider {
    fn install(&mut self, shell_spec: &mut ShellSpec, commands: &HookCommandSet) -> Result<()> {
        if commands.commands().is_empty() {
            return Ok(());
        }

        let hook_dir = std::env::temp_dir().join(format!(
            "{}-{}",
            hook_dir_prefix(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|duration| duration.as_nanos())
                .unwrap_or(0)
        ));
        fs::create_dir_all(&hook_dir)?;

        let request_pipe = hook_dir.join("request.pipe");
        let response_pipe = hook_dir.join("response.pipe");
        let rcfile = hook_dir.join("ai-remote-warden.bashrc");

        create_fifo(&request_pipe)?;
        create_fifo(&response_pipe)?;

        let request_file = open_fifo_read_write(&request_pipe)?;
        let response_file = open_fifo_read_write(&response_pipe)?;
        let response_writer = Arc::new(Mutex::new(response_file));

        let script = render_bash_hook_script(&request_pipe, &response_pipe, commands.commands());
        fs::write(&rcfile, script)?;

        shell_spec.args = vec![
            "--noprofile".to_string(),
            "--rcfile".to_string(),
            rcfile.to_string_lossy().to_string(),
            "-i".to_string(),
        ];

        let (event_tx, event_rx) = unbounded_channel();
        thread::spawn(move || {
            let reader = BufReader::new(request_file);
            for line in reader.lines() {
                let Ok(line) = line else { break };
                let command = line.trim().to_string();
                if command.is_empty() {
                    continue;
                }

                let event = CommandExecutionEvent {
                    command,
                    cwd: std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")),
                };
                let _ = event_tx.send(TerminalEvent::CommandReady(event));
            }
        });

        self.event_rx = Some(event_rx);
        self.response_writer = Some(response_writer);
        self.hook_dir = Some(hook_dir);
        Ok(())
    }

    fn next_event<'a>(&'a mut self) -> Pin<Box<dyn Future<Output = TerminalEvent> + Send + 'a>> {
        Box::pin(async move {
            match self.event_rx.as_mut() {
                Some(event_rx) => event_rx.recv().await.unwrap_or(TerminalEvent::Exited(-1)),
                None => std::future::pending::<TerminalEvent>().await,
            }
        })
    }

    fn resolve_command(&mut self, decision: PolicyDecision) -> Result<()> {
        let verdict = match decision {
            PolicyDecision::Allow => "allow\n",
            PolicyDecision::Deny { .. } | PolicyDecision::RequireApproval { .. } => "deny\n",
        };

        if let Some(writer) = self.response_writer.as_ref() {
            let mut writer = writer
                .lock()
                .map_err(|_| AppError::Message("failed to acquire approval writer".to_string()))?;
            writer.write_all(verdict.as_bytes())?;
            writer.flush()?;
        }

        Ok(())
    }
}

impl Drop for BashHookProvider {
    fn drop(&mut self) {
        self.response_writer.take();
        if let Some(hook_dir) = self.hook_dir.take() {
            let _ = fs::remove_dir_all(hook_dir);
        }
    }
}

fn hook_provider_for(shell_kind: ShellKind) -> Box<dyn HookProvider> {
    match shell_kind {
        ShellKind::Bash => Box::new(BashHookProvider::new()),
        ShellKind::Zsh | ShellKind::PowerShell => Box::new(NoopHookProvider),
    }
}

fn normalize_hook_command_name(raw: &str) -> Option<String> {
    let command = raw.split_whitespace().next()?.trim();
    if is_safe_hook_command_name(command) {
        Some(command.to_string())
    } else {
        None
    }
}

fn is_safe_hook_command_name(name: &str) -> bool {
    let mut chars = name.chars();
    matches!(chars.next(), Some(first) if first.is_ascii_alphabetic() || first == '_')
        && chars.all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
}

fn create_fifo(path: &Path) -> Result<()> {
    let path_bytes = std::ffi::CString::new(path.as_os_str().as_bytes())
        .map_err(|_| AppError::Message("invalid fifo path".to_string()))?;
    let result = unsafe { libc::mkfifo(path_bytes.as_ptr(), 0o600) };
    if result != 0 {
        let err = std::io::Error::last_os_error();
        if err.kind() != std::io::ErrorKind::AlreadyExists {
            return Err(AppError::Io(err));
        }
    }
    Ok(())
}

fn open_fifo_read_write(path: &Path) -> Result<File> {
    OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .map_err(AppError::Io)
}

fn render_bash_hook_script(
    request_pipe: &Path,
    response_pipe: &Path,
    commands: &[String],
) -> String {
    let denied_message = denied_message();
    let unalias_line = if commands.is_empty() {
        String::new()
    } else {
        format!("unalias {} 2>/dev/null || true", commands.join(" "))
    };
    let wrapper_lines = commands
        .iter()
        .map(|command| format!("{command}() {{ __warden_gate {command} \"$@\"; }}"))
        .collect::<Vec<_>>()
        .join("\n");

    format!(
        r#"
if [ -f /etc/bash.bashrc ]; then
  . /etc/bash.bashrc
fi
if [ -f "$HOME/.bashrc" ]; then
  . "$HOME/.bashrc"
fi

export PS1='\[\033[1;38;5;46m\][warden]\[\033[0m\] \[\033[1;38;5;81m\]\W\[\033[0m\]\$ '

export AIWARDEN_REQUEST_PIPE="{request_pipe}"
export AIWARDEN_RESPONSE_PIPE="{response_pipe}"

exec 9<>"$AIWARDEN_REQUEST_PIPE"
exec 8<>"$AIWARDEN_RESPONSE_PIPE"

__warden_render_command() {{
  local rendered="$1"
  shift
  local arg
  for arg in "$@"; do
    printf -v rendered '%s %q' "$rendered" "$arg"
  done
  printf '%s\n' "$rendered"
}}

__warden_gate() {{
  local original_cmd="$1"
  shift
  __warden_render_command "$original_cmd" "$@" >&9
  local decision=""
  IFS= read -r decision <&8
  if [ "$decision" = "allow" ]; then
    command "$original_cmd" "$@"
  else
    printf '{denied_message}\n' >&2
    return 126
  fi
}}

{unalias_line}
{wrapper_lines}
"#,
        denied_message = denied_message.replace('\'', r"'\''"),
        request_pipe = request_pipe.display(),
        response_pipe = response_pipe.display(),
        unalias_line = unalias_line,
        wrapper_lines = wrapper_lines,
    )
}
