use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver};

use crate::brand::{denied_message, hook_dir_prefix};
use crate::errors::{AppError, Result};
use crate::policy::PolicyDecision;
use crate::terminal::{ShellKind, ShellSpec, TerminalEvent};

#[derive(Debug, Clone)]
pub struct CommandExecutionEvent {
    pub command: String,
    pub shell_kind: ShellKind,
    pub cwd: PathBuf,
    pub timestamp_unix_ms: u128,
}

pub struct CommandHookBridge {
    event_rx: Option<UnboundedReceiver<TerminalEvent>>,
    response_writer: Option<Arc<Mutex<File>>>,
    hook_dir: Option<PathBuf>,
}

impl CommandHookBridge {
    pub fn new() -> Self {
        Self {
            event_rx: None,
            response_writer: None,
            hook_dir: None,
        }
    }

    pub fn install(&mut self, shell_spec: &mut ShellSpec) -> Result<()> {
        if !matches!(shell_spec.kind, ShellKind::Bash) {
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

        let script = render_bash_hook_script(&request_pipe, &response_pipe);
        fs::write(&rcfile, script)?;

        shell_spec.args = vec![
            "--noprofile".to_string(),
            "--rcfile".to_string(),
            rcfile.to_string_lossy().to_string(),
            "-i".to_string(),
        ];

        let (event_tx, event_rx) = unbounded_channel();
        let shell_kind = shell_spec.kind.clone();
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
                    shell_kind: shell_kind.clone(),
                    cwd: std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")),
                    timestamp_unix_ms: SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .map(|duration| duration.as_millis())
                        .unwrap_or(0),
                };
                let _ = event_tx.send(TerminalEvent::CommandReady(event));
            }
        });

        self.event_rx = Some(event_rx);
        self.response_writer = Some(response_writer);
        self.hook_dir = Some(hook_dir);
        Ok(())
    }

    pub async fn next_event(&mut self) -> TerminalEvent {
        loop {
            if let Some(event_rx) = self.event_rx.as_mut() {
                if let Some(event) = event_rx.recv().await {
                    return event;
                }
            } else {
                std::future::pending::<TerminalEvent>().await;
            }
        }
    }

    pub fn resolve_command(&mut self, decision: PolicyDecision) -> Result<()> {
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

impl Drop for CommandHookBridge {
    fn drop(&mut self) {
        self.response_writer.take();
        if let Some(hook_dir) = self.hook_dir.take() {
            let _ = fs::remove_dir_all(hook_dir);
        }
    }
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

fn render_bash_hook_script(request_pipe: &Path, response_pipe: &Path) -> String {
    let denied_message = denied_message();
    format!(
        r#"
if [ -f /etc/bash.bashrc ]; then
  . /etc/bash.bashrc
fi
if [ -f "$HOME/.bashrc" ]; then
  . "$HOME/.bashrc"
fi

export DEBUGIT_REQUEST_PIPE="{request_pipe}"
export DEBUGIT_RESPONSE_PIPE="{response_pipe}"

exec 9<>"$DEBUGIT_REQUEST_PIPE"
exec 8<>"$DEBUGIT_RESPONSE_PIPE"

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
  elif [ "$decision" = "handled" ]; then
    return 0
  else
    printf '{denied_message}\n' >&2
    return 126
  fi
}}

unalias sudo rm cat grep head tail sed awk less vim nano cp scp base64 python python3 perl psql mkfs shutdown reboot 2>/dev/null || true

sudo() {{ __warden_gate sudo "$@"; }}
rm() {{ __warden_gate rm "$@"; }}
cat() {{ __warden_gate cat "$@"; }}
grep() {{ __warden_gate grep "$@"; }}
head() {{ __warden_gate head "$@"; }}
tail() {{ __warden_gate tail "$@"; }}
sed() {{ __warden_gate sed "$@"; }}
awk() {{ __warden_gate awk "$@"; }}
less() {{ __warden_gate less "$@"; }}
vim() {{ __warden_gate vim "$@"; }}
nano() {{ __warden_gate nano "$@"; }}
cp() {{ __warden_gate cp "$@"; }}
scp() {{ __warden_gate scp "$@"; }}
base64() {{ __warden_gate base64 "$@"; }}
python() {{ __warden_gate python "$@"; }}
python3() {{ __warden_gate python3 "$@"; }}
perl() {{ __warden_gate perl "$@"; }}
psql() {{ __warden_gate psql "$@"; }}
mkfs() {{ __warden_gate mkfs "$@"; }}
shutdown() {{ __warden_gate shutdown "$@"; }}
reboot() {{ __warden_gate reboot "$@"; }}
"#,
        denied_message = denied_message.replace('\'', r"'\''"),
        request_pipe = request_pipe.display(),
        response_pipe = response_pipe.display(),
    )
}
