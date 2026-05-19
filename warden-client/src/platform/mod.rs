use std::path::PathBuf;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::thread;
use std::time::Duration;

use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use crossterm::terminal;
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver};

use crate::errors::Result;
use crate::terminal::{ShellKind, ShellSpec};

#[derive(Debug, Clone, Copy)]
pub struct TerminalSize {
    pub cols: u16,
    pub rows: u16,
}

#[derive(Debug)]
pub enum PlatformEvent {
    HostInput(Vec<u8>),
    Resize(TerminalSize),
}

pub struct PlatformContext {
    event_rx: UnboundedReceiver<PlatformEvent>,
    stop_flag: Arc<AtomicBool>,
    reader_started: bool,
}

impl PlatformContext {
    pub fn new() -> Self {
        let (_tx, rx) = unbounded_channel();
        Self {
            event_rx: rx,
            stop_flag: Arc::new(AtomicBool::new(false)),
            reader_started: false,
        }
    }

    pub fn detect_shell(&self, preferred_shell: Option<String>) -> Result<ShellSpec> {
        let program = preferred_shell.unwrap_or_else(|| "bash".to_string());
        let kind = match program.as_str() {
            "zsh" => ShellKind::Zsh,
            "pwsh" | "powershell" => ShellKind::PowerShell,
            _ => ShellKind::Bash,
        };

        Ok(ShellSpec {
            kind,
            program,
            args: Vec::new(),
        })
    }

    pub fn capture_env(&self) -> Vec<(String, String)> {
        std::env::vars().collect()
    }

    pub fn current_dir(&self) -> Result<PathBuf> {
        Ok(std::env::current_dir()?)
    }

    pub fn terminal_size(&self) -> Result<TerminalSize> {
        let (cols, rows) = terminal::size().unwrap_or((120, 40));
        Ok(TerminalSize { cols, rows })
    }

    pub fn enter_raw_mode(&mut self) -> Result<()> {
        terminal::enable_raw_mode()?;
        if !self.reader_started {
            self.start_event_reader();
            self.reader_started = true;
        }
        Ok(())
    }

    pub fn restore_terminal(&self) -> Result<()> {
        self.stop_flag.store(true, Ordering::SeqCst);
        terminal::disable_raw_mode()?;
        Ok(())
    }

    pub async fn next_event(&mut self) -> PlatformEvent {
        self.event_rx
            .recv()
            .await
            .expect("platform event channel unexpectedly closed")
    }

    fn start_event_reader(&mut self) {
        let (tx, rx) = unbounded_channel();
        self.event_rx = rx;
        self.stop_flag.store(false, Ordering::SeqCst);

        let stop_flag = Arc::clone(&self.stop_flag);
        thread::spawn(move || {
            while !stop_flag.load(Ordering::SeqCst) {
                if event::poll(Duration::from_millis(100)).unwrap_or(false) {
                    match event::read() {
                        Ok(Event::Key(key)) if key.kind == KeyEventKind::Press => {
                            if let Some(bytes) = key_to_bytes(key.code, key.modifiers) {
                                let _ = tx.send(PlatformEvent::HostInput(bytes));
                            }
                        }
                        Ok(Event::Resize(cols, rows)) => {
                            let _ = tx.send(PlatformEvent::Resize(TerminalSize { cols, rows }));
                        }
                        Ok(_) => {}
                        Err(_) => break,
                    }
                }
            }
        });
    }
}

impl Drop for PlatformContext {
    fn drop(&mut self) {
        let _ = self.restore_terminal();
    }
}

fn key_to_bytes(code: KeyCode, modifiers: KeyModifiers) -> Option<Vec<u8>> {
    match code {
        KeyCode::Enter => Some(vec![b'\n']),
        KeyCode::Tab => Some(vec![b'\t']),
        KeyCode::Backspace => Some(vec![0x7f]),
        KeyCode::Esc => Some(vec![0x1b]),
        KeyCode::Left => Some(b"\x1b[D".to_vec()),
        KeyCode::Right => Some(b"\x1b[C".to_vec()),
        KeyCode::Up => Some(b"\x1b[A".to_vec()),
        KeyCode::Down => Some(b"\x1b[B".to_vec()),
        KeyCode::Char(ch) => {
            if modifiers.contains(KeyModifiers::CONTROL) {
                if ch.is_ascii_alphabetic() {
                    Some(vec![(ch.to_ascii_lowercase() as u8) - b'a' + 1])
                } else {
                    None
                }
            } else {
                let mut buf = [0u8; 4];
                let s = ch.encode_utf8(&mut buf);
                Some(s.as_bytes().to_vec())
            }
        }
        _ => None,
    }
}
