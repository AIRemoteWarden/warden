use std::path::PathBuf;
use std::thread;

use portable_pty::{native_pty_system, ChildKiller, CommandBuilder, MasterPty, PtySize};
use tokio::sync::mpsc::UnboundedSender;

use crate::errors::{AppError, Result};
use crate::platform::TerminalSize;
use crate::terminal::{ShellSpec, TerminalEvent};

pub trait TerminalBackend: Send {
    fn start(
        &mut self,
        shell_spec: ShellSpec,
        cwd: PathBuf,
        env: Vec<(String, String)>,
        size: TerminalSize,
        event_tx: UnboundedSender<TerminalEvent>,
    ) -> Result<()>;
    fn write_input(&mut self, bytes: &[u8]) -> Result<()>;
    fn resize(&mut self, cols: u16, rows: u16) -> Result<()>;
    fn terminate(&mut self) -> Result<()>;
}

#[derive(Default)]
pub struct PtyBackend {
    master: Option<Box<dyn MasterPty + Send>>,
    writer: Option<Box<dyn std::io::Write + Send>>,
    child_killer: Option<Box<dyn ChildKiller + Send + Sync>>,
}

impl TerminalBackend for PtyBackend {
    fn start(
        &mut self,
        shell_spec: ShellSpec,
        cwd: PathBuf,
        env: Vec<(String, String)>,
        size: TerminalSize,
        event_tx: UnboundedSender<TerminalEvent>,
    ) -> Result<()> {
        let pty_system = native_pty_system();
        let pair = pty_system
            .openpty(PtySize {
                rows: size.rows,
                cols: size.cols,
                pixel_width: 0,
                pixel_height: 0,
            })
            .map_err(|e| AppError::Message(e.to_string()))?;

        let mut command = CommandBuilder::new(&shell_spec.program);
        for arg in &shell_spec.args {
            command.arg(arg);
        }
        command.cwd(cwd);
        for (key, value) in env {
            command.env(key, value);
        }

        let mut child = pair
            .slave
            .spawn_command(command)
            .map_err(|e| AppError::Message(e.to_string()))?;
        drop(pair.slave);

        let writer = pair
            .master
            .take_writer()
            .map_err(|e| AppError::Message(e.to_string()))?;
        let mut reader = pair
            .master
            .try_clone_reader()
            .map_err(|e| AppError::Message(e.to_string()))?;
        let child_killer = child.clone_killer();
        let output_tx = event_tx.clone();

        thread::spawn(move || {
            let mut buf = [0u8; 4096];
            loop {
                match std::io::Read::read(&mut reader, &mut buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        let _ = output_tx.send(TerminalEvent::Output(buf[..n].to_vec()));
                    }
                    Err(_) => break,
                }
            }
        });

        thread::spawn(move || {
            let status = child
                .wait()
                .map(|status| i32::try_from(status.exit_code()).unwrap_or(-1))
                .unwrap_or(-1);
            let _ = event_tx.send(TerminalEvent::Exited(status));
        });

        self.master = Some(pair.master);
        self.writer = Some(writer);
        self.child_killer = Some(child_killer);
        Ok(())
    }

    fn write_input(&mut self, bytes: &[u8]) -> Result<()> {
        if let Some(writer) = self.writer.as_mut() {
            std::io::Write::write_all(writer, bytes)?;
            std::io::Write::flush(writer)?;
        }
        Ok(())
    }

    fn resize(&mut self, cols: u16, rows: u16) -> Result<()> {
        if let Some(master) = self.master.as_mut() {
            master
                .resize(PtySize {
                    rows,
                    cols,
                    pixel_width: 0,
                    pixel_height: 0,
                })
                .map_err(|e| AppError::Message(e.to_string()))?;
        }
        Ok(())
    }

    fn terminate(&mut self) -> Result<()> {
        self.writer.take();
        self.master.take();
        if let Some(child_killer) = self.child_killer.as_mut() {
            let _ = child_killer.kill();
        }
        Ok(())
    }
}
