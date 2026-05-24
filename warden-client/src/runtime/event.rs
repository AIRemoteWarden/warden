use crate::platform::TerminalSize;
use crate::terminal::CommandExecutionEvent;
use crate::transport::IdleTimeoutWarning;

#[derive(Debug)]
pub enum RuntimeEvent {
    HostInput(Vec<u8>),
    GuestInput(Vec<u8>),
    ShellOutput(Vec<u8>),
    ShellExited(i32),
    AiAssessmentFinished(std::result::Result<String, String>),
    GuestJoined,
    GuestLeft,
    IdleTimeoutWarning(IdleTimeoutWarning),
    Resize(TerminalSize),
    CommandReady(CommandExecutionEvent),
    TransportClosed,
}

#[derive(Debug)]
pub enum ShutdownReason {
    ShellExited(i32),
    TransportClosed,
}
