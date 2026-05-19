use crate::platform::TerminalSize;
use crate::policy::PolicyDecision;
use crate::terminal::CommandExecutionEvent;

#[derive(Debug)]
pub enum RuntimeEvent {
    HostInput(Vec<u8>),
    GuestInput(Vec<u8>),
    ShellOutput(Vec<u8>),
    ShellExited(i32),
    GuestJoined,
    GuestLeft,
    Resize(TerminalSize),
    CommandReady(CommandExecutionEvent),
    ApprovalDecision(PolicyDecision),
    TransportClosed,
    ForceDisconnect,
}

#[derive(Debug)]
pub enum ShutdownReason {
    HostDisconnected,
    ShellExited(i32),
    TransportClosed,
}
