#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeState {
    Booting,
    CreatingSession,
    StartingShell,
    AwaitingGuest,
    Interactive,
    ApprovalPending,
    Disconnecting,
    Closed,
}
