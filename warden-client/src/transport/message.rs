#[derive(Debug)]
pub struct SessionCreated {
    pub session_id: String,
    pub host_token: String,
    pub guest_url: String,
    pub relay_url: String,
    pub idle_timeout_seconds: Option<u64>,
    pub idle_warning_seconds: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct IdleTimeoutWarning {
    pub remaining_seconds: u64,
    pub expires_at: String,
}

#[derive(Debug)]
pub enum TransportEvent {
    GuestJoined,
    GuestLeft,
    GuestInput(Vec<u8>),
    IdleTimeoutWarning(IdleTimeoutWarning),
    RemoteClose,
    TransportError,
}
