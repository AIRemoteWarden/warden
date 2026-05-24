#[derive(Debug)]
pub struct SessionCreated {
    pub session_id: String,
    pub host_token: String,
    pub guest_url: String,
    pub relay_url: String,
    pub idle_timeout_seconds: Option<u64>,
}

#[derive(Debug)]
pub enum TransportEvent {
    GuestJoined,
    GuestLeft,
    GuestInput(Vec<u8>),
    RemoteClose,
    TransportError,
}
