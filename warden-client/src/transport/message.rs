#[derive(Debug)]
pub struct SessionCreated {
    pub session_id: String,
    pub host_token: String,
    pub guest_url: String,
    pub relay_url: String,
}

#[derive(Debug)]
pub enum TransportEvent {
    GuestJoined,
    GuestLeft,
    GuestInput(Vec<u8>),
    RemoteClose,
    TransportError,
}
