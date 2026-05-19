mod control;
mod message;
mod relay;

pub use message::{SessionCreated, TransportEvent};

use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};

use crate::brand::{
    offline_guest_url, offline_host_token, offline_session_id, APP_NAME,
};
use crate::config::AppConfig;
use crate::errors::{AppError, Result};
use crate::platform::TerminalSize;
use crate::policy::PolicyDecision;
use crate::runtime::SessionContext;

pub struct TransportManager {
    http: reqwest::Client,
    event_rx: UnboundedReceiver<TransportEvent>,
    event_tx: UnboundedSender<TransportEvent>,
    relay_writer: Option<UnboundedSender<relay::OutboundRelayMessage>>,
    offline_mode: bool,
}

impl TransportManager {
    pub fn new() -> Self {
        let (event_tx, event_rx) = unbounded_channel();
        let http = reqwest::Client::builder()
            .connect_timeout(std::time::Duration::from_millis(300))
            .timeout(std::time::Duration::from_millis(800))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());
        Self {
            http,
            event_rx,
            event_tx,
            relay_writer: None,
            offline_mode: false,
        }
    }

    pub async fn create_session(&mut self, config: &AppConfig) -> Result<SessionCreated> {
        match control::create_session(&self.http, config).await {
            Ok(created) => {
                self.offline_mode = false;
                Ok(created)
            }
            Err(_err) if is_local_dev_endpoint(&config.control_base_url) => {
                self.offline_mode = true;
                eprintln!(
                    "{APP_NAME}: control server unavailable, falling back to offline session"
                );
                Ok(SessionCreated {
                    session_id: offline_session_id(),
                    host_token: offline_host_token(),
                    guest_url: offline_guest_url(),
                    relay_url: config.relay_base_url.clone(),
                })
            }
            Err(err) => Err(err),
        }
    }

    pub async fn connect_relay(&mut self, session: &SessionContext) -> Result<()> {
        if self.offline_mode {
            return Ok(());
        }

        let writer = relay::connect(&session.relay_url, &session.host_token, self.event_tx.clone()).await?;
        self.relay_writer = Some(writer);
        Ok(())
    }

    pub async fn next_event(&mut self) -> TransportEvent {
        self.event_rx
            .recv()
            .await
            .unwrap_or(TransportEvent::TransportError)
    }

    pub async fn send_terminal_bytes(&mut self, bytes: &[u8]) -> Result<()> {
        self.send_outbound(relay::output_message(bytes))
    }

    fn send_outbound(&mut self, message: relay::OutboundRelayMessage) -> Result<()> {
        if self.offline_mode {
            return Ok(());
        }

        if let Some(writer) = self.relay_writer.as_ref() {
            writer
                .send(message)
                .map_err(|_| AppError::Message("relay writer closed".to_string()))?;
        }
        Ok(())
    }

    pub async fn send_approval_state(&mut self, decision: &PolicyDecision) -> Result<()> {
        self.send_outbound(relay::approval_message(decision))
    }

    pub async fn send_guest_feedback(&mut self, message: &str) -> Result<()> {
        self.send_outbound(relay::feedback_message(message))
    }

    pub fn send_resize(&mut self, size: TerminalSize) {
        let _ = self.send_outbound(relay::resize_message(size));
    }

    pub async fn close(&mut self) -> Result<()> {
        if self.offline_mode {
            return Ok(());
        }

        let _ = self.send_outbound(relay::OutboundRelayMessage::Close);
        self.relay_writer = None;
        Ok(())
    }
}

fn is_local_dev_endpoint(url: &str) -> bool {
    url.contains("127.0.0.1") || url.contains("localhost")
}
