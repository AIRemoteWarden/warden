use base64::Engine;
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc::{unbounded_channel, UnboundedSender};
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::Message;

use crate::errors::{AppError, Result};
use crate::policy::{PolicyDecision, RiskLevel};
use crate::platform::TerminalSize;
use crate::transport::TransportEvent;

#[derive(Debug, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum OutboundRelayMessage {
    HostOutput { data_b64: String },
    Resize { cols: u16, rows: u16 },
    ApprovalState {
        decision: String,
        reason: Option<String>,
        risk: Option<String>,
    },
    Feedback { message: String },
    Close,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum InboundRelayMessage {
    GuestJoined,
    GuestLeft,
    GuestInput { data_b64: String },
    Close,
    Error,
}

pub async fn connect(
    relay_url: &str,
    host_token: &str,
    event_tx: UnboundedSender<TransportEvent>,
) -> Result<UnboundedSender<OutboundRelayMessage>> {
    let mut request = relay_url
        .into_client_request()
        .map_err(|e| AppError::Message(e.to_string()))?;
    request
        .headers_mut()
        .insert(
            "Authorization",
            tokio_tungstenite::tungstenite::http::HeaderValue::from_str(
                &format!("Bearer {host_token}"),
            )
            .map_err(|e| AppError::Message(e.to_string()))?,
        );

    let (ws_stream, _) = tokio_tungstenite::connect_async(request)
        .await
        .map_err(|e| AppError::Message(e.to_string()))?;

    let (mut write_half, mut read_half) = ws_stream.split();
    let (writer_tx, mut writer_rx) = unbounded_channel::<OutboundRelayMessage>();

    let read_event_tx = event_tx.clone();
    tokio::spawn(async move {
        while let Some(message) = read_half.next().await {
            match message {
                Ok(Message::Text(text)) => match serde_json::from_str::<InboundRelayMessage>(&text)
                {
                    Ok(InboundRelayMessage::GuestJoined) => {
                        let _ = read_event_tx.send(TransportEvent::GuestJoined);
                    }
                    Ok(InboundRelayMessage::GuestLeft) => {
                        let _ = read_event_tx.send(TransportEvent::GuestLeft);
                    }
                    Ok(InboundRelayMessage::GuestInput { data_b64 }) => {
                        if let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(data_b64)
                        {
                            let _ = read_event_tx.send(TransportEvent::GuestInput(bytes));
                        }
                    }
                    Ok(InboundRelayMessage::Close) => {
                        let _ = read_event_tx.send(TransportEvent::RemoteClose);
                        break;
                    }
                    Ok(InboundRelayMessage::Error) | Err(_) => {
                        let _ = read_event_tx.send(TransportEvent::TransportError);
                    }
                },
                Ok(Message::Close(_)) => {
                    let _ = read_event_tx.send(TransportEvent::RemoteClose);
                    break;
                }
                Ok(_) => {}
                Err(_) => {
                    let _ = read_event_tx.send(TransportEvent::TransportError);
                    break;
                }
            }
        }
    });

    tokio::spawn(async move {
        while let Some(message) = writer_rx.recv().await {
            let text = match serde_json::to_string(&message) {
                Ok(text) => text,
                Err(_) => continue,
            };

            if write_half.send(Message::Text(text)).await.is_err() {
                break;
            }

            if matches!(message, OutboundRelayMessage::Close) {
                let _ = write_half.close().await;
                break;
            }
        }
    });

    Ok(writer_tx)
}

pub fn output_message(bytes: &[u8]) -> OutboundRelayMessage {
    OutboundRelayMessage::HostOutput {
        data_b64: base64::engine::general_purpose::STANDARD.encode(bytes),
    }
}

pub fn resize_message(size: TerminalSize) -> OutboundRelayMessage {
    OutboundRelayMessage::Resize {
        cols: size.cols,
        rows: size.rows,
    }
}

pub fn approval_message(decision: &PolicyDecision) -> OutboundRelayMessage {
    match decision {
        PolicyDecision::Allow => OutboundRelayMessage::ApprovalState {
            decision: "allow".to_string(),
            reason: None,
            risk: None,
        },
        PolicyDecision::Deny { reason } => OutboundRelayMessage::ApprovalState {
            decision: "deny".to_string(),
            reason: Some(reason.clone()),
            risk: None,
        },
        PolicyDecision::RequireApproval { reason, risk } => OutboundRelayMessage::ApprovalState {
            decision: "require_approval".to_string(),
            reason: Some(reason.clone()),
            risk: Some(match risk {
                RiskLevel::High => "high",
            }
            .to_string()),
        },
    }
}

pub fn feedback_message(message: &str) -> OutboundRelayMessage {
    OutboundRelayMessage::Feedback {
        message: message.to_string(),
    }
}
