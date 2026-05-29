use serde::{Deserialize, Serialize};

use crate::config::AppConfig;
use crate::errors::{AppError, Result};
use crate::transport::SessionCreated;

#[derive(Debug, Serialize)]
struct CreateSessionRequest {
    readonly: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    idle_timeout_seconds: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    idle_warning_seconds: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    demo_session_id: Option<String>,
}

#[derive(Debug, Deserialize)]
struct CreateSessionResponse {
    session_id: String,
    host_token: String,
    guest_url: String,
    relay_url: Option<String>,
    idle_timeout_seconds: Option<u64>,
    idle_warning_seconds: Option<u64>,
}

pub async fn create_session(
    client: &reqwest::Client,
    config: &AppConfig,
) -> Result<SessionCreated> {
    let url = format!("{}/v1/sessions", config.control_base_url.trim_end_matches('/'));
    let response = client
        .post(url)
        .json(&CreateSessionRequest {
            readonly: config.options.readonly,
            idle_timeout_seconds: config.options.idle_timeout_seconds,
            idle_warning_seconds: config.options.idle_warning_seconds,
            demo_session_id: config.options.demo_session_id.clone(),
        })
        .send()
        .await
        .map_err(|e| AppError::Message(e.to_string()))?;

    let response = response
        .error_for_status()
        .map_err(|e| AppError::Message(e.to_string()))?;
    let payload: CreateSessionResponse = response
        .json()
        .await
        .map_err(|e| AppError::Message(e.to_string()))?;

    Ok(SessionCreated {
        session_id: payload.session_id,
        host_token: payload.host_token,
        guest_url: payload.guest_url,
        relay_url: payload
            .relay_url
            .unwrap_or_else(|| config.relay_base_url.clone()),
        idle_timeout_seconds: payload.idle_timeout_seconds,
        idle_warning_seconds: payload.idle_warning_seconds,
    })
}
