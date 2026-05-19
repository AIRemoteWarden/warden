use serde::{Deserialize, Serialize};

use crate::config::AppConfig;
use crate::errors::{AppError, Result};

#[derive(Clone)]
pub struct AiClient {
    http: reqwest::Client,
    base_url: String,
    model: String,
}

impl AiClient {
    pub fn new(config: &AppConfig) -> Self {
        let http = reqwest::Client::builder()
            .connect_timeout(std::time::Duration::from_millis(600))
            .timeout(std::time::Duration::from_secs(15))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());

        Self {
            http,
            base_url: config.ai_base_url.trim_end_matches('/').to_string(),
            model: config.ai_model.clone(),
        }
    }

    pub async fn assess_command(&self, command: &str, reason: &str) -> Result<String> {
        let prompt = format!(
            "You are a security expert. Reply in plain English. \
Format your answer exactly as short multi-line text, using line breaks between sections. \
Use this structure:\n\
Risk: <low|medium|high>\n\
- <short reason 1>\n\
- <short reason 2>\n\
- <optional short reason 3>\n\
Recommendation: <one short sentence>\n\
Keep every bullet concise. Do not use Markdown headings, tables, or paragraphs. \
Command under review: `{command}`. \
Local policy trigger reason: {reason}."
        );

        let payload = ChatCompletionRequest {
            model: self.model.clone(),
            messages: vec![ChatRequestMessage {
                role: "user".to_string(),
                content: prompt,
            }],
            temperature: 0.2,
            max_tokens: 300,
        };

        let response = self
            .http
            .post(format!("{}/chat/completions", self.base_url))
            .json(&payload)
            .send()
            .await
            .map_err(|e| AppError::Message(format!("ai request failed: {e}")))?;

        let response = response
            .error_for_status()
            .map_err(|e| AppError::Message(format!("ai service returned error: {e}")))?;

        let payload: ChatCompletionResponse = response
            .json()
            .await
            .map_err(|e| AppError::Message(format!("invalid ai response: {e}")))?;

        payload
            .choices
            .into_iter()
            .next()
            .map(|choice| {
                let content = choice.message.content.trim();
                if !content.is_empty() {
                    return content.to_string();
                }

                choice
                    .message
                    .reasoning_content
                    .unwrap_or_default()
                    .trim()
                    .to_string()
            })
            .filter(|content| !content.is_empty())
            .ok_or_else(|| AppError::Message("ai returned empty assessment".to_string()))
    }
}

#[derive(Serialize)]
struct ChatCompletionRequest {
    model: String,
    messages: Vec<ChatRequestMessage>,
    temperature: f32,
    max_tokens: u32,
}

#[derive(Serialize)]
struct ChatRequestMessage {
    role: String,
    content: String,
}

#[derive(Deserialize)]
struct ChatResponseMessage {
    content: String,
    #[serde(default)]
    reasoning_content: Option<String>,
}

#[derive(Deserialize)]
struct ChatCompletionResponse {
    choices: Vec<ChatCompletionChoice>,
}

#[derive(Deserialize)]
struct ChatCompletionChoice {
    message: ChatResponseMessage,
}
