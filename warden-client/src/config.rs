use std::path::{Path, PathBuf};

use serde::Deserialize;
use url::Url;

use crate::errors::{AppError, Result};

#[derive(Debug, Clone)]
pub struct AppConfig {
    pub control_base_url: String,
    pub relay_base_url: String,
    pub ai_base_url: String,
    pub ai_model: String,
    pub preferred_shell: Option<String>,
    pub readonly: bool,
    pub policy: PolicyConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PolicyConfig {
    pub shell: ShellPolicyConfig,
    pub files: FilePolicyConfig,
    pub databases: DatabasePolicyConfig,
    #[serde(default)]
    pub distribution: PolicyDistributionConfig,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct ShellPolicyConfig {
    #[serde(default)]
    pub dangerous_commands: Vec<String>,
    #[serde(default)]
    pub approval_commands: Vec<String>,
    #[serde(default)]
    pub hook_commands: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct FilePolicyConfig {
    #[serde(default)]
    pub sensitive_rules: Vec<FileSensitiveRuleConfig>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct FileSensitiveRuleConfig {
    pub path: Option<String>,
    pub basename: Option<String>,
    pub suffix: Option<String>,
    pub path_component: Option<String>,
    pub kind: SensitiveFileKind,
    #[serde(default)]
    pub allow_redaction: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SensitiveFileKind {
    ShadowFile,
    SshMaterial,
    EnvFile,
    PemKey,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct DatabasePolicyConfig {
    #[serde(default)]
    pub column_rules: Vec<DbMaskRule>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DbMaskRule {
    pub engine: Option<String>,
    pub table: String,
    pub column: String,
    pub rule: DbMaskRuleKind,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DbMaskRuleKind {
    FullMask,
    Last4,
    PartialEmail,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct PolicyDistributionConfig {
    pub remote: Option<RemotePolicySourceConfig>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RemotePolicySourceConfig {
    #[serde(default)]
    pub enabled: bool,
    pub endpoint: String,
    pub cache_ttl_seconds: Option<u64>,
}

impl AppConfig {
    pub async fn load(server: Option<&str>) -> Result<Self> {
        let endpoints = EndpointConfig::from_server_arg(server)?;
        let default_ai_base_url = std::env::var("AIWARDEN_AI_BASE_URL")
            .or_else(|_| std::env::var("DEBUGIT_AI_BASE_URL"))
            .unwrap_or_else(|_| "http://localhost:9001/v1".to_string());

        let policy = if let Ok(path) = std::env::var("AI_REMOTE_WARDEN_POLICY") {
            let path = PathBuf::from(path);
            if !path.exists() {
                return Err(AppError::Message(format!(
                    "policy file not found: {}",
                    path.display()
                )));
            }
            load_local_policy(&path)?
        } else {
            fetch_backend_policy(&endpoints.control_base_url).await?
        };

        Ok(Self {
            control_base_url: endpoints.control_base_url,
            relay_base_url: endpoints.relay_base_url,
            ai_base_url: Self::normalize_llm_base_url(&default_ai_base_url)?,
            ai_model: std::env::var("AIWARDEN_AI_MODEL")
                .or_else(|_| std::env::var("DEBUGIT_AI_MODEL"))
                .unwrap_or_else(|_| "default".to_string()),
            preferred_shell: None,
            readonly: false,
            policy,
        })
    }

    pub fn normalize_llm_base_url(input: &str) -> Result<String> {
        let raw = input.trim();
        if raw.is_empty() {
            return Err(AppError::InvalidArguments(
                "llm base url cannot be empty".to_string(),
            ));
        }

        let candidate = if raw.starts_with("http://") || raw.starts_with("https://") {
            raw.to_string()
        } else {
            format!("http://{raw}")
        };

        let mut url = Url::parse(&candidate)
            .map_err(|err| AppError::InvalidArguments(format!("invalid llm base url: {err}")))?;

        let normalized_path = match url.path().trim_end_matches('/') {
            "" => "/v1".to_string(),
            "/v1" => "/v1".to_string(),
            path => path.to_string(),
        };
        url.set_path(&normalized_path);

        Ok(url.to_string().trim_end_matches('/').to_string())
    }
}

#[derive(Debug, Clone)]
struct EndpointConfig {
    control_base_url: String,
    relay_base_url: String,
}

impl EndpointConfig {
    fn from_server_arg(server: Option<&str>) -> Result<Self> {
        let server = server.unwrap_or("localhost");
        if server.starts_with("http://") || server.starts_with("https://") {
            let url = Url::parse(server)
                .map_err(|err| AppError::Message(format!("invalid server url: {err}")))?;
            let host = url
                .host_str()
                .ok_or(AppError::Message("server url is missing host".to_string()))?;
            let scheme = url.scheme();
            let control_port = url.port().unwrap_or(8080);
            return Ok(Self {
                control_base_url: format!("{scheme}://{host}:{control_port}"),
                relay_base_url: format!(
                    "{}://{}:{}",
                    if scheme == "https" { "wss" } else { "ws" },
                    host,
                    control_port
                ),
            });
        }

        let host = server.trim();
        if host.is_empty() {
            return Err(AppError::Message("server host cannot be empty".to_string()));
        }

        Ok(Self {
            control_base_url: format!("http://{host}:8080"),
            relay_base_url: format!("ws://{host}:8080"),
        })
    }
}

fn load_local_policy(path: &Path) -> Result<PolicyConfig> {
    let raw = std::fs::read_to_string(path)?;
    serde_json::from_str(&raw)
        .map_err(|err| AppError::Message(format!("failed to parse policy file: {err}")))
}

async fn fetch_backend_policy(control_base_url: &str) -> Result<PolicyConfig> {
    let endpoint = format!("{}/v1/policy/default", control_base_url.trim_end_matches('/'));
    fetch_policy_from_endpoint(&endpoint).await
}

async fn fetch_policy_from_endpoint(endpoint: &str) -> Result<PolicyConfig> {
    let http = reqwest::Client::builder()
        .connect_timeout(std::time::Duration::from_millis(600))
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .unwrap_or_else(|_| reqwest::Client::new());

    let response = http
        .get(endpoint)
        .send()
        .await
        .map_err(|err| AppError::Message(format!("failed to fetch policy from backend: {err}")))?;

    let response = response
        .error_for_status()
        .map_err(|err| AppError::Message(format!("backend policy request failed: {err}")))?;

    response
        .json()
        .await
        .map_err(|err| AppError::Message(format!("invalid backend policy response: {err}")))
}
