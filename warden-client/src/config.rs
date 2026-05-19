use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;

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
    pub approval_enabled: bool,
    pub policy_snapshot: PolicySnapshot,
    pub config_path: Option<PathBuf>,
}

#[derive(Debug, Clone)]
pub struct PolicySnapshot {
    pub config: PolicyConfig,
    pub source: PolicySource,
    pub version_hint: String,
}

#[derive(Debug, Clone)]
pub enum PolicySource {
    LocalFile { path: PathBuf },
    BackendDefault { endpoint: String },
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

        let policy_snapshot = if let Ok(path) = std::env::var("AI_REMOTE_WARDEN_POLICY") {
            let path = PathBuf::from(path);
            if !path.exists() {
                return Err(AppError::Message(format!(
                    "policy file not found: {}",
                    path.display()
                )));
            }
            load_local_policy_snapshot(&path)?
        } else {
            fetch_backend_policy_snapshot(&endpoints.control_base_url).await?
        };

        Ok(Self {
            control_base_url: endpoints.control_base_url,
            relay_base_url: endpoints.relay_base_url,
            ai_base_url: std::env::var("DEBUGIT_AI_BASE_URL")
                .unwrap_or_else(|_| "http://localhost:9001/v1".to_string()),
            ai_model: std::env::var("DEBUGIT_AI_MODEL")
                .unwrap_or_else(|_| "default".to_string()),
            preferred_shell: None,
            readonly: false,
            approval_enabled: true,
            policy_snapshot,
            config_path: local_override_path(),
        })
    }

    pub async fn reload_policy_snapshot(&mut self) -> Result<()> {
        let snapshot = match &self.policy_snapshot.source {
            PolicySource::LocalFile { path } => load_local_policy_snapshot(path)?,
            PolicySource::BackendDefault { endpoint } => {
                fetch_policy_snapshot_from_endpoint(endpoint).await?
            }
        };

        self.policy_snapshot = snapshot;
        Ok(())
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
            let relay_port = if url.port().is_some() {
                control_port + 1
            } else {
                8081
            };
            return Ok(Self {
                control_base_url: format!("{scheme}://{host}:{control_port}"),
                relay_base_url: format!(
                    "{}://{}:{}",
                    if scheme == "https" { "wss" } else { "ws" },
                    host,
                    relay_port
                ),
            });
        }

        let host = server.trim();
        if host.is_empty() {
            return Err(AppError::Message("server host cannot be empty".to_string()));
        }

        Ok(Self {
            control_base_url: format!("http://{host}:8080"),
            relay_base_url: format!("ws://{host}:8081"),
        })
    }
}

fn local_override_path() -> Option<PathBuf> {
    std::env::var("AI_REMOTE_WARDEN_POLICY").ok().map(PathBuf::from)
}

fn load_local_policy_snapshot(path: &Path) -> Result<PolicySnapshot> {
    let raw = std::fs::read_to_string(path)?;
    let config: PolicyConfig = serde_json::from_str(&raw)
        .map_err(|err| AppError::Message(format!("failed to parse policy file: {err}")))?;

    let metadata = std::fs::metadata(path)?;
    let modified = metadata
        .modified()
        .ok()
        .and_then(|time| time.duration_since(UNIX_EPOCH).ok())
        .map(|duration| duration.as_secs())
        .unwrap_or(0);

    Ok(PolicySnapshot {
        config,
        source: PolicySource::LocalFile {
            path: path.to_path_buf(),
        },
        version_hint: format!("local:{}:{modified}", path.display()),
    })
}

async fn fetch_backend_policy_snapshot(control_base_url: &str) -> Result<PolicySnapshot> {
    let endpoint = format!("{}/v1/policy/default", control_base_url.trim_end_matches('/'));
    fetch_policy_snapshot_from_endpoint(&endpoint).await
}

async fn fetch_policy_snapshot_from_endpoint(endpoint: &str) -> Result<PolicySnapshot> {
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

    let version_hint = response
        .headers()
        .get("ETag")
        .and_then(|value| value.to_str().ok())
        .map(ToString::to_string)
        .unwrap_or_else(|| endpoint.to_string());

    let config: PolicyConfig = response
        .json()
        .await
        .map_err(|err| AppError::Message(format!("invalid backend policy response: {err}")))?;

    Ok(PolicySnapshot {
        config,
        source: PolicySource::BackendDefault {
            endpoint: endpoint.to_string(),
        },
        version_hint,
    })
}
