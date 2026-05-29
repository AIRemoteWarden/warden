use crate::config::{AppConfig, ClientOptions};
use crate::errors::{AppError, Result};
use crate::platform::PlatformContext;
use crate::policy::PolicyEngine;
use crate::terminal::TerminalManager;
use crate::transport::TransportManager;
use crate::ui::UiRenderer;
use std::str::FromStr;

pub struct CliBootstrap;

pub struct RuntimeParts {
    pub platform: PlatformContext,
    pub terminal: TerminalManager,
    pub transport: TransportManager,
    pub policy: PolicyEngine,
    pub ui: UiRenderer,
}

impl CliBootstrap {
    pub async fn bootstrap_runtime_parts() -> Result<(AppConfig, RuntimeParts)> {
        let options = Self::parse_args()?;
        let config = Self::build_config(options).await?;
        let platform = PlatformContext::new();
        let terminal = TerminalManager::new();
        let transport = TransportManager::new(config.options.insecure);
        let policy = PolicyEngine::new(config.policy.clone());
        let ui = UiRenderer::new();

        Ok((
            config,
            RuntimeParts {
                platform,
                terminal,
                transport,
                policy,
                ui,
            },
        ))
    }

    fn parse_args() -> Result<ClientOptions> {
        let mut args = std::env::args().skip(1);
        let mut parsed = ClientOptions::default();

        while let Some(arg) = args.next() {
            match arg.as_str() {
                "start" => {}
                "demo-host" => parsed.demo_host = true,
                "--readonly" => parsed.readonly = true,
                "--idle-timeout" => {
                    let raw = args.next().ok_or(AppError::InvalidArguments(
                        "missing idle timeout seconds".into(),
                    ))?;
                    let seconds = u64::from_str(&raw).map_err(|_| {
                        AppError::InvalidArguments(
                            "idle timeout must be a positive integer number of seconds".into(),
                        )
                    })?;
                    if seconds == 0 {
                        return Err(AppError::InvalidArguments(
                            "idle timeout must be greater than zero".into(),
                        ));
                    }
                    parsed.idle_timeout_seconds = Some(seconds);
                }
                "--idle-warning" => {
                    let raw = args.next().ok_or(AppError::InvalidArguments(
                        "missing idle warning seconds".into(),
                    ))?;
                    let seconds = u64::from_str(&raw).map_err(|_| {
                        AppError::InvalidArguments(
                            "idle warning must be a non-negative integer number of seconds".into(),
                        )
                    })?;
                    parsed.idle_warning_seconds = Some(seconds);
                }
                "--shell" => {
                    let shell = args
                        .next()
                        .ok_or(AppError::InvalidArguments("missing shell name".into()))?;
                    parsed.preferred_shell = Some(shell);
                }
                "--server" => {
                    let server = args
                        .next()
                        .ok_or(AppError::InvalidArguments("missing server host".into()))?;
                    parsed.server = Some(server);
                }
                "--llm" => {
                    let llm = args
                        .next()
                        .ok_or(AppError::InvalidArguments("missing llm base url".into()))?;
                    parsed.llm = Some(llm);
                }
                "--insecure" => parsed.insecure = true,
                "doctor" => return Err(AppError::Unsupported("doctor is not implemented yet")),
                other => {
                    return Err(AppError::InvalidArguments(format!(
                        "unknown argument: {other}"
                    )))
                }
            }
        }

        if parsed.demo_session_id.is_none() {
            parsed.demo_session_id = std::env::var("WARDEN_DEMO_SESSION_ID").ok();
        }

        Ok(parsed)
    }

    async fn build_config(options: ClientOptions) -> Result<AppConfig> {
        AppConfig::load(options).await
    }
}
