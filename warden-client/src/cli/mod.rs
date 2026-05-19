use crate::config::AppConfig;
use crate::errors::{AppError, Result};
use crate::platform::PlatformContext;
use crate::policy::PolicyEngine;
use crate::terminal::TerminalManager;
use crate::transport::TransportManager;
use crate::ui::UiRenderer;

#[derive(Debug, Clone, Default)]
pub struct CommandArgs {
    pub readonly: bool,
    pub preferred_shell: Option<String>,
    pub server: Option<String>,
    pub llm: Option<String>,
}

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
        let args = Self::parse_args()?;
        let config = Self::build_config(args).await?;
        let platform = PlatformContext::new();
        let terminal = TerminalManager::new();
        let transport = TransportManager::new();
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

    fn parse_args() -> Result<CommandArgs> {
        let mut args = std::env::args().skip(1);
        let mut parsed = CommandArgs::default();

        while let Some(arg) = args.next() {
            match arg.as_str() {
                "start" => {}
                "--readonly" => parsed.readonly = true,
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
                "doctor" => return Err(AppError::Unsupported("doctor is not implemented yet")),
                other => {
                    return Err(AppError::InvalidArguments(format!(
                        "unknown argument: {other}"
                    )))
                }
            }
        }

        Ok(parsed)
    }

    async fn build_config(args: CommandArgs) -> Result<AppConfig> {
        let mut config = AppConfig::load(args.server.as_deref()).await?;
        config.readonly = args.readonly;
        config.preferred_shell = args.preferred_shell;
        if let Some(llm) = args.llm {
            config.ai_base_url = AppConfig::normalize_llm_base_url(&llm)?;
        }
        Ok(config)
    }
}
