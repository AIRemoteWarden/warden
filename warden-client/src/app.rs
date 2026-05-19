use crate::ai::AiClient;
use crate::cli::CliBootstrap;
use crate::errors::Result;
use crate::runtime::AppRuntime;

pub struct App {
    runtime: AppRuntime,
}

impl App {
    pub async fn bootstrap() -> Result<Self> {
        let (config, runtime_parts) = CliBootstrap::bootstrap_runtime_parts().await?;
        let ai = AiClient::new(&config);
        let runtime = AppRuntime::new(
            config,
            runtime_parts.platform,
            runtime_parts.terminal,
            runtime_parts.transport,
            runtime_parts.policy,
            ai,
            runtime_parts.ui,
        );
        Ok(Self { runtime })
    }

    pub async fn run(mut self) -> Result<()> {
        self.runtime.run().await
    }
}
