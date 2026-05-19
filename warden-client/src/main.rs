mod app;
mod ai;
mod brand;
mod cli;
mod config;
mod errors;
mod platform;
mod policy;
mod runtime;
mod terminal;
mod transport;
mod ui;

use app::App;
use errors::Result;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let app = App::bootstrap().await?;
    app.run().await
}
