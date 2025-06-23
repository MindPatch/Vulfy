use clap::Parser;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

mod cli;
mod error;
mod scanner;
mod matcher;
mod reporter;
mod types;

use cli::Cli;
use error::VulfyResult;

#[tokio::main]
async fn main() -> VulfyResult<()> {
    // Initialize structured logging
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "vulfy=info".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    // Parse CLI arguments
    let cli = Cli::parse();
    
    // Execute the command
    cli.execute().await
}
