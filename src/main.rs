mod api;
mod config;
mod domain;
mod security;

use std::net::SocketAddr;

use anyhow::Context;
use api::AppState;
use tokio::net::TcpListener;
use tracing::info;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_tracing();
    let config = config::AppConfig::from_env();

    let app = api::router(AppState {
        config: config.clone(),
    });

    let addr: SocketAddr = format!("{}:{}", config.host, config.port)
        .parse()
        .context("invalid listen address")?;
    let listener = TcpListener::bind(addr).await.context("bind listener")?;

    info!(%addr, issuer = %config.issuer, "starting auth service");
    axum::serve(listener, app)
        .await
        .context("http server failed")?;
    Ok(())
}

fn init_tracing() {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| "info,sqlx=warn,tower_http=warn".into());

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .json()
        .init();
}
