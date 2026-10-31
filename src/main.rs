use patchriot_dispatcher::{AppState, connect, router};
use std::net::SocketAddr;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let database_url = std::env::var("DATABASE_URL").map_err(|_| "DATABASE_URL is required")?;
    let internal_key = std::env::var("PATCHRIOT_INTERNAL_KEY")
        .map_err(|_| "PATCHRIOT_INTERNAL_KEY is required")?;
    let audience =
        std::env::var("PATCHRIOT_AUDIENCE").map_err(|_| "PATCHRIOT_AUDIENCE is required")?;
    let bind: SocketAddr = std::env::var("PATCHRIOT_BIND")
        .unwrap_or_else(|_| "127.0.0.1:7411".into())
        .parse()?;
    let pool = connect(&database_url)
        .await
        .map_err(|_| "database connection or migration failed")?;
    let state = AppState::new(pool, internal_key, audience)?;
    let listener = tokio::net::TcpListener::bind(bind).await?;
    eprintln!("Patchriot dispatcher listening on {bind}");
    axum::serve(listener, router(state))
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await?;
    Ok(())
}
