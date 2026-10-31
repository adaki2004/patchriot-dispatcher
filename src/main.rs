use patchriot_dispatcher::{AppState, connect, router, websites};
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
    let seconds = std::env::var("PATCHRIOT_AGENT_ATTEMPT_SECONDS")
        .unwrap_or_else(|_| "600".into())
        .parse::<u64>()
        .map_err(|_| "PATCHRIOT_AGENT_ATTEMPT_SECONDS must be an integer")?;
    let state =
        AppState::new(pool.clone(), internal_key, audience)?.with_agent_attempt_seconds(seconds)?;
    let listener = tokio::net::TcpListener::bind(bind).await?;
    let (stop, stopped) = tokio::sync::watch::channel(false);
    let collector = tokio::spawn(websites::run_worker(pool, stopped));
    eprintln!("Patchriot dispatcher listening on {bind}");
    let stopping = stop.clone();
    let result = axum::serve(listener, router(state))
        .with_graceful_shutdown(async move {
            shutdown_signal().await;
            let _ = stopping.send(true);
        })
        .await;
    let _ = stop.send(true);
    collector.await?;
    result?;
    Ok(())
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .expect("install SIGTERM handler");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = terminate.recv() => {}
        }
    }
    #[cfg(not(unix))]
    let _ = tokio::signal::ctrl_c().await;
}
