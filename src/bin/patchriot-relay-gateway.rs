//! Agent-only companion for a private hosted dispatcher. Tailscale Serve shares
//! this loopback listener; no internal routes, core key or background workers.
use patchriot_dispatcher::{AppState, connect, relay_router};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let database_url = std::env::var("DATABASE_URL").map_err(|_| "DATABASE_URL is required")?;
    let audience =
        std::env::var("PATCHRIOT_AUDIENCE").map_err(|_| "PATCHRIOT_AUDIENCE is required")?;
    let seconds = std::env::var("PATCHRIOT_AGENT_ATTEMPT_SECONDS")
        .unwrap_or_else(|_| "600".into())
        .parse::<u64>()
        .map_err(|_| "PATCHRIOT_AGENT_ATTEMPT_SECONDS must be an integer")?;
    let pool = connect(&database_url)
        .await
        .map_err(|_| "database connection or migration failed")?;
    let state = AppState::relay_only(pool, audience)?.with_agent_attempt_seconds(seconds)?;
    // Deliberately fixed: PATCHRIOT_BIND cannot turn this into a public listener.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:7412").await?;
    eprintln!("Patchriot relay gateway listening on loopback port 7412");
    axum::serve(listener, relay_router(state))
        .with_graceful_shutdown(async {
            #[cfg(unix)]
            {
                let mut terminate =
                    tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                        .expect("install SIGTERM handler");
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => {},
                    _ = terminate.recv() => {},
                }
            }
            #[cfg(not(unix))]
            let _ = tokio::signal::ctrl_c().await;
        })
        .await?;
    Ok(())
}
