//! Agent-only companion for a private hosted dispatcher. The default listener
//! is loopback; a managed HTTPS proxy can use an explicit container bind.
//! Neither mode has internal routes, a core key or background workers.
use patchriot_dispatcher::{AppState, connect, relay_router};
use std::net::SocketAddr;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let configured_bind = std::env::var("PATCHRIOT_GATEWAY_BIND").ok();
    let bind = gateway_bind(configured_bind.as_deref())?;
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
    let state = AppState::relay_only(pool, audience)?
        .with_agent_attempt_seconds(seconds)?
        .with_compute_group_concurrency(
            std::env::var("PATCHRIOT_COMPUTE_GROUP_CONCURRENCY")
                .unwrap_or_else(|_| "1".into())
                .parse::<u8>()
                .map_err(|_| "PATCHRIOT_COMPUTE_GROUP_CONCURRENCY must be 1..4")?,
        )?
        .with_credential_key(std::env::var("PATCHRIOT_CREDENTIAL_KEY").ok())?;
    // This separate variable never changes the main dispatcher's internal bind.
    // A non-loopback listener needs HTTPS termination; the binary does not add TLS.
    let listener = tokio::net::TcpListener::bind(bind).await?;
    eprintln!("Patchriot relay gateway listening on {bind}");
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

fn gateway_bind(configured: Option<&str>) -> Result<SocketAddr, &'static str> {
    let bind: SocketAddr = configured
        .unwrap_or("127.0.0.1:7412")
        .parse()
        .map_err(|_| "PATCHRIOT_GATEWAY_BIND must be an IP:port")?;
    if bind.port() == 0 || bind.ip().is_multicast() {
        return Err("PATCHRIOT_GATEWAY_BIND needs a nonzero port and a unicast or wildcard IP");
    }
    Ok(bind)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gateway_stays_on_loopback_unless_explicitly_configured() {
        assert_eq!(
            gateway_bind(None).unwrap(),
            "127.0.0.1:7412".parse().unwrap()
        );
        assert_eq!(
            gateway_bind(Some("[::]:7412")).unwrap(),
            "[::]:7412".parse().unwrap()
        );
        assert_eq!(
            gateway_bind(Some("0.0.0.0:7412")).unwrap(),
            "0.0.0.0:7412".parse().unwrap()
        );
        for value in [
            "",
            "localhost:7412",
            "127.0.0.1:0",
            "239.0.0.1:7412",
            "[ff02::1]:7412",
        ] {
            assert!(gateway_bind(Some(value)).is_err(), "{value}");
        }
    }
}
