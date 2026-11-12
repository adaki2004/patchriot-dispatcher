use patchriot_dispatcher::{
    AppState, connect, ownership, relay_router, router, screening, websites,
};
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
    let relay_bind = std::env::var("PATCHRIOT_RELAY_BIND")
        .ok()
        .map(|value| value.parse::<SocketAddr>())
        .transpose()
        .map_err(|_| "PATCHRIOT_RELAY_BIND must be a loopback IP:port")?;
    validate_binds(bind, relay_bind)?;
    let pool = connect(&database_url)
        .await
        .map_err(|_| "database connection or migration failed")?;
    let seconds = std::env::var("PATCHRIOT_AGENT_ATTEMPT_SECONDS")
        .unwrap_or_else(|_| "600".into())
        .parse::<u64>()
        .map_err(|_| "PATCHRIOT_AGENT_ATTEMPT_SECONDS must be an integer")?;
    let state = AppState::new(pool.clone(), internal_key, audience)?
        .with_venice_fallback(
            std::env::var("PATCHRIOT_VENICE_FALLBACK_ENABLED").as_deref() == Ok("true"),
        )
        .with_inference_routing(
            std::env::var("PATCHRIOT_INFERENCE_PRIMARY_MODEL")
                .ok()
                .as_deref(),
            std::env::var("PATCHRIOT_INFERENCE_SECONDARY_MODEL")
                .ok()
                .as_deref(),
        )?
        .with_balanced_inference(
            std::env::var("PATCHRIOT_INFERENCE_BALANCED_POOLS").as_deref() == Ok("true"),
        )?
        .with_agent_attempt_seconds(seconds)?
        .with_live_requests_per_day(
            std::env::var("PATCHRIOT_LIVE_REQUESTS_PER_DAY")
                .unwrap_or_else(|_| "10".into())
                .parse::<u16>()
                .map_err(|_| "PATCHRIOT_LIVE_REQUESTS_PER_DAY must be 1..100")?,
        )?
        .with_live_reviews_per_requester(
            std::env::var("PATCHRIOT_LIVE_REVIEWS_PER_REQUESTER")
                .unwrap_or_else(|_| "3".into())
                .parse::<u8>()
                .map_err(|_| "PATCHRIOT_LIVE_REVIEWS_PER_REQUESTER must be 1..30")?,
        )?
        .with_compute_group_concurrency(
            std::env::var("PATCHRIOT_COMPUTE_GROUP_CONCURRENCY")
                .unwrap_or_else(|_| "1".into())
                .parse::<u8>()
                .map_err(|_| "PATCHRIOT_COMPUTE_GROUP_CONCURRENCY must be 1..4")?,
        )?
        .with_credential_key(std::env::var("PATCHRIOT_CREDENTIAL_KEY").ok())?
        .with_owned_test_origins(
            std::env::var("PATCHRIOT_OWNED_TEST_ORIGINS")
                .ok()
                .map(|value| serde_json::from_str::<Vec<String>>(&value))
                .transpose()
                .map_err(
                    |_| "PATCHRIOT_OWNED_TEST_ORIGINS must be a JSON array of exact HTTPS origins",
                )?
                .unwrap_or_default(),
        )?
        .with_near_ai_key(std::env::var("PATCHRIOT_NEAR_AI_KEY").ok())?
        .with_context_screening(std::env::var("PATCHRIOT_JEV_OPENROUTER_KEY").ok())?;
    let jev = std::env::var("PATCHRIOT_JEV_OPENROUTER_KEY")
        .ok()
        .map(|key| screening::Jev::new(&key))
        .transpose()?;
    let listener = tokio::net::TcpListener::bind(bind).await?;
    let relay_listener = match relay_bind {
        Some(address) => Some(tokio::net::TcpListener::bind(address).await?),
        None => None,
    };
    let (stop, stopped) = tokio::sync::watch::channel(false);
    let cleanup = tokio::spawn(patchriot_dispatcher::run_cleanup(
        pool.clone(),
        stopped.clone(),
    ));
    let screening = tokio::spawn(screening::run_worker(pool.clone(), jev, stopped.clone()));
    let report_checks = tokio::spawn(patchriot_dispatcher::report_checks::run_worker(
        pool.clone(),
        state.report_checker(),
        stopped.clone(),
    ));
    let collector = tokio::spawn(websites::run_worker(pool.clone(), stopped.clone()));
    let resolver = hickory_resolver::TokioResolver::builder_tokio()?.build()?;
    let ownership = tokio::spawn(ownership::run_worker(pool, resolver, stopped.clone()));
    eprintln!("Patchriot dispatcher listening on {bind}");
    let stopping = stop.clone();
    let signal = tokio::spawn(async move {
        shutdown_signal().await;
        let _ = stopping.send(true);
    });
    let result = if let Some(relay_listener) = relay_listener {
        eprintln!(
            "Patchriot relay gateway listening on {} (proxy with Tailscale Serve)",
            relay_listener.local_addr()?
        );
        tokio::try_join!(
            serve(
                listener,
                router(state.clone()),
                stopped.clone(),
                stop.clone()
            ),
            serve(relay_listener, relay_router(state), stopped, stop.clone()),
        )
        .map(|_| ())
    } else {
        serve(listener, router(state), stopped, stop.clone()).await
    };
    let _ = stop.send(true);
    signal.abort();
    collector.await?;
    screening.await?;
    report_checks.await?;
    ownership.await?;
    cleanup.await?;
    result?;
    Ok(())
}

fn validate_binds(internal: SocketAddr, relay: Option<SocketAddr>) -> Result<(), &'static str> {
    if let Some(relay) = relay {
        if !internal.ip().is_loopback() || !relay.ip().is_loopback() {
            return Err(
                "mesh mode requires both listeners on loopback; expose only the relay port through Tailscale Serve",
            );
        }
        if internal.port() == 0 || relay.port() == 0 || internal == relay {
            return Err(
                "mesh mode requires distinct, nonzero internal and relay listener addresses",
            );
        }
    }
    Ok(())
}

async fn serve(
    listener: tokio::net::TcpListener,
    router: axum::Router,
    mut stopped: tokio::sync::watch::Receiver<bool>,
    stop: tokio::sync::watch::Sender<bool>,
) -> std::io::Result<()> {
    let result = axum::serve(listener, router)
        .with_graceful_shutdown(async move {
            let _ = stopped.wait_for(|stopped| *stopped).await;
        })
        .await;
    // A listener failure also stops its sibling and background workers.
    let _ = stop.send(true);
    result
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

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn mesh_listeners_cannot_expose_internal_routes_on_a_public_bind() {
        let internal = "127.0.0.1:7411".parse().unwrap();
        assert!(validate_binds(internal, Some("127.0.0.1:7412".parse().unwrap())).is_ok());
        assert!(validate_binds(internal, None).is_ok());
        for address in [
            "0.0.0.0:7412",
            "100.64.0.1:7412",
            "[::]:7412",
            "127.0.0.1:0",
            "127.0.0.1:7411",
        ] {
            assert!(validate_binds(internal, Some(address.parse().unwrap())).is_err());
        }
        assert!(
            validate_binds(
                "0.0.0.0:7411".parse().unwrap(),
                Some("127.0.0.1:7412".parse().unwrap())
            )
            .is_err()
        );
    }
}
