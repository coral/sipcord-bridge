//! Sipcord Bridge - Static Router Binary
//!
//! Standalone SIP-to-Discord voice bridge using a TOML dialplan.

#![feature(portable_simd)]
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]

use std::path::PathBuf;
use std::sync::Arc;

use tracing::{error, info};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use sipcord_bridge::BridgeError;
use sipcord_bridge::call::BridgeCoordinator;
use sipcord_bridge::config::{APP_CONFIG, AppConfig, ConfigError, EnvConfig, SipConfig};
use sipcord_bridge::routing::static_router::StaticBackend;
use sipcord_bridge::transport::discord::SharedDiscordClient;
use sipcord_bridge::transport::sip::SipTransport;

#[tokio::main]
async fn main() -> Result<(), BridgeError> {
    if rustls::crypto::ring::default_provider()
        .install_default()
        .is_err()
    {
        panic!("rustls crypto provider already installed or feature missing");
    }

    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "sipcord_bridge=info,pjsip=warn".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    info!("Starting Sipcord Bridge v{}", env!("CARGO_PKG_VERSION"));

    EnvConfig::init()?;

    let config_path = PathBuf::from(&EnvConfig::global().config_path);
    let app_config = AppConfig::load(&config_path)?;
    APP_CONFIG
        .set(app_config)
        .map_err(|_| BridgeError::Config(ConfigError::EnvAlreadyInitialised))?;
    info!("Loaded config from {}", config_path.display());

    run_static_router().await
}

async fn run_static_router() -> Result<(), BridgeError> {
    let bot_token = EnvConfig::global()
        .discord_bot_token
        .clone()
        .ok_or(ConfigError::MissingEnvVar("DISCORD_BOT_TOKEN"))?;
    let sip_config = SipConfig::from_env()?;

    // Load dialplan
    let dialplan_path = PathBuf::from(&EnvConfig::global().dialplan_path);
    let backend = Arc::new(StaticBackend::load(&dialplan_path, bot_token.clone())?);

    // Create SIP transport (no TLS for static router)
    let sip_transport = SipTransport::new(sip_config.clone(), None);
    let sip_event_tx = sip_transport.event_sender();

    // Create channel for outbound call events (SIP callbacks still emit these)
    let (outbound_event_tx, mut outbound_event_rx) = tokio::sync::mpsc::unbounded_channel();
    sipcord_bridge::transport::sip::set_outbound_event_sender(outbound_event_tx);

    // Forward outbound call events to the main SIP event channel
    let sip_event_tx_for_outbound = sip_event_tx.clone();
    tokio::spawn(async move {
        while let Some(event) = outbound_event_rx.recv().await {
            let _ = sip_event_tx_for_outbound.send(event);
        }
    });

    // Create shared Discord client
    let shared_discord = SharedDiscordClient::new(&bot_token).await?;
    info!("Shared Discord client initialized");

    let bridge = BridgeCoordinator::new(
        backend,
        sip_transport.commands(),
        sip_transport.events(),
        shared_discord,
    )?;

    info!("Starting components...");

    let mut sip_handle = tokio::spawn(async move {
        if let Err(e) = sip_transport.run().await {
            error!("SIP server error: {}", e);
        }
    });

    let mut bridge_handle = tokio::spawn(async move {
        if let Err(e) = bridge.run().await {
            error!("Bridge coordinator error: {}", e);
        }
    });

    info!(
        "Static router running on {}:{}",
        sip_config.public_host, sip_config.port
    );

    tokio::select! {
        _ = tokio::signal::ctrl_c() => info!("Shutdown signal received"),
        sip_res = &mut sip_handle => { if let Err(e) = sip_res { error!("SIP task failed: {}", e); } },
        bridge_res = &mut bridge_handle => { if let Err(e) = bridge_res { error!("Bridge task failed: {}", e); } },
    }

    info!("Shutting down...");

    std::thread::spawn(|| {
        std::thread::sleep(std::time::Duration::from_secs(2));
        std::process::exit(0);
    });

    sip_handle.abort();
    bridge_handle.abort();
    sipcord_bridge::transport::sip::shutdown_pjsua();

    info!("Shutdown complete");
    Ok(())
}
