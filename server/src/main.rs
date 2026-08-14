use axum::Router;
use inquire::Select;
use std::net::SocketAddr;
use std::sync::Arc;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

mod app_state;
mod asset_types;
mod request_logger;
mod routes;

use app_state::AppState;
use request_logger::RequestLoggerLayer;
use std::path::Path;

#[tokio::main]
async fn main() {
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::new(
            std::env::var("RUST_LOG").unwrap_or_else(|_| "info".into()),
        ))
        .with(tracing_subscriber::fmt::layer())
        .init();

    let modes = vec!["Asset Grab Mode", "Regular Mode", "Reflection Mode"];
    let mode = Select::new("How do you want to start Studio-Offline?", modes)
        .prompt()
        .unwrap_or("No mode selected");

    if mode == "No mode selected" {
        println!("No mode selected, exiting...");
        return;
    }

    if mode == "Asset Grab Mode" && !std::path::Path::new("cookie.txt").exists() {
        tracing::error!("cookie.txt not found in the root directory.");
        tracing::error!(
            "This file is REQUIRED for Asset Grab Mode due to recent changes in Roblox's assetdelivery APIs."
        );
        tracing::error!("Please create a cookie.txt containing your .ROBLOSECURITY cookie.");
        return;
    }

    if !Path::new("./static").exists() {
        tracing::error!(
            "Static directory (required) not found in directory. Please reinstall Studio-Offline."
        );
        return;
    }

    println!("Webserver is running on mode: {mode}");

    let app_state = Arc::new(AppState {
        mode: mode.to_string(),
    });

    let app = Router::new()
        .nest(
            "/v2/settings/application/PCStudioApp",
            routes::client_settings::routes(),
        )
        .nest("/oauth", routes::oauth::routes())
        .nest("/assets", routes::upload::routes())
        .merge(routes::assets::routes())
        .merge(routes::static_handlers::routes())
        .merge(routes::datastores::routes())
        .merge(routes::telemetry::routes())
        .merge(routes::universal_app_config::routes())
        .layer(RequestLoggerLayer)
        .with_state(app_state);

    let addr = SocketAddr::from(([127, 0, 0, 1], 80));
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    tracing::info!("listening on {}", addr);
    axum::serve(listener, app).await.unwrap();
}
