use api_test::{get_app, init_tracing, pre_task};
use std::env;
use tracing::info;

#[tokio::main]
async fn main() {
    init_tracing();
    dotenv::dotenv().ok();
    info!("envioment variables loaded");

    pre_task().await;

    let app = get_app();

    let bind_addr = env::var("BIND_ADDRESS").unwrap_or_else(|_| "127.0.0.1:3000".to_string());
    let listener = tokio::net::TcpListener::bind(&bind_addr)
        .await
        .unwrap();
    let listen_addr = listener.local_addr().unwrap().to_string();
    info!(url = listen_addr, "start listning");
    axum::serve(listener, app).await.unwrap();
}
