pub mod controller;
pub mod middleware;

use axum::{
    Router,
    body::Body,
    http::{HeaderValue, Request},
    middleware::{self as axum_middleware, Next},
    response::Html,
    response::Response,
    routing::{get, post},
};

use crate::controller::ping_handler::ping_handler;
use crate::middleware::discord_verify::verify_discord_signature;

async fn add_headers(req: Request<Body>, next: Next) -> Response {
    let mut response = next.run(req).await;

    // User-Agentヘッダーがなければ追加
    if !response.headers().contains_key("user-agent") {
        response
            .headers_mut()
            .insert("user-agent", HeaderValue::from_static("MyApp/1.0"));
    }

    // Content-Typeヘッダーがなければ追加
    if !response.headers().contains_key("content-type") {
        response
            .headers_mut()
            .insert("content-type", HeaderValue::from_static("application/json"));
    }

    response
}

pub fn get_app() -> Router {
    // Discord関連のルート（署名検証付き）
    let discord_routes = Router::new()
        .route("/webhook", post(ping_handler))
        .layer(axum_middleware::from_fn(verify_discord_signature));

    // 公開ルート（署名検証なし）
    let public_routes = Router::new().route("/", get(handler));

    // 統合
    Router::new()
        .nest("/discord", discord_routes)
        .merge(public_routes)
        .layer(axum_middleware::from_fn(add_headers))
}

async fn handler() -> Html<&'static str> {
    println!("request");
    Html("<h1>Hello, World!</h1>")
}
