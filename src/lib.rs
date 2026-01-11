pub mod controller;

use axum::{
    Router,
    body::Body,
    http::{HeaderValue, Request},
    middleware::{self, Next},
    response::Html,
    response::Response,
    routing::{get, post},
};

use crate::controller::ping_handler::ping_handler;

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
    Router::new()
        .route("/", get(handler))
        .route("/", post(ping_handler))
        .layer(middleware::from_fn(add_headers))
}

async fn handler() -> Html<&'static str> {
    println!("request");
    Html("<h1>Hello, World!</h1>")
}
