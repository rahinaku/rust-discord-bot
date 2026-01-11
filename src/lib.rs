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
        .route("/", post(ping_handler))
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

#[cfg(test)]
pub mod test_utils {
    use ed25519_dalek::{Signer, SigningKey};

    /// テスト用の固定鍵ペアを生成
    pub fn get_test_keypair() -> (SigningKey, String) {
        let signing_key = SigningKey::from_bytes(&[
            157, 97, 177, 157, 239, 253, 90, 96, 186, 132, 74, 244, 146, 236, 44, 196, 68, 73, 197,
            105, 123, 50, 105, 25, 112, 59, 172, 3, 28, 174, 127, 96,
        ]);
        let verifying_key = signing_key.verifying_key();
        let public_key_hex = hex::encode(verifying_key.to_bytes());
        (signing_key, public_key_hex)
    }

    /// Discord署名を生成
    pub fn create_discord_signature(
        signing_key: &SigningKey,
        timestamp: &str,
        body: &[u8],
    ) -> String {
        let mut message = timestamp.as_bytes().to_vec();
        message.extend_from_slice(body);
        let signature = signing_key.sign(&message);
        hex::encode(signature.to_bytes())
    }

    /// 現在のUNIXタイムスタンプを文字列で取得
    pub fn get_current_timestamp() -> String {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            .to_string()
    }
}
