pub mod application;
pub mod controller;
pub mod domain;
pub mod infrastructure;
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
use tracing::{info, instrument, trace};
use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};

use crate::middleware::discord_verify::verify_discord_signature;
use crate::{
    application::register_slash_command::RegisterSlashCommnadsUseCase,
    controller::ping_handler::ping_handler,
    infrastructure::{config::EnvConfigRepository, discord_client::DiscordApiClient},
};

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

pub fn init_tracing() {
    let _ = tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .with(tracing_subscriber::fmt::layer().with_writer(std::io::stdout))
        .try_init();
    info!("log tracing started");
}

#[instrument(skip(discord_repo, config_repo))]
pub async fn pre_task_with_deps<D, C>(discord_repo: D, config_repo: C)
where
    D: crate::domain::discord::DiscordRepository + std::fmt::Debug,
    C: crate::domain::config::ConfigRepository + std::fmt::Debug,
{
    // slashコマンドを登録
    let use_case = RegisterSlashCommnadsUseCase::new(discord_repo, config_repo);

    match use_case.execute().await {
        Ok(_) => info!("finished pre task."),
        Err(e) => panic!("Pre-task faild: {}", e),
    }
}

#[instrument]
pub async fn pre_task() {
    // デフォルトの実装を使用
    let discord_client = DiscordApiClient::new();
    let config_repo = EnvConfigRepository::new();

    pre_task_with_deps(discord_client, config_repo).await;
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
    trace!("reqested root page");
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
