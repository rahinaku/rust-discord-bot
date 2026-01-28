use axum::{extract::Request, middleware::Next, response::Response};
use tracing::info;

/// Discord署名検証ミドルウェア
pub async fn request_log(request: Request, next: Next) -> Response {
    let uri = request.uri();
    let method = request.method();

    info!(uri =%uri, method=%method, "incoming request");

    // ヘッダーから署名とタイムスタンプを取得
    next.run(request).await
}
