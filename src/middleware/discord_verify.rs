use axum::{
    body::Body,
    extract::Request,
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use std::env;

/// Discord署名検証ミドルウェア
pub async fn verify_discord_signature(
    request: Request,
    next: Next,
) -> Result<Response, impl IntoResponse> {
    let (parts, body) = request.into_parts();

    // ヘッダーから署名とタイムスタンプを取得
    let signature_hex = parts
        .headers
        .get("x-signature-ed25519")
        .and_then(|v| v.to_str().ok())
        .ok_or((
            StatusCode::UNAUTHORIZED,
            "Missing signature header".to_string(),
        ))?;

    let timestamp = parts
        .headers
        .get("x-signature-timestamp")
        .and_then(|v| v.to_str().ok())
        .ok_or((
            StatusCode::UNAUTHORIZED,
            "Missing timestamp header".to_string(),
        ))?;

    // ボディを読み取る
    let body_bytes = axum::body::to_bytes(body, usize::MAX)
        .await
        .map_err(|_| (StatusCode::BAD_REQUEST, "Failed to read body".to_string()))?;

    // 環境変数から公開鍵を取得
    let public_key = env::var("DISCORD_PUBLIC_KEY").map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Missing DISCORD_PUBLIC_KEY".to_string(),
        )
    })?;

    // 署名を検証
    verify_signature(signature_hex, timestamp, &body_bytes, &public_key).map_err(|e| {
        (
            StatusCode::UNAUTHORIZED,
            format!("Verification failed: {}", e),
        )
    })?;

    // タイムスタンプの有効性チェック（オプション: 5分以内）
    if let Err(e) = verify_timestamp(timestamp) {
        return Err((
            StatusCode::UNAUTHORIZED,
            format!("Invalid timestamp: {}", e),
        ));
    }

    // リクエストを再構築して次のハンドラーへ
    let request = Request::from_parts(parts, Body::from(body_bytes));
    Ok(next.run(request).await)
}

/// Ed25519署名の検証
fn verify_signature(
    signature_hex: &str,
    timestamp: &str,
    body: &[u8],
    public_key_hex: &str,
) -> Result<(), String> {
    // 1. 公開鍵をデコード
    let public_key_bytes =
        hex::decode(public_key_hex).map_err(|e| format!("Invalid public key hex: {}", e))?;

    let public_key = VerifyingKey::from_bytes(
        public_key_bytes
            .as_slice()
            .try_into()
            .map_err(|_| "Invalid public key length")?,
    )
    .map_err(|e| format!("Invalid public key: {}", e))?;

    // 2. 署名をデコード
    let signature_bytes =
        hex::decode(signature_hex).map_err(|e| format!("Invalid signature hex: {}", e))?;

    let signature = Signature::from_bytes(
        signature_bytes
            .as_slice()
            .try_into()
            .map_err(|_| "Invalid signature length")?,
    );

    // 3. メッセージを構築 (timestamp + body)
    let mut message = timestamp.as_bytes().to_vec();
    message.extend_from_slice(body);

    // 4. 署名を検証
    public_key
        .verify(&message, &signature)
        .map_err(|e| format!("Signature verification failed: {}", e))?;

    Ok(())
}

/// タイムスタンプの有効性検証（リプレイアタック防止）
fn verify_timestamp(timestamp: &str) -> Result<(), String> {
    let timestamp_num: i64 = timestamp.parse().map_err(|_| "Invalid timestamp format")?;

    let current_time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| "System time error")?
        .as_secs() as i64;

    let diff = (current_time - timestamp_num).abs();

    // 5分以内のリクエストのみ許可
    if diff > 300 {
        return Err(format!("Timestamp too old or in future: {} seconds", diff));
    }

    Ok(())
}
