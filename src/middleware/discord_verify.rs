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

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        Router, body::Body, extract::Request, http::StatusCode, middleware, response::Response,
        routing::post,
    };
    use ed25519_dalek::{Signer, SigningKey};
    use std::env;
    use tower::ServiceExt;

    // テスト用のハンドラー（常に200 OKを返す）
    async fn test_handler() -> Response {
        Response::builder()
            .status(StatusCode::OK)
            .body(Body::from("OK"))
            .unwrap()
    }

    mod verify_discord_signature {
        use super::*;
        use serial_test::serial;

        #[tokio::test]
        #[serial]
        async fn success_with_valid_signature() {
            // テスト用の鍵ペアを生成
            let signing_key = SigningKey::from_bytes(&[
                157, 97, 177, 157, 239, 253, 90, 96, 186, 132, 74, 244, 146, 236, 44, 196, 68, 73,
                197, 105, 123, 50, 105, 25, 112, 59, 172, 3, 28, 174, 127, 96,
            ]);
            let verifying_key = signing_key.verifying_key();
            let public_key_hex = hex::encode(verifying_key.to_bytes());

            // 環境変数をセット
            unsafe { env::set_var("DISCORD_PUBLIC_KEY", &public_key_hex) };

            // テストデータ
            let current_time = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            let timestamp = current_time.to_string();
            let body = b"{\"type\":1}";

            // メッセージを構築して署名を生成
            let mut message = timestamp.as_bytes().to_vec();
            message.extend_from_slice(body);
            let signature = signing_key.sign(&message);
            let signature_hex = hex::encode(signature.to_bytes());

            // ルーターを構築
            let app = Router::new()
                .route("/", post(test_handler))
                .layer(middleware::from_fn(verify_discord_signature));

            // リクエストを構築して送信
            let request = Request::builder()
                .method("POST")
                .uri("/")
                .header("x-signature-ed25519", signature_hex)
                .header("x-signature-timestamp", timestamp)
                .body(Body::from(&body[..]))
                .unwrap();

            let response = app.oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::OK);

            // クリーンアップ
            unsafe { env::remove_var("DISCORD_PUBLIC_KEY") };
        }

        #[tokio::test]
        #[serial]
        async fn missing_signature_header() {
            // ルーターを構築
            let app = Router::new()
                .route("/", post(test_handler))
                .layer(middleware::from_fn(verify_discord_signature));

            // リクエストを構築（署名ヘッダーなし）
            let request = Request::builder()
                .method("POST")
                .uri("/")
                .header("x-signature-timestamp", "1234567890")
                .body(Body::from("{}"))
                .unwrap();

            let response = app.oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        }

        #[tokio::test]
        #[serial]
        async fn missing_timestamp_header() {
            // ルーターを構築
            let app = Router::new()
                .route("/", post(test_handler))
                .layer(middleware::from_fn(verify_discord_signature));

            // リクエストを構築（タイムスタンプヘッダーなし）
            let request = Request::builder()
                .method("POST")
                .uri("/")
                .header("x-signature-ed25519", "0".repeat(128))
                .body(Body::from("{}"))
                .unwrap();

            let response = app.oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        }

        #[tokio::test]
        #[serial]
        async fn missing_public_key_env_var() {
            // 環境変数が設定されていないことを確認
            unsafe { env::remove_var("DISCORD_PUBLIC_KEY") };

            // ルーターを構築
            let app = Router::new()
                .route("/", post(test_handler))
                .layer(middleware::from_fn(verify_discord_signature));

            // リクエストを構築
            let request = Request::builder()
                .method("POST")
                .uri("/")
                .header("x-signature-ed25519", "0".repeat(128))
                .header("x-signature-timestamp", "1234567890")
                .body(Body::from("{}"))
                .unwrap();

            let response = app.oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        }

        #[tokio::test]
        #[serial]
        async fn invalid_signature() {
            // テスト用の鍵ペアを生成
            let signing_key = SigningKey::from_bytes(&[
                157, 97, 177, 157, 239, 253, 90, 96, 186, 132, 74, 244, 146, 236, 44, 196, 68, 73,
                197, 105, 123, 50, 105, 25, 112, 59, 172, 3, 28, 174, 127, 96,
            ]);
            let verifying_key = signing_key.verifying_key();
            let public_key_hex = hex::encode(verifying_key.to_bytes());

            // 環境変数をセット
            unsafe { env::set_var("DISCORD_PUBLIC_KEY", &public_key_hex) };

            // テストデータ（無効な署名）
            let current_time = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            let timestamp = current_time.to_string();
            let body = b"{\"type\":1}";

            // 無効な署名
            let invalid_signature_hex = "0".repeat(128);

            // ルーターを構築
            let app = Router::new()
                .route("/", post(test_handler))
                .layer(middleware::from_fn(verify_discord_signature));

            // リクエストを構築
            let request = Request::builder()
                .method("POST")
                .uri("/")
                .header("x-signature-ed25519", invalid_signature_hex)
                .header("x-signature-timestamp", timestamp)
                .body(Body::from(&body[..]))
                .unwrap();

            let response = app.oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

            // クリーンアップ
            unsafe { env::remove_var("DISCORD_PUBLIC_KEY") };
        }

        #[tokio::test]
        #[serial]
        async fn timestamp_too_old() {
            // テスト用の鍵ペアを生成
            let signing_key = SigningKey::from_bytes(&[
                157, 97, 177, 157, 239, 253, 90, 96, 186, 132, 74, 244, 146, 236, 44, 196, 68, 73,
                197, 105, 123, 50, 105, 25, 112, 59, 172, 3, 28, 174, 127, 96,
            ]);
            let verifying_key = signing_key.verifying_key();
            let public_key_hex = hex::encode(verifying_key.to_bytes());

            // 環境変数をセット
            unsafe { env::set_var("DISCORD_PUBLIC_KEY", &public_key_hex) };

            // テストデータ（古いタイムスタンプ）
            let current_time = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            let old_timestamp = (current_time - 360).to_string(); // 6分前
            let body = b"{\"type\":1}";

            // メッセージを構築して署名を生成
            let mut message = old_timestamp.as_bytes().to_vec();
            message.extend_from_slice(body);
            let signature = signing_key.sign(&message);
            let signature_hex = hex::encode(signature.to_bytes());

            // ルーターを構築
            let app = Router::new()
                .route("/", post(test_handler))
                .layer(middleware::from_fn(verify_discord_signature));

            // リクエストを構築
            let request = Request::builder()
                .method("POST")
                .uri("/")
                .header("x-signature-ed25519", signature_hex)
                .header("x-signature-timestamp", old_timestamp)
                .body(Body::from(&body[..]))
                .unwrap();

            let response = app.oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

            // クリーンアップ
            unsafe { env::remove_var("DISCORD_PUBLIC_KEY") };
        }

        #[tokio::test]
        #[serial]
        async fn invalid_public_key_format() {
            // 無効な公開鍵を環境変数にセット
            unsafe { env::set_var("DISCORD_PUBLIC_KEY", "invalid_hex") };

            // テストデータ
            let current_time = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            let timestamp = current_time.to_string();
            let body = b"{\"type\":1}";

            // ルーターを構築
            let app = Router::new()
                .route("/", post(test_handler))
                .layer(middleware::from_fn(verify_discord_signature));

            // リクエストを構築
            let request = Request::builder()
                .method("POST")
                .uri("/")
                .header("x-signature-ed25519", "0".repeat(128))
                .header("x-signature-timestamp", timestamp)
                .body(Body::from(&body[..]))
                .unwrap();

            let response = app.oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

            // クリーンアップ
            unsafe { env::remove_var("DISCORD_PUBLIC_KEY") };
        }
    }

    mod verify_signature {
        use ed25519_dalek::{Signer, SigningKey};

        #[test]
        fn valid() {
            // テスト用の鍵ペアを生成
            let signing_key = SigningKey::from_bytes(&[
                157, 97, 177, 157, 239, 253, 90, 96, 186, 132, 74, 244, 146, 236, 44, 196, 68, 73,
                197, 105, 123, 50, 105, 25, 112, 59, 172, 3, 28, 174, 127, 96,
            ]);
            let verifying_key = signing_key.verifying_key();
            let public_key_hex = hex::encode(verifying_key.to_bytes());

            // テストデータ
            let timestamp = "1234567890";
            let body = b"{\"type\":1}";

            // メッセージを構築
            let mut message = timestamp.as_bytes().to_vec();
            message.extend_from_slice(body);

            // 署名を生成
            let signature = signing_key.sign(&message);
            let signature_hex = hex::encode(signature.to_bytes());

            // 検証
            let result =
                super::super::verify_signature(&signature_hex, timestamp, body, &public_key_hex);
            assert!(result.is_ok());
        }

        #[test]
        fn invalid_signature() {
            // テスト用の鍵ペアを生成
            let signing_key = SigningKey::from_bytes(&[
                157, 97, 177, 157, 239, 253, 90, 96, 186, 132, 74, 244, 146, 236, 44, 196, 68, 73,
                197, 105, 123, 50, 105, 25, 112, 59, 172, 3, 28, 174, 127, 96,
            ]);
            let verifying_key = signing_key.verifying_key();
            let public_key_hex = hex::encode(verifying_key.to_bytes());

            let timestamp = "1234567890";
            let body = b"{\"type\":1}";

            // 間違った署名（すべて0）
            let invalid_signature_hex = "0".repeat(128);

            let result = super::super::verify_signature(
                &invalid_signature_hex,
                timestamp,
                body,
                &public_key_hex,
            );
            assert!(result.is_err());
            assert!(
                result
                    .unwrap_err()
                    .contains("Signature verification failed")
            );
        }

        #[test]
        fn wrong_message() {
            // テスト用の鍵ペアを生成
            let signing_key = SigningKey::from_bytes(&[
                157, 97, 177, 157, 239, 253, 90, 96, 186, 132, 74, 244, 146, 236, 44, 196, 68, 73,
                197, 105, 123, 50, 105, 25, 112, 59, 172, 3, 28, 174, 127, 96,
            ]);
            let verifying_key = signing_key.verifying_key();
            let public_key_hex = hex::encode(verifying_key.to_bytes());

            let timestamp = "1234567890";
            let body = b"{\"type\":1}";

            // 正しいメッセージで署名を生成
            let mut message = timestamp.as_bytes().to_vec();
            message.extend_from_slice(body);
            let signature = signing_key.sign(&message);
            let signature_hex = hex::encode(signature.to_bytes());

            // 異なるボディで検証
            let different_body = b"{\"type\":2}";
            let result = super::super::verify_signature(
                &signature_hex,
                timestamp,
                different_body,
                &public_key_hex,
            );
            assert!(result.is_err());
            assert!(
                result
                    .unwrap_err()
                    .contains("Signature verification failed")
            );
        }

        #[test]
        fn invalid_public_key_hex() {
            let signature_hex = "a".repeat(128);
            let timestamp = "1234567890";
            let body = b"{\"type\":1}";
            let invalid_public_key_hex = "invalid_hex";

            let result = super::super::verify_signature(
                &signature_hex,
                timestamp,
                body,
                &invalid_public_key_hex,
            );
            assert!(result.is_err());
            assert!(result.unwrap_err().contains("Invalid public key hex"));
        }

        #[test]
        fn invalid_public_key_length() {
            let signature_hex = "a".repeat(128);
            let timestamp = "1234567890";
            let body = b"{\"type\":1}";
            // 正しくない長さの公開鍵（32バイトではない）
            let invalid_public_key_hex = "aabbcc";

            let result = super::super::verify_signature(
                &signature_hex,
                timestamp,
                body,
                &invalid_public_key_hex,
            );
            assert!(result.is_err());
            assert!(result.unwrap_err().contains("Invalid public key length"));
        }

        #[test]
        fn invalid_signature_hex() {
            let signing_key = SigningKey::from_bytes(&[
                157, 97, 177, 157, 239, 253, 90, 96, 186, 132, 74, 244, 146, 236, 44, 196, 68, 73,
                197, 105, 123, 50, 105, 25, 112, 59, 172, 3, 28, 174, 127, 96,
            ]);
            let verifying_key = signing_key.verifying_key();
            let public_key_hex = hex::encode(verifying_key.to_bytes());

            let timestamp = "1234567890";
            let body = b"{\"type\":1}";
            let invalid_signature_hex = "not_valid_hex";

            let result = super::super::verify_signature(
                &invalid_signature_hex,
                timestamp,
                body,
                &public_key_hex,
            );
            assert!(result.is_err());
            assert!(result.unwrap_err().contains("Invalid signature hex"));
        }

        #[test]
        fn invalid_signature_length() {
            let signing_key = SigningKey::from_bytes(&[
                157, 97, 177, 157, 239, 253, 90, 96, 186, 132, 74, 244, 146, 236, 44, 196, 68, 73,
                197, 105, 123, 50, 105, 25, 112, 59, 172, 3, 28, 174, 127, 96,
            ]);
            let verifying_key = signing_key.verifying_key();
            let public_key_hex = hex::encode(verifying_key.to_bytes());

            let timestamp = "1234567890";
            let body = b"{\"type\":1}";
            // 正しくない長さの署名（64バイトではない）
            let invalid_signature_hex = "aabbcc";

            let result = super::super::verify_signature(
                &invalid_signature_hex,
                timestamp,
                body,
                &public_key_hex,
            );
            assert!(result.is_err());
            assert!(result.unwrap_err().contains("Invalid signature length"));
        }

        #[test]
        fn empty_body() {
            // テスト用の鍵ペアを生成
            let signing_key = SigningKey::from_bytes(&[
                157, 97, 177, 157, 239, 253, 90, 96, 186, 132, 74, 244, 146, 236, 44, 196, 68, 73,
                197, 105, 123, 50, 105, 25, 112, 59, 172, 3, 28, 174, 127, 96,
            ]);
            let verifying_key = signing_key.verifying_key();
            let public_key_hex = hex::encode(verifying_key.to_bytes());

            let timestamp = "1234567890";
            let body = b"";

            // メッセージを構築
            let mut message = timestamp.as_bytes().to_vec();
            message.extend_from_slice(body);

            // 署名を生成
            let signature = signing_key.sign(&message);
            let signature_hex = hex::encode(signature.to_bytes());

            // 検証
            let result =
                super::super::verify_signature(&signature_hex, timestamp, body, &public_key_hex);
            assert!(result.is_ok());
        }
    }

    mod verify_timestamp {
        #[test]
        fn valid_current() {
            // 現在時刻のタイムスタンプは有効
            let current_time = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();

            let timestamp = current_time.to_string();
            assert!(super::super::verify_timestamp(&timestamp).is_ok());
        }

        #[test]
        fn valid_within_5_minutes() {
            // 2分前のタイムスタンプは有効
            let current_time = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();

            let timestamp = (current_time - 120).to_string(); // 2分前
            assert!(super::super::verify_timestamp(&timestamp).is_ok());
        }

        #[test]
        fn too_old() {
            // 6分前のタイムスタンプは無効
            let current_time = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();

            let timestamp = (current_time - 360).to_string(); // 6分前
            let result = super::super::verify_timestamp(&timestamp);
            assert!(result.is_err());
            assert!(
                result
                    .unwrap_err()
                    .contains("Timestamp too old or in future")
            );
        }

        #[test]
        fn too_future() {
            // 6分後のタイムスタンプは無効
            let current_time = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();

            let timestamp = (current_time + 360).to_string(); // 6分後
            let result = super::super::verify_timestamp(&timestamp);
            assert!(result.is_err());
            assert!(
                result
                    .unwrap_err()
                    .contains("Timestamp too old or in future")
            );
        }

        #[test]
        fn edge_case_exactly_300_seconds() {
            // ちょうど300秒（5分）の差は有効（境界値テスト）
            let current_time = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();

            let timestamp = (current_time - 300).to_string();
            assert!(super::super::verify_timestamp(&timestamp).is_ok());
        }

        #[test]
        fn edge_case_301_seconds() {
            // 301秒の差は無効（境界値テスト）
            let current_time = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();

            let timestamp = (current_time - 301).to_string();
            let result = super::super::verify_timestamp(&timestamp);
            assert!(result.is_err());
        }

        #[test]
        fn invalid_format() {
            // 無効なフォーマット（数値でない）
            let result = super::super::verify_timestamp("not_a_number");
            assert!(result.is_err());
            assert_eq!(result.unwrap_err(), "Invalid timestamp format");
        }

        #[test]
        fn empty_string() {
            // 空文字列
            let result = super::super::verify_timestamp("");
            assert!(result.is_err());
            assert_eq!(result.unwrap_err(), "Invalid timestamp format");
        }

        #[test]
        fn negative_number() {
            // 負の数値（UNIX エポック以前）
            let result = super::super::verify_timestamp("-100");
            assert!(result.is_err());
            assert!(
                result
                    .unwrap_err()
                    .contains("Timestamp too old or in future")
            );
        }
    }
}
