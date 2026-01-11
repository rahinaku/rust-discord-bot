use api_test::get_app;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use serde_json::json;
use serial_test::serial;
use tower::ServiceExt;

use crate::util::discord_test_helper::{
    cleanup_test_env, create_discord_signature, get_current_timestamp, get_test_keypair,
    set_test_public_key,
};

#[tokio::test]
#[serial]
async fn test_ping_handler_type_1_returns_ok() {
    let (signing_key, public_key_hex) = get_test_keypair();
    set_test_public_key(&public_key_hex);

    let app = get_app();

    // リクエストボディ
    let body = json!({
        "type": 1
    });
    let body_str = body.to_string();
    let body_bytes = body_str.as_bytes();

    // タイムスタンプと署名を生成
    let timestamp = get_current_timestamp();
    let signature = create_discord_signature(&signing_key, &timestamp, body_bytes);

    // リクエストを構築
    let request = Request::builder()
        .method("POST")
        .uri("/discord/webhook")
        .header("x-signature-ed25519", signature)
        .header("x-signature-timestamp", timestamp)
        .header("content-type", "application/json")
        .body(Body::from(body_str))
        .unwrap();

    // リクエストを送信
    let response = app.oneshot(request).await.unwrap();

    // レスポンスを検証
    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let response_json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(response_json["type"], 1);

    cleanup_test_env();
}

#[tokio::test]
#[serial]
async fn test_ping_handler_type_2_returns_bad_request() {
    let (signing_key, public_key_hex) = get_test_keypair();
    set_test_public_key(&public_key_hex);

    let app = get_app();

    // リクエストボディ
    let body = json!({
        "type": 2
    });
    let body_str = body.to_string();
    let body_bytes = body_str.as_bytes();

    // タイムスタンプと署名を生成
    let timestamp = get_current_timestamp();
    let signature = create_discord_signature(&signing_key, &timestamp, body_bytes);

    // リクエストを構築
    let request = Request::builder()
        .method("POST")
        .uri("/discord/webhook")
        .header("x-signature-ed25519", signature)
        .header("x-signature-timestamp", timestamp)
        .header("content-type", "application/json")
        .body(Body::from(body_str))
        .unwrap();

    // リクエストを送信
    let response = app.oneshot(request).await.unwrap();

    // レスポンスを検証
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);

    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let response_json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(response_json["type"], 2);

    cleanup_test_env();
}

#[tokio::test]
async fn test_ping_handler_without_signature_returns_unauthorized() {
    let app = get_app();

    // リクエストボディ
    let body = json!({
        "type": 1
    });
    let body_str = body.to_string();

    // リクエストを構築（署名なし）
    let request = Request::builder()
        .method("POST")
        .uri("/discord/webhook")
        .header("content-type", "application/json")
        .body(Body::from(body_str))
        .unwrap();

    // リクエストを送信
    let response = app.oneshot(request).await.unwrap();

    // レスポンスを検証（署名がないため401）
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
#[serial]
async fn test_ping_handler_with_invalid_signature_returns_unauthorized() {
    let (_, public_key_hex) = get_test_keypair();
    set_test_public_key(&public_key_hex);

    let app = get_app();

    // リクエストボディ
    let body = json!({
        "type": 1
    });
    let body_str = body.to_string();

    // タイムスタンプと無効な署名
    let timestamp = get_current_timestamp();
    let invalid_signature = "0".repeat(128);

    // リクエストを構築
    let request = Request::builder()
        .method("POST")
        .uri("/discord/webhook")
        .header("x-signature-ed25519", invalid_signature)
        .header("x-signature-timestamp", timestamp)
        .header("content-type", "application/json")
        .body(Body::from(body_str))
        .unwrap();

    // リクエストを送信
    let response = app.oneshot(request).await.unwrap();

    // レスポンスを検証（無効な署名のため401）
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    cleanup_test_env();
}
