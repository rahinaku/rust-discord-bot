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
pub fn create_discord_signature(signing_key: &SigningKey, timestamp: &str, body: &[u8]) -> String {
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

/// テスト用環境変数を安全にセット
pub fn set_test_public_key(public_key: &str) {
    unsafe {
        std::env::set_var("DISCORD_PUBLIC_KEY", public_key);
    }
}

/// テスト用環境変数をクリーンアップ
pub fn cleanup_test_env() {
    unsafe {
        std::env::remove_var("DISCORD_PUBLIC_KEY");
    }
}
