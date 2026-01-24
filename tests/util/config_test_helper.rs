use std::env;

/// テスト環境を管理する構造体
///
/// Dropトレイトを実装しているため、スコープを抜けるときに自動的にクリーンアップされます。
/// パニックが発生した場合でもクリーンアップが確実に実行されます。
///
/// # Example
/// ```
/// #[tokio::test]
/// async fn my_test() {
///     let _env = TestEnv::new(); // 環境変数が設定される
///
///     // テストコード...
///
///     // スコープを抜けると自動的に環境変数がクリーンアップされる
/// }
/// ```
pub struct TestEnv {
    _private: (),
}

impl TestEnv {
    /// 新しいテスト環境を作成し、環境変数を設定します
    ///
    /// # Safety
    /// この関数はテスト環境で使用することを想定しています。
    /// serial_testを使用してテストを順次実行することで、スレッド安全性を確保してください。
    pub fn new() -> Self {
        unsafe {
            env::set_var("DISCORD_APP_ID", "test_app_id_123456789");
            env::set_var("DISCORD_TOKEN", "test_bot_token");
        }
        Self { _private: () }
    }

    // /// カスタムの環境変数で新しいテスト環境を作成します
    // pub fn with_vars(app_id: &str, token: &str) -> Self {
    //     unsafe {
    //         env::set_var("DISCORD_APP_ID", app_id);
    //         env::set_var("DISCORD_TOKEN", token);
    //     }
    //     Self { _private: () }
    // }
}

impl Default for TestEnv {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for TestEnv {
    /// スコープを抜けるときに自動的に環境変数をクリーンアップします
    fn drop(&mut self) {
        unsafe {
            env::remove_var("DISCORD_APP_ID");
            env::remove_var("DISCORD_TOKEN");
        }
    }
}
