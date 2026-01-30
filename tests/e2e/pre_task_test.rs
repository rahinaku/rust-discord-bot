use api_test::infrastructure::config::EnvConfigRepository;
use api_test::pre_task_with_deps;
use serial_test::serial;

use crate::util::config_test_helper::TestEnv;
use crate::util::mock_repositories::MockDiscordRepository;

#[tokio::test]
#[serial]
async fn test_pre_task_with_mock_discord_success() {
    // テスト用の環境変数を設定
    let _env = TestEnv::new(); // 環境変数が設定される

    // 外部サービス（Discord API）だけをモック
    // ConfigRepositoryは実際の実装を使用
    let discord_repo = MockDiscordRepository::new();
    let config_repo = EnvConfigRepository::new();

    // pre_taskを実行（Discord APIへのリクエストはモックされる）
    pre_task_with_deps(discord_repo, config_repo).await;
}

#[tokio::test]
#[serial]
#[should_panic(expected = "Pre-task failed: Mock Discord API error")]
async fn test_pre_task_with_mock_discord_failure() {
    // テスト用の環境変数を設定
    let _env = TestEnv::new(); // 環境変数が設定される

    // 失敗するモックDiscordRepositoryを作成
    let discord_repo = MockDiscordRepository::with_failure();
    let config_repo = EnvConfigRepository::new();

    // pre_taskを実行（モックがエラーを返すためパニックする）
    pre_task_with_deps(discord_repo, config_repo).await;
}
