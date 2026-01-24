use api_test::domain::discord::{ApplicationId, BotToken, DiscordRepository, SlashCommandDefinition};

/// モックDiscordRepository - 外部サービス（Discord API）へのリクエストを送信しない
///
/// テストでは実際のConfigRepositoryを使用し、外部APIのみをモックします。
#[derive(Debug, Clone)]
pub struct MockDiscordRepository {
    pub should_succeed: bool,
}

impl MockDiscordRepository {
    pub fn new() -> Self {
        Self {
            should_succeed: true,
        }
    }

    pub fn with_failure() -> Self {
        Self {
            should_succeed: false,
        }
    }
}

impl Default for MockDiscordRepository {
    fn default() -> Self {
        Self::new()
    }
}

impl DiscordRepository for MockDiscordRepository {
    async fn register_commands(
        &self,
        _app_id: &ApplicationId,
        _token: &BotToken,
        _commands: &SlashCommandDefinition,
    ) -> Result<(), String> {
        if self.should_succeed {
            println!(
                "[MockDiscordRepository] register_commands called (mock - not sending actual request)"
            );
            Ok(())
        } else {
            Err("Mock Discord API error".to_string())
        }
    }
}
