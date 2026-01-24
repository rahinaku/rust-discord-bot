use tracing::instrument;

use crate::domain::{config::ConfigRepository, discord::DiscordRepository};

#[derive(Debug)]
pub struct RegisterSlashCommnadsUseCase<D, C>
where
    D: DiscordRepository + std::fmt::Debug,
    C: ConfigRepository + std::fmt::Debug,
{
    discord_repo: D,
    config_repo: C,
}

impl<D, C> RegisterSlashCommnadsUseCase<D, C>
where
    D: DiscordRepository + std::fmt::Debug,
    C: ConfigRepository + std::fmt::Debug,
{
    pub fn new(discord_repo: D, config_repo: C) -> Self {
        Self {
            discord_repo,
            config_repo,
        }
    }

    #[instrument]
    pub async fn execute(&self) -> Result<(), String> {
        // get config data
        let app_id = self.config_repo.get_application_id()?;
        let token = self.config_repo.get_bot_token()?;
        let commands = self.config_repo.load_slash_command_definition()?;

        self.discord_repo
            .register_commands(&app_id, &token, &commands)
            .await?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::discord::{
        ApplicationId, BotToken, CommandDescription, CommandName, SlashCommandDefinition,
    };

    // Mock ConfigRepository implementation
    #[derive(Debug)]
    struct MockConfigRepository {
        app_id_error: Option<String>,
        token_error: Option<String>,
        commands_error: Option<String>,
    }

    impl MockConfigRepository {
        fn new_success() -> Self {
            Self {
                app_id_error: None,
                token_error: None,
                commands_error: None,
            }
        }

        fn with_app_id_error() -> Self {
            Self {
                app_id_error: Some("Failed to get application ID".to_string()),
                token_error: None,
                commands_error: None,
            }
        }

        fn with_token_error() -> Self {
            Self {
                app_id_error: None,
                token_error: Some("Failed to get bot token".to_string()),
                commands_error: None,
            }
        }

        fn with_commands_error() -> Self {
            Self {
                app_id_error: None,
                token_error: None,
                commands_error: Some("Failed to load slash command definition".to_string()),
            }
        }
    }

    impl ConfigRepository for MockConfigRepository {
        fn get_application_id(&self) -> Result<ApplicationId, String> {
            match &self.app_id_error {
                Some(err) => Err(err.clone()),
                None => ApplicationId::new("123456789".to_string()),
            }
        }

        fn get_bot_token(&self) -> Result<BotToken, String> {
            match &self.token_error {
                Some(err) => Err(err.clone()),
                None => BotToken::new("test_token".to_string()),
            }
        }

        fn load_slash_command_definition(&self) -> Result<SlashCommandDefinition, String> {
            match &self.commands_error {
                Some(err) => Err(err.clone()),
                None => Ok(SlashCommandDefinition::new(
                    CommandName::new("test".to_string()).unwrap(),
                    CommandDescription::new("Test command".to_string()).unwrap(),
                )),
            }
        }
    }

    // Mock DiscordRepository implementation
    #[derive(Debug)]
    struct MockDiscordRepository {
        should_succeed: bool,
    }

    impl MockDiscordRepository {
        fn new_success() -> Self {
            Self {
                should_succeed: true,
            }
        }

        fn new_failure() -> Self {
            Self {
                should_succeed: false,
            }
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
                Ok(())
            } else {
                Err("Failed to register commands".to_string())
            }
        }
    }

    #[tokio::test]
    async fn test_execute_success() {
        let discord_repo = MockDiscordRepository::new_success();
        let config_repo = MockConfigRepository::new_success();
        let use_case = RegisterSlashCommnadsUseCase::new(discord_repo, config_repo);

        let result = use_case.execute().await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_execute_fails_when_get_application_id_fails() {
        let discord_repo = MockDiscordRepository::new_success();
        let config_repo = MockConfigRepository::with_app_id_error();
        let use_case = RegisterSlashCommnadsUseCase::new(discord_repo, config_repo);

        let result = use_case.execute().await;

        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Failed to get application ID");
    }

    #[tokio::test]
    async fn test_execute_fails_when_get_bot_token_fails() {
        let discord_repo = MockDiscordRepository::new_success();
        let config_repo = MockConfigRepository::with_token_error();
        let use_case = RegisterSlashCommnadsUseCase::new(discord_repo, config_repo);

        let result = use_case.execute().await;

        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Failed to get bot token");
    }

    #[tokio::test]
    async fn test_execute_fails_when_load_slash_command_definition_fails() {
        let discord_repo = MockDiscordRepository::new_success();
        let config_repo = MockConfigRepository::with_commands_error();
        let use_case = RegisterSlashCommnadsUseCase::new(discord_repo, config_repo);

        let result = use_case.execute().await;

        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err(),
            "Failed to load slash command definition"
        );
    }

    #[tokio::test]
    async fn test_execute_fails_when_register_commands_fails() {
        let discord_repo = MockDiscordRepository::new_failure();
        let config_repo = MockConfigRepository::new_success();
        let use_case = RegisterSlashCommnadsUseCase::new(discord_repo, config_repo);

        let result = use_case.execute().await;

        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Failed to register commands");
    }
}
