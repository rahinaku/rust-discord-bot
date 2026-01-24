use crate::domain::discord::{ApplicationId, BotToken, SlashCommandDefinition};

pub trait ConfigRepository {
    fn get_application_id(&self) -> Result<ApplicationId, String>;
    fn get_bot_token(&self) -> Result<BotToken, String>;
    fn load_slash_command_definition(&self) -> Result<SlashCommandDefinition, String>;
}
