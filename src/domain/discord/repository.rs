use crate::domain::discord::{ApplicationId, BotToken, SlashCommandDefinition};

pub trait DiscordRepository {
    fn register_commands(
        &self,
        app_id: &ApplicationId,
        token: &BotToken,
        commands: &SlashCommandDefinition,
    ) -> impl Future<Output = Result<(), String>> + Send;
}
