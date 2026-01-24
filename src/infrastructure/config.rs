use std::{env, fmt::format, fs};

use serde::Deserialize;
use tracing::{info, instrument};

use crate::domain::{
    config::ConfigRepository,
    discord::{ApplicationId, BotToken, CommandDescription, CommandName, SlashCommandDefinition},
};

#[derive(Deserialize)]
struct SlashCommnadJson {
    name: String,
    description: String,
}

#[derive(Debug)]
pub struct EnvConfigRepository;

impl EnvConfigRepository {
    pub fn new() -> Self {
        Self
    }
}

impl ConfigRepository for EnvConfigRepository {
    #[instrument]
    fn get_application_id(&self) -> Result<crate::domain::discord::ApplicationId, String> {
        let id = env::var("DISCORD_APP_ID")
            .map_err(|_| "DISCORD_APP_ID not found in envionment".to_string())?;
        info!(value = id, "read envionment variable DISCORD_APP_ID");
        ApplicationId::new(id)
    }

    #[instrument]
    fn get_bot_token(&self) -> Result<crate::domain::discord::BotToken, String> {
        let token = env::var("DISCORD_TOKEN")
            .map_err(|_| "DISCORD_TOKEN not found in environment".to_string())?;
        info!("read envionment variable DISCORD_TOKEN");
        BotToken::new(token)
    }

    #[instrument]
    fn load_slash_command_definition(
        &self,
    ) -> Result<crate::domain::discord::SlashCommandDefinition, String> {
        let content = fs::read_to_string("./src/slash_command.json")
            .map_err(|e| format!("Faild to read slash_command.json: {}", e))?;

        let json: SlashCommnadJson =
            serde_json::from_str(&content).map_err(|e| format!("Failed to parse JSON: {}", e))?;

        // Domain Objectに変換
        let name = CommandName::new(json.name)?;
        let description = CommandDescription::new(json.description)?;

        info!(value = name.value(), "read slash_command.json");
        Ok(SlashCommandDefinition::new(name, description))
    }
}
