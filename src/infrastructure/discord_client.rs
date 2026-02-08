use reqwest::Client;
use tracing::instrument;
use tracing::{debug, info};

use crate::domain::discord::DiscordRepository;

#[derive(Debug)]
pub struct DiscordApiClient {
    client: Client,
}

impl DiscordApiClient {
    pub fn new() -> Self {
        Self {
            client: Client::new(),
        }
    }
}

impl DiscordRepository for DiscordApiClient {
    #[instrument(skip(token))]
    async fn register_commands(
        &self,
        app_id: &crate::domain::discord::ApplicationId,
        token: &crate::domain::discord::BotToken,
        commands: &crate::domain::discord::SlashCommandDefinition,
    ) -> Result<(), String> {
        let url = format!(
            "https://discord.com/api/v10/applications/{}/commands",
            app_id.value()
        );

        info!(app_id = app_id.value(), "Registering command");

        let auth_header = format!("Bot {}", token.value());

        let json_body = serde_json::json!([
            {
                "name" : commands.name().as_str(),
                "description" : commands.description().value(),
            }
        ]);

        debug!(
            app_id = app_id.value(),
            body = ?json_body,
            "Registering command body"
        );

        let res = self
            .client
            .put(&url)
            .header(reqwest::header::AUTHORIZATION, auth_header)
            .json(&json_body)
            .send()
            .await
            .map_err(|e| format!("Failed to send request: {}", e))?;

        let status = res.status();
        let body = res
            .text()
            .await
            .map_err(|e| format!("Failed to read response: {}", e))?;

        if !status.is_success() {
            return Err(format!("Discord API returned error: {}", body));
        }

        info!(app_id = app_id.value(), "Registered command");
        Ok(())
    }
}
