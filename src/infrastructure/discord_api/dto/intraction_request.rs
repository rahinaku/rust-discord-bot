use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct CommandOptionDto {
    pub name: String,
    pub r#type: i32,
    pub value: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
pub struct InteractionDataDto {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub options: Vec<CommandOptionDto>,
}

#[derive(Debug, Deserialize)]
pub struct InteractionRequestDto {
    pub id: String,
    pub r#type: i32,
    pub token: String,
    pub application_id: Option<String>,
    pub guild_id: Option<String>,
    pub channel_id: Option<String>,
    pub data: Option<InteractionDataDto>,
}
