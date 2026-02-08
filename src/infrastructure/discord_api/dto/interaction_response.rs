use serde::{Deserialize, Serialize};

pub enum ResponseType {
    Pong = 1,
    ChannelMessageWithSource = 4,
    DeferrdChannelMessageWithSource = 5,
}

pub mod flags {
    pub const EPHEMERAL: i32 = 64;
}

#[derive(Debug, Serialize, Deserialize)]
pub struct InteractionResponseDataDto {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tts: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub flags: Option<i32>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct InteractionResponseDto {
    pub r#type: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<InteractionResponseDataDto>,
}

impl InteractionResponseDto {
    pub fn pong() -> Self {
        Self {
            r#type: ResponseType::Pong as i32,
            data: None,
        }
    }
    pub fn message(content: String, ephemeral: bool) -> Self {
        Self {
            r#type: ResponseType::ChannelMessageWithSource as i32,
            data: Some(InteractionResponseDataDto {
                content: Some(content),
                tts: None,
                flags: if ephemeral {
                    Some(flags::EPHEMERAL)
                } else {
                    None
                },
            }),
        }
    }

    pub fn error(message: String) -> Self {
        Self::message(message, true)
    }
}
