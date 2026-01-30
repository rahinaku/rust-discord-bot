use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InteractionType {
    Ping = 1,
    ApplicationCommand = 2,
    MessageComponent = 3,
    ApplicationCommandAutocomplate = 4,
    ModalSubmit = 5,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum InteractionResponseType {
    Pong = 1,
    ChannelMessageWithSource = 4,
    DeferredChannelMessageWithSource = 5,
    DeferredUpdateMessage = 6,
    UmdateMessage = 7,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CommandOption {
    pub name: String,
    pub r#type: i32,
    pub value: Option<serde_json::Value>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_interaction_type_ping() {
        assert_eq!(InteractionType::Ping as i32, 1);
    }

    #[test]
    fn test_interaction_type_application_command() {
        assert_eq!(InteractionType::ApplicationCommand as i32, 2);
    }

    #[test]
    fn test_interaction_type_message_component() {
        assert_eq!(InteractionType::MessageComponent as i32, 3);
    }

    #[test]
    fn test_interaction_type_application_command_autocomplete() {
        assert_eq!(InteractionType::ApplicationCommandAutocomplate as i32, 4);
    }

    #[test]
    fn test_interaction_type_modal_submit() {
        assert_eq!(InteractionType::ModalSubmit as i32, 5);
    }

    #[test]
    fn test_interaction_response_type_pong() {
        assert_eq!(InteractionResponseType::Pong as i32, 1);
    }

    #[test]
    fn test_interaction_response_type_channel_message() {
        assert_eq!(InteractionResponseType::ChannelMessageWithSource as i32, 4);
    }

    #[test]
    fn test_interaction_response_type_deferred_channel_message() {
        assert_eq!(InteractionResponseType::DeferredChannelMessageWithSource as i32, 5);
    }

    #[test]
    fn test_interaction_response_type_deferred_update() {
        assert_eq!(InteractionResponseType::DeferredUpdateMessage as i32, 6);
    }

    #[test]
    fn test_interaction_response_type_update_message() {
        assert_eq!(InteractionResponseType::UmdateMessage as i32, 7);
    }

    #[test]
    fn test_command_option_deserialize() {
        let json = r#"{"name": "test", "type": 3, "value": "hello"}"#;
        let option: CommandOption = serde_json::from_str(json).unwrap();

        assert_eq!(option.name, "test");
        assert_eq!(option.r#type, 3);
        assert_eq!(option.value, Some(serde_json::json!("hello")));
    }

    #[test]
    fn test_command_option_deserialize_without_value() {
        let json = r#"{"name": "test", "type": 1}"#;
        let option: CommandOption = serde_json::from_str(json).unwrap();

        assert_eq!(option.name, "test");
        assert_eq!(option.r#type, 1);
        assert!(option.value.is_none());
    }

    #[test]
    fn test_interaction_response_type_serialize() {
        let response_type = InteractionResponseType::Pong;
        let serialized = serde_json::to_string(&response_type).unwrap();
        assert_eq!(serialized, "\"Pong\"");
    }
}
