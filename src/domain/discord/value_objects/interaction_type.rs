use crate::domain::discord::errors::DomainError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InteractionType {
    Ping,
    ApplicationCommand,
    MessageComponent,
    ApplicationCommandAutoComplete,
    ModalSubmit,
}

impl InteractionType {
    pub fn from_i32(value: i32) -> Result<Self, DomainError> {
        match value {
            1 => Ok(Self::Ping),
            2 => Ok(Self::ApplicationCommand),
            3 => Ok(Self::MessageComponent),
            4 => Ok(Self::ApplicationCommandAutoComplete),
            5 => Ok(Self::ModalSubmit),
            _ => Err(DomainError::InvalidInteractinType(value)),
        }
    }

    pub fn as_i32(&self) -> i32 {
        match self {
            InteractionType::Ping => 1,
            InteractionType::ApplicationCommand => 2,
            InteractionType::MessageComponent => 3,
            InteractionType::ApplicationCommandAutoComplete => 4,
            InteractionType::ModalSubmit => 5,
        }
    }

    pub fn requires_data(&self) -> bool {
        matches!(
            self,
            Self::ApplicationCommand
                | Self::MessageComponent
                | Self::ApplicationCommandAutoComplete
                | Self::ModalSubmit
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_from_i32_ping() {
        let result = InteractionType::from_i32(1);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), InteractionType::Ping);
    }

    #[test]
    fn test_from_i32_application_command() {
        let result = InteractionType::from_i32(2);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), InteractionType::ApplicationCommand);
    }

    #[test]
    fn test_from_i32_message_component() {
        let result = InteractionType::from_i32(3);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), InteractionType::MessageComponent);
    }

    #[test]
    fn test_from_i32_application_command_auto_complete() {
        let result = InteractionType::from_i32(4);
        assert!(result.is_ok());
        assert_eq!(
            result.unwrap(),
            InteractionType::ApplicationCommandAutoComplete
        );
    }

    #[test]
    fn test_from_i32_modal_submit() {
        let result = InteractionType::from_i32(5);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), InteractionType::ModalSubmit);
    }

    #[test]
    fn test_from_i32_invalid() {
        let result = InteractionType::from_i32(0);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            DomainError::InvalidInteractinType(0)
        ));
    }

    #[test]
    fn test_from_i32_invalid_negative() {
        let result = InteractionType::from_i32(-1);
        assert!(result.is_err());
    }

    #[test]
    fn test_from_i32_invalid_too_large() {
        let result = InteractionType::from_i32(100);
        assert!(result.is_err());
    }

    #[test]
    fn test_as_i32() {
        assert_eq!(InteractionType::Ping.as_i32(), 1);
        assert_eq!(InteractionType::ApplicationCommand.as_i32(), 2);
        assert_eq!(InteractionType::MessageComponent.as_i32(), 3);
        assert_eq!(InteractionType::ApplicationCommandAutoComplete.as_i32(), 4);
        assert_eq!(InteractionType::ModalSubmit.as_i32(), 5);
    }

    #[test]
    fn test_roundtrip() {
        for i in 1..=5 {
            let interaction_type = InteractionType::from_i32(i).unwrap();
            assert_eq!(interaction_type.as_i32(), i);
        }
    }

    #[test]
    fn test_requires_data_ping() {
        assert!(!InteractionType::Ping.requires_data());
    }

    #[test]
    fn test_requires_data_application_command() {
        assert!(InteractionType::ApplicationCommand.requires_data());
    }

    #[test]
    fn test_requires_data_message_component() {
        assert!(InteractionType::MessageComponent.requires_data());
    }

    #[test]
    fn test_requires_data_auto_complete() {
        assert!(InteractionType::ApplicationCommandAutoComplete.requires_data());
    }

    #[test]
    fn test_requires_data_modal_submit() {
        assert!(InteractionType::ModalSubmit.requires_data());
    }

    #[test]
    fn test_equality() {
        assert_eq!(InteractionType::Ping, InteractionType::Ping);
        assert_ne!(InteractionType::Ping, InteractionType::ApplicationCommand);
    }

    #[test]
    fn test_clone() {
        let original = InteractionType::ApplicationCommand;
        let cloned = original;
        assert_eq!(original, cloned);
    }
}
