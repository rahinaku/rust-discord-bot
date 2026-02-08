use crate::domain::discord::{
    errors::DomainError,
    value_objects::{
        command_name::CommandName, command_option::CommandOption, interaction_id::InteractionId,
        interaction_token::InteractionToken, interaction_type::InteractionType,
    },
    ApplicationId,
};

#[derive(Debug)]
pub struct InteractionData {
    id: String,
    name: CommandName,
    options: Vec<CommandOption>,
}

impl InteractionData {
    pub fn new(id: String, name: CommandName, options: Vec<CommandOption>) -> Self {
        Self { id, name, options }
    }

    pub fn command_name(&self) -> &CommandName {
        &self.name
    }

    pub fn options(&self) -> &[CommandOption] {
        &self.options
    }

    pub fn get_option(&self, name: &str) -> Option<&CommandOption> {
        self.options.iter().find(|option| option.name() == name)
    }
}

#[derive(Debug)]
pub struct Interaction {
    id: InteractionId,
    interaction_type: InteractionType,
    token: InteractionToken,
    application_id: Option<ApplicationId>,
    guild_id: Option<String>,
    channel_id: Option<String>,
    data: Option<InteractionData>,
}

impl Interaction {
    pub fn new(
        id: InteractionId,
        interaction_type: InteractionType,
        token: InteractionToken,
        application_id: Option<ApplicationId>,
        guild_id: Option<String>,
        channel_id: Option<String>,
        data: Option<InteractionData>,
    ) -> Result<Self, DomainError> {
        let interaction = Self {
            id,
            interaction_type,
            token,
            application_id,
            guild_id,
            channel_id,
            data,
        };

        interaction.validate()?;

        Ok(interaction)
    }

    fn validate(&self) -> Result<(), DomainError> {
        if self.interaction_type.requires_data() && self.data.is_none() {
            return Err(DomainError::MissingInteractionData(
                self.interaction_type.as_i32(),
            ));
        }
        Ok(())
    }

    pub fn id(&self) -> &InteractionId {
        &self.id
    }

    pub fn interaction_type(&self) -> InteractionType {
        self.interaction_type
    }

    pub fn token(&self) -> &InteractionToken {
        &self.token
    }

    pub fn application_id(&self) -> Option<&ApplicationId> {
        self.application_id.as_ref()
    }

    pub fn guild_id(&self) -> Option<&str> {
        self.guild_id.as_deref()
    }

    pub fn channel_id(&self) -> Option<&str> {
        self.channel_id.as_deref()
    }

    pub fn data(&self) -> Option<&InteractionData> {
        self.data.as_ref()
    }

    /// PING インタラクションかどうか
    pub fn is_ping(&self) -> bool {
        self.interaction_type == InteractionType::Ping
    }

    /// スラッシュコマンドかどうか
    pub fn is_slash_command(&self) -> bool {
        self.interaction_type == InteractionType::ApplicationCommand
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    mod interaction_data_tests {
        use super::*;

        fn create_test_command_name() -> CommandName {
            CommandName::new("test".to_string()).unwrap()
        }

        #[test]
        fn test_new() {
            let name = create_test_command_name();
            let data = InteractionData::new("123".to_string(), name, vec![]);

            assert_eq!(data.command_name().as_str(), "test");
            assert!(data.options().is_empty());
        }

        #[test]
        fn test_command_name() {
            let name = create_test_command_name();
            let data = InteractionData::new("123".to_string(), name, vec![]);

            assert_eq!(data.command_name().as_str(), "test");
        }

        #[test]
        fn test_options_empty() {
            let name = create_test_command_name();
            let data = InteractionData::new("123".to_string(), name, vec![]);

            assert!(data.options().is_empty());
        }

        #[test]
        fn test_options_with_values() {
            let name = create_test_command_name();
            let option =
                CommandOption::new("arg1".to_string(), 3, Some(serde_json::json!("value1")));
            let data = InteractionData::new("123".to_string(), name, vec![option]);

            assert_eq!(data.options().len(), 1);
        }

        #[test]
        fn test_get_option_found() {
            let name = create_test_command_name();
            let option =
                CommandOption::new("arg1".to_string(), 3, Some(serde_json::json!("value1")));
            let data = InteractionData::new("123".to_string(), name, vec![option]);

            let found = data.get_option("arg1");
            assert!(found.is_some());
        }

        #[test]
        fn test_get_option_not_found() {
            let name = create_test_command_name();
            let data = InteractionData::new("123".to_string(), name, vec![]);

            let found = data.get_option("nonexistent");
            assert!(found.is_none());
        }
    }

    mod interaction_tests {
        use super::*;

        fn create_test_interaction_id() -> InteractionId {
            InteractionId::new("123456789")
        }

        fn create_test_token() -> InteractionToken {
            InteractionToken::new("test_token")
        }

        fn create_test_interaction_data() -> InteractionData {
            let command_name = CommandName::new("test".to_string()).unwrap();
            InteractionData::new("data123".to_string(), command_name, vec![])
        }

        #[test]
        fn test_new_ping_success() {
            let result = Interaction::new(
                create_test_interaction_id(),
                InteractionType::Ping,
                create_test_token(),
                None,
                None,
                None,
                None,
            );

            assert!(result.is_ok());
        }

        #[test]
        fn test_new_application_command_with_data_success() {
            let result = Interaction::new(
                create_test_interaction_id(),
                InteractionType::ApplicationCommand,
                create_test_token(),
                None,
                None,
                None,
                Some(create_test_interaction_data()),
            );

            assert!(result.is_ok());
        }

        #[test]
        fn test_new_application_command_without_data_fails() {
            let result = Interaction::new(
                create_test_interaction_id(),
                InteractionType::ApplicationCommand,
                create_test_token(),
                None,
                None,
                None,
                None,
            );

            assert!(result.is_err());
        }

        #[test]
        fn test_is_ping() {
            let interaction = Interaction::new(
                create_test_interaction_id(),
                InteractionType::Ping,
                create_test_token(),
                None,
                None,
                None,
                None,
            )
            .unwrap();

            assert!(interaction.is_ping());
            assert!(!interaction.is_slash_command());
        }

        #[test]
        fn test_is_slash_command() {
            let interaction = Interaction::new(
                create_test_interaction_id(),
                InteractionType::ApplicationCommand,
                create_test_token(),
                None,
                None,
                None,
                Some(create_test_interaction_data()),
            )
            .unwrap();

            assert!(interaction.is_slash_command());
            assert!(!interaction.is_ping());
        }

        #[test]
        fn test_id() {
            let interaction = Interaction::new(
                create_test_interaction_id(),
                InteractionType::Ping,
                create_test_token(),
                None,
                None,
                None,
                None,
            )
            .unwrap();

            assert_eq!(interaction.id().as_str(), "123456789");
        }

        #[test]
        fn test_interaction_type() {
            let interaction = Interaction::new(
                create_test_interaction_id(),
                InteractionType::Ping,
                create_test_token(),
                None,
                None,
                None,
                None,
            )
            .unwrap();

            assert_eq!(interaction.interaction_type(), InteractionType::Ping);
        }

        #[test]
        fn test_token() {
            let interaction = Interaction::new(
                create_test_interaction_id(),
                InteractionType::Ping,
                InteractionToken::new("secret_token"),
                None,
                None,
                None,
                None,
            )
            .unwrap();

            assert_eq!(interaction.token().as_str(), "secret_token");
        }

        #[test]
        fn test_application_id_some() {
            let app_id = ApplicationId::new("app123".to_string()).unwrap();
            let interaction = Interaction::new(
                create_test_interaction_id(),
                InteractionType::Ping,
                create_test_token(),
                Some(app_id),
                None,
                None,
                None,
            )
            .unwrap();

            assert!(interaction.application_id().is_some());
            assert_eq!(interaction.application_id().unwrap().value(), "app123");
        }

        #[test]
        fn test_application_id_none() {
            let interaction = Interaction::new(
                create_test_interaction_id(),
                InteractionType::Ping,
                create_test_token(),
                None,
                None,
                None,
                None,
            )
            .unwrap();

            assert!(interaction.application_id().is_none());
        }

        #[test]
        fn test_guild_id_some() {
            let interaction = Interaction::new(
                create_test_interaction_id(),
                InteractionType::Ping,
                create_test_token(),
                None,
                Some("guild123".to_string()),
                None,
                None,
            )
            .unwrap();

            assert_eq!(interaction.guild_id(), Some("guild123"));
        }

        #[test]
        fn test_guild_id_none() {
            let interaction = Interaction::new(
                create_test_interaction_id(),
                InteractionType::Ping,
                create_test_token(),
                None,
                None,
                None,
                None,
            )
            .unwrap();

            assert!(interaction.guild_id().is_none());
        }

        #[test]
        fn test_channel_id_some() {
            let interaction = Interaction::new(
                create_test_interaction_id(),
                InteractionType::Ping,
                create_test_token(),
                None,
                None,
                Some("channel123".to_string()),
                None,
            )
            .unwrap();

            assert_eq!(interaction.channel_id(), Some("channel123"));
        }

        #[test]
        fn test_channel_id_none() {
            let interaction = Interaction::new(
                create_test_interaction_id(),
                InteractionType::Ping,
                create_test_token(),
                None,
                None,
                None,
                None,
            )
            .unwrap();

            assert!(interaction.channel_id().is_none());
        }

        #[test]
        fn test_data_some() {
            let command_name = CommandName::new("ping".to_string()).unwrap();
            let data = InteractionData::new("data123".to_string(), command_name, vec![]);
            let interaction = Interaction::new(
                create_test_interaction_id(),
                InteractionType::ApplicationCommand,
                create_test_token(),
                None,
                None,
                None,
                Some(data),
            )
            .unwrap();

            assert!(interaction.data().is_some());
            assert_eq!(interaction.data().unwrap().command_name().as_str(), "ping");
        }

        #[test]
        fn test_data_none() {
            let interaction = Interaction::new(
                create_test_interaction_id(),
                InteractionType::Ping,
                create_test_token(),
                None,
                None,
                None,
                None,
            )
            .unwrap();

            assert!(interaction.data().is_none());
        }
    }
}
