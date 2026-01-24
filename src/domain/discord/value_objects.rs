// Discord Application ID
#[derive(Debug, Clone)]
pub struct ApplicationId(String);

impl ApplicationId {
    pub fn new(id: String) -> Result<Self, String> {
        if id.is_empty() {
            return Err("ApplicationId ID cannot be empty".to_string());
        }
        Ok(Self(id))
    }

    pub fn value(&self) -> &str {
        &self.0
    }
}

// Discord bot Token
#[derive(Debug, Clone)]
pub struct BotToken(String);

impl BotToken {
    pub fn new(token: String) -> Result<Self, String> {
        if token.is_empty() {
            return Err("Bot token cannot by empty".to_string());
        }
        return Ok(Self(token));
    }

    pub fn value(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CommandName(String);

impl CommandName {
    pub fn new(name: String) -> Result<Self, String> {
        if name.is_empty() || name.len() > 32 {
            return Err("Command name must be 1-32 characters".to_string());
        }
        Ok(Self(name))
    }

    pub fn value(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone)]
pub struct CommandDescription(String);

impl CommandDescription {
    pub fn new(description: String) -> Result<Self, String> {
        if description.is_empty() || description.len() > 100 {
            return Err("Description must be 1-100 characters".to_string());
        }
        Ok(Self(description))
    }

    pub fn value(&self) -> &str {
        &self.0
    }
}

/// スラッシュコマンド定義
#[derive(Debug)]
pub struct SlashCommandDefinition {
    name: CommandName,
    description: CommandDescription,
}

impl SlashCommandDefinition {
    pub fn new(name: CommandName, description: CommandDescription) -> Self {
        Self { name, description }
    }

    pub fn name(&self) -> &CommandName {
        &self.name
    }

    pub fn description(&self) -> &CommandDescription {
        &self.description
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_application_id_new_with_valid_id() {
        let id = "123456789".to_string();
        let result = ApplicationId::new(id.clone());
        assert!(result.is_ok());
        assert_eq!(result.unwrap().value(), id);
    }

    #[test]
    fn test_application_id_new_with_empty_id() {
        let result = ApplicationId::new("".to_string());
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "ApplicationId ID cannot be empty");
    }

    #[test]
    fn test_bot_token_new_with_valid_token() {
        let token = "Bot.valid.token".to_string();
        let result = BotToken::new(token.clone());
        assert!(result.is_ok());
        assert_eq!(result.unwrap().value(), token);
    }

    #[test]
    fn test_bot_token_new_with_empty_token() {
        let result = BotToken::new("".to_string());
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Bot token cannot by empty");
    }

    #[test]
    fn test_command_name_new_with_valid_name() {
        let name = "test_command".to_string();
        let result = CommandName::new(name.clone());
        assert!(result.is_ok());
        assert_eq!(result.unwrap().value(), name);
    }

    #[test]
    fn test_command_name_new_with_empty_name() {
        let result = CommandName::new("".to_string());
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Command name must be 1-32 characters");
    }

    #[test]
    fn test_command_name_new_with_too_long_name() {
        let name = "a".repeat(33);
        let result = CommandName::new(name);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Command name must be 1-32 characters");
    }

    #[test]
    fn test_command_name_new_with_max_length() {
        let name = "a".repeat(32);
        let result = CommandName::new(name.clone());
        assert!(result.is_ok());
        assert_eq!(result.unwrap().value(), name);
    }

    #[test]
    fn test_command_description_new_with_valid_description() {
        let description = "This is a test command".to_string();
        let result = CommandDescription::new(description.clone());
        assert!(result.is_ok());
        assert_eq!(result.unwrap().value(), description);
    }

    #[test]
    fn test_command_description_new_with_empty_description() {
        let result = CommandDescription::new("".to_string());
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Description must be 1-100 characters");
    }

    #[test]
    fn test_command_description_new_with_too_long_description() {
        let description = "a".repeat(101);
        let result = CommandDescription::new(description);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), "Description must be 1-100 characters");
    }

    #[test]
    fn test_command_description_new_with_max_length() {
        let description = "a".repeat(100);
        let result = CommandDescription::new(description.clone());
        assert!(result.is_ok());
        assert_eq!(result.unwrap().value(), description);
    }

    #[test]
    fn test_slash_command_definition_new() {
        let name = CommandName::new("test".to_string()).unwrap();
        let description = CommandDescription::new("Test description".to_string()).unwrap();

        let command = SlashCommandDefinition::new(name.clone(), description.clone());

        assert_eq!(command.name().value(), name.value());
        assert_eq!(command.description().value(), description.value());
    }

    #[test]
    fn test_command_name_hash_equality() {
        use std::collections::HashSet;

        let name1 = CommandName::new("test".to_string()).unwrap();
        let name2 = CommandName::new("test".to_string()).unwrap();
        let name3 = CommandName::new("other".to_string()).unwrap();

        assert_eq!(name1, name2);
        assert_ne!(name1, name3);

        let mut set = HashSet::new();
        set.insert(name1);
        assert!(set.contains(&name2));
        assert!(!set.contains(&name3));
    }
}
