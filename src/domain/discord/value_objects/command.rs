use crate::domain::discord::value_objects::command_name::CommandName;

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
    fn test_command_name_new_with_valid_name() {
        let name = "test_command".to_string();
        let result = CommandName::new(name.clone());
        assert!(result.is_ok());
        assert_eq!(result.unwrap().as_str(), name);
    }

    #[test]
    fn test_command_name_new_with_empty_name() {
        use crate::domain::discord::errors::DomainError;
        let result = CommandName::new("".to_string());
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            DomainError::InvalidCommandName(_)
        ));
    }

    #[test]
    fn test_command_name_new_with_too_long_name() {
        use crate::domain::discord::errors::DomainError;
        let name = "a".repeat(33);
        let result = CommandName::new(name);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            DomainError::InvalidCommandName(_)
        ));
    }

    #[test]
    fn test_command_name_new_with_max_length() {
        let name = "a".repeat(32);
        let result = CommandName::new(name.clone());
        assert!(result.is_ok());
        assert_eq!(result.unwrap().as_str(), name);
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

        assert_eq!(command.name().as_str(), name.as_str());
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
