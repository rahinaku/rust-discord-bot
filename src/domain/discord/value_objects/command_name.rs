use crate::domain::discord::errors::DomainError;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CommandName(String);

impl CommandName {
    pub fn new(value: impl Into<String>) -> Result<Self, DomainError> {
        let value = value.into();
        if value.is_empty() || value.len() > 32 {
            return Err(DomainError::InvalidCommandName(
                "Command name must be 1-32 characters".to_string(),
            ));
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_with_valid_name() {
        let result = CommandName::new("test");
        assert!(result.is_ok());
        assert_eq!(result.unwrap().as_str(), "test");
    }

    #[test]
    fn test_new_with_string() {
        let result = CommandName::new("command".to_string());
        assert!(result.is_ok());
        assert_eq!(result.unwrap().as_str(), "command");
    }

    #[test]
    fn test_new_with_empty_name() {
        let result = CommandName::new("");
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), DomainError::InvalidCommandName(_)));
    }

    #[test]
    fn test_new_with_max_length() {
        let name = "a".repeat(32);
        let result = CommandName::new(name.clone());
        assert!(result.is_ok());
        assert_eq!(result.unwrap().as_str(), name);
    }

    #[test]
    fn test_new_with_too_long_name() {
        let name = "a".repeat(33);
        let result = CommandName::new(name);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), DomainError::InvalidCommandName(_)));
    }

    #[test]
    fn test_equality() {
        let name1 = CommandName::new("test").unwrap();
        let name2 = CommandName::new("test").unwrap();
        let name3 = CommandName::new("other").unwrap();

        assert_eq!(name1, name2);
        assert_ne!(name1, name3);
    }

    #[test]
    fn test_hash() {
        use std::collections::HashSet;

        let name1 = CommandName::new("test").unwrap();
        let name2 = CommandName::new("test").unwrap();

        let mut set = HashSet::new();
        set.insert(name1);
        assert!(set.contains(&name2));
    }
}
