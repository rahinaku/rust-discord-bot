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
}
