use std::fmt;

#[derive(Debug, Clone)]
pub struct InteractionToken(String);

impl InteractionToken {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

// セキュリティ上、Displayではマスクｊ
impl fmt::Display for InteractionToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "****")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_with_str() {
        let token = InteractionToken::new("secret_token");
        assert_eq!(token.as_str(), "secret_token");
    }

    #[test]
    fn test_new_with_string() {
        let token = InteractionToken::new("another_token".to_string());
        assert_eq!(token.as_str(), "another_token");
    }

    #[test]
    fn test_display_masks_token() {
        let token = InteractionToken::new("super_secret_value");
        let displayed = format!("{}", token);
        assert_eq!(displayed, "****");
        assert!(!displayed.contains("super_secret_value"));
    }

    #[test]
    fn test_debug_shows_token() {
        let token = InteractionToken::new("debug_token");
        let debug_str = format!("{:?}", token);
        assert!(debug_str.contains("debug_token"));
    }

    #[test]
    fn test_clone() {
        let token1 = InteractionToken::new("token");
        let token2 = token1.clone();

        assert_eq!(token1.as_str(), token2.as_str());
    }
}
