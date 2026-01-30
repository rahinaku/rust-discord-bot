#[derive(Debug, Clone)]
pub struct CommandOption {
    name: String,
    option_type: i32,
    value: Option<serde_json::Value>,
}

impl CommandOption {
    pub fn new(name: String, option_type: i32, value: Option<serde_json::Value>) -> Self {
        Self {
            name,
            option_type,
            value,
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn option_type(&self) -> i32 {
        self.option_type
    }

    pub fn value(&self) -> Option<&serde_json::Value> {
        self.value.as_ref()
    }

    pub fn as_string(&self) -> Option<&str> {
        self.value.as_ref()?.as_str()
    }

    pub fn as_i64(&self) -> Option<i64> {
        self.value.as_ref()?.as_i64()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_new_with_value() {
        let option = CommandOption::new("test_option".to_string(), 3, Some(json!("test_value")));

        assert_eq!(option.name(), "test_option");
        assert_eq!(option.option_type(), 3);
        assert!(option.value().is_some());
    }

    #[test]
    fn test_new_without_value() {
        let option = CommandOption::new("empty_option".to_string(), 5, None);

        assert_eq!(option.name(), "empty_option");
        assert_eq!(option.option_type(), 5);
        assert!(option.value().is_none());
    }

    #[test]
    fn test_as_string_with_string_value() {
        let option = CommandOption::new("string_option".to_string(), 3, Some(json!("hello")));

        assert_eq!(option.as_string(), Some("hello"));
    }

    #[test]
    fn test_as_string_with_non_string_value() {
        let option = CommandOption::new("number_option".to_string(), 4, Some(json!(123)));

        assert_eq!(option.as_string(), None);
    }

    #[test]
    fn test_as_string_with_none_value() {
        let option = CommandOption::new("none_option".to_string(), 3, None);

        assert_eq!(option.as_string(), None);
    }

    #[test]
    fn test_as_i64_with_integer_value() {
        let option = CommandOption::new("integer_option".to_string(), 4, Some(json!(42)));

        assert_eq!(option.as_i64(), Some(42));
    }

    #[test]
    fn test_as_i64_with_non_integer_value() {
        let option =
            CommandOption::new("string_option".to_string(), 3, Some(json!("not a number")));

        assert_eq!(option.as_i64(), None);
    }

    #[test]
    fn test_as_i64_with_none_value() {
        let option = CommandOption::new("none_option".to_string(), 4, None);

        assert_eq!(option.as_i64(), None);
    }

    #[test]
    fn test_clone() {
        let option = CommandOption::new("clone_test".to_string(), 3, Some(json!("value")));
        let cloned = option.clone();

        assert_eq!(cloned.name(), option.name());
        assert_eq!(cloned.option_type(), option.option_type());
        assert_eq!(cloned.value(), option.value());
    }
}
