#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct InteractionId(String);

impl InteractionId {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_with_str() {
        let id = InteractionId::new("123456789");
        assert_eq!(id.as_str(), "123456789");
    }

    #[test]
    fn test_new_with_string() {
        let id = InteractionId::new("987654321".to_string());
        assert_eq!(id.as_str(), "987654321");
    }

    #[test]
    fn test_equality() {
        let id1 = InteractionId::new("123");
        let id2 = InteractionId::new("123");
        let id3 = InteractionId::new("456");

        assert_eq!(id1, id2);
        assert_ne!(id1, id3);
    }

    #[test]
    fn test_hash() {
        use std::collections::HashSet;

        let id1 = InteractionId::new("123");
        let id2 = InteractionId::new("123");

        let mut set = HashSet::new();
        set.insert(id1);
        assert!(set.contains(&id2));
    }

    #[test]
    fn test_clone() {
        let id1 = InteractionId::new("123");
        let id2 = id1.clone();

        assert_eq!(id1, id2);
    }

    #[test]
    fn test_debug() {
        let id = InteractionId::new("123");
        let debug_str = format!("{:?}", id);
        assert!(debug_str.contains("123"));
    }
}
