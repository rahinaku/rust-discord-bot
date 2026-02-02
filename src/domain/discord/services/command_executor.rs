use crate::domain::discord::{entities::interaction::Interaction, errors::DomainError};

#[derive(Debug)]
pub struct CommandResult {
    pub content: String,
    pub ephemeral: bool,
}

impl CommandResult {
    pub fn message(content: impl Into<String>) -> Self {
        Self {
            content: content.into(),
            ephemeral: false,
        }
    }

    pub fn ephemeral_message(content: impl Into<String>) -> Self {
        Self {
            content: content.into(),
            ephemeral: true,
        }
    }
}

pub trait CommandExecutor: Send + Sync {
    fn name(&self) -> &str;
    fn execute(&self, interaction: &Interaction) -> Result<CommandResult, DomainError>;
}
