use thiserror::Error;

#[derive(Debug, Error)]
pub enum DomainError {
    #[error("Invalid interaction type: {0}")]
    InvalidInteractinType(i32),

    #[error("Invalid command name: {0}")]
    InvalidCommandName(String),

    #[error("Missing interaction data for type: {0}")]
    MissingInteractionData(i32),

    #[error("Unknown command: {0}")]
    UnknownCommand(String),
}
