use crate::domain::discord::{
    entities::interaction::Interaction,
    errors::DomainError,
    services::command_executor::{CommandExecutor, CommandResult},
};

pub struct PingCommandHandler;

impl CommandExecutor for PingCommandHandler {
    fn name(&self) -> &str {
        "ping"
    }

    fn execute(&self, _interaction: &Interaction) -> Result<CommandResult, DomainError> {
        Ok(CommandResult::message("Pong!"))
    }
}
