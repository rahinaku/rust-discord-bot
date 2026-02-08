use crate::domain::discord::{entities::interaction::Interaction, errors::DomainError, services::command_executor::{CommandExecutor, CommandResult}};

pub struct TestCommandHandler;

impl CommandExecutor for TestCommandHandler {
    fn name(&self)->&str{
        "test"
    }

    fn execute(&self,_interaction:&Interaction) -> Result<CommandResult,DomainError> {
        Ok(CommandResult::message("Hello from test command!"))
    }
}
