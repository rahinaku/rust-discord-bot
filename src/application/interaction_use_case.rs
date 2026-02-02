use std::collections::HashMap;

use crate::{
    domain::discord::{
        entities::interaction::Interaction,
        services::command_executor::{CommandExecutor, CommandResult},
        value_objects::interaction_type::InteractionType,
    },
    handler,
};

#[derive(Debug)]
pub enum InteractionResult {
    Pong,
    CommandResponse(CommandResult),
    Error(String),
}

pub struct InteractionUseCase {
    commands: HashMap<String, Box<dyn CommandExecutor>>,
}

impl InteractionUseCase {
    pub fn new() -> Self {
        Self {
            commands: HashMap::new(),
        }
    }

    pub fn register_command(&mut self, handler: Box<dyn CommandExecutor>) {
        self.commands.insert(handler.name().to_string(), handler);
    }

    pub fn handle(&self, interaction: &Interaction) -> InteractionResult {
        match interaction.interaction_type() {
            InteractionType::Ping => InteractionResult::Pong,
            InteractionType::ApplicationCommand => todo!(),
            _ => InteractionResult::Error(format!(
                "Unsupported interaction type: {}",
                interaction.interaction_type().as_i32()
            )),
        }
    }

    fn handle_slash_command(&self, interaction: &Interaction) -> InteractionResult {
        let command_name = interaction
            .data()
            .map(|d| d.command_name().as_str())
            .unwrap_or("unknown");
        match self.commands.get(command_name) {
            Some(handler) => match handler.execute(interaction) {
                Ok(result) => InteractionResult::CommandResponse(result),
                Err(e) => InteractionResult::Error(e.to_string()),
            },
            None => InteractionResult::Error(format!("Unknown command: {}", command_name)),
        }
    }
}
