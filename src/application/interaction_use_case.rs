use std::{collections::HashMap, sync::WaitTimeoutResult};

use tracing::{info, instrument, warn};

use crate::domain::discord::{
    entities::interaction::Interaction,
    services::command_executor::{CommandExecutor, CommandResult},
    value_objects::interaction_type::InteractionType,
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

    #[instrument(skip(self, interaction), fields(interaction_type = ?interaction.interaction_type()))]
    pub fn handle(&self, interaction: &Interaction) -> InteractionResult {
        match interaction.interaction_type() {
            InteractionType::Ping => {
                info!("Received PING, responding with PONG");
                InteractionResult::Pong
            }
            InteractionType::ApplicationCommand => self.handle_slash_command(interaction),
            _ => {
                warn!(
                    interaction_type = interaction.interaction_type().as_i32(),
                    "Unsupported interaction type"
                );
                InteractionResult::Error(format!(
                    "Unsupported interaction type: {}",
                    interaction.interaction_type().as_i32()
                ))
            }
        }
    }

    #[instrument(skip(self, interaction), fields(command_name))]
    fn handle_slash_command(&self, interaction: &Interaction) -> InteractionResult {
        let command_name = interaction
            .data()
            .map(|d| d.command_name().as_str())
            .unwrap_or("unknown");

        tracing::Span::current().record("command_name", command_name);
        info!(command_name, "Executing slash command");

        match self.commands.get(command_name) {
            Some(handler) => match handler.execute(interaction) {
                Ok(result) => {
                    info!(command_name, "Command executed successfully");
                    InteractionResult::CommandResponse(result)
                }
                Err(e) => {
                    warn!(command_name, error = %e, "Command execution failed");
                    InteractionResult::Error(e.to_string())
                }
            },
            None => {
                warn!(command_name, "Unknown command");
                InteractionResult::Error(format!("Unknown command: {}", command_name))
            }
        }
    }
}
