use crate::infrastructure::discord_api::dto::interaction_response::InteractionResponseDto;
use crate::{
    application::interaction_use_case::InteractionResult,
    domain::discord::{
        ApplicationId,
        entities::interaction::{Interaction, InteractionData},
        errors::DomainError,
        value_objects::{
            command_name::CommandName, command_option::CommandOption,
            interaction_id::InteractionId, interaction_token::InteractionToken,
            interaction_type::InteractionType,
        },
    },
    infrastructure::discord_api::dto::intraction_request::InteractionRequestDto,
};

pub struct InteractionMapper;

impl InteractionMapper {
    pub fn to_domain(dto: InteractionRequestDto) -> Result<Interaction, DomainError> {
        let interaction_type = InteractionType::from_i32(dto.r#type)?;

        let data = dto
            .data
            .map(|d| {
                let name = CommandName::new(d.name)?;
                let options = d
                    .options
                    .into_iter()
                    .map(|o| CommandOption::new(o.name, o.r#type, o.value))
                    .collect();

                Ok::<_, DomainError>(InteractionData::new(d.id, name, options))
            })
            .transpose()?;
        let application_id = dto
            .application_id
            .map(|id| ApplicationId::new(id).map_err(|e| DomainError::ValidationError(e)))
            .transpose()?;

        Interaction::new(
            InteractionId::new(dto.id),
            interaction_type,
            InteractionToken::new(dto.token),
            application_id,
            dto.guild_id,
            dto.channel_id,
            data,
        )
    }

    pub fn to_rsponse(result: InteractionResult) -> InteractionResponseDto {
        match result {
            InteractionResult::Pong => InteractionResponseDto::pong(),
            InteractionResult::CommandResponse(cmd_result) => {
                InteractionResponseDto::message(cmd_result.content, cmd_result.ephemeral)
            }
            InteractionResult::Error(message) => InteractionResponseDto::error(message),
        }
    }
}
