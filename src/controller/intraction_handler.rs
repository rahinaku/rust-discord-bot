use std::sync::Arc;

use axum::{Json, response::IntoResponse};
use reqwest::StatusCode;
use tracing::{Span, instrument};

use crate::{
    application::interaction_use_case::InteractionUseCase,
    infrastructure::discord_api::{
        dto::intraction_request::InteractionRequestDto,
        mappers::interaction_mapper::InteractionMapper,
    },
};

#[instrument(skip(use_case, dto), fields(interaction_type))]
pub async fn interaction_handler(
    axum::extract::State(use_case): axum::extract::State<Arc<InteractionUseCase>>,
    Json(dto): Json<InteractionRequestDto>,
) -> impl IntoResponse {
    // DTO -> ドメインエンティティ
    let interaction = match InteractionMapper::to_domain(dto) {
        Ok(i) => i,
        Err(e) => {
            let response = InteractionMapper::to_rsponse(
                crate::application::interaction_use_case::InteractionResult::Error(e.to_string()),
            );
            return (StatusCode::OK, Json(response));
        }
    };

    // インタラクションタイプをログに記録
    Span::current().record(
        "interaction_type",
        tracing::field::debug(interaction.interaction_type()),
    );

    let result = use_case.handle(&interaction);

    let response = InteractionMapper::to_rsponse(result);

    (StatusCode::OK, Json(response))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::infrastructure::discord_api::dto::{
        intraction_request::{InteractionDataDto, InteractionRequestDto},
        interaction_response::InteractionResponseDto,
    };
    use axum::body::to_bytes;
    use axum::http::StatusCode as HttpStatusCode;

    fn create_use_case() -> Arc<InteractionUseCase> {
        Arc::new(InteractionUseCase::new())
    }

    fn create_ping_dto() -> InteractionRequestDto {
        InteractionRequestDto {
            id: "123456789".to_string(),
            r#type: 1, // Ping
            token: "test_token".to_string(),
            application_id: None,
            guild_id: None,
            channel_id: None,
            data: None,
        }
    }

    fn create_application_command_dto(command_name: &str) -> InteractionRequestDto {
        InteractionRequestDto {
            id: "123456789".to_string(),
            r#type: 2, // ApplicationCommand
            token: "test_token".to_string(),
            application_id: Some("app123".to_string()),
            guild_id: Some("guild123".to_string()),
            channel_id: Some("channel123".to_string()),
            data: Some(InteractionDataDto {
                id: "data123".to_string(),
                name: command_name.to_string(),
                options: vec![],
            }),
        }
    }

    fn create_invalid_type_dto() -> InteractionRequestDto {
        InteractionRequestDto {
            id: "123456789".to_string(),
            r#type: 999, // 不正なタイプ
            token: "test_token".to_string(),
            application_id: None,
            guild_id: None,
            channel_id: None,
            data: None,
        }
    }

    async fn call_handler(
        use_case: Arc<InteractionUseCase>,
        dto: InteractionRequestDto,
    ) -> (HttpStatusCode, InteractionResponseDto) {
        let response = interaction_handler(axum::extract::State(use_case), Json(dto))
            .await
            .into_response();

        let (parts, body) = response.into_parts();
        let bytes = to_bytes(body, usize::MAX).await.unwrap();
        let response_dto: InteractionResponseDto = serde_json::from_slice(&bytes).unwrap();

        (parts.status, response_dto)
    }

    #[tokio::test]
    async fn test_ping_returns_pong() {
        let use_case = create_use_case();
        let dto = create_ping_dto();

        let (status, response) = call_handler(use_case, dto).await;

        // PONGレスポンス (type=1)
        assert_eq!(status, HttpStatusCode::OK);
        assert_eq!(response.r#type, 1);
        assert!(response.data.is_none());
    }

    #[tokio::test]
    async fn test_unknown_command_returns_error() {
        let use_case = create_use_case();
        let dto = create_application_command_dto("unknown_command");

        let (status, response) = call_handler(use_case, dto).await;

        assert_eq!(status, HttpStatusCode::OK);
        // エラーレスポンス (type=4: ChannelMessageWithSource)
        assert_eq!(response.r#type, 4);
        assert!(response.data.is_some());
        let data = response.data.unwrap();
        assert!(data.content.unwrap().contains("Unknown command"));
    }

    #[tokio::test]
    async fn test_invalid_interaction_type_returns_error() {
        let use_case = create_use_case();
        let dto = create_invalid_type_dto();

        let (status, response) = call_handler(use_case, dto).await;

        assert_eq!(status, HttpStatusCode::OK);
        // エラーレスポンス
        assert_eq!(response.r#type, 4);
        assert!(response.data.is_some());
    }

    #[tokio::test]
    async fn test_application_command_without_data_returns_error() {
        let use_case = create_use_case();
        // dataなしのApplicationCommand（バリデーションエラー）
        let dto = InteractionRequestDto {
            id: "123456789".to_string(),
            r#type: 2, // ApplicationCommand
            token: "test_token".to_string(),
            application_id: None,
            guild_id: None,
            channel_id: None,
            data: None, // dataが必要だが欠落
        };

        let (status, response) = call_handler(use_case, dto).await;

        assert_eq!(status, HttpStatusCode::OK);
        // エラーレスポンス
        assert_eq!(response.r#type, 4);
        assert!(response.data.is_some());
    }
}
