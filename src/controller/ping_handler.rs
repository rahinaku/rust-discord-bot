use axum::{Json, http::StatusCode, response::IntoResponse};
use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
pub struct PingRequestBody {
    pub r#type: i32,
}

#[derive(Serialize)]
pub struct PingResponseBody {
    pub r#type: i32,
}

pub async fn ping_handler(Json(input): Json<PingRequestBody>) -> impl IntoResponse {
    if input.r#type == 1 {
        let res_body = Json(PingResponseBody { r#type: 1 });

        (StatusCode::OK, res_body)
    } else {
        (
            StatusCode::BAD_REQUEST,
            Json(PingResponseBody {
                r#type: input.r#type,
            }),
        )
    }
}
