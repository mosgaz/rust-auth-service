use axum::{extract::State, http::StatusCode, routing::get, Json, Router};
use chrono::Utc;
use serde::Serialize;

use crate::{config::AppConfig, security};

#[derive(Clone)]
pub struct AppState {
    pub config: AppConfig,
}

#[derive(Debug, Serialize)]
struct HealthResponse {
    status: &'static str,
    timestamp: String,
    service: String,
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/health/live", get(live))
        .route("/health/ready", get(ready))
        .route("/.well-known/jwks.json", get(jwks))
        .with_state(state)
}

async fn live(State(state): State<AppState>) -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok",
        timestamp: Utc::now().to_rfc3339(),
        service: state.config.service_name,
    })
}

async fn ready(State(state): State<AppState>) -> (StatusCode, Json<HealthResponse>) {
    (
        StatusCode::OK,
        Json(HealthResponse {
            status: "ready",
            timestamp: Utc::now().to_rfc3339(),
            service: state.config.service_name,
        }),
    )
}

async fn jwks() -> Json<security::JwksResponse> {
    Json(security::demo_jwks())
}
