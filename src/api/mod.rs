use axum::{
    extract::State,
    http::StatusCode,
    routing::{get, patch, post},
    Json, Router,
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

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
        .route("/auth/login", post(login))
        .route("/auth/refresh", post(refresh))
        .route("/auth/logout", post(logout))
        .route("/auth/revoke-all", post(revoke_all))
        .route("/auth/sessions", get(list_sessions))
        .route(
            "/auth/sessions/{family_id}",
            axum::routing::delete(delete_session),
        )
        .route("/auth/sessions/{family_id}/trust", patch(trust_session))
        .route("/auth/sessions/push-token", post(register_push_token))
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

#[derive(Debug, Deserialize)]
struct LoginRequest {
    identity: String,
    password: String,
    device_name: String,
    device_type: String,
}

#[derive(Debug, Serialize)]
struct LoginResponse {
    access_token: String,
    refresh_token: String,
    expires_in: u64,
    token_type: &'static str,
    family_id: Uuid,
}

#[derive(Debug, Deserialize)]
struct RefreshRequest {
    refresh_token: String,
}

#[derive(Debug, Serialize)]
struct RefreshResponse {
    access_token: String,
    refresh_token: String,
    expires_in: u64,
}

#[derive(Debug, Serialize)]
struct SessionListResponse {
    sessions: Vec<SessionDto>,
}

#[derive(Debug, Serialize)]
struct SessionDto {
    family_id: Uuid,
    device_name: String,
    device_type: String,
    last_active: String,
    created_at: String,
    ip_address: String,
    is_current: bool,
    is_trusted: bool,
}

#[derive(Debug, Deserialize)]
struct PushTokenRequest {
    push_token: String,
    platform: String,
    app_version: String,
}

async fn login(Json(payload): Json<LoginRequest>) -> Result<Json<LoginResponse>, StatusCode> {
    if payload.identity.trim().is_empty()
        || payload.password.trim().is_empty()
        || payload.device_name.trim().is_empty()
        || payload.device_type.trim().is_empty()
    {
        return Err(StatusCode::BAD_REQUEST);
    }

    Ok(Json(LoginResponse {
        access_token: format!("demo-access-{}", Uuid::new_v4()),
        refresh_token: format!("demo-refresh-{}", Uuid::new_v4()),
        expires_in: 900,
        token_type: "Bearer",
        family_id: Uuid::new_v4(),
    }))
}

async fn refresh(Json(payload): Json<RefreshRequest>) -> Result<Json<RefreshResponse>, StatusCode> {
    if payload.refresh_token.trim().is_empty() {
        return Err(StatusCode::BAD_REQUEST);
    }

    Ok(Json(RefreshResponse {
        access_token: format!("demo-access-{}", Uuid::new_v4()),
        refresh_token: format!("demo-refresh-{}", Uuid::new_v4()),
        expires_in: 900,
    }))
}

async fn logout() -> StatusCode {
    StatusCode::NO_CONTENT
}

async fn revoke_all() -> StatusCode {
    StatusCode::NO_CONTENT
}

async fn list_sessions() -> Json<SessionListResponse> {
    Json(SessionListResponse { sessions: vec![] })
}

async fn delete_session() -> StatusCode {
    StatusCode::NO_CONTENT
}

async fn trust_session() -> StatusCode {
    StatusCode::NO_CONTENT
}

async fn register_push_token(
    Json(payload): Json<PushTokenRequest>,
) -> Result<StatusCode, StatusCode> {
    if payload.push_token.trim().is_empty()
        || payload.platform.trim().is_empty()
        || payload.app_version.trim().is_empty()
    {
        return Err(StatusCode::BAD_REQUEST);
    }

    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use axum::{body::Body, http::Request};
    use serde_json::{json, Value};
    use tower::ServiceExt;

    use super::{router, AppState};
    use crate::config::AppConfig;

    fn test_app() -> axum::Router {
        router(AppState {
            config: AppConfig::from_env(),
        })
    }

    #[tokio::test]
    async fn login_returns_tokens() {
        let app = test_app();
        let request = Request::builder()
            .uri("/auth/login")
            .method("POST")
            .header("content-type", "application/json")
            .body(Body::from(
                json!({
                    "identity": "user@example.com",
                    "password": "secret",
                    "device_name": "MacBook",
                    "device_type": "desktop"
                })
                .to_string(),
            ))
            .expect("build request");

        let response = app.oneshot(request).await.expect("route response");
        assert_eq!(response.status(), axum::http::StatusCode::OK);

        let body = http_body_util::BodyExt::collect(response.into_body())
            .await
            .expect("collect body")
            .to_bytes();
        let payload: Value = serde_json::from_slice(&body).expect("decode json");

        assert!(payload.get("access_token").is_some());
        assert!(payload.get("refresh_token").is_some());
        assert_eq!(payload.get("expires_in"), Some(&Value::from(900)));
        assert_eq!(payload.get("token_type"), Some(&Value::from("Bearer")));
    }

    #[tokio::test]
    async fn refresh_rejects_empty_token() {
        let app = test_app();
        let request = Request::builder()
            .uri("/auth/refresh")
            .method("POST")
            .header("content-type", "application/json")
            .body(Body::from(
                json!({
                    "refresh_token": ""
                })
                .to_string(),
            ))
            .expect("build request");

        let response = app.oneshot(request).await.expect("route response");
        assert_eq!(response.status(), axum::http::StatusCode::BAD_REQUEST);
    }
}
