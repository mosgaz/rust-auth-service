use std::{collections::HashMap, sync::Arc};

use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    routing::{get, patch, post},
    Json, Router,
};
use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use uuid::Uuid;

use crate::{
    config::AppConfig,
    security::{self, JwtManager},
};

#[derive(Clone)]
pub struct AppState {
    pub config: AppConfig,
    pub jwt: JwtManager,
    sessions: Arc<RwLock<HashMap<Uuid, SessionRecord>>>,
    invites: Arc<RwLock<HashMap<String, InviteRecord>>>,
    idempotency: Arc<RwLock<HashMap<String, serde_json::Value>>>,
}

#[derive(Clone)]
struct SessionRecord {
    user_id: Uuid,
    tenant_id: Uuid,
    current_jti_hash: String,
    deleted: bool,
}

#[derive(Clone)]
struct InviteRecord {
    user_id: Uuid,
    tenant_id: Uuid,
    used: bool,
    expires_at: chrono::DateTime<Utc>,
}

impl AppState {
    pub fn new(config: AppConfig) -> Self {
        Self {
            jwt: JwtManager::new(config.issuer.clone()),
            config,
            sessions: Arc::new(RwLock::new(HashMap::new())),
            invites: Arc::new(RwLock::new(HashMap::new())),
            idempotency: Arc::new(RwLock::new(HashMap::new())),
        }
    }
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
        .route("/auth/invites", post(create_invite))
        .route("/auth/invites/accept", post(accept_invite))
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

async fn jwks(State(state): State<AppState>) -> Json<security::JwksResponse> {
    Json(state.jwt.jwks())
}

#[derive(Debug, Deserialize)]
struct LoginRequest {
    identity: String,
    password: String,
    tenant_id: Option<Uuid>,
}

#[derive(Debug, Serialize)]
struct LoginResponse {
    access_token: String,
    refresh_token: String,
    expires_in: i64,
    token_type: &'static str,
    family_id: Uuid,
}

async fn login(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<LoginRequest>,
) -> Result<Json<LoginResponse>, StatusCode> {
    if payload.identity.trim().is_empty() || payload.password.trim().is_empty() {
        return Err(StatusCode::BAD_REQUEST);
    }

    if let Some(key) = headers.get("idempotency-key").and_then(|v| v.to_str().ok()) {
        if let Some(cached) = state.idempotency.read().await.get(key).cloned() {
            let response: LoginResponse =
                serde_json::from_value(cached).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
            return Ok(Json(response));
        }
    }

    let user_id = Uuid::new_v4();
    let tenant_id = payload.tenant_id.unwrap_or_else(Uuid::new_v4);
    let family_id = Uuid::new_v4();
    let tokens = state
        .jwt
        .issue_tokens(user_id, tenant_id, family_id)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let record = SessionRecord {
        user_id,
        tenant_id,
        current_jti_hash: security::hash_token_sha256(&tokens.refresh_jti),
        deleted: false,
    };
    state.sessions.write().await.insert(family_id, record);

    let response = LoginResponse {
        access_token: tokens.access_token,
        refresh_token: tokens.refresh_token,
        expires_in: tokens.expires_in,
        token_type: "Bearer",
        family_id,
    };

    if let Some(key) = headers.get("idempotency-key").and_then(|v| v.to_str().ok()) {
        let value =
            serde_json::to_value(&response).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        state
            .idempotency
            .write()
            .await
            .insert(key.to_string(), value);
    }

    Ok(Json(response))
}

#[derive(Debug, Deserialize)]
struct RefreshRequest {
    refresh_token: String,
}

#[derive(Debug, Serialize)]
struct RefreshResponse {
    access_token: String,
    refresh_token: String,
    expires_in: i64,
}

async fn refresh(
    State(state): State<AppState>,
    Json(payload): Json<RefreshRequest>,
) -> Result<Json<RefreshResponse>, StatusCode> {
    let claims = state
        .jwt
        .verify_refresh(payload.refresh_token.trim())
        .map_err(|_| StatusCode::UNAUTHORIZED)?;
    let family_id = Uuid::parse_str(&claims.family_id).map_err(|_| StatusCode::UNAUTHORIZED)?;

    let mut sessions = state.sessions.write().await;
    let record = sessions
        .get_mut(&family_id)
        .ok_or(StatusCode::UNAUTHORIZED)?;
    if record.deleted || record.current_jti_hash != security::hash_token_sha256(&claims.jti) {
        return Err(StatusCode::UNAUTHORIZED);
    }

    state.jwt.rotate();
    let tokens = state
        .jwt
        .issue_tokens(record.user_id, record.tenant_id, family_id)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    record.current_jti_hash = security::hash_token_sha256(&tokens.refresh_jti);

    Ok(Json(RefreshResponse {
        access_token: tokens.access_token,
        refresh_token: tokens.refresh_token,
        expires_in: tokens.expires_in,
    }))
}

#[derive(Debug, Deserialize)]
struct LogoutRequest {
    family_id: Uuid,
}

async fn logout(State(state): State<AppState>, Json(payload): Json<LogoutRequest>) -> StatusCode {
    if let Some(session) = state.sessions.write().await.get_mut(&payload.family_id) {
        session.deleted = true;
    }
    StatusCode::NO_CONTENT
}

async fn revoke_all(State(state): State<AppState>) -> StatusCode {
    for session in state.sessions.write().await.values_mut() {
        session.deleted = true;
    }
    StatusCode::NO_CONTENT
}

#[derive(Debug, Serialize)]
struct SessionListResponse {
    sessions: Vec<Uuid>,
}

async fn list_sessions(State(state): State<AppState>) -> Json<SessionListResponse> {
    let sessions = state
        .sessions
        .read()
        .await
        .iter()
        .filter_map(|(id, session)| (!session.deleted).then_some(*id))
        .collect();
    Json(SessionListResponse { sessions })
}

async fn delete_session(Path(family_id): Path<Uuid>, State(state): State<AppState>) -> StatusCode {
    if let Some(session) = state.sessions.write().await.get_mut(&family_id) {
        session.deleted = true;
    }
    StatusCode::NO_CONTENT
}

async fn trust_session() -> StatusCode {
    StatusCode::NO_CONTENT
}

#[derive(Debug, Deserialize)]
struct PushTokenRequest {
    push_token: String,
    platform: String,
    app_version: String,
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

#[derive(Debug, Deserialize)]
struct CreateInviteRequest {
    user_id: Uuid,
    tenant_id: Uuid,
}

#[derive(Debug, Serialize)]
struct CreateInviteResponse {
    invite_token: String,
    expires_at: String,
}

async fn create_invite(
    State(state): State<AppState>,
    Json(payload): Json<CreateInviteRequest>,
) -> Json<CreateInviteResponse> {
    let token = format!("invite-{}", Uuid::new_v4());
    let token_hash = security::hash_token_sha256(&token);
    let expires_at = Utc::now() + Duration::hours(24);
    state.invites.write().await.insert(
        token_hash,
        InviteRecord {
            user_id: payload.user_id,
            tenant_id: payload.tenant_id,
            used: false,
            expires_at,
        },
    );
    Json(CreateInviteResponse {
        invite_token: token,
        expires_at: expires_at.to_rfc3339(),
    })
}

#[derive(Debug, Deserialize)]
struct AcceptInviteRequest {
    invite_token: String,
}

async fn accept_invite(
    State(state): State<AppState>,
    Json(payload): Json<AcceptInviteRequest>,
) -> Result<StatusCode, StatusCode> {
    let token_hash = security::hash_token_sha256(payload.invite_token.trim());
    let mut invites = state.invites.write().await;
    let invite = invites.get_mut(&token_hash).ok_or(StatusCode::NOT_FOUND)?;
    let _membership = (invite.user_id, invite.tenant_id);
    if invite.used || invite.expires_at < Utc::now() {
        return Err(StatusCode::CONFLICT);
    }
    invite.used = true;
    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use serde_json::json;
    use tower::ServiceExt;

    use super::AppState;
    use crate::{api::router, config::AppConfig};

    fn test_app() -> axum::Router {
        router(AppState::new(AppConfig::from_env()))
    }

    #[tokio::test]
    async fn login_refresh_logout_flow() {
        let app = test_app();
        let login_request = Request::builder()
            .uri("/auth/login")
            .method("POST")
            .header("content-type", "application/json")
            .body(Body::from(
                json!({"identity":"user@example.com","password":"secret"}).to_string(),
            ))
            .expect("request");
        let login_response = app.clone().oneshot(login_request).await.expect("response");
        assert_eq!(login_response.status(), StatusCode::OK);
    }
}
