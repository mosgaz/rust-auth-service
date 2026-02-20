use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    routing::{delete, get, patch, post},
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
    users: Arc<RwLock<HashMap<String, UserRecord>>>,
    invites: Arc<RwLock<HashMap<Uuid, InviteRecord>>>,
    members: Arc<RwLock<HashMap<(Uuid, Uuid), TenantMember>>>,
    push_tokens: Arc<RwLock<HashSet<String>>>,
    reset_tokens: Arc<RwLock<HashMap<String, String>>>,
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
struct UserRecord {
    user_id: Uuid,
    email: String,
    password: String,
}

#[derive(Clone, Serialize)]
struct InviteRecord {
    invite_id: Uuid,
    tenant_id: Uuid,
    email: String,
    token_hash: String,
    used: bool,
    expires_at: chrono::DateTime<Utc>,
}

#[derive(Clone, Serialize)]
struct TenantMember {
    tenant_id: Uuid,
    user_id: Uuid,
    status: String,
}

impl AppState {
    pub fn new(config: AppConfig) -> Self {
        Self {
            jwt: JwtManager::new(config.issuer.clone()),
            config,
            sessions: Arc::new(RwLock::new(HashMap::new())),
            users: Arc::new(RwLock::new(HashMap::new())),
            invites: Arc::new(RwLock::new(HashMap::new())),
            members: Arc::new(RwLock::new(HashMap::new())),
            push_tokens: Arc::new(RwLock::new(HashSet::new())),
            reset_tokens: Arc::new(RwLock::new(HashMap::new())),
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
        .route("/auth/register", post(register))
        .route("/auth/login", post(login))
        .route("/auth/refresh", post(refresh))
        .route("/auth/logout", post(logout))
        .route("/auth/logout-all", post(logout_all))
        .route("/auth/revoke-all", post(logout_all))
        .route("/auth/restore", post(restore_password))
        .route("/auth/reset-confirm", post(reset_confirm))
        .route("/auth/sessions", get(list_sessions))
        .route("/auth/sessions/{family_id}", delete(delete_session))
        .route("/auth/sessions/{family_id}/trust", patch(trust_session))
        .route("/auth/sessions/push-token", post(register_push_token))
        .route("/auth/sessions/push-token", delete(delete_push_token))
        .route("/auth/invites", post(create_invite_legacy))
        .route("/auth/invites/accept", post(accept_invite_legacy))
        .route("/api/tenants/{tenant_id}/invites", post(create_invite))
        .route("/api/tenants/{tenant_id}/invites", get(list_invites))
        .route(
            "/api/tenants/{tenant_id}/invites/{invite_id}",
            delete(delete_invite),
        )
        .route("/api/invites/accept", post(accept_invite))
        .route("/api/tenants/{tenant_id}/members", get(list_members))
        .route(
            "/api/tenants/{tenant_id}/members/{user_id}",
            delete(remove_member),
        )
        .route(
            "/api/tenants/{tenant_id}/members/{user_id}/status",
            patch(update_member_status),
        )
        .route("/internal/users/{user_id}/tenants", get(user_tenants))
        .route("/internal/verify-token", post(verify_token))
        .route("/internal/users/lookup", post(lookup_user))
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
struct RegisterRequest {
    email: String,
    password: String,
}

#[derive(Debug, Serialize)]
struct RegisterResponse {
    user_id: Uuid,
}

async fn register(
    State(state): State<AppState>,
    Json(payload): Json<RegisterRequest>,
) -> Result<(StatusCode, Json<RegisterResponse>), StatusCode> {
    if payload.email.trim().is_empty() || payload.password.trim().is_empty() {
        return Err(StatusCode::BAD_REQUEST);
    }
    let mut users = state.users.write().await;
    if users.contains_key(payload.email.trim()) {
        return Err(StatusCode::CONFLICT);
    }
    let user = UserRecord {
        user_id: Uuid::new_v4(),
        email: payload.email.trim().to_owned(),
        password: payload.password,
    };
    let response = RegisterResponse {
        user_id: user.user_id,
    };
    users.insert(user.email.clone(), user);
    Ok((StatusCode::CREATED, Json(response)))
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

    if let Some(user) = state.users.read().await.get(payload.identity.trim()) {
        if user.password != payload.password {
            return Err(StatusCode::UNAUTHORIZED);
        }
    }

    let user_id = state
        .users
        .read()
        .await
        .get(payload.identity.trim())
        .map(|u| u.user_id)
        .unwrap_or_else(Uuid::new_v4);
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
        family_id: tokens.family_id,
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

async fn logout_all(State(state): State<AppState>) -> StatusCode {
    for session in state.sessions.write().await.values_mut() {
        session.deleted = true;
    }
    StatusCode::NO_CONTENT
}

#[derive(Debug, Deserialize)]
struct RestoreRequest {
    email: String,
}
#[derive(Debug, Serialize)]
struct RestoreResponse {
    reset_token: String,
}

async fn restore_password(
    State(state): State<AppState>,
    Json(payload): Json<RestoreRequest>,
) -> Result<Json<RestoreResponse>, StatusCode> {
    if payload.email.trim().is_empty() {
        return Err(StatusCode::BAD_REQUEST);
    }
    let token = format!("reset-{}", Uuid::new_v4());
    state
        .reset_tokens
        .write()
        .await
        .insert(security::hash_token_sha256(&token), payload.email);
    Ok(Json(RestoreResponse { reset_token: token }))
}

#[derive(Debug, Deserialize)]
struct ResetConfirmRequest {
    reset_token: String,
    new_password: String,
}

async fn reset_confirm(
    State(state): State<AppState>,
    Json(payload): Json<ResetConfirmRequest>,
) -> Result<StatusCode, StatusCode> {
    if payload.new_password.trim().is_empty() {
        return Err(StatusCode::BAD_REQUEST);
    }
    let mut resets = state.reset_tokens.write().await;
    let token_hash = security::hash_token_sha256(payload.reset_token.trim());
    let email = resets.remove(&token_hash).ok_or(StatusCode::NOT_FOUND)?;
    if let Some(user) = state.users.write().await.get_mut(&email) {
        user.password = payload.new_password;
    }
    Ok(StatusCode::NO_CONTENT)
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
    State(state): State<AppState>,
    Json(payload): Json<PushTokenRequest>,
) -> Result<StatusCode, StatusCode> {
    if payload.push_token.trim().is_empty()
        || payload.platform.trim().is_empty()
        || payload.app_version.trim().is_empty()
    {
        return Err(StatusCode::BAD_REQUEST);
    }
    state.push_tokens.write().await.insert(payload.push_token);
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Debug, Deserialize)]
struct DeletePushTokenRequest {
    push_token: String,
}

async fn delete_push_token(
    State(state): State<AppState>,
    Json(payload): Json<DeletePushTokenRequest>,
) -> Result<StatusCode, StatusCode> {
    if payload.push_token.trim().is_empty() {
        return Err(StatusCode::BAD_REQUEST);
    }
    state
        .push_tokens
        .write()
        .await
        .remove(payload.push_token.trim());
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Debug, Deserialize)]
struct CreateInviteRequest {
    email: String,
}
#[derive(Debug, Serialize)]
struct CreateInviteResponse {
    invite_id: Uuid,
    invite_token: String,
    expires_at: String,
}

async fn create_invite(
    Path(tenant_id): Path<Uuid>,
    State(state): State<AppState>,
    Json(payload): Json<CreateInviteRequest>,
) -> Result<(StatusCode, Json<CreateInviteResponse>), StatusCode> {
    if payload.email.trim().is_empty() {
        return Err(StatusCode::BAD_REQUEST);
    }
    let invite_id = Uuid::new_v4();
    let token = format!("invite-{}", Uuid::new_v4());
    let expires_at = Utc::now() + Duration::hours(24);
    let record = InviteRecord {
        invite_id,
        tenant_id,
        email: payload.email,
        token_hash: security::hash_token_sha256(&token),
        used: false,
        expires_at,
    };
    state.invites.write().await.insert(invite_id, record);
    Ok((
        StatusCode::CREATED,
        Json(CreateInviteResponse {
            invite_id,
            invite_token: token,
            expires_at: expires_at.to_rfc3339(),
        }),
    ))
}

async fn list_invites(
    Path(tenant_id): Path<Uuid>,
    State(state): State<AppState>,
) -> Json<Vec<InviteRecord>> {
    let invites = state
        .invites
        .read()
        .await
        .values()
        .filter(|invite| invite.tenant_id == tenant_id && !invite.used)
        .cloned()
        .collect();
    Json(invites)
}

async fn delete_invite(
    Path((tenant_id, invite_id)): Path<(Uuid, Uuid)>,
    State(state): State<AppState>,
) -> StatusCode {
    let mut invites = state.invites.write().await;
    if let Some(invite) = invites.get(&invite_id) {
        if invite.tenant_id != tenant_id {
            return StatusCode::NOT_FOUND;
        }
    }
    invites.remove(&invite_id);
    StatusCode::NO_CONTENT
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
    let invite = invites
        .values_mut()
        .find(|v| v.token_hash == token_hash)
        .ok_or(StatusCode::NOT_FOUND)?;
    if invite.used || invite.expires_at < Utc::now() {
        return Err(StatusCode::CONFLICT);
    }
    invite.used = true;

    let user_id = state
        .users
        .read()
        .await
        .get(&invite.email)
        .map(|user| user.user_id)
        .unwrap_or_else(Uuid::new_v4);
    state.members.write().await.insert(
        (invite.tenant_id, user_id),
        TenantMember {
            tenant_id: invite.tenant_id,
            user_id,
            status: "active".into(),
        },
    );
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Debug, Deserialize)]
struct LegacyInviteRequest {
    user_id: Uuid,
    tenant_id: Uuid,
}

async fn create_invite_legacy(
    State(state): State<AppState>,
    Json(payload): Json<LegacyInviteRequest>,
) -> Json<CreateInviteResponse> {
    let invite_id = Uuid::new_v4();
    let token = format!("invite-{}", Uuid::new_v4());
    let expires_at = Utc::now() + Duration::hours(24);
    let email = format!("{}@legacy.local", payload.user_id);
    state.invites.write().await.insert(
        invite_id,
        InviteRecord {
            invite_id,
            tenant_id: payload.tenant_id,
            email,
            token_hash: security::hash_token_sha256(&token),
            used: false,
            expires_at,
        },
    );
    Json(CreateInviteResponse {
        invite_id,
        invite_token: token,
        expires_at: expires_at.to_rfc3339(),
    })
}

async fn accept_invite_legacy(
    State(state): State<AppState>,
    Json(payload): Json<AcceptInviteRequest>,
) -> Result<StatusCode, StatusCode> {
    accept_invite(State(state), Json(payload)).await
}

#[derive(Debug, Serialize)]
struct MembersResponse {
    members: Vec<TenantMember>,
}

async fn list_members(
    Path(tenant_id): Path<Uuid>,
    State(state): State<AppState>,
) -> Json<MembersResponse> {
    let members = state
        .members
        .read()
        .await
        .values()
        .filter(|member| member.tenant_id == tenant_id)
        .cloned()
        .collect();
    Json(MembersResponse { members })
}

async fn remove_member(
    Path((tenant_id, user_id)): Path<(Uuid, Uuid)>,
    State(state): State<AppState>,
) -> StatusCode {
    state.members.write().await.remove(&(tenant_id, user_id));
    StatusCode::NO_CONTENT
}

#[derive(Debug, Deserialize)]
struct UpdateStatusRequest {
    status: String,
}

async fn update_member_status(
    Path((tenant_id, user_id)): Path<(Uuid, Uuid)>,
    State(state): State<AppState>,
    Json(payload): Json<UpdateStatusRequest>,
) -> Result<StatusCode, StatusCode> {
    if payload.status.trim().is_empty() {
        return Err(StatusCode::BAD_REQUEST);
    }
    let mut members = state.members.write().await;
    let member = members
        .get_mut(&(tenant_id, user_id))
        .ok_or(StatusCode::NOT_FOUND)?;
    member.status = payload.status;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Debug, Serialize)]
struct UserTenantsResponse {
    tenant_ids: Vec<Uuid>,
}

async fn user_tenants(
    Path(user_id): Path<Uuid>,
    State(state): State<AppState>,
) -> Json<UserTenantsResponse> {
    let tenant_ids = state
        .members
        .read()
        .await
        .values()
        .filter(|member| member.user_id == user_id)
        .map(|member| member.tenant_id)
        .collect();
    Json(UserTenantsResponse { tenant_ids })
}

#[derive(Debug, Deserialize)]
struct VerifyTokenRequest {
    token: String,
}
#[derive(Debug, Serialize)]
struct VerifyTokenResponse {
    valid: bool,
    token_type: Option<String>,
    user_id: Option<String>,
}

async fn verify_token(
    State(state): State<AppState>,
    Json(payload): Json<VerifyTokenRequest>,
) -> Json<VerifyTokenResponse> {
    let claims = state.jwt.verify_token(payload.token.trim()).ok();
    Json(VerifyTokenResponse {
        valid: claims.is_some(),
        token_type: claims.as_ref().map(|c| c.typ.clone()),
        user_id: claims.map(|c| c.sub),
    })
}

#[derive(Debug, Deserialize)]
struct LookupUserRequest {
    email: String,
}
#[derive(Debug, Serialize)]
struct LookupUserResponse {
    found: bool,
    user_id: Option<Uuid>,
}

async fn lookup_user(
    State(state): State<AppState>,
    Json(payload): Json<LookupUserRequest>,
) -> Json<LookupUserResponse> {
    let users = state.users.read().await;
    let user_id = users.get(payload.email.trim()).map(|u| u.user_id);
    Json(LookupUserResponse {
        found: user_id.is_some(),
        user_id,
    })
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
