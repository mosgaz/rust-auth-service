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
    security_events: Arc<RwLock<Vec<String>>>,
}

#[derive(Clone)]
struct SessionRecord {
    user_id: Uuid,
    tenant_id: Uuid,
    current_jti_hash: String,
    used_jti_hashes: HashSet<String>,
    device_name: String,
    device_type: String,
    device_info: Option<serde_json::Value>,
    is_trusted: bool,
    created_at: chrono::DateTime<Utc>,
    last_active_at: chrono::DateTime<Utc>,
    deleted: bool,
}

#[derive(Clone)]
struct UserRecord {
    user_id: Uuid,
    email: String,
    password_hash: String,
}

#[derive(Clone)]
struct InviteRecord {
    invite_id: Uuid,
    tenant_id: Uuid,
    email: String,
    token_hash: String,
    raw_token: String,
    used: bool,
    expires_at: chrono::DateTime<Utc>,
}

fn hash_password(password: &str) -> Result<String, StatusCode> {
    if password.trim().is_empty() {
        return Err(StatusCode::BAD_REQUEST);
    }
    Ok(format!("sha256${}", security::hash_token_sha256(password)))
}

fn verify_password(password_hash: &str, password: &str) -> bool {
    password_hash == format!("sha256${}", security::hash_token_sha256(password))
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
            security_events: Arc::new(RwLock::new(Vec::new())),
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

fn idempotency_key(headers: &HeaderMap) -> Option<&str> {
    headers.get("idempotency-key").and_then(|v| v.to_str().ok())
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
    let password_hash = security::hash_password(payload.password.trim())
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let user = UserRecord {
        user_id: Uuid::new_v4(),
        email: payload.email.trim().to_owned(),
        password_hash,
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
    device_name: Option<String>,
    device_type: Option<String>,
    device_info: Option<serde_json::Value>,
}

#[derive(Debug, Serialize, Deserialize)]
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

    if let Some(key) = idempotency_key(&headers) {
        if let Some(cached) = state.idempotency.read().await.get(key).cloned() {
            let response: LoginResponse =
                serde_json::from_value(cached).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
            return Ok(Json(response));
        }
    }

    let user = state
        .users
        .read()
        .await
        .get(payload.identity.trim())
        .cloned()
        .ok_or(StatusCode::UNAUTHORIZED)?;
    if !security::verify_password(payload.password.trim(), &user.password_hash) {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let family_id = Uuid::new_v4();
    let tenant_id = payload.tenant_id.unwrap_or_else(Uuid::new_v4);
    let tokens = state
        .jwt
        .issue_tokens(user.user_id, tenant_id, family_id)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let current_hash = security::hash_token_sha256(&tokens.refresh_jti);
    let mut used = HashSet::new();
    used.insert(current_hash.clone());
    state.sessions.write().await.insert(
        family_id,
        SessionRecord {
            user_id: user.user_id,
            tenant_id,
            current_jti_hash: current_hash,
            used_jti_hashes: used,
            device_name: payload.device_name.unwrap_or_else(|| "unknown".into()),
            device_type: payload.device_type.unwrap_or_else(|| "browser".into()),
            device_info: payload.device_info,
            is_trusted: false,
            created_at: Utc::now(),
            last_active_at: Utc::now(),
            deleted: false,
        },
    );

    let response = LoginResponse {
        access_token: tokens.access_token,
        refresh_token: tokens.refresh_token,
        expires_in: tokens.expires_in,
        token_type: "Bearer",
        family_id: tokens.family_id,
    };

    if let Some(key) = idempotency_key(&headers) {
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
    let family_id = Uuid::parse_str(&claims.fam).map_err(|_| StatusCode::UNAUTHORIZED)?;

    let mut sessions = state.sessions.write().await;
    let record = sessions
        .get_mut(&family_id)
        .ok_or(StatusCode::UNAUTHORIZED)?;
    let incoming_hash = security::hash_token_sha256(&claims.jti);

    if record.deleted {
        return Err(StatusCode::UNAUTHORIZED);
    }
    if record.used_jti_hashes.contains(&incoming_hash) && record.current_jti_hash != incoming_hash {
        record.deleted = true;
        state
            .security_events
            .write()
            .await
            .push(format!("refresh_reuse_detected:{family_id}"));
        return Err(StatusCode::UNAUTHORIZED);
    }
    if record.current_jti_hash != incoming_hash {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let tokens = state
        .jwt
        .issue_tokens(record.user_id, record.tenant_id, family_id)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let new_hash = security::hash_token_sha256(&tokens.refresh_jti);
    record.current_jti_hash = new_hash.clone();
    record.used_jti_hashes.insert(new_hash);
    record.last_active_at = Utc::now();

    Ok(Json(RefreshResponse {
        access_token: tokens.access_token,
        refresh_token: tokens.refresh_token,
        expires_in: tokens.expires_in,
    }))
}

#[derive(Debug, Deserialize)]
struct LogoutRequest {
    family_id: Option<Uuid>,
    refresh_token: Option<String>,
}

async fn logout(
    State(state): State<AppState>,
    Json(payload): Json<LogoutRequest>,
) -> Result<StatusCode, StatusCode> {
    let family_id = if let Some(family_id) = payload.family_id {
        family_id
    } else if let Some(refresh_token) = payload.refresh_token {
        let claims = state
            .jwt
            .verify_refresh(refresh_token.trim())
            .map_err(|_| StatusCode::UNAUTHORIZED)?;
        Uuid::parse_str(&claims.fam).map_err(|_| StatusCode::UNAUTHORIZED)?
    } else {
        return Err(StatusCode::BAD_REQUEST);
    };

    if let Some(session) = state.sessions.write().await.get_mut(&family_id) {
        session.deleted = true;
    }
    Ok(StatusCode::NO_CONTENT)
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

async fn restore_password(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<RestoreRequest>,
) -> Result<StatusCode, StatusCode> {
    let key = idempotency_key(&headers).ok_or(StatusCode::BAD_REQUEST)?;
    if state.idempotency.read().await.contains_key(key) {
        return Ok(StatusCode::ACCEPTED);
    }
    if payload.email.trim().is_empty() {
        return Err(StatusCode::BAD_REQUEST);
    }
    let token = format!("reset-{}", Uuid::new_v4());
    state
        .reset_tokens
        .write()
        .await
        .insert(security::hash_token_sha256(&token), payload.email);
    state
        .idempotency
        .write()
        .await
        .insert(key.to_string(), serde_json::json!({"status":"accepted"}));
    Ok(StatusCode::ACCEPTED)
}

#[derive(Debug, Deserialize)]
struct ResetConfirmRequest {
    reset_token: String,
    new_password: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct SuccessResponse {
    success: bool,
}

async fn reset_confirm(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<ResetConfirmRequest>,
) -> Result<Json<SuccessResponse>, StatusCode> {
    let key = idempotency_key(&headers).ok_or(StatusCode::BAD_REQUEST)?;
    if let Some(cached) = state.idempotency.read().await.get(key).cloned() {
        let response: SuccessResponse =
            serde_json::from_value(cached).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        return Ok(Json(response));
    }

    if payload.new_password.trim().is_empty() {
        return Err(StatusCode::BAD_REQUEST);
    }

    let mut resets = state.reset_tokens.write().await;
    let token_hash = security::hash_token_sha256(payload.reset_token.trim());
    let email = resets.remove(&token_hash).ok_or(StatusCode::NOT_FOUND)?;
    let new_hash = security::hash_password(payload.new_password.trim())
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    if let Some(user) = state.users.write().await.get_mut(&email) {
        user.password_hash = new_hash;
    }

    let response = SuccessResponse { success: true };
    state.idempotency.write().await.insert(
        key.to_string(),
        serde_json::to_value(&response).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?,
    );
    Ok(Json(response))
}

#[derive(Debug, Serialize)]
struct SessionView {
    family_id: Uuid,
    device_name: String,
    device_type: String,
    device_info: Option<serde_json::Value>,
    is_trusted: bool,
    created_at: String,
    last_active_at: String,
}

#[derive(Debug, Serialize)]
struct SessionListResponse {
    sessions: Vec<SessionView>,
}

async fn list_sessions(State(state): State<AppState>) -> Json<SessionListResponse> {
    let sessions = state
        .sessions
        .read()
        .await
        .iter()
        .filter_map(|(id, session)| {
            (!session.deleted).then_some(SessionView {
                family_id: *id,
                device_name: session.device_name.clone(),
                device_type: session.device_type.clone(),
                device_info: session.device_info.clone(),
                is_trusted: session.is_trusted,
                created_at: session.created_at.to_rfc3339(),
                last_active_at: session.last_active_at.to_rfc3339(),
            })
        })
        .collect();
    Json(SessionListResponse { sessions })
}

async fn delete_session(Path(family_id): Path<Uuid>, State(state): State<AppState>) -> StatusCode {
    if let Some(session) = state.sessions.write().await.get_mut(&family_id) {
        session.deleted = true;
    }
    StatusCode::NO_CONTENT
}

#[derive(Debug, Deserialize)]
struct TrustSessionRequest {
    is_trusted: bool,
}

async fn trust_session(
    Path(family_id): Path<Uuid>,
    State(state): State<AppState>,
    Json(payload): Json<TrustSessionRequest>,
) -> Result<StatusCode, StatusCode> {
    let mut sessions = state.sessions.write().await;
    let session = sessions.get_mut(&family_id).ok_or(StatusCode::NOT_FOUND)?;
    session.is_trusted = payload.is_trusted;
    Ok(StatusCode::NO_CONTENT)
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
    user_id: Uuid,
    is_new: bool,
    invite_id: Uuid,
    invite_token: String,
}

async fn create_invite(
    Path(tenant_id): Path<Uuid>,
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<CreateInviteRequest>,
) -> Result<(StatusCode, Json<CreateInviteResponse>), StatusCode> {
    let key = idempotency_key(&headers).ok_or(StatusCode::BAD_REQUEST)?;
    if let Some(cached) = state.idempotency.read().await.get(key).cloned() {
        let response: CreateInviteResponse =
            serde_json::from_value(cached).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        return Ok((StatusCode::CREATED, Json(response)));
    }

    if payload.email.trim().is_empty() {
        return Err(StatusCode::BAD_REQUEST);
    }

    let existing_user_id = state
        .users
        .read()
        .await
        .get(payload.email.trim())
        .map(|u| u.user_id);
    let user_id = existing_user_id.unwrap_or_else(Uuid::new_v4);
    let is_new = existing_user_id.is_none();

    let invite_id = Uuid::new_v4();
    let token = format!("invite-{}", Uuid::new_v4());
    let expires_at = Utc::now() + Duration::hours(24);
    let existing_user = state.users.read().await.get(payload.email.trim()).cloned();
    let user_id = existing_user
        .as_ref()
        .map(|user| user.user_id)
        .unwrap_or_else(Uuid::new_v4);
    let is_new = existing_user.is_none();

    let record = InviteRecord {
        invite_id,
        tenant_id,
        email: payload.email.trim().to_string(),
        token_hash: security::hash_token_sha256(&token),
        raw_token: token.clone(),
        used: false,
        expires_at,
    };
    state.invites.write().await.insert(invite_id, record);

    let response = CreateInviteResponse {
        user_id,
        is_new,
        invite_id,
        invite_token: token,
    };
    state.idempotency.write().await.insert(
        key.to_string(),
        serde_json::to_value(&response).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?,
    );

    Ok((StatusCode::CREATED, Json(response)))
}

#[derive(Debug, Serialize)]
struct InviteView {
    invite_id: Uuid,
    email: String,
    expires_at: String,
}

async fn list_invites(
    Path(tenant_id): Path<Uuid>,
    State(state): State<AppState>,
) -> Json<Vec<InviteView>> {
    let invites = state
        .invites
        .read()
        .await
        .values()
        .filter(|invite| invite.tenant_id == tenant_id && !invite.used)
        .map(|invite| InviteView {
            invite_id: invite.invite_id,
            email: invite.email.clone(),
            expires_at: invite.expires_at.to_rfc3339(),
        })
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
    token: String,
}

#[derive(Debug, Serialize)]
struct AcceptInviteResponse {
    tenant_id: Uuid,
    user_id: Uuid,
    status: &'static str,
}

async fn accept_invite(
    State(state): State<AppState>,
    Json(payload): Json<AcceptInviteRequest>,
) -> Result<Json<AcceptInviteResponse>, StatusCode> {
    let token_hash = security::hash_token_sha256(payload.token.trim());
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

    Ok(Json(AcceptInviteResponse {
        tenant_id: invite.tenant_id,
        user_id,
        status: "accepted",
    }))
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
            raw_token: token.clone(),
            used: false,
            expires_at,
        },
    );
    Json(CreateInviteResponse {
        user_id: payload.user_id,
        is_new: false,
        invite_id,
        invite_token: token,
    })
}

async fn accept_invite_legacy(
    State(state): State<AppState>,
    Json(payload): Json<AcceptInviteRequest>,
) -> Result<Json<AcceptInviteResponse>, StatusCode> {
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
