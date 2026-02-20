use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use rust_auth_service::{
    api::{router, AppState},
    config::AppConfig,
};
use serde_json::{json, Value};
use tower::ServiceExt;
use uuid::Uuid;

#[tokio::test]
async fn full_new_endpoints_flow() {
    let app = router(AppState::new(AppConfig::from_env()));

    let register_req = Request::builder()
        .uri("/auth/register")
        .method("POST")
        .header("content-type", "application/json")
        .body(Body::from(
            json!({"email":"user@example.com","password":"secret"}).to_string(),
        ))
        .unwrap();
    let register_res = app.clone().oneshot(register_req).await.unwrap();
    assert_eq!(register_res.status(), StatusCode::CREATED);

    let tenant_id = Uuid::new_v4();
    let login_req = Request::builder()
        .uri("/auth/login")
        .method("POST")
        .header("content-type", "application/json")
        .header("idempotency-key", "idem-1")
        .body(Body::from(
            json!({"identity":"user@example.com","password":"secret", "tenant_id": tenant_id})
                .to_string(),
        ))
        .unwrap();
    let login_res = app.clone().oneshot(login_req).await.unwrap();
    assert_eq!(login_res.status(), StatusCode::OK);
    let login_body = http_body_util::BodyExt::collect(login_res.into_body())
        .await
        .unwrap()
        .to_bytes();
    let login_payload: Value = serde_json::from_slice(&login_body).unwrap();

    let verify_req = Request::builder()
        .uri("/internal/verify-token")
        .method("POST")
        .header("content-type", "application/json")
        .body(Body::from(
            json!({"token": login_payload["access_token"]}).to_string(),
        ))
        .unwrap();
    let verify_res = app.clone().oneshot(verify_req).await.unwrap();
    assert_eq!(verify_res.status(), StatusCode::OK);

    let restore_req = Request::builder()
        .uri("/auth/restore")
        .method("POST")
        .header("content-type", "application/json")
        .body(Body::from(json!({"email":"user@example.com"}).to_string()))
        .unwrap();
    let restore_res = app.clone().oneshot(restore_req).await.unwrap();
    assert_eq!(restore_res.status(), StatusCode::OK);
    let restore_body = http_body_util::BodyExt::collect(restore_res.into_body())
        .await
        .unwrap()
        .to_bytes();
    let restore_payload: Value = serde_json::from_slice(&restore_body).unwrap();

    let reset_req = Request::builder()
        .uri("/auth/reset-confirm")
        .method("POST")
        .header("content-type", "application/json")
        .body(Body::from(
            json!({"reset_token": restore_payload["reset_token"], "new_password":"new-secret"})
                .to_string(),
        ))
        .unwrap();
    let reset_res = app.clone().oneshot(reset_req).await.unwrap();
    assert_eq!(reset_res.status(), StatusCode::NO_CONTENT);

    let push_req = Request::builder()
        .uri("/auth/sessions/push-token")
        .method("POST")
        .header("content-type", "application/json")
        .body(Body::from(
            json!({"push_token":"token-1","platform":"ios","app_version":"1.0.0"}).to_string(),
        ))
        .unwrap();
    let push_res = app.clone().oneshot(push_req).await.unwrap();
    assert_eq!(push_res.status(), StatusCode::NO_CONTENT);

    let delete_push_req = Request::builder()
        .uri("/auth/sessions/push-token")
        .method("DELETE")
        .header("content-type", "application/json")
        .body(Body::from(json!({"push_token":"token-1"}).to_string()))
        .unwrap();
    let delete_push_res = app.clone().oneshot(delete_push_req).await.unwrap();
    assert_eq!(delete_push_res.status(), StatusCode::NO_CONTENT);

    let create_invite_req = Request::builder()
        .uri(format!("/api/tenants/{tenant_id}/invites"))
        .method("POST")
        .header("content-type", "application/json")
        .body(Body::from(json!({"email":"user@example.com"}).to_string()))
        .unwrap();
    let create_invite_res = app.clone().oneshot(create_invite_req).await.unwrap();
    assert_eq!(create_invite_res.status(), StatusCode::CREATED);
    let create_invite_body = http_body_util::BodyExt::collect(create_invite_res.into_body())
        .await
        .unwrap()
        .to_bytes();
    let create_invite_payload: Value = serde_json::from_slice(&create_invite_body).unwrap();
    let invite_id = create_invite_payload["invite_id"].as_str().unwrap();

    let list_invites_req = Request::builder()
        .uri(format!("/api/tenants/{tenant_id}/invites"))
        .method("GET")
        .body(Body::empty())
        .unwrap();
    let list_invites_res = app.clone().oneshot(list_invites_req).await.unwrap();
    assert_eq!(list_invites_res.status(), StatusCode::OK);

    let accept_invite_req = Request::builder()
        .uri("/api/invites/accept")
        .method("POST")
        .header("content-type", "application/json")
        .body(Body::from(
            json!({"invite_token": create_invite_payload["invite_token"]}).to_string(),
        ))
        .unwrap();
    let accept_invite_res = app.clone().oneshot(accept_invite_req).await.unwrap();
    assert_eq!(accept_invite_res.status(), StatusCode::NO_CONTENT);

    let members_req = Request::builder()
        .uri(format!("/api/tenants/{tenant_id}/members"))
        .method("GET")
        .body(Body::empty())
        .unwrap();
    let members_res = app.clone().oneshot(members_req).await.unwrap();
    assert_eq!(members_res.status(), StatusCode::OK);
    let members_body = http_body_util::BodyExt::collect(members_res.into_body())
        .await
        .unwrap()
        .to_bytes();
    let members_payload: Value = serde_json::from_slice(&members_body).unwrap();
    let member_user_id = members_payload["members"][0]["user_id"].as_str().unwrap();

    let patch_status_req = Request::builder()
        .uri(format!(
            "/api/tenants/{tenant_id}/members/{member_user_id}/status"
        ))
        .method("PATCH")
        .header("content-type", "application/json")
        .body(Body::from(json!({"status":"suspended"}).to_string()))
        .unwrap();
    let patch_status_res = app.clone().oneshot(patch_status_req).await.unwrap();
    assert_eq!(patch_status_res.status(), StatusCode::NO_CONTENT);

    let tenants_req = Request::builder()
        .uri(format!("/internal/users/{member_user_id}/tenants"))
        .method("GET")
        .body(Body::empty())
        .unwrap();
    let tenants_res = app.clone().oneshot(tenants_req).await.unwrap();
    assert_eq!(tenants_res.status(), StatusCode::OK);

    let lookup_req = Request::builder()
        .uri("/internal/users/lookup")
        .method("POST")
        .header("content-type", "application/json")
        .body(Body::from(json!({"email":"user@example.com"}).to_string()))
        .unwrap();
    let lookup_res = app.clone().oneshot(lookup_req).await.unwrap();
    assert_eq!(lookup_res.status(), StatusCode::OK);

    let remove_member_req = Request::builder()
        .uri(format!("/api/tenants/{tenant_id}/members/{member_user_id}"))
        .method("DELETE")
        .body(Body::empty())
        .unwrap();
    let remove_member_res = app.clone().oneshot(remove_member_req).await.unwrap();
    assert_eq!(remove_member_res.status(), StatusCode::NO_CONTENT);

    let delete_invite_req = Request::builder()
        .uri(format!("/api/tenants/{tenant_id}/invites/{invite_id}"))
        .method("DELETE")
        .body(Body::empty())
        .unwrap();
    let delete_invite_res = app.clone().oneshot(delete_invite_req).await.unwrap();
    assert_eq!(delete_invite_res.status(), StatusCode::NO_CONTENT);

    let logout_all_req = Request::builder()
        .uri("/auth/logout-all")
        .method("POST")
        .body(Body::empty())
        .unwrap();
    let logout_all_res = app.clone().oneshot(logout_all_req).await.unwrap();
    assert_eq!(logout_all_res.status(), StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn covers_remaining_routes() {
    let app = router(AppState::new(AppConfig::from_env()));

    let live_res = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/health/live")
                .method("GET")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(live_res.status(), StatusCode::OK);

    let ready_res = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/health/ready")
                .method("GET")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(ready_res.status(), StatusCode::OK);

    let jwks_res = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/.well-known/jwks.json")
                .method("GET")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(jwks_res.status(), StatusCode::OK);

    let register_res = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/auth/register")
                .method("POST")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({"email":"coverage@example.com","password":"secret"}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(register_res.status(), StatusCode::CREATED);

    let tenant_id = Uuid::new_v4();
    let login_res = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/auth/login")
                .method("POST")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({"identity":"coverage@example.com","password":"secret", "tenant_id": tenant_id})
                        .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(login_res.status(), StatusCode::OK);
    let login_body = http_body_util::BodyExt::collect(login_res.into_body())
        .await
        .unwrap()
        .to_bytes();
    let login_payload: Value = serde_json::from_slice(&login_body).unwrap();

    let refresh_res = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/auth/refresh")
                .method("POST")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({"refresh_token": login_payload["refresh_token"]}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(refresh_res.status(), StatusCode::OK);

    let sessions_res = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/auth/sessions")
                .method("GET")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(sessions_res.status(), StatusCode::OK);

    let family_id = login_payload["family_id"].as_str().unwrap();
    let trust_res = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/auth/sessions/{family_id}/trust"))
                .method("PATCH")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(trust_res.status(), StatusCode::NO_CONTENT);

    let delete_session_res = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/auth/sessions/{family_id}"))
                .method("DELETE")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(delete_session_res.status(), StatusCode::NO_CONTENT);

    let logout_res = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/auth/logout")
                .method("POST")
                .header("content-type", "application/json")
                .body(Body::from(json!({"family_id": family_id}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(logout_res.status(), StatusCode::NO_CONTENT);

    let revoke_all_res = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/auth/revoke-all")
                .method("POST")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(revoke_all_res.status(), StatusCode::NO_CONTENT);

    let create_legacy_invite_res = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/auth/invites")
                .method("POST")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({"user_id": Uuid::new_v4(), "tenant_id": tenant_id}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(create_legacy_invite_res.status(), StatusCode::OK);
    let create_legacy_invite_body =
        http_body_util::BodyExt::collect(create_legacy_invite_res.into_body())
            .await
            .unwrap()
            .to_bytes();
    let create_legacy_invite_payload: Value =
        serde_json::from_slice(&create_legacy_invite_body).unwrap();

    let accept_legacy_invite_res = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/auth/invites/accept")
                .method("POST")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({"invite_token": create_legacy_invite_payload["invite_token"]})
                        .to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(accept_legacy_invite_res.status(), StatusCode::NO_CONTENT);
}
