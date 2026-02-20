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
        .header("idempotency-key", "idem-login")
        .body(Body::from(
            json!({"identity":"user@example.com","password":"secret", "tenant_id": tenant_id, "device_name": "iPhone", "device_type": "mobile"})
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
                .header("content-type", "application/json")
                .body(Body::from(json!({"is_trusted": true}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(trust_res.status(), StatusCode::NO_CONTENT);

    let restore_req = Request::builder()
        .uri("/auth/restore")
        .method("POST")
        .header("content-type", "application/json")
        .header("idempotency-key", "idem-restore")
        .body(Body::from(json!({"email":"user@example.com"}).to_string()))
        .unwrap();
    let restore_res = app.clone().oneshot(restore_req).await.unwrap();
    assert_eq!(restore_res.status(), StatusCode::ACCEPTED);

    let create_invite_req = Request::builder()
        .uri(format!("/api/tenants/{tenant_id}/invites"))
        .method("POST")
        .header("content-type", "application/json")
        .header("idempotency-key", "idem-invite")
        .body(Body::from(json!({"email":"user@example.com"}).to_string()))
        .unwrap();
    let create_invite_res = app.clone().oneshot(create_invite_req).await.unwrap();
    assert_eq!(create_invite_res.status(), StatusCode::CREATED);
    let create_invite_body = http_body_util::BodyExt::collect(create_invite_res.into_body())
        .await
        .unwrap()
        .to_bytes();
    let create_invite_payload: Value = serde_json::from_slice(&create_invite_body).unwrap();

    let accept_invite_req = Request::builder()
        .uri("/api/invites/accept")
        .method("POST")
        .header("content-type", "application/json")
        .body(Body::from(
            json!({"token": create_invite_payload["invite_token"]}).to_string(),
        ))
        .unwrap();
    let accept_invite_res = app.clone().oneshot(accept_invite_req).await.unwrap();
    assert_eq!(accept_invite_res.status(), StatusCode::OK);

    let logout_req = Request::builder()
        .uri("/auth/logout")
        .method("POST")
        .header("content-type", "application/json")
        .body(Body::from(
            json!({"refresh_token": login_payload["refresh_token"]}).to_string(),
        ))
        .unwrap();
    let logout_res = app.clone().oneshot(logout_req).await.unwrap();
    assert_eq!(logout_res.status(), StatusCode::NO_CONTENT);
}
