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
        .body(Body::from(
            json!({
                "identity":"user@example.com",
                "password":"secret",
                "tenant_id": tenant_id,
                "device_name": "iPhone",
                "device_type": "mobile",
                "device_info": {"os":"iOS"}
            })
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

    let trust_res = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/auth/sessions/{}/trust",
                    login_payload["family_id"].as_str().unwrap()
                ))
                .method("PATCH")
                .header("content-type", "application/json")
                .body(Body::from(json!({"is_trusted": true}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(trust_res.status(), StatusCode::NO_CONTENT);

    let logout_res = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/auth/logout")
                .method("POST")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({"refresh_token": login_payload["refresh_token"]}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(logout_res.status(), StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn idempotency_is_required_for_restore_reset_and_invites() {
    let app = router(AppState::new(AppConfig::from_env()));
    let tenant_id = Uuid::new_v4();

    let restore_without_key = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/auth/restore")
                .method("POST")
                .header("content-type", "application/json")
                .body(Body::from(json!({"email":"user@example.com"}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(restore_without_key.status(), StatusCode::BAD_REQUEST);

    let restore_with_key = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/auth/restore")
                .method("POST")
                .header("content-type", "application/json")
                .header("idempotency-key", "restore-1")
                .body(Body::from(json!({"email":"user@example.com"}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(restore_with_key.status(), StatusCode::ACCEPTED);

    let reset_without_key = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/auth/reset-confirm")
                .method("POST")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({"reset_token":"invalid","new_password":"new-secret"}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(reset_without_key.status(), StatusCode::BAD_REQUEST);

    let invite_without_key = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/api/tenants/{tenant_id}/invites"))
                .method("POST")
                .header("content-type", "application/json")
                .body(Body::from(json!({"email":"user@example.com"}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(invite_without_key.status(), StatusCode::BAD_REQUEST);
}
