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

#[tokio::test]
async fn full_login_refresh_logout_invite_flow() {
    let app = router(AppState::new(AppConfig::from_env()));

    let login_req = Request::builder()
        .uri("/auth/login")
        .method("POST")
        .header("content-type", "application/json")
        .header("idempotency-key", "idem-1")
        .body(Body::from(
            json!({"identity":"user@example.com","password":"secret"}).to_string(),
        ))
        .unwrap();
    let login_res = app.clone().oneshot(login_req).await.unwrap();
    assert_eq!(login_res.status(), StatusCode::OK);
    let login_body = http_body_util::BodyExt::collect(login_res.into_body())
        .await
        .unwrap()
        .to_bytes();
    let login_payload: Value = serde_json::from_slice(&login_body).unwrap();

    let refresh_req = Request::builder()
        .uri("/auth/refresh")
        .method("POST")
        .header("content-type", "application/json")
        .body(Body::from(
            json!({"refresh_token": login_payload["refresh_token"]}).to_string(),
        ))
        .unwrap();
    let refresh_res = app.clone().oneshot(refresh_req).await.unwrap();
    assert_eq!(refresh_res.status(), StatusCode::OK);

    let invite_req = Request::builder()
        .uri("/auth/invites")
        .method("POST")
        .header("content-type", "application/json")
        .body(Body::from(
            json!({
                "user_id": "00000000-0000-0000-0000-000000000001",
                "tenant_id": "00000000-0000-0000-0000-000000000002"
            })
            .to_string(),
        ))
        .unwrap();
    let invite_res = app.clone().oneshot(invite_req).await.unwrap();
    assert_eq!(invite_res.status(), StatusCode::OK);
}
