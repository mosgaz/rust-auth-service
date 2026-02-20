#[derive(Debug, Clone)]
pub struct AppConfig {
    pub host: String,
    pub port: u16,
    pub issuer: String,
    pub service_name: String,
}

impl AppConfig {
    pub fn from_env() -> Self {
        Self {
            host: std::env::var("AUTH_HOST").unwrap_or_else(|_| "0.0.0.0".to_string()),
            port: std::env::var("AUTH_PORT")
                .ok()
                .and_then(|value| value.parse().ok())
                .unwrap_or(8080),
            issuer: std::env::var("AUTH_ISSUER")
                .unwrap_or_else(|_| "https://auth.example.com".to_string()),
            service_name: "auth".to_string(),
        }
    }
}
