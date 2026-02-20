use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde::Serialize;
use sha2::{Digest, Sha256};

pub fn hash_token_sha256(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    let digest = hasher.finalize();
    URL_SAFE_NO_PAD.encode(digest)
}

#[derive(Debug, Clone, Serialize)]
pub struct Jwk {
    pub kid: String,
    pub kty: String,
    pub alg: String,
    #[serde(rename = "use")]
    pub use_field: String,
    pub n: String,
    pub e: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct JwksResponse {
    pub keys: Vec<Jwk>,
}

pub fn demo_jwks() -> JwksResponse {
    JwksResponse {
        keys: vec![Jwk {
            kid: "key-id-2024-01".to_string(),
            kty: "RSA".to_string(),
            alg: "RS256".to_string(),
            use_field: "sig".to_string(),
            n: "demo-modulus-base64url".to_string(),
            e: "AQAB".to_string(),
        }],
    }
}

#[cfg(test)]
mod tests {
    use super::hash_token_sha256;

    #[test]
    fn hashes_token_deterministically() {
        let a = hash_token_sha256("refresh-token");
        let b = hash_token_sha256("refresh-token");
        assert_eq!(a, b);
    }
}
