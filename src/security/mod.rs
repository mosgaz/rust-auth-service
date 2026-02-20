use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::{Duration, Utc};
use jsonwebtoken::{
    decode, decode_header, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation,
};
use rsa::{pkcs1::DecodeRsaPublicKey, BigUint, RsaPublicKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

pub fn hash_token_sha256(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    URL_SAFE_NO_PAD.encode(hasher.finalize())
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

#[derive(Debug, Clone)]
pub struct JwtTokens {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_in: i64,
    pub family_id: Uuid,
    pub refresh_jti: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub tenant_id: String,
    pub family_id: String,
    pub jti: String,
    pub typ: String,
    pub iss: String,
    pub exp: i64,
    pub iat: i64,
}

#[derive(Clone)]
struct SigningMaterial {
    kid: String,
    enc: EncodingKey,
    dec: DecodingKey,
    jwk: Jwk,
}

#[derive(Clone)]
pub struct JwtManager {
    state: Arc<RwLock<JwtState>>,
    issuer: String,
}

#[derive(Clone)]
struct JwtState {
    active: usize,
    keys: Vec<SigningMaterial>,
    by_kid: HashMap<String, usize>,
}

impl JwtManager {
    pub fn new(issuer: String) -> Self {
        let keys = vec![build_material(
            "key-2026-01",
            DEFAULT_PUBLIC_KEY_PEM,
            DEFAULT_PRIVATE_KEY_PEM,
        )];
        let by_kid = keys
            .iter()
            .enumerate()
            .map(|(i, k)| (k.kid.clone(), i))
            .collect();
        Self {
            state: Arc::new(RwLock::new(JwtState {
                active: 0,
                keys,
                by_kid,
            })),
            issuer,
        }
    }

    pub fn rotate(&self) {
        let mut state = self.state.write().expect("jwt write lock");
        state.active = (state.active + 1) % state.keys.len();
    }

    pub fn jwks(&self) -> JwksResponse {
        let state = self.state.read().expect("jwt read lock");
        JwksResponse {
            keys: state.keys.iter().map(|k| k.jwk.clone()).collect(),
        }
    }

    pub fn issue_tokens(
        &self,
        user_id: Uuid,
        tenant_id: Uuid,
        family_id: Uuid,
    ) -> anyhow::Result<JwtTokens> {
        let now = Utc::now();
        let access_exp = now + Duration::minutes(15);
        let refresh_exp = now + Duration::days(30);
        let access_jti = Uuid::new_v4().to_string();
        let refresh_jti = Uuid::new_v4().to_string();

        let state = self.state.read().expect("jwt read lock");
        let key = &state.keys[state.active];

        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(key.kid.clone());
        let access_claims = Claims {
            sub: user_id.to_string(),
            tenant_id: tenant_id.to_string(),
            family_id: family_id.to_string(),
            jti: access_jti,
            typ: "access".into(),
            iss: self.issuer.clone(),
            exp: access_exp.timestamp(),
            iat: now.timestamp(),
        };
        let refresh_claims = Claims {
            sub: user_id.to_string(),
            tenant_id: tenant_id.to_string(),
            family_id: family_id.to_string(),
            jti: refresh_jti.clone(),
            typ: "refresh".into(),
            iss: self.issuer.clone(),
            exp: refresh_exp.timestamp(),
            iat: now.timestamp(),
        };

        Ok(JwtTokens {
            access_token: encode(&header, &access_claims, &key.enc)?,
            refresh_token: encode(&header, &refresh_claims, &key.enc)?,
            expires_in: 900,
            family_id,
            refresh_jti,
        })
    }

    pub fn verify_refresh(&self, token: &str) -> anyhow::Result<Claims> {
        let data = self.decode_claims(token)?;
        if data.typ != "refresh" {
            anyhow::bail!("not a refresh token");
        }
        Ok(data)
    }

    pub fn verify_token(&self, token: &str) -> anyhow::Result<Claims> {
        self.decode_claims(token)
    }

    fn decode_claims(&self, token: &str) -> anyhow::Result<Claims> {
        let header = decode_header(token)?;
        let kid = header.kid.ok_or_else(|| anyhow::anyhow!("missing kid"))?;
        let state = self.state.read().expect("jwt read lock");
        let idx = *state
            .by_kid
            .get(&kid)
            .ok_or_else(|| anyhow::anyhow!("unknown kid"))?;
        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_issuer(&[self.issuer.clone()]);
        let data = decode::<Claims>(token, &state.keys[idx].dec, &validation)?;
        Ok(data.claims)
    }
}

fn build_material(kid: &str, public_key_pem: &str, private_key_pem: &str) -> SigningMaterial {
    let enc = EncodingKey::from_rsa_pem(private_key_pem.as_bytes()).expect("valid private key");
    let dec = DecodingKey::from_rsa_pem(public_key_pem.as_bytes()).expect("valid public key");
    let rsa = RsaPublicKey::from_pkcs1_pem(public_key_pem).expect("public key parse");
    let n = URL_SAFE_NO_PAD.encode(BigUint::to_bytes_be(rsa.n()));
    let e = URL_SAFE_NO_PAD.encode(BigUint::to_bytes_be(rsa.e()));

    SigningMaterial {
        kid: kid.to_string(),
        enc,
        dec,
        jwk: Jwk {
            kid: kid.to_string(),
            kty: "RSA".to_string(),
            alg: "RS256".to_string(),
            use_field: "sig".to_string(),
            n,
            e,
        },
    }
}

const DEFAULT_PRIVATE_KEY_PEM: &str = r#"-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAytP4i8w3VxPmhMVB0+0PWsRgM1JsYf4IIQrMSIJ9oQ3J4HJE
8xQHr4PJ/Qm3pQXQNOzCf6xDw4Yzo/jjI6WrWZW4JLqna3laL5cV15AsIYM7KGZ5
jOB6Mr3Glu+XfmgYENXxYJ8lFB6qwrj9zNTQUNS3qpyzWTCUBn8DOlrqcpW+0QmV
No4EgvFP9/Fw7Gyn2O3aF9t6yzx5mA3m4w8WV3yrdc6fWbi67B9uq9QYIazwQKia
EHP3+VUW1TsB9N5x5dToG6g7dohg9Ntrc1UaTA4GbKDkr7qbDIH4s1+p4MWHv9fw
6Ls9iOcgD3tVt2l9/rnfJO72fA+uJIorB0DDFQIDAQABAoIBAQCb0Pi+Zz0Dp9xT
1KlhCC2g8r8af6XdBw/WY5J7N2EJ2xAS5mP+pVDmH2U8+adP4XrP6G3fYlT83PIh
ZflXgiynv49f53nRulnRKD0fW2V5ZfHf35Nc6YHDozqDQE2QOQnNMi4M0xr0sEtq
kVrrqWcnbZQYQ8XkWGNnFS4s7rKGk8QwsGGqGXNPtC2lNTx8eClbnf6VqmyjStv2
NKrqA2YxmDKbnBvACzk9H2mupIh7JPm8PUm4d9+3J3g4+2k7QwE4wySkMCmJluTl
29Q6xCcwsw5Q8kL8NT6vDmsvRmxWCCxG3Lh4D8JgeIwd9P8mCUlxQcbwTqF0Fv6h
FttfQmOBAoGBAPeafk1l6dpQ0YxQhX47vT8E6PvaAAdt5z4EcN+doBfP4w7pCg3Q
q9R4bpLzA49l0fx3nqvM9InTxoV4Q8nDL+fipRU+uM6fLqfI9rb8u8gJYFM2jK5Y
6fM7m8mNh6D5Wtw9Ya53SGel4GW75pNGR6dA7r43+qCxTv8NI4KVUOVvAoGBANjE
z4D8r9MwaDuc3G6K5f5B7af7O7mQ4la3p2b4OlTWcbdnmx+PTK2fNf1B6DKk2jRl
KGOQ3B1w2IWmw0mHxv+iFKvPj5Fv5WwGCnQmrGrMi1aX76d8j4RHoCkBjGmri1Yg
D0fdM/VDMOIkWMxWQ+VQmR40UBvAblA4fVvPRV4RAoGAJqWhhr5cL3OWnWh3b8UQ
58EsSkr8odCOjWmQe7f9zcn1ycw7W8P4rNEI+bdU4WcC8w4HDo5NQUR1oDh6xV6L
cwA+8hJ3s0hIOIDeI2kAJFtUrDl/LQJ3mta9dG9I5gib35dVvTY98JGO4z+rwdGG
TcV6U1PkviVwxt7tR0fDE4sCgYEArf5bIG4Pn5+NRfTrCj8GGW88JngKByn8n9yL
G6h8Gf9krAylVGyRr4fYj4h11vk9QvRnzgXu/P5NnUfzb9Kf2fXbI4c0YvoaV2zB
A9St2hNeJkhv8R5G37B5V8CA8v2I7xpq5fao3xM9L2rT0YhB2rVA7sQK4DjrfVOR
S8+X0MECgYBz9HRLmI8h6x5D+Kj4yB0Bqf+WmCc1vby7k7jFEk6ofYVhPA5A8WH5
/K2M63s3sQoYf5k8G4ymbep31TPqs4fWI9Mv0jgQdaZ4afzlcMmXhF7rlFMVOmQ2
48kuX2+krA6quxUO1XxYgLC/4hTrxJb8CY9xUtJQvV7lwrYhRjM75g==
-----END RSA PRIVATE KEY-----"#;

const DEFAULT_PUBLIC_KEY_PEM: &str = r#"-----BEGIN RSA PUBLIC KEY-----
MIIBCgKCAQEAytP4i8w3VxPmhMVB0+0PWsRgM1JsYf4IIQrMSIJ9oQ3J4HJE8xQH
r4PJ/Qm3pQXQNOzCf6xDw4Yzo/jjI6WrWZW4JLqna3laL5cV15AsIYM7KGZ5jOB6
Mr3Glu+XfmgYENXxYJ8lFB6qwrj9zNTQUNS3qpyzWTCUBn8DOlrqcpW+0QmVNo4E
gvFP9/Fw7Gyn2O3aF9t6yzx5mA3m4w8WV3yrdc6fWbi67B9uq9QYIazwQKiaEHP3
+VUW1TsB9N5x5dToG6g7dohg9Ntrc1UaTA4GbKDkr7qbDIH4s1+p4MWHv9fw6Ls9
iOcgD3tVt2l9/rnfJO72fA+uJIorB0DDFQIDAQAB
-----END RSA PUBLIC KEY-----"#;

#[cfg(test)]
mod tests {
    use super::{hash_token_sha256, JwtManager};
    use uuid::Uuid;

    #[test]
    fn hashes_token_deterministically() {
        assert_eq!(
            hash_token_sha256("refresh-token"),
            hash_token_sha256("refresh-token")
        );
    }

    #[test]
    fn issues_and_verifies_refresh_token() {
        let jwt = JwtManager::new("issuer".into());
        let tokens = jwt
            .issue_tokens(Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4())
            .expect("issue");
        let claims = jwt.verify_refresh(&tokens.refresh_token).expect("verify");
        assert_eq!(claims.typ, "refresh");
    }
}
