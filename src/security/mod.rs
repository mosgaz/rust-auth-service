use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::{Duration, Utc};
use jsonwebtoken::{
    decode, decode_header, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation,
};
use rsa::{pkcs1::DecodeRsaPublicKey, traits::PublicKeyParts, BigUint, RsaPublicKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

pub fn hash_token_sha256(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    URL_SAFE_NO_PAD.encode(hasher.finalize())
}

pub fn hash_password(password: &str) -> anyhow::Result<String> {
    let salt = Uuid::new_v4().to_string();
    let hash = hash_token_sha256(&format!("{}:{}", salt, password));
    Ok(format!("sha256${salt}${hash}"))
}

pub fn verify_password(password: &str, password_hash: &str) -> bool {
    let Some(rest) = password_hash.strip_prefix("sha256$") else {
        return false;
    };
    let mut parts = rest.split('$');
    let Some(salt) = parts.next() else {
        return false;
    };
    let Some(expected_hash) = parts.next() else {
        return false;
    };
    if parts.next().is_some() {
        return false;
    }
    hash_token_sha256(&format!("{}:{}", salt, password)) == expected_hash
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
    #[serde(alias = "tenant_id")]
    pub tid: String,
    #[serde(alias = "family_id")]
    pub fam: String,
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
            tid: tenant_id.to_string(),
            fam: family_id.to_string(),
            jti: access_jti,
            typ: "access".into(),
            iss: self.issuer.clone(),
            exp: access_exp.timestamp(),
            iat: now.timestamp(),
        };
        let refresh_claims = Claims {
            sub: user_id.to_string(),
            tid: tenant_id.to_string(),
            fam: family_id.to_string(),
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
MIIEpAIBAAKCAQEAtVBEUZ1gwbxc8dHJ6qUMKTSTopP/Jj3dp7Fu0rHqP6avIbZ+
q7LEerGWLl3as4ghzb215sUCGkw6ud22KM4FW2aL0r5b33hnDmu2+Gzm1VWjDr45
sU/fZOY1XpvhbrdHyldOaB8PXgyh81N2dgzE70mCtQOHpbYOTRcGe1VOJeNyi4uC
ChtgqiZryJzI2UdonXYQn5p0hGE5o4FDFEtVg/B1oP7fuKkiatuoaGKCaQi4L5uE
bz7z5uV+YMfHsIlBSNO1Cdm1HwAjuyOUv5owzIjAlezKfMqz286FAlf0XI/2bka6
S9D5j9JDgnQBrgisO90ETdd0yG2EeMdcsXA0jwIDAQABAoIBAAeYuSwO4yFq3MgN
np9JUqpH93w4ethlf4Ee/YIwDcekmlzYEmmWNVuLT5FaFvzY/MrrzRBsplW8u48o
W2aimcsxD4sBCm9hUja39kllTVdDMxrohxlHO+20eX2hG/+xXSgnTUkugqHRogLE
YfJjPuhkVOjJoOglVGcQH7zmH5PrEsLWDEzV9g/jq+gEe8F462QauJeDRrQpYCxV
huHDDtjgzEai4WU7fIWnI1+V+cRGm7mkAP4sjvFa0qZ/BcUfTuF6v4fk5YILoCbH
8oVwfjDQJU67Ri/pSl9bAZf+iVGLQSKtSvRVWDnstotZYdUR5VnLKu14dwlZ1F9m
m1gp050CgYEA4GuOGpm9XrAUGt04jLebi7riLbnm4tLjyCbwZ3twEHXuIAjPyGmv
NGNOgkBrXUfVuFD6WYrHO3/OXKQUmh0Q+yL936FICO36sWnUZKsGpbUARs8xT7Uq
2b3p/mA6rdxHSITQ9Xu8B3KTTfYR6WWbS5Cwkp4HPiniSgJBYpP3SY0CgYEAztPa
PinYAvRE9dBlRBtklYN8Z5NvtPzMdRpjprEmK+9Cko8USKoXNkl3lDIgUh8w2uU6
SfgCs/t1ywRZJzESTw5EQCldSQdpZ3b7QCxpUAQv6M/MoFnAnLmt7XvciwjoqiB9
PwdHSRsXem3zIbQur7Y8Rd7L/HWok16Ug4+OmYsCgYEAhgZVuHcmS/02FJEXK5qf
j0RNvWcvhzjRBgCTRAnI9FupmYIJrTPIia3g/hLAy9WRwmDCEmW59EOwl0z6bMt9
D65nFX35SjPtqrR8Pp6Q+rds8dzdIzAb5ivwKZWIlbpe6+U98c0yjvQTGtUg/1VJ
+Efx2636v1o+JVrRd7DMVyUCgYBSRifszoxlMHI2Ln36B8ONTk6wjQ/EuUND2gmG
B7YdiAG9dzkkZrTxHWx6AS6mPE4c5U64mfXJTuBesA4e7wBPfmdb9phrMo2VYNk1
f/UspV3BiNfneYyLS7mKXNkwXYzgECiCaAzNYf+G7jHnWFux/hYf3S7b8JnsdZUy
eGrLXQKBgQCZOlUVozCwODeQPcZZ28eKDpFPMxAh20iyHjzVwIbiOSyXWjgC7Tfq
gDT5s+OcfyhhFQkON7uu2QE6eT5VGsagcJBKSVRDopNnCyJxFNyREXugdpKM9r/6
tUcXca1ANhPx4ees0yBNd9fFWaU0+ONGledrLF2ncqjriC9He+vYlA==
-----END RSA PRIVATE KEY-----"#;

const DEFAULT_PUBLIC_KEY_PEM: &str = r#"-----BEGIN RSA PUBLIC KEY-----
MIIBCgKCAQEAtVBEUZ1gwbxc8dHJ6qUMKTSTopP/Jj3dp7Fu0rHqP6avIbZ+q7LE
erGWLl3as4ghzb215sUCGkw6ud22KM4FW2aL0r5b33hnDmu2+Gzm1VWjDr45sU/f
ZOY1XpvhbrdHyldOaB8PXgyh81N2dgzE70mCtQOHpbYOTRcGe1VOJeNyi4uCChtg
qiZryJzI2UdonXYQn5p0hGE5o4FDFEtVg/B1oP7fuKkiatuoaGKCaQi4L5uEbz7z
5uV+YMfHsIlBSNO1Cdm1HwAjuyOUv5owzIjAlezKfMqz286FAlf0XI/2bka6S9D5
j9JDgnQBrgisO90ETdd0yG2EeMdcsXA0jwIDAQAB
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
