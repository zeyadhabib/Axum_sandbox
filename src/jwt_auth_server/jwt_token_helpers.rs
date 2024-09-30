use std::{fs::File, io::Read, path::PathBuf};

use axum::http::StatusCode;
use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, TokenData, Validation};
use serde_json::json;

#[allow(dead_code)]
#[async_trait::async_trait]
pub trait IJwtTokenHelper {
    async fn encode_jwt(&self, claims: &mut serde_json::Value) -> Result<String, StatusCode>;
    async fn decode_jwt(
        &self,
        jwt_token: String,
    ) -> Result<TokenData<serde_json::Value>, StatusCode>;
}

#[derive(Default)]
pub struct JwtTokenHelper {}

#[async_trait::async_trait]
impl IJwtTokenHelper for JwtTokenHelper {
    async fn encode_jwt(&self, claims: &mut serde_json::Value) -> Result<String, StatusCode> {
        let mut secret = Vec::new();
        let file = File::open(
            PathBuf::from("certs")
                .join("server-leaf")
                .join("server-leaf.key"),
        );

        match file {
            Ok(mut file) => match file.read_to_end(&mut secret) {
                Ok(_) => {
                    let now = Utc::now();
                    let expire: chrono::TimeDelta = Duration::hours(24);
                    let exp: usize = (now + expire).timestamp() as usize;
                    let iat: usize = now.timestamp() as usize;
                    match claims.as_object_mut() {
                        Some(map) => {
                            map.insert("iat".to_string(), json!(iat));
                            map.insert("exp".to_string(), json!(exp));
                            encode(
                                &Header::default(),
                                &claims,
                                &EncodingKey::from_secret(secret.as_ref()),
                            )
                            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
                        }
                        None => Err(StatusCode::INTERNAL_SERVER_ERROR),
                    }
                }
                Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
            },
            Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
        }
    }

    async fn decode_jwt(
        &self,
        jwt_token: String,
    ) -> Result<TokenData<serde_json::Value>, StatusCode> {
        let mut secret = Vec::new();
        let file = File::open(
            PathBuf::from("certs")
                .join("server-leaf")
                .join("server-leaf.key"),
        );

        match file {
            Ok(mut file) => match file.read_to_end(&mut secret) {
                Ok(_) => decode(
                    &jwt_token,
                    &DecodingKey::from_secret(secret.as_ref()),
                    &Validation::default(),
                )
                .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR),
                Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
            },
            Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
        }
    }
}
