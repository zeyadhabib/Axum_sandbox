use std::{fs::File, io::Read, path::PathBuf};

use axum::http::StatusCode;
use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, TokenData, Validation};
use serde::{Deserialize, Serialize};

#[derive(Deserialize, Serialize)]
// Define a structure for holding claims data used in JWT tokens
pub struct Claims {
    pub exp: usize,    // Expiry time of the token
    pub iat: usize,    // Issued at time of the token
    pub email: String, // Email associated with the token
}

#[allow(dead_code)]
#[async_trait::async_trait]
pub trait IJwtTokenHelper {
    async fn encode_jwt(&self, email: String) -> Result<String, StatusCode>;
    async fn decode_jwt(&self, jwt_token: String) -> Result<TokenData<Claims>, StatusCode>;
}

pub struct JwtTokenHelper {}

#[async_trait::async_trait]
impl IJwtTokenHelper for JwtTokenHelper {
    async fn encode_jwt(&self, email: String) -> Result<String, StatusCode> {
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
                    let claim = Claims { iat, exp, email };

                    encode(
                        &Header::default(),
                        &claim,
                        &EncodingKey::from_secret(secret.as_ref()),
                    )
                    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
                }
                Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
            },
            Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
        }
    }

    async fn decode_jwt(&self, jwt_token: String) -> Result<TokenData<Claims>, StatusCode> {
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
