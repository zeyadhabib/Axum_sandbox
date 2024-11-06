pub mod dummy_users_database;

use std::sync::Arc;

use axum::http::StatusCode;
use serde::{Deserialize, Serialize};

#[derive(Deserialize, Clone, Debug)]
pub struct SignUpRequest {
    pub email: String,
    pub first_name: String,
    pub middle_name: Option<String>,
    pub last_name: String,
    pub password: String
}

#[derive(Deserialize, Clone, Debug)]
pub struct LoginRequest {
    pub email: String,
    pub password: String 
}

#[derive(Deserialize, Clone, Debug)]
pub struct DeleteUserRequest {
    pub email: String,
    pub password: String 
}

impl Into<LoginRequest> for DeleteUserRequest {
    fn into(self) -> LoginRequest {
        LoginRequest {
            email: self.email,
            password: self.password
        }
    }
}

#[allow(dead_code)]
#[derive(Deserialize, Clone, Debug)]
pub struct InternalStoredUser {
    pub uuid: u128,
    pub email: String,
    pub first_name: String,
    pub middle_name: Option<String>,
    pub last_name: String,
    pub password: String
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct UserResponse {
    pub uuid: u128,
    pub email: String
}

#[allow(dead_code)]
#[derive(Deserialize, Clone, Debug)]
pub struct UserDataBaseResponse {
    pub uuid: u128,
    pub email: String,
    pub password: String
}

#[async_trait::async_trait]
pub trait UsersDataBase {
    async fn get_user (&self, user: LoginRequest) -> Result<UserDataBaseResponse, StatusCode>;
    async fn delete_user (&self, user: DeleteUserRequest) -> Result<UserResponse, StatusCode>;
    async fn add_user (&self, user: SignUpRequest) -> Result<UserResponse, StatusCode>;
}

#[derive(Clone)]
pub struct AppState {
    pub handle: Arc<dyn UsersDataBase + Sync + Send>
}