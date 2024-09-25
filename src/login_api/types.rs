pub mod dummy_users_database;

use std::sync::Arc;

use axum::http::Error;
use serde::{Deserialize, Serialize};

pub type Email = String;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct NewUserRequest {
    pub first_name: String,
    pub middle_name: Option<String>,
    pub last_name: String,
    pub email: String,
    pub password: String
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct InternalUser {
    pub uuid: u64,
    pub first_name: String,
    pub middle_name: Option<String>,
    pub last_name: String,
    pub email: String,
    pub password: String
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct User {
    pub email: String,
    pub password: String
}

#[async_trait::async_trait]
pub trait UsersDataBase {
    async fn get_user (&self, email: String) -> Option<User>;
    async fn delete_user (&self, user: User) -> Option<User>;
    async fn add_user (&self, user: NewUserRequest) -> Result<User, Error>;
}

#[derive(Clone)]
pub struct AppState {
    pub handle: Arc<dyn UsersDataBase + Sync + Send>
}