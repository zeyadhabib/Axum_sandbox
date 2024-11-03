use axum::http::StatusCode;

use super::{
    DeleteUserRequest, Email, InternalStoredUser, LoginRequest, SignUpRequest, UserDataBaseResponse, UserResponse, UsersDataBase
};
use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};

#[derive(Default, Clone)]
pub struct DummyUserDataBase {
    store: Arc<RwLock<HashMap<Email, InternalStoredUser>>>,
}

#[async_trait::async_trait]
impl UsersDataBase for DummyUserDataBase {
    async fn get_user(&self, user: LoginRequest) -> Result<UserDataBaseResponse, StatusCode> {
        let user = self
            .store
            .read()
            .unwrap()
            .get(&user.email)
            .map(|internal_user| UserDataBaseResponse {
                uuid: internal_user.uuid,
                email: internal_user.email.clone(),
                password: internal_user.password.clone()
            });

        match user {
            Some(user) => Ok(user),
            None => Err(StatusCode::INTERNAL_SERVER_ERROR),
        }
    }

    async fn add_user(&self, user: SignUpRequest) -> Result<UserResponse, StatusCode> {
        let internal_user = InternalStoredUser {
            uuid: self.store.read().unwrap().len() as u128,
            first_name: user.first_name,
            middle_name: user.middle_name,
            last_name: user.last_name,
            email: user.email,
            password: user.password,
        };

        let user = self
            .store
            .write()
            .unwrap()
            .entry(internal_user.email.clone())
            .or_insert(internal_user)
            .clone();
        println!("{:?}", self.store.read().unwrap());
        Ok(UserResponse {
            uuid: user.uuid,
            email: user.email.clone(),
        })
    }

    async fn delete_user(&self, user: DeleteUserRequest) -> Result<UserResponse, StatusCode> {
        let deleted = self.store.write().unwrap().remove(&user.email);
        println!("{:?}", self.store.read().unwrap());

        match deleted {
            Some(user) => Ok(UserResponse {
                uuid: user.uuid,
                email: user.email.clone(),
            }),
            None => Err(StatusCode::INTERNAL_SERVER_ERROR),
        }
    }
}
