use axum::http::StatusCode;

use super::{Email, InternalUser, NewUserRequest, User, UsersDataBase};
use std::{
    collections::HashMap,
    sync::{Arc, RwLock},
};

#[derive(Default, Clone)]
pub struct DummyUserDataBase {
    store: Arc<RwLock<HashMap<Email, InternalUser>>>,
}

#[async_trait::async_trait]
impl UsersDataBase for DummyUserDataBase {
    async fn get_user(&self, email: String) -> Option<User> {
        self.store.read().unwrap().get(&email).map(|user| User {
            email: user.email.clone(),
            password: user.password.clone(),
        })
    }

    async fn add_user(&self, user: NewUserRequest) -> Result<User, StatusCode> {
        let internal_user = InternalUser {
            uuid: self.store.read().unwrap().len() as u64,
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
        Ok(User {
            email: user.email.clone(),
            password: user.password.clone(),
        })
    }

    async fn delete_user(&self, user: User) -> Option<User> {
        let deleted = self.store.write().unwrap().remove(&user.email);
        println!("{:?}", self.store.read().unwrap());
        deleted.map(|internal_user| User {
            email: internal_user.email,
            password: internal_user.password,
        })
    }
}
