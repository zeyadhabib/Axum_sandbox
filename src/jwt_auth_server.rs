pub mod types;
pub mod jwt_token_helpers;

use std::{error::Error, net::SocketAddr, path::PathBuf, sync::Arc};

use axum::{
    extract::{Query, State},
    http::StatusCode,
    routing::get,
    Json, Router,
};
use axum_server::tls_openssl::OpenSSLConfig;
use openssl::ssl::{SslAcceptor, SslFiletype, SslMethod};
use types::{dummy_users_database::DummyUserDataBase, AppState, NewUserRequest, User};

async fn sign_up(
    State(data_base_handle): State<AppState>,
    Query(new_user): Query<NewUserRequest>,
) -> Json<User> {
    let result = data_base_handle.handle.add_user(new_user).await.unwrap();
    Json(result)
}

async fn sign_in(State(data_base_handle): State<AppState>, Query(user): Query<User>) -> StatusCode {
    let handle = data_base_handle.handle;
    if let Some(found_user) = handle.get_user(user.email).await {
        if user.password == found_user.password {
            StatusCode::OK
        } else {
            StatusCode::UNAUTHORIZED
        }
    } else {
        StatusCode::UNAUTHORIZED
    }
}

async fn delete_user(
    State(data_base_handle): State<AppState>,
    Query(user): Query<User>,
) -> StatusCode {
    let handle = data_base_handle.handle;
    if let Some(found_user) = handle.get_user(user.email.clone()).await {
        if user.password == found_user.password {
            handle.delete_user(user).await;
            StatusCode::OK
        } else {
            StatusCode::UNAUTHORIZED
        }
    } else {
        StatusCode::UNAUTHORIZED
    }
}

pub async fn start_login_server() -> Result<(), Box<dyn Error>> {
    let app_state = AppState {
        handle: Arc::new(DummyUserDataBase::default()),
    };
    let app = Router::new()
        .route("/sign-up", get(sign_up))
        .route("/sign-in", get(sign_in))
        .route("/remove-user", get(delete_user))
        .with_state(app_state.clone());

    let mut acceptor = SslAcceptor::mozilla_intermediate(SslMethod::tls()).unwrap();
    acceptor.set_private_key_file(
        PathBuf::from("certs")
            .join("server-leaf")
            .join("server-leaf.key"),
        SslFiletype::PEM,
    )?;
    acceptor
        .set_certificate_chain_file(PathBuf::from("certs").join("server-leaf").join("chain.pem"))?;
    acceptor.check_private_key()?;
    acceptor.set_ca_file(PathBuf::from("certs").join("chain.pem"))?;
    let acceptor = Arc::new(acceptor.build());
    let config = OpenSSLConfig::from_acceptor(acceptor);
    let address = SocketAddr::from(([127, 0, 0, 1], 8081));
    println!("Listening on address: {address}\n");

    axum_server::bind_openssl(address, config)
        .serve(app.into_make_service())
        .await?;

    Ok(())
}
