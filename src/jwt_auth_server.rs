pub mod jwt_token_helpers;
pub mod types;

use std::{error::Error, net::SocketAddr, path::PathBuf, sync::Arc};

use axum::{
    body::Body,
    extract::{Query, Request, State},
    http::{header::AUTHORIZATION, Response, StatusCode},
    middleware::{from_fn, Next},
    routing::get,
    Json, Router,
};
use axum_server::tls_openssl::OpenSSLConfig;
use jwt_token_helpers::IJwtTokenHelper;
use openssl::ssl::{SslAcceptor, SslFiletype, SslMethod};
use types::{dummy_users_database::DummyUserDataBase, AppState, NewUserRequest, User};

async fn sign_up(
    State(data_base_handle): State<AppState>,
    Query(new_user): Query<NewUserRequest>,
) -> Result<Json<User>, StatusCode> {
    let result = data_base_handle.handle.add_user(new_user).await?;
    Ok(Json(result))
}

async fn sign_in(
    State(data_base_handle): State<AppState>,
    Query(user): Query<User>,
) -> Result<Json<String>, StatusCode> {
    let handle = data_base_handle.handle;
    if let Some(found_user) = handle.get_user(user.email.clone()).await {
        if user.password == found_user.password {
            let token_generator = jwt_token_helpers::JwtTokenHelper::default();
            token_generator
                .encode_jwt(user.email.clone())
                .await
                .map(|token| Json(token))
        } else {
            Err(StatusCode::UNAUTHORIZED)
        }
    } else {
        Err(StatusCode::UNAUTHORIZED)
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

pub async fn authorize(mut req: Request, next: Next) -> Result<Response<Body>, StatusCode> {
    let auth_header = req.headers_mut().get(AUTHORIZATION);

    let auth_header = match auth_header {
        Some(header) => header.to_str().map_err(|_| StatusCode::FORBIDDEN)?,
        None => return Err(StatusCode::FORBIDDEN),
    };

    let mut header = auth_header.split_whitespace();

    let (_bearer, token) = (header.next(), header.next());
    let token_generator = jwt_token_helpers::JwtTokenHelper::default();

    let token_data = match token_generator.decode_jwt(token.unwrap().to_string()).await {
        Ok(data) => data,
        Err(_) => return Err(StatusCode::UNAUTHORIZED),
    };

    req.extensions_mut().insert(token_data.claims.email.clone());
    Ok(next.run(req).await)
}

pub async fn start_server() -> Result<(), Box<dyn Error>> {
    let app_state = AppState {
        handle: Arc::new(DummyUserDataBase::default()),
    };
    let unprotected_routes = Router::new()
        .route("/sign-up", get(sign_up))
        .route("/sign-in", get(sign_in))
        // .route("/remove-user", get(delete_user))
        .with_state(app_state.clone());

    let protected_routes = Router::new().nest(
        "/protected",
        Router::new()
            .route("/delete-user", get(delete_user))
            .with_state(app_state)
            .route_layer(from_fn(authorize)),
    );

    let app = unprotected_routes.merge(protected_routes);

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
