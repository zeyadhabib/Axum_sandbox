pub mod jwt_token_helpers;
pub mod types;

use std::{error::Error, net::SocketAddr, path::PathBuf, sync::Arc};

use axum::{
    body::Body,
    extract::{Request, State},
    http::{header::AUTHORIZATION, HeaderMap, HeaderValue, Response, StatusCode},
    middleware::{from_fn, Next},
    routing::get,
    Json, Router,
};
use axum_server::tls_openssl::OpenSSLConfig;
use jwt_token_helpers::IJwtTokenHelper;
use openssl::ssl::{SslAcceptor, SslFiletype, SslMethod};
use serde_json::json;

use types::{dummy_users_database::DummyUserDataBase, AppState, DeleteUserRequest, LoginRequest, SignUpRequest, UserResponse};

async fn sign_up(
    State(data_base_handle): State<AppState>,
    Json(new_user): Json<SignUpRequest>,
) -> Result<Json<UserResponse>, StatusCode> {
    let result = data_base_handle.handle.add_user(new_user).await?;
    Ok(Json(result))
}

async fn sign_in(
    State(data_base_handle): State<AppState>,
    Json(user): Json<LoginRequest>,
) -> Result<Json<String>, StatusCode> {
    let handle = data_base_handle.handle;
    if let Ok(found_user) = handle.get_user(user.clone()).await {
        if user.password == found_user.password {
            let email = found_user.email.clone();
            let mut claims = json!({
                "email": email
            });
            let token_generator = jwt_token_helpers::JwtTokenHelper::default();
            token_generator
                .encode_jwt(&mut claims)
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
    headers: HeaderMap,
    State(data_base_handle): State<AppState>,
    Json(user): Json<DeleteUserRequest>,
) -> Result<Json<UserResponse>, StatusCode> {
    match headers.get("email").map(|value| value.to_str()) {
        Some(Ok(requesting_email)) => match requesting_email == &user.email {
            true => {
                let handle = data_base_handle.handle;
                if let Ok(found_user) = handle.get_user(user.clone()).await {
                    if user.password == found_user.password {
                        if let Ok(user) = handle.delete_user(user).await {
                            Ok(Json(user))
                        } else {
                            Err(StatusCode::INTERNAL_SERVER_ERROR)
                        }
                    } else {
                        Err(StatusCode::UNAUTHORIZED)
                    }
                } else {
                    Err(StatusCode::UNAUTHORIZED)
                }
            },
            false => Err(StatusCode::UNAUTHORIZED)
        },
        _ => Err(StatusCode::UNAUTHORIZED),
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

    let claims = match token_generator.decode_jwt(token.unwrap().to_string()).await {
        Ok(data) => data.claims,
        Err(_) => return Err(StatusCode::UNAUTHORIZED),
    };

    match claims.get("email").map(|value| value.as_str()) {
        Some(Some(email)) => {
            let res = req
                .headers_mut()
                .insert("email", HeaderValue::from_str(email).unwrap());
            println!("{res:?}");
            println!("{:?}", req.headers());
            Ok(next.run(req).await)
        }
        _ => Err(StatusCode::UNAUTHORIZED),
    }
}

pub async fn start_server() -> Result<(), Box<dyn Error>> {
    let app_state = AppState {
        handle: Arc::new(DummyUserDataBase::default()),
    };
    let unprotected_routes = Router::new()
        .route("/sign-up", get(sign_up))
        .route("/sign-in", get(sign_in))
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
