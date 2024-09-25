use axum::{response::Html, routing::get, Router};
use axum_server::tls_openssl::OpenSSLConfig;
use core::error;
use openssl::ssl::{SslAcceptor, SslFiletype, SslMethod, SslVerifyMode};
use std::{net::SocketAddr, path::PathBuf, sync::Arc};

pub async fn start_pki_server () -> Result<(), Box<dyn error::Error>> {
    let routes_hello_world = Router::new().route(
        "/hello",
        get(|| async { Html("Hello <strong>World!!!</strong>") }),
    );

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
    acceptor.set_verify(SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT);
    let acceptor = Arc::new(acceptor.build());
    let config = OpenSSLConfig::from_acceptor(acceptor);
    let address = SocketAddr::from(([127, 0, 0, 1], 8080));
    println!("Listening on address: {address}\n");

    axum_server::bind_openssl(address, config)
        .serve(routes_hello_world.into_make_service())
        .await?;

    Ok(())
}