mod jwt_auth_server;
mod pki_auth_server;

use std::error::Error;

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let handle = tokio::spawn(async move {
        let error = pki_auth_server::start_pki_server().await.unwrap_err();
        println!("{error}");
    });

    let handle_2 = tokio::spawn(async move {
        let error = jwt_auth_server::start_login_server().await.unwrap_err();
        println!("{error}");
    });

    // let handle2 = tokio::spawn(async mode {
    // });
    handle.await?;
    handle_2.await?;
    Ok(())
}
