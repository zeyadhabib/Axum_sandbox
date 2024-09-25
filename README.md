# Axum Training project

### Server:
- Dummy Axum server that uses peer PKI authentication.
- Meant for backend servers communicating with one another using PKI.

To run:
```chmod +x ./gen.sh && cargo run --release```

This dummy server enforces that the client present a certificate that is signed by a trusted certificate authority, to ensure that I used an SslAcceptor from the openssl crate and configured it to refuse unauthenticated client connections:
```acceptor.set_verify(SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT);```

You can also add you own logic above this by using: ```acceptor.set_verify_callback(...)```

### Client:
- For test purposes for the server use this curl command:

    ```curl -v --cert certs/client-leaf/client-leaf.pem --key certs/client-leaf/client-leaf.key "https://127.0.0.1:8080/hello" --cacert certs/chain.pem```