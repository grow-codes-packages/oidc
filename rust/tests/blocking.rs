// Skeleton created by sdk-kit 0.3.0; owned by this repository (edit freely).
//! Blocking client (feature `blocking`) against a minimal HTTP server; adapt it with the
//! blocking client.
#![cfg(feature = "blocking")]

use std::io::{Read, Write};
use std::net::TcpListener;

use grow_oidc as sdk;
use sdk::core::ErrorCode;

use sdk::blocking::OidcClient as Client;

use sdk::OidcConfig as Config;

/// Minimal HTTP server on a thread (no async runtime involved).
fn serve(responses: Vec<&'static str>) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        for body in responses {
            let (mut stream, _) = listener.accept().unwrap();
            let mut buf = [0u8; 4096];
            let _ = stream.read(&mut buf);
            let (status, json) = body.split_once(' ').unwrap();
            let resp = format!(
                "HTTP/1.1 {status} X\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{json}",
                json.len()
            );
            stream.write_all(resp.as_bytes()).unwrap();
        }
    });
    format!("http://{addr}")
}

#[test]
fn blocking_client() {
    let url = serve(vec![
        r#"200 {"issuer":"x"}"#,
        r#"200 {"userinfo_endpoint":"/api/userinfo"}"#,
        r#"200 {"sub":"u"}"#,
    ]);
    let cfg = Config::builder().url(url).token("t-1234").build().unwrap();
    let c = Client::new(cfg).unwrap();
    assert!(c.health().unwrap().healthy);
    c.ping().unwrap();
    assert_eq!(
        c.server_version().unwrap_err().code(),
        ErrorCode::Unsupported
    );
    assert!(!c.async_client().is_closed());
    assert_eq!(c.block_on(async { 7 }), 7);
    // background tasks keep running between blocking calls (one worker thread)
    let (tx, rx) = std::sync::mpsc::channel();
    c.block_on(async move {
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            let _ = tx.send(());
        });
    });
    rx.recv_timeout(std::time::Duration::from_secs(5))
        .expect("background task ran outside block_on");
    c.close();
    c.close();
    assert_eq!(c.ping().unwrap_err().code(), ErrorCode::Cancelled);
    let _ = Client::from_env();
    let bad = Config::builder()
        .ca_cert_path("/nonexistent")
        .build()
        .unwrap();
    assert_eq!(Client::new(bad).unwrap_err().code(), ErrorCode::Config);
}
