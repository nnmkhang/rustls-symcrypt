use std::io::Write;
use std::sync::Arc;

use rustls::server::Acceptor;
use rustls::ServerConfig;

use rustls::crypto::ring::default_provider;
use rustls_symcrypt::default_symcrypt_provider;

use std::fs::File;
use std::io::BufReader;
use std::path::PathBuf;

static TEST_CERT_PATH: once_cell::sync::Lazy<PathBuf> = once_cell::sync::Lazy::new(|| {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("bin");
    path.push("certs");
    path
});



fn main() {
    println!("The feature flags enabled are:");

    #[cfg(feature = "rust-symcrypt")]
    println!("Using rust-symcrypt as the provider");

    #[cfg(feature = "ring")]
    println!("Using ring as the provider");

    // openssl s_server -accept 4443 -cert localhost.crt  -key localhost.key -debug
    let cert_path = TEST_CERT_PATH.join("localhost.pem").into_os_string().into_string().unwrap();
    let key_path = TEST_CERT_PATH.join("localhost.key").into_os_string().into_string().unwrap();

    let certs = rustls_pemfile::certs(&mut BufReader::new(&mut File::open(cert_path).unwrap()))
        .collect::<Result<Vec<_>, _>>()
        .unwrap();

    let private_key =
        rustls_pemfile::private_key(&mut BufReader::new(&mut File::open(key_path).unwrap()))
            .unwrap()
            .unwrap();


    #[cfg(feature = "ring")]
    let mut server_config = ServerConfig::builder_with_provider(Arc::new(default_provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(certs, private_key)
        .unwrap();

    #[cfg(feature = "rust-symcrypt")]
    let mut server_config = ServerConfig::builder_with_provider(Arc::new(default_symcrypt_provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(certs, private_key)
        .unwrap();

    server_config.key_log = Arc::new(rustls::KeyLogFile::new());
    let server_config = Arc::new(server_config);

    let listener = std::net::TcpListener::bind(format!("[::]:{}", 4443)).unwrap();
    for stream in listener.incoming() {
        let mut stream = stream.unwrap();
        let mut acceptor = Acceptor::default();

        let accepted = loop {
            acceptor.read_tls(&mut stream).unwrap();
            if let Some(accepted) = acceptor.accept().unwrap() {
                break accepted;
            }
        };

        match accepted.into_connection(server_config.clone()) {
            Ok(mut conn) => {
                let msg = concat!(
                    "HTTP/1.1 200 OK\r\n",
                    "Connection: Closed\r\n",
                    "Content-Type: text/html\r\n",
                    "\r\n",
                    "<h1>Hello World! From your own RUSTLS server</h1>\r\n"
                )
                .as_bytes();

                // Note: do not use `unwrap()` on IO in real programs!
                conn.writer().write_all(msg).unwrap();
                conn.write_tls(&mut stream).unwrap();
                conn.complete_io(&mut stream).unwrap();

                conn.send_close_notify();
                conn.write_tls(&mut stream).unwrap();
                conn.complete_io(&mut stream).unwrap();
            }
            Err(_) => {
                // error here
            }
        }
    }
}
