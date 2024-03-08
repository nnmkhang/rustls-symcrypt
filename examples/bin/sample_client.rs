use std::env;

// stuff for ruslts
use rustls::crypto::ring::{cipher_suite, default_provider};
use rustls::pki_types::CertificateDer;
use rustls::RootCertStore;
use rustls_symcrypt::{
    default_symcrypt_provider, custom_symcrypt_provider, TLS13_AES_128_GCM_SHA256,
    TLS13_AES_256_GCM_SHA384, TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, SECP256R1
};
use webpki_roots::TLS_SERVER_ROOTS;


use std::io::{stdout, Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
//use env_logger;
// use log::{debug, error, trace};
// use rustls_platform_verifier::Verifier;
use std::fs::File;
use std::io::BufReader;
use std::path::PathBuf;
use structopt::StructOpt;


static TEST_CERT_PATH: once_cell::sync::Lazy<PathBuf> = once_cell::sync::Lazy::new(|| {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push("bin");
    path.push("certs");
    path
});

// openssl s_server -accept 4443 -cert localhost.crt  -key localhost.key -debug

// #[derive(Debug, StructOpt)]
// #[structopt(name = "sample client", about = "A simple tls client using rustls and SymCrypt as a provider")]
// struct Opt {

//     #[structopt(long)]
//     key: String,

//     #[structopt(long)]
//     cert: PathBuf,

// }


fn main() {

    // let opt = Opt::from_args();

    // println!("{:?}", opt.cert);




    env_logger::init();
    //env::set_var("SSLKEYLOGFILE", "./sslkeylogfile.txt");

    println!("The feature flags enabled are: ");

    #[cfg(feature = "rust-symcrypt")]
    println!("rust-symcrypt as provider");

    #[cfg(feature = "ring")]
    println!("ring as provider");

    #[cfg(feature = "localhost")]
    println!("connecting to localhost");

    #[cfg(feature = "internet")]
    println!("connecting to internet");

    #[cfg(feature = "localrust")]
    println!("connecting to local rust server");

    let mut root_store = rustls::RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.iter().cloned().collect(),
    };

    //let mut root_store = RootCertStore::empty();
    let cert_path = TEST_CERT_PATH.join("RootCA.pem").into_os_string().into_string().unwrap();


    let certs = rustls_pemfile::certs(&mut BufReader::new(
        &mut File::open(cert_path).unwrap(),
    ))
    .collect::<Result<Vec<_>, _>>()
    .unwrap();

    // let certs = rustls_pemfile::certs(&mut BufReader::new(
    //     &mut File::open(opt.cert).unwrap(),
    // ))
    // .collect::<Result<Vec<_>, _>>()
    // .unwrap();


    root_store.add_parsable_certificates(certs);
    println!("roots: {:?}", root_store);

    // need to add platform verifier to the symcrypt provider since there is a known bug where you cant add
    // outside roots to the webpki store.

    #[cfg(feature = "ring")]
    let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(default_provider()))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    let cipher_suites = vec![TLS13_AES_128_GCM_SHA256, TLS13_AES_256_GCM_SHA384];
    let kx_group = vec![SECP256R1];
    // #[cfg(feature = "rust-symcrypt")]
    // let mut config =
    //     rustls::ClientConfig::builder_with_provider(Arc::new(symcrypt_provider()))
    //     .with_safe_default_protocol_versions()
    //     .unwrap()
    //     // .dangerous()
    //     // .with_custom_certificate_verifier(Arc::new(Verifier::new()))
    //     .with_root_certificates(root_store)
    //     .with_no_client_auth();

    #[cfg(feature = "rust-symcrypt")]
    let mut config = rustls::ClientConfig::builder_with_provider(Arc::new(
        custom_symcrypt_provider(Some(cipher_suites), Some(kx_group)).unwrap()
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    // .dangerous()
    // .with_custom_certificate_verifier(Arc::new(Verifier::new()))
    .with_root_certificates(root_store)
    .with_no_client_auth();

    // config using platform verifier, this sort of works, need to get a proper test cert that will pass cert chain validation.
    // let mut config = rustls_platform_verifier::tls_config();

    config.key_log = Arc::new(rustls::KeyLogFile::new());

    // connect to internet
    #[cfg(feature = "internet")]
    let server_name = "www.rust-lang.org".try_into().unwrap();

    #[cfg(feature = "internet")]
    let mut sock = TcpStream::connect("www.rust-lang.org:443").unwrap();

    //connect to server
    #[cfg(feature = "localhost")]
    let server_name = "localhost".try_into().unwrap();

    #[cfg(feature = "localhost")]
    let mut sock = TcpStream::connect("localhost:4443").unwrap();

    let mut conn = rustls::ClientConnection::new(Arc::new(config), server_name).unwrap();
    let mut tls = rustls::Stream::new(&mut conn, &mut sock);

    #[cfg(feature = "internet")]
    tls.write_all(
        // this does handshake data ( makes tls connection )
        concat!(
            "GET / HTTP/1.1\r\n",
            "Host: rust-lang.org\r\n",
            "Connection: close\r\n",
            "Accept-Encoding: identity\r\n",
            "\r\n"
        )
        .as_bytes(),
    )
    .unwrap();

    #[cfg(feature = "localhost")]
    tls.write_all(
        // this does handshake data ( makes tls connection )
        concat!(
            "GET / HTTP/1.1\r\n",
            "Host: localhost\r\n",
            "Connection: close\r\n",
            "Accept-Encoding: identity\r\n",
            "\r\n"
        )
        .as_bytes(),
    )
    .unwrap();

    let ciphersuite = tls.conn.negotiated_cipher_suite().unwrap();
    writeln!(
        &mut std::io::stderr(),
        "Current ciphersuite: {:?}",
        ciphersuite.suite()
    )
    .unwrap();

    println!("Sending application Data:");

    let mut plaintext = Vec::new();
    tls.read_to_end(&mut plaintext).unwrap();
    stdout().write_all(&plaintext).unwrap();

    println!("Connection established");
}
