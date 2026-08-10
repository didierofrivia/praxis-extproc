// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Shane Utt

//! TLS configuration for the ExtProc gRPC listener.
//!
//! Supports three modes: self-signed (ephemeral cert), provided
//! (cert and key from disk), and plaintext (no TLS).
//!
//! TLS termination uses the [`openssl`] crate which delegates directly to
//! system `OpenSSL`, enabling FIPS compliance via the OS crypto library.
//! mTLS client certificate verification is supported via `ca_cert_path`.

use std::{
    io,
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use futures::StreamExt as _;
use openssl::{
    pkey::PKey,
    ssl::{AlpnError, Ssl, SslAcceptor, SslAcceptorBuilder, SslFiletype, SslMethod, SslVerifyMode, select_next_proto},
    x509::X509,
};
use serde::Deserialize;
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::{TcpListener, TcpStream},
};
use tokio_stream::{Stream, wrappers::TcpListenerStream};
use tonic::transport::server::{Connected, TcpConnectInfo};
use tracing::info;

// -----------------------------------------------------------------------------
// TlsMode
// -----------------------------------------------------------------------------

/// TLS mode for the gRPC listener.
///
/// ```
/// use praxis_extproc::tls::TlsMode;
///
/// let mode = TlsMode::default();
/// assert!(matches!(mode, TlsMode::None));
/// ```
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TlsMode {
    /// Generate an ephemeral self-signed certificate at startup.
    SelfSigned,

    /// Load certificate and key from the provided file paths.
    Provided,

    /// No TLS (plaintext gRPC).
    #[default]
    None,
}

// -----------------------------------------------------------------------------
// TlsConfig
// -----------------------------------------------------------------------------

/// TLS settings from the configuration file.
///
/// ```
/// use praxis_extproc::tls::TlsConfig;
///
/// let cfg = TlsConfig::default();
/// assert!(matches!(cfg.mode, praxis_extproc::tls::TlsMode::None));
/// ```
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct TlsConfig {
    /// Which TLS mode to use.
    pub mode: TlsMode,

    /// Path to the PEM certificate file (required for `provided` mode).
    pub cert_path: Option<String>,

    /// Path to the PEM private key file (required for `provided` mode).
    pub key_path: Option<String>,

    /// Path to a PEM CA certificate for mTLS client verification.
    ///
    /// When set, the server requires clients to present a valid certificate
    /// signed by this CA (`provided` mode only).
    pub ca_cert_path: Option<String>,
}

// -----------------------------------------------------------------------------
// OpenSslStream
// -----------------------------------------------------------------------------

/// A TLS-wrapped [`TcpStream`] backed by `OpenSSL` that implements [`Connected`],
/// [`AsyncRead`], and [`AsyncWrite`] for use with tonic's
/// `serve_with_incoming_shutdown`.
pub struct OpenSslStream {
    /// Underlying async TLS stream.
    inner: tokio_openssl::SslStream<TcpStream>,
    /// Local socket address, captured before the TLS handshake.
    local_addr: Option<SocketAddr>,
    /// Remote socket address, captured before the TLS handshake.
    remote_addr: Option<SocketAddr>,
}

impl Connected for OpenSslStream {
    type ConnectInfo = TcpConnectInfo;

    fn connect_info(&self) -> Self::ConnectInfo {
        TcpConnectInfo {
            local_addr: self.local_addr,
            remote_addr: self.remote_addr,
        }
    }
}

impl AsyncRead for OpenSslStream {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for OpenSslStream {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

// -----------------------------------------------------------------------------
// TLS Setup
// -----------------------------------------------------------------------------

/// Build an [`SslAcceptor`] from the TLS settings.
///
/// Returns `None` for plaintext mode. Generates a self-signed cert
/// or loads from disk depending on the mode.
///
/// # Errors
///
/// Returns an error if cert/key/CA path fields are set for a mode that
/// does not use them, if cert/key/CA files cannot be read, or if
/// self-signed certificate generation or `OpenSSL` setup fails.
pub fn build_tls_config(cfg: &TlsConfig) -> crate::error::Result<Option<SslAcceptor>> {
    match cfg.mode {
        TlsMode::None => {
            validate_no_path_fields("none", cfg)?;
            Ok(None)
        },
        TlsMode::SelfSigned => {
            validate_no_path_fields("self_signed", cfg)?;
            build_self_signed().map(Some)
        },
        TlsMode::Provided => build_provided(cfg).map(Some),
    }
}

/// Reject any path fields that are set but unused in the given mode.
///
/// Prevents silent misconfiguration where a user sets e.g. `ca_cert_path`
/// expecting mTLS but the active mode ignores it.
fn validate_no_path_fields(mode: &'static str, cfg: &TlsConfig) -> crate::error::Result<()> {
    if cfg.cert_path.is_some() {
        return Err(crate::error::ExtProcError::Config(format!(
            "tls.cert_path is not used in `{mode}` mode"
        )));
    }
    if cfg.key_path.is_some() {
        return Err(crate::error::ExtProcError::Config(format!(
            "tls.key_path is not used in `{mode}` mode"
        )));
    }
    if cfg.ca_cert_path.is_some() {
        return Err(crate::error::ExtProcError::Config(format!(
            "tls.ca_cert_path is not used in `{mode}` mode"
        )));
    }
    Ok(())
}

/// Maximum number of TLS handshakes running concurrently via `buffer_unordered`.
///
/// When all slots are occupied the accept loop stalls until one completes
/// or times out, providing natural back-pressure on new connections.
pub const HANDSHAKE_CONCURRENCY: usize = 64;

/// Maximum duration allowed for a single TLS handshake.
///
/// Connections that stall during the handshake are dropped after this
/// deadline, freeing their slot for the next accept.
pub const HANDSHAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Build a stream of TLS-wrapped connections from a bound [`TcpListener`].
///
/// Up to `concurrency` handshakes run concurrently via `buffer_unordered`;
/// the accept loop stalls naturally when all slots are taken. Each handshake
/// is bounded by `timeout`: a stalled client is dropped and its slot freed
/// without blocking other accepts.
pub fn build_tls_incoming(
    listener: TcpListener,
    acceptor: SslAcceptor,
    concurrency: usize,
    timeout: std::time::Duration,
) -> impl Stream<Item = Result<OpenSslStream, io::Error>> {
    let acceptor = Arc::new(acceptor);
    TcpListenerStream::new(listener)
        .map(move |result| {
            let acceptor = Arc::clone(&acceptor);
            async move {
                tokio::time::timeout(timeout, perform_handshake(result, acceptor))
                    .await
                    .unwrap_or_else(|_| Err(io::Error::new(io::ErrorKind::TimedOut, "TLS handshake timed out")))
            }
        })
        .buffer_unordered(concurrency)
}

/// Perform a TLS handshake on an accepted TCP connection.
///
/// Wraps `result` in an [`OpenSslStream`], capturing socket addresses
/// before the handshake so [`Connected::connect_info`] is always populated.
///
/// # Errors
///
/// Returns an error if the TCP accept, SSL context creation, or TLS
/// handshake fails.
async fn perform_handshake(
    result: Result<TcpStream, io::Error>,
    acceptor: Arc<SslAcceptor>,
) -> Result<OpenSslStream, io::Error> {
    let stream = result?;
    let local_addr = stream.local_addr().ok();
    let remote_addr = stream.peer_addr().ok();
    let ssl = Ssl::new(acceptor.context()).map_err(io::Error::other)?;
    let mut tls = tokio_openssl::SslStream::new(ssl, stream).map_err(io::Error::other)?;
    Pin::new(&mut tls)
        .accept()
        .await
        .map_err(|e| io::Error::new(io::ErrorKind::ConnectionAborted, e))?;
    Ok(OpenSslStream {
        inner: tls,
        local_addr,
        remote_addr,
    })
}

/// Generate an ephemeral self-signed certificate using `rcgen`.
fn build_self_signed() -> crate::error::Result<SslAcceptor> {
    info!("generating self-signed TLS certificate");
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()])
        .map_err(|e| crate::error::ExtProcError::Config(format!("self-signed cert: {e}")))?;
    let x509 = X509::from_pem(cert.cert.pem().as_bytes())
        .map_err(|e| crate::error::ExtProcError::Config(format!("X509: {e}")))?;
    let pkey = PKey::private_key_from_pem(cert.key_pair.serialize_pem().as_bytes())
        .map_err(|e| crate::error::ExtProcError::Config(format!("private key: {e}")))?;
    let mut builder = SslAcceptor::mozilla_intermediate(SslMethod::tls())
        .map_err(|e| crate::error::ExtProcError::Config(format!("SSL context: {e}")))?;
    builder
        .set_certificate(&x509)
        .map_err(|e| crate::error::ExtProcError::Config(format!("set certificate: {e}")))?;
    builder
        .set_private_key(&pkey)
        .map_err(|e| crate::error::ExtProcError::Config(format!("set private key: {e}")))?;
    set_alpn_h2(&mut builder)?;
    Ok(builder.build())
}

/// Load certificate and key from disk, optionally configuring mTLS.
///
/// When `ca_cert_path` is set the server requires clients to present a
/// certificate signed by that CA (`PEER | FAIL_IF_NO_PEER_CERT`).
///
/// # Errors
///
/// Returns an error if `cert_path` or `key_path` is missing, if any
/// file cannot be read, or if `OpenSSL` setup fails.
fn build_provided(cfg: &TlsConfig) -> crate::error::Result<SslAcceptor> {
    let cert_path = cfg
        .cert_path
        .as_deref()
        .ok_or_else(|| crate::error::ExtProcError::Config("tls.cert_path required for provided mode".to_owned()))?;
    let key_path = cfg
        .key_path
        .as_deref()
        .ok_or_else(|| crate::error::ExtProcError::Config("tls.key_path required for provided mode".to_owned()))?;
    info!(cert = cert_path, key = key_path, "loading TLS certificate");
    let mut builder = SslAcceptor::mozilla_intermediate(SslMethod::tls())
        .map_err(|e| crate::error::ExtProcError::Config(format!("SSL context: {e}")))?;
    builder
        .set_certificate_chain_file(cert_path)
        .map_err(|e| crate::error::ExtProcError::Config(format!("certificate: {e}")))?;
    builder
        .set_private_key_file(key_path, SslFiletype::PEM)
        .map_err(|e| crate::error::ExtProcError::Config(format!("private key: {e}")))?;
    set_alpn_h2(&mut builder)?;
    if let Some(ca_path) = &cfg.ca_cert_path {
        info!(ca = ca_path, "enabling mTLS client verification");
        builder
            .set_ca_file(ca_path)
            .map_err(|e| crate::error::ExtProcError::Config(format!("CA cert: {e}")))?;
        builder.set_verify(SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT);
    }
    Ok(builder.build())
}

/// Configure H2 ALPN on the provided [`SslAcceptorBuilder`].
///
/// Sets `h2` as the only advertised protocol and installs a selection
/// callback that honours client preference via [`select_next_proto`].
///
/// # Errors
///
/// Returns an error if the `OpenSSL` ALPN protos call fails.
fn set_alpn_h2(builder: &mut SslAcceptorBuilder) -> crate::error::Result<()> {
    builder
        .set_alpn_protos(b"\x02h2")
        .map_err(|e| crate::error::ExtProcError::Config(format!("ALPN protos: {e}")))?;
    builder.set_alpn_select_callback(|_ssl, client| select_next_proto(b"\x02h2", client).ok_or(AlpnError::NOACK));
    Ok(())
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::needless_raw_strings,
    reason = "tests"
)]
mod tests {
    use std::{io, time::Duration};

    use openssl::ssl::{SslAcceptor, SslConnector, SslMethod, SslVerifyMode};
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use tonic::transport::server::Connected as _;

    use super::*;

    fn make_test_acceptor() -> SslAcceptor {
        build_tls_config(&TlsConfig {
            mode: TlsMode::SelfSigned,
            cert_path: None,
            key_path: None,
            ca_cert_path: None,
        })
        .expect("build_tls_config")
        .expect("SelfSigned should return Some acceptor")
    }

    async fn connect_test_client(addr: SocketAddr) -> tokio_openssl::SslStream<TcpStream> {
        let mut builder = SslConnector::builder(SslMethod::tls()).expect("SslConnector builder");
        builder.set_verify(SslVerifyMode::NONE);
        let connector = builder.build();
        let tcp = TcpStream::connect(addr).await.expect("TCP connect");
        let ssl = connector
            .configure()
            .expect("configure")
            .into_ssl("localhost")
            .expect("into_ssl");
        let mut tls = tokio_openssl::SslStream::new(ssl, tcp).expect("SslStream::new");
        Pin::new(&mut tls).connect().await.expect("TLS handshake");
        tls
    }

    #[tokio::test]
    async fn build_tls_incoming_accepts_connection_and_exchanges_data() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("local addr");
        let mut incoming = build_tls_incoming(listener, make_test_acceptor(), HANDSHAKE_CONCURRENCY, HANDSHAKE_TIMEOUT);

        let server = tokio::spawn(async move {
            let mut stream = incoming.next().await.expect("stream item").expect("no TLS error");
            let info = stream.connect_info();
            assert!(info.local_addr.is_some(), "local addr should be populated");
            assert!(info.remote_addr.is_some(), "remote addr should be populated");
            let mut buf = [0_u8; 5];
            stream.read_exact(&mut buf).await.expect("server read");
            stream.write_all(&buf).await.expect("server write");
        });

        let client = tokio::spawn(async move {
            let mut tls = connect_test_client(addr).await;
            tls.write_all(b"hello").await.expect("client write");
            let mut buf = [0_u8; 5];
            tls.read_exact(&mut buf).await.expect("client read");
            assert_eq!(&buf, b"hello", "echoed bytes must match");
        });

        server.await.expect("server task");
        client.await.expect("client task");
    }

    #[tokio::test]
    async fn build_tls_incoming_timeout_drops_stalled_handshake() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let timeout = Duration::from_millis(100);
        let mut incoming = build_tls_incoming(listener, make_test_acceptor(), 1, timeout);

        // Connect raw TCP but never send a TLS ClientHello — this stalls the handshake.
        let _stall = TcpStream::connect(addr).await.expect("stall connect");

        let result = incoming.next().await.expect("should yield an item");
        assert!(result.is_err(), "stalled handshake should produce an error");
        let err = result.err().expect("checked: is_err() was true");
        assert_eq!(err.kind(), io::ErrorKind::TimedOut, "error kind should be TimedOut");
    }

    #[tokio::test]
    async fn build_tls_incoming_concurrency_holds_back_pressure() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let timeout = Duration::from_millis(150);
        let mut incoming = build_tls_incoming(listener, make_test_acceptor(), 1, timeout);

        // Occupy the single slot with a stalling connection.
        let _stall = TcpStream::connect(addr).await.expect("stall connect");

        // Legitimate client connects; TCP handshake completes in the OS backlog
        // but our accept loop cannot proceed until the slot is freed.
        let client = tokio::spawn(async move { connect_test_client(addr).await });

        // First item: the stalling connection times out.
        let first = incoming.next().await.expect("first item");
        assert!(first.is_err(), "stalled connection should time out");
        let first_err = first.err().expect("checked: is_err()");
        assert_eq!(first_err.kind(), io::ErrorKind::TimedOut, "should be timeout");

        // Second item: slot freed, legitimate client accepted and handshake succeeds.
        let second = incoming.next().await.expect("second item");
        assert!(second.is_ok(), "legitimate client should succeed after slot frees");

        drop(client.await.expect("client task"));
    }

    #[test]
    fn none_mode_rejects_cert_path() {
        let cfg = TlsConfig {
            mode: TlsMode::None,
            cert_path: Some("/some/cert.pem".to_owned()),
            key_path: None,
            ca_cert_path: None,
        };
        let result = build_tls_config(&cfg);
        assert!(result.is_err(), "none mode with cert_path should error");
        let err = result.err().expect("checked: is_err()");
        assert!(err.to_string().contains("cert_path"), "error should mention cert_path");
    }

    #[test]
    fn self_signed_mode_rejects_ca_cert_path() {
        let cfg = TlsConfig {
            mode: TlsMode::SelfSigned,
            cert_path: None,
            key_path: None,
            ca_cert_path: Some("/some/ca.pem".to_owned()),
        };
        let result = build_tls_config(&cfg);
        assert!(result.is_err(), "self_signed mode with ca_cert_path should error");
        let err = result.err().expect("checked: is_err()");
        assert!(
            err.to_string().contains("ca_cert_path"),
            "error should mention ca_cert_path"
        );
    }

    #[test]
    fn none_mode_returns_none() {
        let cfg = TlsConfig::default();
        let result = build_tls_config(&cfg).expect("should succeed");
        assert!(result.is_none(), "None mode should return None");
    }

    #[test]
    fn self_signed_mode_returns_some() {
        let cfg = TlsConfig {
            mode: TlsMode::SelfSigned,
            cert_path: None,
            key_path: None,
            ca_cert_path: None,
        };
        let result = build_tls_config(&cfg).expect("should succeed");
        assert!(result.is_some(), "SelfSigned mode should return Some");
    }

    #[test]
    fn provided_mode_missing_cert_path_errors() {
        let cfg = TlsConfig {
            mode: TlsMode::Provided,
            cert_path: None,
            key_path: Some("/tmp/key.pem".to_owned()),
            ca_cert_path: None,
        };
        let result = build_tls_config(&cfg);
        assert!(result.is_err(), "missing cert_path should error");
        let err = result.err().expect("checked: is_err() was true");
        assert!(err.to_string().contains("cert_path"), "error should mention cert_path");
    }

    #[test]
    fn provided_mode_missing_key_path_errors() {
        let cfg = TlsConfig {
            mode: TlsMode::Provided,
            cert_path: Some("/tmp/cert.pem".to_owned()),
            key_path: None,
            ca_cert_path: None,
        };
        let result = build_tls_config(&cfg);
        assert!(result.is_err(), "missing key_path should error");
        let err = result.err().expect("checked: is_err() was true");
        assert!(err.to_string().contains("key_path"), "error should mention key_path");
    }

    #[test]
    fn provided_mode_nonexistent_files_errors() {
        let cfg = TlsConfig {
            mode: TlsMode::Provided,
            cert_path: Some("/nonexistent/cert.pem".to_owned()),
            key_path: Some("/nonexistent/key.pem".to_owned()),
            ca_cert_path: None,
        };
        assert!(build_tls_config(&cfg).is_err(), "nonexistent files should error");
    }

    #[test]
    fn default_tls_mode_is_none() {
        assert!(matches!(TlsMode::default(), TlsMode::None), "default should be None");
    }

    #[test]
    fn tls_config_deserializes_self_signed() {
        let cfg: TlsConfig = serde_yaml::from_str("mode: self_signed").unwrap();
        assert!(
            matches!(cfg.mode, TlsMode::SelfSigned),
            "should deserialize self_signed"
        );
    }

    #[test]
    fn tls_config_deserializes_provided_with_paths() {
        let cfg: TlsConfig = serde_yaml::from_str(
            r#"
mode: provided
cert_path: /etc/tls/cert.pem
key_path: /etc/tls/key.pem
"#,
        )
        .unwrap();
        assert!(matches!(cfg.mode, TlsMode::Provided), "should deserialize provided");
        assert_eq!(
            cfg.cert_path.as_deref(),
            Some("/etc/tls/cert.pem"),
            "cert path should match"
        );
        assert_eq!(
            cfg.key_path.as_deref(),
            Some("/etc/tls/key.pem"),
            "key path should match"
        );
    }

    #[test]
    fn tls_config_deserializes_mtls() {
        let cfg: TlsConfig = serde_yaml::from_str(
            r#"
mode: provided
cert_path: /etc/tls/cert.pem
key_path: /etc/tls/key.pem
ca_cert_path: /etc/tls/ca.pem
"#,
        )
        .unwrap();
        assert_eq!(
            cfg.ca_cert_path.as_deref(),
            Some("/etc/tls/ca.pem"),
            "CA path should match"
        );
    }

    #[test]
    fn provided_mode_nonexistent_ca_cert_errors() {
        let server = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).expect("server cert generation");

        let tmp = std::env::temp_dir();
        let cert_path = tmp.join("praxis_tls_neg_test_cert.pem");
        let key_path = tmp.join("praxis_tls_neg_test_key.pem");

        std::fs::write(&cert_path, server.cert.pem()).expect("write cert");
        std::fs::write(&key_path, server.key_pair.serialize_pem()).expect("write key");

        let cfg = TlsConfig {
            mode: TlsMode::Provided,
            cert_path: Some(format!("{}", cert_path.display())),
            key_path: Some(format!("{}", key_path.display())),
            ca_cert_path: Some("/nonexistent/ca.pem".to_owned()),
        };

        let result = build_tls_config(&cfg);
        assert!(result.is_err(), "nonexistent CA cert should error");
        let err = result.err().expect("checked: is_err() was true");
        assert!(err.to_string().contains("CA"), "error should mention CA");
    }

    #[test]
    fn provided_mode_with_ca_cert_enables_mtls() {
        let ca = rcgen::generate_simple_self_signed(vec!["ca.example.com".to_owned()]).expect("CA cert generation");
        let server = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).expect("server cert generation");

        let tmp = std::env::temp_dir();
        let cert_path = tmp.join("praxis_tls_test_cert.pem");
        let key_path = tmp.join("praxis_tls_test_key.pem");
        let ca_path = tmp.join("praxis_tls_test_ca.pem");

        std::fs::write(&cert_path, server.cert.pem()).expect("write cert");
        std::fs::write(&key_path, server.key_pair.serialize_pem()).expect("write key");
        std::fs::write(&ca_path, ca.cert.pem()).expect("write CA cert");

        let cfg = TlsConfig {
            mode: TlsMode::Provided,
            cert_path: Some(format!("{}", cert_path.display())),
            key_path: Some(format!("{}", key_path.display())),
            ca_cert_path: Some(format!("{}", ca_path.display())),
        };

        let result = build_tls_config(&cfg);
        assert!(result.is_ok(), "mTLS config should load without error");
        let acceptor = result.ok().flatten().expect("should return Some acceptor");
        let verify_mode = acceptor.context().verify_mode();
        assert!(
            verify_mode.contains(SslVerifyMode::PEER),
            "acceptor should require client certificate"
        );
        assert!(
            verify_mode.contains(SslVerifyMode::FAIL_IF_NO_PEER_CERT),
            "acceptor should reject missing client certificate"
        );
    }
}
