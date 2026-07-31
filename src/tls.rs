// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Shane Utt

//! TLS configuration for the ExtProc gRPC listener.
//!
//! Supports three modes: self-signed (ephemeral cert), provided
//! (cert and key from disk), and plaintext (no TLS).
//!
//! TLS termination uses [`native-tls`] which delegates to the system's
//! `OpenSSL` on Linux, enabling FIPS compliance via the OS TLS library.

use std::{
    io,
    net::SocketAddr,
    pin::Pin,
    task::{Context, Poll},
};

use native_tls::{Identity, TlsAcceptor};
use serde::Deserialize;
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::{TcpListener, TcpStream},
};
use tokio_native_tls::TlsAcceptor as TokioTlsAcceptor;
use tokio_stream::{Stream, StreamExt as _, wrappers::TcpListenerStream};
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
// NativeTlsStream
// -----------------------------------------------------------------------------

/// A TLS-wrapped [`TcpStream`] that implements [`Connected`], [`AsyncRead`],
/// and [`AsyncWrite`] for use with tonic's `serve_with_incoming_shutdown`.
pub struct NativeTlsStream {
    /// Underlying TLS stream.
    inner: tokio_native_tls::TlsStream<TcpStream>,
    /// Local socket address, captured before the TLS handshake.
    local_addr: Option<SocketAddr>,
    /// Remote socket address, captured before the TLS handshake.
    remote_addr: Option<SocketAddr>,
}

impl Connected for NativeTlsStream {
    type ConnectInfo = TcpConnectInfo;

    fn connect_info(&self) -> Self::ConnectInfo {
        TcpConnectInfo {
            local_addr: self.local_addr,
            remote_addr: self.remote_addr,
        }
    }
}

impl AsyncRead for NativeTlsStream {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for NativeTlsStream {
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

/// Build a [`TokioTlsAcceptor`] from the TLS settings.
///
/// Returns `None` for plaintext mode. Generates a self-signed cert
/// or loads from disk depending on the mode.
///
/// # Errors
///
/// Returns an error if cert/key/CA files cannot be read or if
/// self-signed certificate generation fails.
pub fn build_tls_config(cfg: &TlsConfig) -> crate::error::Result<Option<TokioTlsAcceptor>> {
    match cfg.mode {
        TlsMode::None => Ok(None),
        TlsMode::SelfSigned => build_self_signed().map(Some),
        TlsMode::Provided => build_provided(cfg).map(Some),
    }
}

/// Build a stream of TLS-wrapped connections from a bound [`TcpListener`].
///
/// Each incoming TCP connection is upgraded via the provided [`TokioTlsAcceptor`].
/// The resulting stream yields [`NativeTlsStream`] items for use with
/// tonic's `serve_with_incoming_shutdown`.
pub fn build_tls_incoming(
    listener: TcpListener,
    acceptor: TokioTlsAcceptor,
) -> impl Stream<Item = Result<NativeTlsStream, io::Error>> {
    TcpListenerStream::new(listener).then(move |result| {
        let acceptor = acceptor.clone();
        async move {
            let stream = result?;
            let local_addr = stream.local_addr().ok();
            let remote_addr = stream.peer_addr().ok();
            let inner = acceptor
                .accept(stream)
                .await
                .map_err(|e| io::Error::new(io::ErrorKind::ConnectionAborted, e))?;
            Ok(NativeTlsStream {
                inner,
                local_addr,
                remote_addr,
            })
        }
    })
}

/// Generate an ephemeral self-signed certificate using `rcgen`.
fn build_self_signed() -> crate::error::Result<TokioTlsAcceptor> {
    info!("generating self-signed TLS certificate");

    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()])
        .map_err(|e| crate::error::ExtProcError::Config(format!("self-signed cert: {e}")))?;

    let cert_pem = cert.cert.pem();
    let key_pem = cert.key_pair.serialize_pem();

    let identity = Identity::from_pkcs8(cert_pem.as_bytes(), key_pem.as_bytes())
        .map_err(|e| crate::error::ExtProcError::Config(format!("identity: {e}")))?;

    let mut builder = TlsAcceptor::builder(identity);
    builder.accept_alpn(&["h2"]);
    builder
        .build()
        .map(TokioTlsAcceptor::from)
        .map_err(|e| crate::error::ExtProcError::Config(format!("TLS acceptor: {e}")))
}

/// Load certificate and key from disk, optionally configuring mTLS.
///
/// # Errors
///
/// Returns an error if `cert_path` or `key_path` is missing, if any
/// file cannot be read, or if TLS acceptor construction fails.
fn build_provided(cfg: &TlsConfig) -> crate::error::Result<TokioTlsAcceptor> {
    let cert_path = cfg
        .cert_path
        .as_deref()
        .ok_or_else(|| crate::error::ExtProcError::Config("tls.cert_path required for provided mode".to_owned()))?;

    let key_path = cfg
        .key_path
        .as_deref()
        .ok_or_else(|| crate::error::ExtProcError::Config("tls.key_path required for provided mode".to_owned()))?;

    info!(cert = cert_path, key = key_path, "loading TLS certificate");

    let cert_pem =
        std::fs::read(cert_path).map_err(|e| crate::error::ExtProcError::Config(format!("read {cert_path}: {e}")))?;
    let key_pem =
        std::fs::read(key_path).map_err(|e| crate::error::ExtProcError::Config(format!("read {key_path}: {e}")))?;

    let identity = Identity::from_pkcs8(&cert_pem, &key_pem)
        .map_err(|e| crate::error::ExtProcError::Config(format!("identity: {e}")))?;

    if cfg.ca_cert_path.is_some() {
        return Err(crate::error::ExtProcError::Config(
            "mTLS client certificate verification requires the openssl crate and is not yet supported; remove ca_cert_path".to_owned(),
        ));
    }

    let mut builder = TlsAcceptor::builder(identity);
    builder.accept_alpn(&["h2"]);
    builder
        .build()
        .map(TokioTlsAcceptor::from)
        .map_err(|e| crate::error::ExtProcError::Config(format!("TLS acceptor: {e}")))
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
    use super::*;

    #[test]
    fn none_mode_returns_none() {
        let cfg = TlsConfig::default();
        let result = build_tls_config(&cfg).expect("should succeed");
        assert!(result.is_none(), "None mode should return None");
    }

    #[test]
    #[cfg(not(target_os = "macos"))]
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
        let err = build_tls_config(&cfg).unwrap_err();
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
        let err = build_tls_config(&cfg).unwrap_err();
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
}
