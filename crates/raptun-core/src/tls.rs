//! QUIC/TLS setup for Raptun.
//!
//! QUIC mandates TLS 1.3, so the channel is always encrypted and the *server*
//! is always authenticated — Raptun does not implement any of its own crypto
//! for the data path. What this module adds is the tunnel-appropriate trust
//! model:
//!
//! * **Self-signed + fingerprint pinning (trust-on-first-use).** Tunnels rarely
//!   have a public-CA name, so by default the server mints a self-signed cert
//!   with [`rcgen`] and prints its SHA-256 fingerprint; the client is configured
//!   (out of band) to trust exactly that fingerprint. This defeats MITM without
//!   a CA.
//! * **App-level PSK.** The `--psk` is *not* a second encryption layer — the
//!   channel is already encrypted. It authenticates the *client* to the server
//!   so unauthorized peers can't consume resources, and is checked in the
//!   [`crate::session`] handshake, not here.

use std::sync::Arc;

use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{verify_tls12_signature, verify_tls13_signature, CryptoProvider};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use sha2::{Digest, Sha256};

use crate::{CoreError, Result};

/// ALPN protocol identifier advertised by both ends. Namespacing the tunnel on
/// its own ALPN keeps it from being confused with HTTP/3 on shared ports.
pub const ALPN: &[u8] = b"raptun/1";

/// Ensure a process-wide rustls [`CryptoProvider`] is installed (ring backend).
///
/// rustls 0.23 requires a default provider to be installed before building any
/// config unless one is passed explicitly. Calling this more than once is
/// harmless — the second install simply fails and we ignore it.
pub fn ensure_crypto_provider() {
    // `install_default` returns Err if one is already installed; that's fine.
    let _ = rustls::crypto::ring::default_provider().install_default();
}

/// A server's TLS identity: certificate chain + private key, plus the
/// fingerprint to hand operators for client pinning.
pub struct ServerIdentity {
    /// DER-encoded certificate chain (leaf first).
    pub cert_chain: Vec<CertificateDer<'static>>,
    /// DER-encoded PKCS#8 private key.
    pub private_key: PrivateKeyDer<'static>,
    /// Hex SHA-256 of the leaf certificate DER, for `--fingerprint` pinning.
    pub fingerprint_hex: String,
}

impl ServerIdentity {
    /// Generate a fresh self-signed identity valid for `sni`.
    pub fn generate_self_signed(sni: &str) -> Result<Self> {
        let certified = rcgen::generate_simple_self_signed(vec![sni.to_string()])
            .map_err(|e| CoreError::Tls(format!("rcgen: {e}")))?;

        // `cert.der()` yields the leaf DER; the key pair serializes to PKCS#8 DER.
        let leaf_der = certified.cert.der().clone();
        let key_der = PrivateKeyDer::try_from(certified.key_pair.serialize_der())
            .map_err(|e| CoreError::Tls(format!("private key: {e}")))?;
        let fingerprint_hex = fingerprint_of(&leaf_der);

        Ok(Self {
            cert_chain: vec![leaf_der],
            private_key: key_der,
            fingerprint_hex,
        })
    }

    /// Load a PEM certificate chain + private key from operator-provided bytes.
    pub fn load_pem(cert_pem: &[u8], key_pem: &[u8]) -> Result<Self> {
        let cert_chain = rustls_pemfile::certs(&mut &cert_pem[..])
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|e| CoreError::Tls(format!("cert pem: {e}")))?;
        if cert_chain.is_empty() {
            return Err(CoreError::Tls("no certificates in PEM".into()));
        }
        let private_key = rustls_pemfile::private_key(&mut &key_pem[..])
            .map_err(|e| CoreError::Tls(format!("key pem: {e}")))?
            .ok_or_else(|| CoreError::Tls("no private key in PEM".into()))?;
        let fingerprint_hex = fingerprint_of(&cert_chain[0]);
        Ok(Self {
            cert_chain,
            private_key,
            fingerprint_hex,
        })
    }
}

/// Compute the `SHA256:<hex>` fingerprint of a DER certificate, matching the
/// form printed by the server and accepted by `--fingerprint`.
pub fn fingerprint_of(cert: &CertificateDer<'_>) -> String {
    let digest = Sha256::digest(cert.as_ref());
    format!("SHA256:{}", hex::encode(digest))
}

/// How a client decides whether to trust the server's certificate.
#[derive(Debug, Clone)]
pub enum ServerTrust {
    /// Trust exactly this leaf-certificate fingerprint (`SHA256:<hex>` or bare
    /// hex). The recommended tunnel mode.
    Fingerprint(String),
    /// Skip verification entirely. **Testing only** — vulnerable to MITM.
    Insecure,
}

/// Build a `quinn::ClientConfig` implementing [`ServerTrust`].
///
/// When `allow_0rtt` is `true`, the underlying rustls client config enables
/// TLS 1.3 early data (0-RTT), allowing the client to send application data
/// before the handshake completes on subsequent connections (when the server
/// has issued a session ticket).
pub fn client_config(trust: &ServerTrust, allow_0rtt: bool) -> Result<quinn::ClientConfig> {
    ensure_crypto_provider();

    let verifier: Arc<dyn ServerCertVerifier> = match trust {
        ServerTrust::Fingerprint(fp) => Arc::new(PinnedFingerprintVerifier::new(fp)),
        ServerTrust::Insecure => Arc::new(NoVerification::new()),
    };

    let mut crypto = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    crypto.alpn_protocols = vec![ALPN.to_vec()];
    crypto.enable_early_data = allow_0rtt;

    let quic = QuicClientConfig::try_from(crypto)
        .map_err(|e| CoreError::Tls(format!("quic client config: {e}")))?;
    Ok(quinn::ClientConfig::new(Arc::new(quic)))
}

/// Build a `quinn::ServerConfig` from a [`ServerIdentity`]. The returned config
/// still needs its transport parameters set by [`crate::endpoint`].
pub fn server_config(identity: &ServerIdentity) -> Result<quinn::ServerConfig> {
    ensure_crypto_provider();

    let mut crypto = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            identity.cert_chain.clone(),
            identity.private_key.clone_key(),
        )
        .map_err(|e| CoreError::Tls(format!("server single cert: {e}")))?;
    crypto.alpn_protocols = vec![ALPN.to_vec()];

    let quic = QuicServerConfig::try_from(crypto)
        .map_err(|e| CoreError::Tls(format!("quic server config: {e}")))?;
    Ok(quinn::ServerConfig::with_crypto(Arc::new(quic)))
}

/// Normalize a fingerprint string to lowercase hex without the `SHA256:` prefix
/// or any separators, so pins can be pasted in either form.
fn normalize_fingerprint(fp: &str) -> String {
    fp.trim()
        .strip_prefix("SHA256:")
        .or_else(|| fp.trim().strip_prefix("sha256:"))
        .unwrap_or(fp.trim())
        .chars()
        .filter(|c| !c.is_whitespace() && *c != ':')
        .flat_map(|c| c.to_lowercase())
        .collect()
}

/// A [`ServerCertVerifier`] that accepts a server certificate iff its leaf
/// SHA-256 matches a pinned value. Signature verification (proving the server
/// holds the matching private key) is delegated to the standard webpki helpers,
/// so pinning does not weaken the handshake — it only replaces chain-to-CA
/// validation with exact-leaf matching.
#[derive(Debug)]
struct PinnedFingerprintVerifier {
    expected_hex: String,
    provider: Arc<CryptoProvider>,
}

impl PinnedFingerprintVerifier {
    fn new(fingerprint: &str) -> Self {
        Self {
            expected_hex: normalize_fingerprint(fingerprint),
            provider: Arc::new(rustls::crypto::ring::default_provider()),
        }
    }
}

impl ServerCertVerifier for PinnedFingerprintVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        let presented = fingerprint_of(end_entity);
        let presented_hex = normalize_fingerprint(&presented);
        // Constant-time-ish compare on equal-length hex strings.
        if presented_hex.len() == self.expected_hex.len()
            && presented_hex
                .bytes()
                .zip(self.expected_hex.bytes())
                .fold(0u8, |acc, (a, b)| acc | (a ^ b))
                == 0
        {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General(
                "server certificate fingerprint mismatch".into(),
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// A verifier that accepts anything. **Testing only.**
#[derive(Debug)]
struct NoVerification {
    provider: Arc<CryptoProvider>,
}

impl NoVerification {
    fn new() -> Self {
        Self {
            provider: Arc::new(rustls::crypto::ring::default_provider()),
        }
    }
}

impl ServerCertVerifier for NoVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Constant-time comparison of a presented PSK against the configured one.
///
/// Used by the session handshake. Constant-time to avoid leaking the secret via
/// timing. Returns `true` when both are absent (anonymous allowed) or equal.
pub fn psk_matches(configured: Option<&str>, presented: &[u8]) -> bool {
    match configured {
        None => presented.is_empty(),
        Some(secret) => {
            let a = secret.as_bytes();
            if a.len() != presented.len() {
                return false;
            }
            let mut diff = 0u8;
            for (x, y) in a.iter().zip(presented.iter()) {
                diff |= x ^ y;
            }
            diff == 0
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn psk_constant_time_compare() {
        assert!(psk_matches(Some("hunter2"), b"hunter2"));
        assert!(!psk_matches(Some("hunter2"), b"hunter3"));
        assert!(!psk_matches(Some("hunter2"), b"short"));
        assert!(psk_matches(None, b""));
        assert!(!psk_matches(None, b"anything"));
    }

    #[test]
    fn fingerprint_normalization() {
        assert_eq!(normalize_fingerprint("SHA256:AABBCC"), "aabbcc");
        assert_eq!(normalize_fingerprint("aa:bb:cc"), "aabbcc");
        assert_eq!(normalize_fingerprint("  aabbcc  "), "aabbcc");
    }

    #[test]
    fn self_signed_identity_has_matching_fingerprint() {
        let id = ServerIdentity::generate_self_signed("raptun.test").unwrap();
        assert!(id.fingerprint_hex.starts_with("SHA256:"));
        // The advertised fingerprint must equal the hash of the leaf we ship.
        assert_eq!(id.fingerprint_hex, fingerprint_of(&id.cert_chain[0]));
    }

    #[test]
    fn client_config_builds_for_each_trust_mode() {
        let id = ServerIdentity::generate_self_signed("raptun.test").unwrap();
        assert!(client_config(&ServerTrust::Fingerprint(id.fingerprint_hex.clone()), false).is_ok());
        assert!(client_config(&ServerTrust::Insecure, false).is_ok());
        assert!(client_config(&ServerTrust::Insecure, true).is_ok());
        assert!(server_config(&id).is_ok());
    }
}
