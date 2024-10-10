use crate::cert::verify::CertVerifier;
use crate::cert::verify::VerifiyPolicy::Contains;
use crate::cert::verify::VerifyPolicyOutput;
use crate::tee::claims::Claims;
use std::sync::Arc;
use tokio_rustls::rustls::client::danger::HandshakeSignatureValid;
use tokio_rustls::rustls::client::danger::ServerCertVerified;
use tokio_rustls::rustls::server::danger::ClientCertVerified;
use tokio_rustls::rustls::server::ParsedCertificate;
use tokio_rustls::rustls::CertificateError;
use tokio_rustls::rustls::Error;
use tokio_rustls::rustls::{
    client::{danger::ServerCertVerifier, WebPkiServerVerifier},
    server::{danger::ClientCertVerifier, WebPkiClientVerifier},
};

pub mod client;
pub mod server;

pub use client::RustlsClient;
pub use server::RustlsServer;

#[derive(Debug)]
struct RatsClientVerifier {
    default_client_verifier: Arc<dyn ClientCertVerifier>,
}

#[derive(Debug)]
struct RatsServerVerifier {
    default_server_verifier: Arc<WebPkiServerVerifier>,
}

impl ClientCertVerifier for RatsClientVerifier {
    fn root_hint_subjects(&self) -> &[tokio_rustls::rustls::DistinguishedName] {
        self.default_client_verifier.root_hint_subjects()
    }

    fn verify_client_cert(
        &self,
        end_entity: &tokio_rustls::rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[tokio_rustls::rustls::pki_types::CertificateDer<'_>],
        _now: tokio_rustls::rustls::pki_types::UnixTime,
    ) -> Result<tokio_rustls::rustls::server::danger::ClientCertVerified, Error> {
        let res = CertVerifier::new(Contains(Claims::new())).verify(&end_entity);
        match res {
            Ok(VerifyPolicyOutput::Passed) => {
                return Ok(ClientCertVerified::assertion());
            }
            Ok(VerifyPolicyOutput::Failed) => {
                return Err(Error::General(
                    "Verify failed because of claims".to_string(),
                ));
            }
            Err(err) => {
                return Err(Error::General(
                    format!("Verify failed with err: {:?}", err).to_string(),
                ));
            }
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &tokio_rustls::rustls::pki_types::CertificateDer<'_>,
        dss: &tokio_rustls::rustls::DigitallySignedStruct,
    ) -> Result<tokio_rustls::rustls::client::danger::HandshakeSignatureValid, Error> {
        self.default_client_verifier
            .verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &tokio_rustls::rustls::pki_types::CertificateDer<'_>,
        dss: &tokio_rustls::rustls::DigitallySignedStruct,
    ) -> Result<tokio_rustls::rustls::client::danger::HandshakeSignatureValid, Error> {
        self.default_client_verifier
            .verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<tokio_rustls::rustls::SignatureScheme> {
        self.default_client_verifier.supported_verify_schemes()
    }
}

impl ServerCertVerifier for RatsServerVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &tokio_rustls::rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[tokio_rustls::rustls::pki_types::CertificateDer<'_>],
        _server_name: &tokio_rustls::rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: tokio_rustls::rustls::pki_types::UnixTime,
    ) -> Result<tokio_rustls::rustls::client::danger::ServerCertVerified, tokio_rustls::rustls::Error>
    {
        let res = CertVerifier::new(Contains(Claims::new())).verify(&end_entity);
        match res {
            Ok(VerifyPolicyOutput::Passed) => {
                return Ok(ServerCertVerified::assertion());
            }
            Ok(VerifyPolicyOutput::Failed) => {
                return Err(Error::General(
                    "Verify failed because of claims".to_string(),
                ));
            }
            Err(err) => {
                return Err(Error::General(
                    format!("Verify failed with err: {:?}", err).to_string(),
                ));
            }
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &tokio_rustls::rustls::pki_types::CertificateDer<'_>,
        dss: &tokio_rustls::rustls::DigitallySignedStruct,
    ) -> Result<
        tokio_rustls::rustls::client::danger::HandshakeSignatureValid,
        tokio_rustls::rustls::Error,
    > {
        self.default_server_verifier
            .verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &tokio_rustls::rustls::pki_types::CertificateDer<'_>,
        dss: &tokio_rustls::rustls::DigitallySignedStruct,
    ) -> Result<
        tokio_rustls::rustls::client::danger::HandshakeSignatureValid,
        tokio_rustls::rustls::Error,
    > {
        self.default_server_verifier
            .verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<tokio_rustls::rustls::SignatureScheme> {
        self.default_server_verifier.supported_verify_schemes()
    }
}

#[cfg(test)]
mod test {}
