pub mod element;

use crate::crypto::*;
use crate::errors::*;

use pkcs8::{AssociatedOid, LineEnding, ObjectIdentifier};
use std::str::FromStr;
use std::time::Duration;
use x509_cert::builder::Builder;
use x509_cert::builder::{CertificateBuilder, Profile};
use x509_cert::der::EncodePem;
use x509_cert::ext::AsExtension;
use x509_cert::name::Name;
use x509_cert::serial_number::SerialNumber;
use x509_cert::spki::SubjectPublicKeyInfoOwned;
use x509_cert::time::Validity;

pub const OID_TCG_DICE_TAGGED_EVIDENCE: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.23.133.5.4.9");

struct DiceEvidenceExtension<T: AsRef<[u8]>>(T);

impl<T: AsRef<[u8]>> AssociatedOid for DiceEvidenceExtension<T> {
    const OID: ObjectIdentifier = OID_TCG_DICE_TAGGED_EVIDENCE;
}

impl<T: AsRef<[u8]>> x509_cert::der::Encode for DiceEvidenceExtension<T> {
    fn encoded_len(&self) -> x509_cert::der::Result<x509_cert::der::Length> {
        Ok(x509_cert::der::Length::new(self.0.as_ref().len() as u16))
    }

    fn encode(&self, encoder: &mut impl x509_cert::der::Writer) -> x509_cert::der::Result<()> {
        encoder.write(self.0.as_ref())
    }
}

impl<T: AsRef<[u8]>> AsExtension for DiceEvidenceExtension<T> {
    fn critical(
        &self,
        _subject: &x509_cert::name::Name,
        _extensions: &[x509_cert::ext::Extension],
    ) -> bool {
        false
    }

    fn to_extension(
        &self,
        subject: &x509_cert::name::Name,
        extensions: &[x509_cert::ext::Extension],
    ) -> std::prelude::v1::Result<x509_cert::ext::Extension, x509_cert::der::Error> {
        let content = x509_cert::der::asn1::OctetString::new(self.0.as_ref())?;

        Ok(x509_cert::ext::Extension {
            extn_id: <Self as AssociatedOid>::OID,
            critical: self.critical(subject, extensions),
            extn_value: content,
        })
    }
}

pub const OID_TCG_DICE_ENDORSEMENT_MANIFEST: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("2.23.133.5.4.2");

struct DiceEndorsementExtension<T: AsRef<[u8]>>(T);

impl<T: AsRef<[u8]>> AssociatedOid for DiceEndorsementExtension<T> {
    const OID: ObjectIdentifier = OID_TCG_DICE_ENDORSEMENT_MANIFEST;
}

impl<T: AsRef<[u8]>> x509_cert::der::Encode for DiceEndorsementExtension<T> {
    fn encoded_len(&self) -> x509_cert::der::Result<x509_cert::der::Length> {
        Ok(x509_cert::der::Length::new(self.0.as_ref().len() as u16))
    }

    fn encode(&self, encoder: &mut impl x509_cert::der::Writer) -> x509_cert::der::Result<()> {
        encoder.write(self.0.as_ref())
    }
}

impl<T: AsRef<[u8]>> AsExtension for DiceEndorsementExtension<T> {
    fn critical(
        &self,
        _subject: &x509_cert::name::Name,
        _extensions: &[x509_cert::ext::Extension],
    ) -> bool {
        false
    }

    fn to_extension(
        &self,
        subject: &x509_cert::name::Name,
        extensions: &[x509_cert::ext::Extension],
    ) -> std::prelude::v1::Result<x509_cert::ext::Extension, x509_cert::der::Error> {
        let content = x509_cert::der::asn1::OctetString::new(self.0.as_ref())?;

        Ok(x509_cert::ext::Extension {
            extn_id: <Self as AssociatedOid>::OID,
            critical: self.critical(subject, extensions),
            extn_value: content,
        })
    }
}

pub fn gen_cert_pem(
    subject: &str,
    hash_algo: HashAlgo,
    private_key: &AsymmetricPrivateKey,
    evidence_buffer: &[u8],
    endorsements_buffer: Option<&[u8]>,
) -> Result<String> {
    let serial_number = SerialNumber::from(42u32);
    let validity = Validity::from_now(Duration::new(5, 0))
        .kind(ErrorKind::GenCertError)
        .context("bad validity value")?;
    let profile = Profile::Root;
    let subject = Name::from_str(subject)
        .kind(ErrorKind::GenCertError)
        .context("bad subject value")?;

    let pub_key_info = match private_key {
        AsymmetricPrivateKey::Rsa(key) => SubjectPublicKeyInfoOwned::from_key(key.to_public_key()),
        AsymmetricPrivateKey::P256(key) => SubjectPublicKeyInfoOwned::from_key(key.public_key()),
    }
    .kind(ErrorKind::GenCertError)
    .context("failed to create SubjectPublicKeyInfo")?;

    #[macro_export]
    macro_rules! build_with_signer {
        ($signer:expr) => {
            build_with_signer!($signer, _)
        };
        ($signer:expr, $signature_type:ty) => {{
            let signer = $signer;

            let mut builder = CertificateBuilder::new(
                profile,
                serial_number,
                validity,
                subject,
                pub_key_info,
                &signer,
            )
            .kind(ErrorKind::GenCertError)
            .context("failed to create certificate builder")?;

            builder
                .add_extension(&DiceEvidenceExtension(evidence_buffer))
                .kind(ErrorKind::GenCertError)
                .context("failed to add evidence extension")?;

            if let Some(endorsements_buffer) = endorsements_buffer {
                builder
                    .add_extension(&DiceEndorsementExtension(endorsements_buffer))
                    .kind(ErrorKind::GenCertError)
                    .context("failed to add endorsement extension")?;
            }

            let certificate: x509_cert::Certificate = builder
                .build::<$signature_type>()
                .kind(ErrorKind::GenCertError)
                .context("failed to create certificate")?;

            certificate
        }};
    }

    let certificate = match private_key {
        AsymmetricPrivateKey::Rsa(key) => match hash_algo {
            HashAlgo::Sha256 => {
                build_with_signer!(rsa::pkcs1v15::SigningKey::<sha2::Sha256>::new(key.clone()))
            }
            HashAlgo::Sha384 => {
                build_with_signer!(rsa::pkcs1v15::SigningKey::<sha2::Sha384>::new(key.clone()))
            }
            HashAlgo::Sha512 => {
                build_with_signer!(rsa::pkcs1v15::SigningKey::<sha2::Sha512>::new(key.clone()))
            }
        },
        AsymmetricPrivateKey::P256(key) => {
            /* for p256(prime256v1), the hash algorithm implicitly is sha256 */
            build_with_signer!(
                p256::ecdsa::SigningKey::from(key),
                p256::ecdsa::DerSignature
            )
        }
    };

    let pem = certificate
        .to_pem(LineEnding::LF)
        .kind(ErrorKind::GenCertError)
        .context("failed to encode certificate as pem")?;

    Ok(pem)
}

#[cfg(test)]
pub mod tests {

    use super::*;

    #[test]
    fn test_gen_cert() -> Result<()> {
        let key = DefaultCrypto::gen_private_key(AsymmetricAlgo::Ecc256)?;
        let pem = gen_cert_pem(
            "CN=rats-rs,O=Inclavare Containers",
            HashAlgo::Sha256,
            &key,
            b"\x01\x02\x03\x04",
            Some(b"\x05\x06\x07\x08"),
        )?;
        println!("generated pem:\n{}", pem);
        // you can also view the cert manually with https://certificatedecoder.dev/

        Ok(())
    }
}
