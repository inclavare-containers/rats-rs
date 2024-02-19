// Copyright (c) 2021 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0 or MIT

use rsa::signature::{RandomizedSigner, SignatureEncoding};
use spdmlib::secret::asym_sign::SecretAsymSigner;

use spdmlib::protocol::{SpdmBaseAsymAlgo, SpdmBaseHashAlgo, SpdmSignatureStruct};

use crate::crypto::AsymmetricPrivateKey;

pub struct RatsSecretAsymSigner {
    private_key: AsymmetricPrivateKey,
}

impl RatsSecretAsymSigner {
    pub fn new(private_key: AsymmetricPrivateKey) -> Self {
        Self { private_key }
    }
}

impl SecretAsymSigner for RatsSecretAsymSigner {
    fn supported_algo(&self) -> (SpdmBaseHashAlgo, SpdmBaseAsymAlgo) {
        (
            SpdmBaseHashAlgo::all(),
            match &self.private_key {
                AsymmetricPrivateKey::Rsa2048(_) => {
                    SpdmBaseAsymAlgo::TPM_ALG_RSASSA_2048 | SpdmBaseAsymAlgo::TPM_ALG_RSAPSS_2048
                }
                AsymmetricPrivateKey::Rsa3072(_) => {
                    SpdmBaseAsymAlgo::TPM_ALG_RSASSA_3072 | SpdmBaseAsymAlgo::TPM_ALG_RSAPSS_3072
                }
                AsymmetricPrivateKey::Rsa4096(_) => {
                    SpdmBaseAsymAlgo::TPM_ALG_RSASSA_4096 | SpdmBaseAsymAlgo::TPM_ALG_RSAPSS_4096
                }
                AsymmetricPrivateKey::P256(_) => SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P256,
            },
        )
    }

    fn sign(
        &self,
        base_hash_algo: SpdmBaseHashAlgo,
        base_asym_algo: SpdmBaseAsymAlgo,
        data: &[u8],
    ) -> Option<SpdmSignatureStruct> {
        let digest = match (&self.private_key, base_asym_algo) {
            (AsymmetricPrivateKey::Rsa2048(key), SpdmBaseAsymAlgo::TPM_ALG_RSAPSS_2048)
            | (AsymmetricPrivateKey::Rsa3072(key), SpdmBaseAsymAlgo::TPM_ALG_RSAPSS_3072)
            | (AsymmetricPrivateKey::Rsa4096(key), SpdmBaseAsymAlgo::TPM_ALG_RSAPSS_4096) => {
                match base_hash_algo {
                    SpdmBaseHashAlgo::TPM_ALG_SHA_256 => {
                        rsa::pss::SigningKey::<sha2::Sha256>::new(key.clone())
                            .sign_with_rng(&mut rand::rngs::OsRng, data)
                            .to_bytes()
                    }
                    SpdmBaseHashAlgo::TPM_ALG_SHA_384 => {
                        rsa::pss::SigningKey::<sha2::Sha256>::new(key.clone())
                            .sign_with_rng(&mut rand::rngs::OsRng, data)
                            .to_bytes()
                    }
                    SpdmBaseHashAlgo::TPM_ALG_SHA_512 => {
                        rsa::pss::SigningKey::<sha2::Sha256>::new(key.clone())
                            .sign_with_rng(&mut rand::rngs::OsRng, data)
                            .to_bytes()
                    }
                    _ => unreachable!(),
                }
            }
            (AsymmetricPrivateKey::Rsa2048(key), SpdmBaseAsymAlgo::TPM_ALG_RSASSA_2048)
            | (AsymmetricPrivateKey::Rsa3072(key), SpdmBaseAsymAlgo::TPM_ALG_RSASSA_3072)
            | (AsymmetricPrivateKey::Rsa4096(key), SpdmBaseAsymAlgo::TPM_ALG_RSASSA_4096) => {
                match base_hash_algo {
                    SpdmBaseHashAlgo::TPM_ALG_SHA_256 => {
                        rsa::pkcs1v15::SigningKey::<sha2::Sha256>::new(key.clone())
                            .sign_with_rng(&mut rand::rngs::OsRng, data)
                            .to_bytes()
                    }
                    SpdmBaseHashAlgo::TPM_ALG_SHA_384 => {
                        rsa::pkcs1v15::SigningKey::<sha2::Sha256>::new(key.clone())
                            .sign_with_rng(&mut rand::rngs::OsRng, data)
                            .to_bytes()
                    }
                    SpdmBaseHashAlgo::TPM_ALG_SHA_512 => {
                        rsa::pkcs1v15::SigningKey::<sha2::Sha256>::new(key.clone())
                            .sign_with_rng(&mut rand::rngs::OsRng, data)
                            .to_bytes()
                    }
                    _ => unreachable!(),
                }
            }
            (AsymmetricPrivateKey::P256(key), SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P256) => {
                let sign_key = p256::ecdsa::SigningKey::from(key);
                let k: p256::ecdsa::Signature =
                    sign_key.sign_with_rng(&mut rand::rngs::OsRng, data);
                k.to_vec().into()
            }
            _ => {
                panic!("unsupported operation, maybe code bug triggered")
            }
        };
        let mut res = SpdmSignatureStruct {
            data_size: digest.len() as u16,
            ..Default::default()
        };
        res.data[..digest.len()].copy_from_slice(&digest);
        Some(res)
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use spdmlib::protocol::{
        SpdmBaseAsymAlgo, SpdmBaseHashAlgo, SpdmSignatureStruct, RSAPSS_2048_KEY_SIZE,
        RSAPSS_3072_KEY_SIZE, RSAPSS_4096_KEY_SIZE, RSASSA_2048_KEY_SIZE, RSASSA_3072_KEY_SIZE,
        RSASSA_4096_KEY_SIZE, SPDM_MAX_ASYM_KEY_SIZE,
    };
    use std::path::PathBuf;

    pub struct DummySecretAsymSigner {}

    impl SecretAsymSigner for DummySecretAsymSigner {
        fn sign(
            &self,
            base_hash_algo: SpdmBaseHashAlgo,
            base_asym_algo: SpdmBaseAsymAlgo,
            data: &[u8],
        ) -> Option<SpdmSignatureStruct> {
            match (base_hash_algo, base_asym_algo) {
                (
                    SpdmBaseHashAlgo::TPM_ALG_SHA_256,
                    SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P256,
                ) => sign_ecdsa_asym_algo(&ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING, data),
                (
                    SpdmBaseHashAlgo::TPM_ALG_SHA_384,
                    SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384,
                ) => sign_ecdsa_asym_algo(&ring::signature::ECDSA_P384_SHA384_FIXED_SIGNING, data),
                (SpdmBaseHashAlgo::TPM_ALG_SHA_256, SpdmBaseAsymAlgo::TPM_ALG_RSASSA_2048)
                | (SpdmBaseHashAlgo::TPM_ALG_SHA_256, SpdmBaseAsymAlgo::TPM_ALG_RSASSA_3072)
                | (SpdmBaseHashAlgo::TPM_ALG_SHA_256, SpdmBaseAsymAlgo::TPM_ALG_RSASSA_4096) => {
                    sign_rsa_asym_algo(
                        &ring::signature::RSA_PKCS1_SHA256,
                        base_asym_algo.get_size() as usize,
                        data,
                    )
                }
                (SpdmBaseHashAlgo::TPM_ALG_SHA_256, SpdmBaseAsymAlgo::TPM_ALG_RSAPSS_2048)
                | (SpdmBaseHashAlgo::TPM_ALG_SHA_256, SpdmBaseAsymAlgo::TPM_ALG_RSAPSS_3072)
                | (SpdmBaseHashAlgo::TPM_ALG_SHA_256, SpdmBaseAsymAlgo::TPM_ALG_RSAPSS_4096) => {
                    sign_rsa_asym_algo(
                        &ring::signature::RSA_PSS_SHA256,
                        base_asym_algo.get_size() as usize,
                        data,
                    )
                }
                (SpdmBaseHashAlgo::TPM_ALG_SHA_384, SpdmBaseAsymAlgo::TPM_ALG_RSASSA_2048)
                | (SpdmBaseHashAlgo::TPM_ALG_SHA_384, SpdmBaseAsymAlgo::TPM_ALG_RSASSA_3072)
                | (SpdmBaseHashAlgo::TPM_ALG_SHA_384, SpdmBaseAsymAlgo::TPM_ALG_RSASSA_4096) => {
                    sign_rsa_asym_algo(
                        &ring::signature::RSA_PKCS1_SHA384,
                        base_asym_algo.get_size() as usize,
                        data,
                    )
                }
                (SpdmBaseHashAlgo::TPM_ALG_SHA_384, SpdmBaseAsymAlgo::TPM_ALG_RSAPSS_2048)
                | (SpdmBaseHashAlgo::TPM_ALG_SHA_384, SpdmBaseAsymAlgo::TPM_ALG_RSAPSS_3072)
                | (SpdmBaseHashAlgo::TPM_ALG_SHA_384, SpdmBaseAsymAlgo::TPM_ALG_RSAPSS_4096) => {
                    sign_rsa_asym_algo(
                        &ring::signature::RSA_PSS_SHA384,
                        base_asym_algo.get_size() as usize,
                        data,
                    )
                }
                (SpdmBaseHashAlgo::TPM_ALG_SHA_512, SpdmBaseAsymAlgo::TPM_ALG_RSASSA_2048)
                | (SpdmBaseHashAlgo::TPM_ALG_SHA_512, SpdmBaseAsymAlgo::TPM_ALG_RSASSA_3072)
                | (SpdmBaseHashAlgo::TPM_ALG_SHA_512, SpdmBaseAsymAlgo::TPM_ALG_RSASSA_4096) => {
                    sign_rsa_asym_algo(
                        &ring::signature::RSA_PKCS1_SHA512,
                        base_asym_algo.get_size() as usize,
                        data,
                    )
                }
                (SpdmBaseHashAlgo::TPM_ALG_SHA_512, SpdmBaseAsymAlgo::TPM_ALG_RSAPSS_2048)
                | (SpdmBaseHashAlgo::TPM_ALG_SHA_512, SpdmBaseAsymAlgo::TPM_ALG_RSAPSS_3072)
                | (SpdmBaseHashAlgo::TPM_ALG_SHA_512, SpdmBaseAsymAlgo::TPM_ALG_RSAPSS_4096) => {
                    sign_rsa_asym_algo(
                        &ring::signature::RSA_PSS_SHA512,
                        base_asym_algo.get_size() as usize,
                        data,
                    )
                }
                _ => {
                    panic!("unsupported algorithm: base_hash_algo: {base_hash_algo:?} base_asym_algo: {base_asym_algo:?}");
                }
            }
        }

        fn supported_algo(&self) -> (SpdmBaseHashAlgo, SpdmBaseAsymAlgo) {
            (
                SpdmBaseHashAlgo::TPM_ALG_SHA_256 | SpdmBaseHashAlgo::TPM_ALG_SHA_384,
                // | SpdmBaseHashAlgo::TPM_ALG_SHA_512,
                SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P256
                    | SpdmBaseAsymAlgo::TPM_ALG_ECDSA_ECC_NIST_P384
                    | SpdmBaseAsymAlgo::TPM_ALG_RSAPSS_2048
                    | SpdmBaseAsymAlgo::TPM_ALG_RSAPSS_3072
                    | SpdmBaseAsymAlgo::TPM_ALG_RSAPSS_4096
                    | SpdmBaseAsymAlgo::TPM_ALG_RSASSA_2048
                    | SpdmBaseAsymAlgo::TPM_ALG_RSASSA_3072
                    | SpdmBaseAsymAlgo::TPM_ALG_RSASSA_4096,
            )
        }
    }

    fn sign_ecdsa_asym_algo(
        algorithm: &'static ring::signature::EcdsaSigningAlgorithm,
        data: &[u8],
    ) -> Option<SpdmSignatureStruct> {
        // openssl genpkey -algorithm ec -pkeyopt ec_paramgen_curve:P-256 -pkeyopt ec_param_enc:named_curve -outform DER > private.der
        // or  openssl.exe ecparam -name prime256v1 -genkey -out private.der -outform der
        // openssl.exe pkcs8 -in private.der -inform DER -topk8 -nocrypt -outform DER > private.p8

        let crate_dir = get_test_key_directory();
        println!("crate dir: {:?}", crate_dir.as_os_str().to_str());
        let key_file_path = if algorithm == &ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING {
            crate_dir.join("../spdm-rs/test_key/ecp256/end_responder.key.p8")
        } else if algorithm == &ring::signature::ECDSA_P384_SHA384_FIXED_SIGNING {
            crate_dir.join("../spdm-rs/test_key/ecp384/end_responder.key.p8")
        } else {
            panic!("not support")
        };
        let der_file = std::fs::read(key_file_path).expect("unable to read key der!");
        let key_bytes = der_file.as_slice();
        let rng = ring::rand::SystemRandom::new();
        let key_pair: ring::signature::EcdsaKeyPair =
            ring::signature::EcdsaKeyPair::from_pkcs8(algorithm, key_bytes, &rng).ok()?;

        let rng = ring::rand::SystemRandom::new();

        let signature = key_pair.sign(&rng, data).ok()?;
        let signature = signature.as_ref();

        let mut full_signature: [u8; SPDM_MAX_ASYM_KEY_SIZE] = [0u8; SPDM_MAX_ASYM_KEY_SIZE];
        full_signature[..signature.len()].copy_from_slice(signature);

        Some(SpdmSignatureStruct {
            data_size: signature.len() as u16,
            data: full_signature,
        })
    }

    fn sign_rsa_asym_algo(
        padding_alg: &'static dyn ring::signature::RsaEncoding,
        key_len: usize,
        data: &[u8],
    ) -> Option<SpdmSignatureStruct> {
        // openssl.exe genpkey -algorithm rsa -pkeyopt rsa_keygen_bits:2048 -pkeyopt rsa_keygen_pubexp:65537 -outform DER > private.der
        let crate_dir = get_test_key_directory();

        #[allow(unreachable_patterns)]
        let key_file_path = match key_len {
            RSASSA_2048_KEY_SIZE | RSAPSS_2048_KEY_SIZE => {
                crate_dir.join("../spdm-rs/test_key/rsa2048/end_responder.key.der")
            }
            RSASSA_3072_KEY_SIZE | RSAPSS_3072_KEY_SIZE => {
                crate_dir.join("../spdm-rs/test_key/rsa3072/end_responder.key.der")
            }
            RSASSA_4096_KEY_SIZE | RSAPSS_4096_KEY_SIZE => {
                crate_dir.join("../spdm-rs/test_key/rsa3072/end_responder.key.der")
            }
            _ => {
                panic!("RSA key len not supported")
            }
        };
        let der_file = std::fs::read(key_file_path).expect("unable to read key der!");
        let key_bytes = der_file.as_slice();

        let key_pair: ring::signature::RsaKeyPair =
            ring::signature::RsaKeyPair::from_der(key_bytes).ok()?;

        if key_len != key_pair.public().modulus_len() {
            panic!();
        }

        let rng = ring::rand::SystemRandom::new();

        let mut full_sign = [0u8; SPDM_MAX_ASYM_KEY_SIZE];
        key_pair
            .sign(padding_alg, &rng, data, &mut full_sign[0..key_len])
            .ok()?;

        Some(SpdmSignatureStruct {
            data_size: key_len as u16,
            data: full_sign,
        })
    }

    fn get_test_key_directory() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
    }
}
