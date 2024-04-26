#![allow(dead_code)]
#![allow(unused_variables)]
use crate::cert::dice::cbor::generate_claims_buffer;
use crate::errors::*;
use crate::tee::GenericEvidence;
use codec::u24;
use codec::Codec;
use codec::Writer;
use log::error;
use spdmlib::config;
use spdmlib::crypto::hash;
use spdmlib::message::*;
use spdmlib::protocol::*;
use spdmlib::secret::measurement::MeasurementProvider;

pub const RATS_MEASUREMENT_BLOCK_INDEX: u8 = 0x01;

/// This struct is related to the `GET_MEASUREMENTS`/`MEASUREMENTS` SPDM messages. And it has implemented `MeasurementProvider` to provide a callback for generating measurement，and a callback for calculating measurement summary.
pub(crate) struct RatsMeasurementProvider {
    claims_buffer: Vec<u8>,
}

impl RatsMeasurementProvider {
    pub fn new_from_evidence(evidence: &impl GenericEvidence) -> Result<Self> {
        let claims = evidence.get_claims()?;
        let claims_buffer = generate_claims_buffer(&claims)?;
        Ok(Self { claims_buffer })
    }
}

impl RatsMeasurementProvider {
    fn create_rats_measurement_block(
        &self,
        measurement_hash_algo: SpdmMeasurementHashAlgo,
    ) -> Result<SpdmMeasurementBlockStructure> {
        let mut value = [0u8; config::MAX_SPDM_MEASUREMENT_VALUE_LEN];

        if measurement_hash_algo == SpdmMeasurementHashAlgo::RAW_BIT_STREAM {
            /* The representation of measurement is raw bit streams */
            if self.claims_buffer.len() > value.len() {
                todo!(
                    "The claims_buffer is too long to fit in a measurement block: {} > {}",
                    self.claims_buffer.len(),
                    value.len()
                );
            }
            let value_size = self.claims_buffer.len() as u16;
            value[..value_size as usize].copy_from_slice(&self.claims_buffer);

            Ok(SpdmMeasurementBlockStructure {
                index: RATS_MEASUREMENT_BLOCK_INDEX,
                measurement_specification: SpdmMeasurementSpecification::DMTF,
                measurement_size: value_size + 3,
                measurement: SpdmDmtfMeasurementStructure {
                    r#type: SpdmDmtfMeasurementType::SpdmDmtfMeasurementManifest, /* Freeform measurement manifest */
                    representation: SpdmDmtfMeasurementRepresentation::SpdmDmtfMeasurementRawBit,
                    value_size,
                    value,
                },
            })
        } else {
            /* The representation of measurement is digest */
            let hash_algo = match measurement_hash_algo {
                SpdmMeasurementHashAlgo::TPM_ALG_SHA_256 => SpdmBaseHashAlgo::TPM_ALG_SHA_256,
                SpdmMeasurementHashAlgo::TPM_ALG_SHA_384 => SpdmBaseHashAlgo::TPM_ALG_SHA_384,
                SpdmMeasurementHashAlgo::TPM_ALG_SHA_512 => SpdmBaseHashAlgo::TPM_ALG_SHA_512,
                _ => {
                    return Err(Error::kind_with_msg(
                        ErrorKind::UnsupportedHashAlgo,
                        format!("Unsupported measurement hash algo {measurement_hash_algo:?}"),
                    ));
                }
            };

            let digest =
                hash::hash_all(hash_algo, &self.claims_buffer).ok_or(Error::kind_with_msg(
                    ErrorKind::CalculateHashFailed,
                    format!("The spdmlib failed to calculate hash with algo {hash_algo:?}"),
                ))?;

            let value_size = digest.data_size;
            value[..value_size as usize].copy_from_slice(&digest.data[..value_size as usize]);

            Ok(SpdmMeasurementBlockStructure {
                index: RATS_MEASUREMENT_BLOCK_INDEX,
                measurement_specification: SpdmMeasurementSpecification::DMTF,
                measurement_size: value_size + 3,
                measurement: SpdmDmtfMeasurementStructure {
                    r#type: SpdmDmtfMeasurementType::SpdmDmtfMeasurementManifest, /* Freeform measurement manifest */
                    representation: SpdmDmtfMeasurementRepresentation::SpdmDmtfMeasurementDigest,
                    value_size,
                    value,
                },
            })
        }
    }

    fn create_rats_measurement_block_data(
        &self,
        measurement_hash_algo: SpdmMeasurementHashAlgo,
    ) -> Result<(
        [u8; config::MAX_SPDM_MEASUREMENT_RECORD_SIZE],
        usize, /* length */
    )> {
        let block = self
            .create_rats_measurement_block(measurement_hash_algo)
            .context("Failed to create measurement block")?;

        let mut measurement_record_data = [0u8; config::MAX_SPDM_MEASUREMENT_RECORD_SIZE];
        let mut writer = Writer::init(&mut measurement_record_data);
        block.encode(&mut writer).map_err(|e| {
            Error::kind_with_msg(
                ErrorKind::SpdmlibError,
                format!("The spdmlib failed to encode measurement block to bytes: {e:?}"),
            )
        })?;
        let length = writer.used();

        Ok((measurement_record_data, length))
    }
}

impl MeasurementProvider for RatsMeasurementProvider {
    fn measurement_collection(
        &self,
        spdm_version: SpdmVersion,
        measurement_specification: SpdmMeasurementSpecification,
        measurement_hash_algo: SpdmMeasurementHashAlgo,
        measurement_index: usize,
    ) -> Option<SpdmMeasurementRecordStructure> {
        if measurement_specification != SpdmMeasurementSpecification::DMTF {
            error!("Unsupported measurement specification: {measurement_specification:?}");
            return None;
        }

        if measurement_index
            == SpdmMeasurementOperation::SpdmMeasurementQueryTotalNumber.get_u8() as usize
        {
            /* Get number of measurements */
            Some(SpdmMeasurementRecordStructure {
                number_of_blocks: 1, /* We only have one measurement block */
                ..Default::default()
            })
        } else if measurement_index
            == SpdmMeasurementOperation::SpdmMeasurementRequestAll.get_u8() as usize /* Get all measurements */
            || measurement_index == RATS_MEASUREMENT_BLOCK_INDEX as usize
        /* Note that since we only have one measurement block so it is ok to merge two if branch here. */
        {
            /* Note: we call create_rats_measurement_block() here since we only have one measurement block */
            let (measurement_record_data, measurement_record_length) = self
                .create_rats_measurement_block_data(measurement_hash_algo)
                .map_err(|e| {
                    error!("Failed to create measurement block data: {e:?}");
                    e
                })
                .ok()?;

            Some(SpdmMeasurementRecordStructure {
                number_of_blocks: 1, /* We only have one measurement block */
                measurement_record_length: u24::new(measurement_record_length as u32),
                measurement_record_data,
            })
        } else {
            None
        }
    }

    fn generate_measurement_summary_hash(
        &self,
        spdm_version: SpdmVersion,
        base_hash_algo: SpdmBaseHashAlgo,
        measurement_specification: SpdmMeasurementSpecification,
        measurement_hash_algo: SpdmMeasurementHashAlgo,
        measurement_summary_hash_type: SpdmMeasurementSummaryHashType,
    ) -> Option<SpdmDigestStruct> {
        match measurement_summary_hash_type {
            SpdmMeasurementSummaryHashType::SpdmMeasurementSummaryHashTypeAll
            | SpdmMeasurementSummaryHashType::SpdmMeasurementSummaryHashTypeTcb => {
                /* Note: we call create_rats_measurement_block() here since we only have one measurement block */
                let (measurement_record_data, measurement_record_length) = self
                    .create_rats_measurement_block_data(measurement_hash_algo)
                    .map_err(|e| {
                        error!("Failed to create measurement block data: {e:?}");
                        e
                    })
                    .ok()?;

                let digest = hash::hash_all(
                    base_hash_algo,
                    &measurement_record_data[..measurement_record_length],
                )?;
                Some(digest)
            }
            SpdmMeasurementSummaryHashType::SpdmMeasurementSummaryHashTypeNone => None,
            _ => None,
        }
    }
}

pub(crate) struct EmptyMeasurementProvider {}

impl MeasurementProvider for EmptyMeasurementProvider {
    fn measurement_collection(
        &self,
        spdm_version: SpdmVersion,
        measurement_specification: SpdmMeasurementSpecification,
        measurement_hash_algo: SpdmMeasurementHashAlgo,
        measurement_index: usize,
    ) -> Option<SpdmMeasurementRecordStructure> {
        if measurement_specification != SpdmMeasurementSpecification::DMTF {
            error!("Unsupported measurement specification: {measurement_specification:?}");
            return None;
        }

        if measurement_index
            == SpdmMeasurementOperation::SpdmMeasurementQueryTotalNumber.get_u8() as usize
        {
            /* Get number of measurements */
            Some(SpdmMeasurementRecordStructure {
                number_of_blocks: 0, /* No measurements */
                ..Default::default()
            })
        } else if measurement_index
        == SpdmMeasurementOperation::SpdmMeasurementRequestAll.get_u8() as usize /* Get all measurements */
        || measurement_index == RATS_MEASUREMENT_BLOCK_INDEX as usize
        /* Note that since we only have one measurement block so it is ok to merge two if branch here. */
        {
            Some(SpdmMeasurementRecordStructure {
                number_of_blocks: 0, /* No measurements */
                measurement_record_length: u24::new(0u32),
                measurement_record_data: [0u8; config::MAX_SPDM_MEASUREMENT_RECORD_SIZE],
            })
        } else {
            None
        }
    }

    fn generate_measurement_summary_hash(
        &self,
        spdm_version: SpdmVersion,
        base_hash_algo: SpdmBaseHashAlgo,
        measurement_specification: SpdmMeasurementSpecification,
        measurement_hash_algo: SpdmMeasurementHashAlgo,
        measurement_summary_hash_type: SpdmMeasurementSummaryHashType,
    ) -> Option<SpdmDigestStruct> {
        match measurement_summary_hash_type {
            SpdmMeasurementSummaryHashType::SpdmMeasurementSummaryHashTypeAll
            | SpdmMeasurementSummaryHashType::SpdmMeasurementSummaryHashTypeTcb => {
                Some(hash::hash_all(base_hash_algo, &[])?)
            }
            SpdmMeasurementSummaryHashType::SpdmMeasurementSummaryHashTypeNone => None,
            _ => None,
        }
    }
}
