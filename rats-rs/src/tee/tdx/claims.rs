use super::evidence::{Quote, TdxEvidence};
use crate::errors::*;
use crate::tee::claims::Claims;
use crate::tee::intel_dcap::sgx_report2_body_t;
use crate::tee::intel_dcap::sgx_report2_body_v1_5_t;

/* TDX built-in claims */
/* Refer to: https://github.com/intel/SGXDataCenterAttestationPrimitives/blob/cd27223301e7c2bc80c9c5084ad6f5c2b9d24f5c/QuoteGeneration/quote_wrapper/common/inc/sgx_quote_4.h#L123-L137 */
/* TEE_TCB_SVN Array */
pub const BUILT_IN_CLAIM_TDX_TEE_TCB_SVN: &'static str = "tdx_tee_tcb_svn";
/* Measurement of the SEAM module */
pub const BUILT_IN_CLAIM_TDX_MR_SEAM: &'static str = "tdx_mr_seam";
/* Measurement of a 3rd party SEAM module’s signer (SHA384 hash). The value is 0’ed for Intel SEAM module */
pub const BUILT_IN_CLAIM_TDX_MRSIGNER_SEAM: &'static str = "tdx_mrsigner_seam";
/* MBZ: TDX 1.0 */
pub const BUILT_IN_CLAIM_TDX_SEAM_ATTRIBUTES: &'static str = "tdx_seam_attributes";
/* TD's attributes */
pub const BUILT_IN_CLAIM_TDX_TD_ATTRIBUTES: &'static str = "tdx_td_attributes";
/* TD's XFAM */
pub const BUILT_IN_CLAIM_TDX_XFAM: &'static str = "tdx_xfam";
/* Measurement of the initial contents of the TD */
pub const BUILT_IN_CLAIM_TDX_MR_TD: &'static str = "tdx_mr_td";
/* Software defined ID for non-owner-defined configuration on the guest TD. e.g., runtime or OS configuration */
pub const BUILT_IN_CLAIM_TDX_MR_CONFIG_ID: &'static str = "tdx_mr_config_id";
/* Software defined ID for the guest TD's owner */
pub const BUILT_IN_CLAIM_TDX_MR_OWNER: &'static str = "tdx_mr_owner";
/* Software defined ID for owner-defined configuration of the guest TD, e.g., specific to the workload rather than the runtime or OS */
pub const BUILT_IN_CLAIM_TDX_MR_OWNER_CONFIG: &'static str = "tdx_mr_owner_config";
/* Array of 4(TDX1: NUM_RTMRS is 4) runtime extendable measurement registers */
pub const BUILT_IN_CLAIM_TDX_RT_MR0: &'static str = "tdx_rt_mr0";
pub const BUILT_IN_CLAIM_TDX_RT_MR1: &'static str = "tdx_rt_mr1";
pub const BUILT_IN_CLAIM_TDX_RT_MR2: &'static str = "tdx_rt_mr2";
pub const BUILT_IN_CLAIM_TDX_RT_MR3: &'static str = "tdx_rt_mr3";

/* TDX built-in claims, for TDX 1.5 only */
/* Refer to: https://github.com/intel/SGXDataCenterAttestationPrimitives/blob/cd27223301e7c2bc80c9c5084ad6f5c2b9d24f5c/QuoteGeneration/quote_wrapper/common/inc/sgx_quote_5.h#L99-L100 */
/* Array of TEE TCB SVNs (for TD preserving). */
pub const BUILT_IN_CLAIM_TDX_TEE_TCB_SVN2: &'static str = "tdx_tee_tcb_svn2";
/* If is one or more bound or pre-bound service TDs, SERVTD_HASH is the SHA384 hash of the TDINFO_STRUCTs of those service TDs bound. */
pub const BUILT_IN_CLAIM_TDX_MR_SERVICETD: &'static str = "tdx_mr_servicetd";

macro_rules! as_slice {
    ($value: expr) => {
        unsafe {
            let v = core::ptr::addr_of!($value);
            let v = core::ptr::read_unaligned(v);
            let s = core::slice::from_raw_parts(
                &v as *const _ as *const u8,
                core::mem::size_of_val(&v),
            );
            #[allow(forgetting_copy_types)]
            core::mem::forget(v);
            s
        }
    };
}

fn append_claims_sgx_report2_body_t(claims: &mut Claims, report_body: &sgx_report2_body_t) {
    claims.insert(
        BUILT_IN_CLAIM_TDX_TEE_TCB_SVN.into(),
        as_slice!(report_body.tee_tcb_svn).into(),
    );
    claims.insert(
        BUILT_IN_CLAIM_TDX_MR_SEAM.into(),
        as_slice!(report_body.mr_seam).into(),
    );
    claims.insert(
        BUILT_IN_CLAIM_TDX_MRSIGNER_SEAM.into(),
        as_slice!(report_body.mrsigner_seam).into(),
    );
    claims.insert(
        BUILT_IN_CLAIM_TDX_SEAM_ATTRIBUTES.into(),
        as_slice!(report_body.seam_attributes).into(),
    );
    claims.insert(
        BUILT_IN_CLAIM_TDX_TD_ATTRIBUTES.into(),
        as_slice!(report_body.td_attributes).into(),
    );
    claims.insert(
        BUILT_IN_CLAIM_TDX_XFAM.into(),
        as_slice!(report_body.xfam).into(),
    );
    claims.insert(
        BUILT_IN_CLAIM_TDX_MR_TD.into(),
        as_slice!(report_body.mr_td).into(),
    );
    claims.insert(
        BUILT_IN_CLAIM_TDX_MR_CONFIG_ID.into(),
        as_slice!(report_body.mr_config_id).into(),
    );
    claims.insert(
        BUILT_IN_CLAIM_TDX_MR_OWNER.into(),
        as_slice!(report_body.mr_owner).into(),
    );
    claims.insert(
        BUILT_IN_CLAIM_TDX_MR_OWNER_CONFIG.into(),
        as_slice!(report_body.mr_owner_config).into(),
    );
    claims.insert(
        BUILT_IN_CLAIM_TDX_RT_MR0.into(),
        as_slice!(report_body.rt_mr[0]).into(),
    );
    claims.insert(
        BUILT_IN_CLAIM_TDX_RT_MR1.into(),
        as_slice!(report_body.rt_mr[1]).into(),
    );
    claims.insert(
        BUILT_IN_CLAIM_TDX_RT_MR2.into(),
        as_slice!(report_body.rt_mr[2]).into(),
    );
    claims.insert(
        BUILT_IN_CLAIM_TDX_RT_MR3.into(),
        as_slice!(report_body.rt_mr[3]).into(),
    );
}

fn append_claims_sgx_report2_body_v1_5_t(
    claims: &mut Claims,
    report_body: &sgx_report2_body_v1_5_t,
) {
    claims.insert(
        BUILT_IN_CLAIM_TDX_TEE_TCB_SVN.into(),
        as_slice!(report_body.tee_tcb_svn).into(),
    );
    claims.insert(
        BUILT_IN_CLAIM_TDX_MR_SEAM.into(),
        as_slice!(report_body.mr_seam).into(),
    );
    claims.insert(
        BUILT_IN_CLAIM_TDX_MRSIGNER_SEAM.into(),
        as_slice!(report_body.mrsigner_seam).into(),
    );
    claims.insert(
        BUILT_IN_CLAIM_TDX_SEAM_ATTRIBUTES.into(),
        as_slice!(report_body.seam_attributes).into(),
    );
    claims.insert(
        BUILT_IN_CLAIM_TDX_TD_ATTRIBUTES.into(),
        as_slice!(report_body.td_attributes).into(),
    );
    claims.insert(
        BUILT_IN_CLAIM_TDX_XFAM.into(),
        as_slice!(report_body.xfam).into(),
    );
    claims.insert(
        BUILT_IN_CLAIM_TDX_MR_TD.into(),
        as_slice!(report_body.mr_td).into(),
    );
    claims.insert(
        BUILT_IN_CLAIM_TDX_MR_CONFIG_ID.into(),
        as_slice!(report_body.mr_config_id).into(),
    );
    claims.insert(
        BUILT_IN_CLAIM_TDX_MR_OWNER.into(),
        as_slice!(report_body.mr_owner).into(),
    );
    claims.insert(
        BUILT_IN_CLAIM_TDX_MR_OWNER_CONFIG.into(),
        as_slice!(report_body.mr_owner_config).into(),
    );
    claims.insert(
        BUILT_IN_CLAIM_TDX_RT_MR0.into(),
        as_slice!(report_body.rt_mr[0]).into(),
    );
    claims.insert(
        BUILT_IN_CLAIM_TDX_RT_MR1.into(),
        as_slice!(report_body.rt_mr[1]).into(),
    );
    claims.insert(
        BUILT_IN_CLAIM_TDX_RT_MR2.into(),
        as_slice!(report_body.rt_mr[2]).into(),
    );
    claims.insert(
        BUILT_IN_CLAIM_TDX_RT_MR3.into(),
        as_slice!(report_body.rt_mr[3]).into(),
    );
    /* for TDX 1.5 only */
    claims.insert(
        BUILT_IN_CLAIM_TDX_TEE_TCB_SVN2.into(),
        as_slice!(report_body.tee_tcb_svn2).into(),
    );
    /* for TDX 1.5 only */
    claims.insert(
        BUILT_IN_CLAIM_TDX_MR_SERVICETD.into(),
        as_slice!(report_body.mr_servicetd).into(),
    );
}

impl TdxEvidence {
    // TODO: test this with mulformed quote
    pub fn gen_claims_from_quote(&self) -> Result<Claims> {
        let mut claims = Claims::default();

        /* common claims */
        claims.insert(
            crate::tee::claims::BUILT_IN_CLAIM_COMMON_QUOTE.into(),
            self.as_quote_data().into(),
        );
        claims.insert(
            crate::tee::claims::BUILT_IN_CLAIM_COMMON_QUOTE_TYPE.into(),
            "tdx".as_bytes().into(),
        );

        /* TDX claims */

        match self.as_quote()? {
            Quote::Quote4(quote) => {
                append_claims_sgx_report2_body_t(&mut claims, &quote.report_body)
            }
            Quote::Quote5Tdx10(_, report_body) => {
                append_claims_sgx_report2_body_t(&mut claims, &report_body)
            }
            Quote::Quote5Tdx15(_, report_body) => {
                append_claims_sgx_report2_body_v1_5_t(&mut claims, &report_body)
            }
        }

        Ok(claims)
    }
}
