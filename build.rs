use std::{env, path::PathBuf};

const SGX_SDK_DEFAULT: &'static str = "/opt/intel/sgxsdk";

const SGX_BINDGEN_HEADER: &'static str = "
#include <sgx_quote_3.h>
#include <sgx_quote_4.h>
#include <sgx_quote_5.h>
";

#[cfg(any(feature = "attester-sgx-dcap", feature = "verifier-sgx-dcap", feature = "attester-tdx", feature = "verifier-tdx"))]
fn main() {
    let mut builder = bindgen::Builder::default();

    // Set sdk to search path if SGX_SDK is in environment variable
    let sgx_sdk_dir = env::var("SGX_SDK").unwrap_or_else(|_| SGX_SDK_DEFAULT.into());

    let mut sdk_inc = String::from("-I");
    sdk_inc.push_str(&sgx_sdk_dir);
    sdk_inc.push_str("/include/");
    // Include search path
    builder = builder.clang_arg(sdk_inc);

    let bindings = builder
        .header_contents("bindings.h", &SGX_BINDGEN_HEADER)
        // Disable Debug trait for packed C structures
        .no_debug("_quote_t")
        .no_debug("_sgx_ql_auth_data_t")
        .no_debug("_sgx_ql_certification_data_t")
        .no_debug("_sgx_ql_ecdsa_sig_data_t")
        .no_debug("_sgx_quote3_t")
        .no_debug("_sgx_ql_att_key_id_param_t")
        // Enable Default trait
        .derive_default(true)
        // Tell cargo to invalidate the built crate whenever any of the
        // included header files changed.
        .parse_callbacks(Box::new(bindgen::CargoCallbacks))
        // Finish the builder and generate the bindings.
        .generate()
        // Unwrap the Result and panic on failure.
        .expect("Unable to generate bindings");

    // Write the bindings to the $OUT_DIR/bindings.rs file.
    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("sgx_dcap_bindings.rs"))
        .expect("Couldn't write bindings!");
}
