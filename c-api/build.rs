use std::env;

fn main() ->shadow_rs::SdResult<()> {
    /* Generate header files with cbindgen */
    let cur_crate_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let config_file = format!("{cur_crate_dir}/cbindgen.toml");

    let config = cbindgen::Config::from_file(&config_file).unwrap();

    cbindgen::Builder::new()
        .with_crate(&cur_crate_dir)
        .with_src(format!("{cur_crate_dir}/../rats-cert/src/crypto/mod.rs"))
        .with_src(format!("{cur_crate_dir}/../rats-cert/src/errors.rs"))
        .with_src(format!("{cur_crate_dir}/../rats-cert/src/cert/verify.rs"))
        // TODO: add supporting for generating claims name definition automatically after [this issue](https://github.com/mozilla/cbindgen/issues/927) is solved
        // .with_src(format!("{cur_crate_dir}/../rats-cert/src/tee/sgx_dcap/claims.rs"))
        // .with_src(format!("{cur_crate_dir}/../rats-cert/src/tee/tdx/claims.rs"))
        // .with_src(format!("{cur_crate_dir}/../rats-cert/src/tee/claims.rs"))
        .with_config(config)
        .generate()
        .expect("Unable to generate bindings")
        .write_to_file("include/rats-cert.h");

        shadow_rs::new()

}
