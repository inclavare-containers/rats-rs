use std::env;

fn main() {
    /* Generate header files with cbindgen */
    let cur_crate_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let config_file = format!("{cur_crate_dir}/cbindgen.toml");

    let config = cbindgen::Config::from_file(&config_file).unwrap();

    cbindgen::Builder::new()
        .with_crate(&cur_crate_dir)
        .with_src(format!("{cur_crate_dir}/../rats-rs/src/crypto/mod.rs"))
        .with_src(format!("{cur_crate_dir}/../rats-rs/src/errors.rs"))
        .with_src(format!("{cur_crate_dir}/../rats-rs/src/cert/verify.rs"))
        // TODO: add supporting for generating claims name definition automatically after [this issue](https://github.com/mozilla/cbindgen/issues/927) is solved
        // .with_src(format!("{cur_crate_dir}/../rats-rs/src/tee/sgx_dcap/claims.rs"))
        // .with_src(format!("{cur_crate_dir}/../rats-rs/src/tee/tdx/claims.rs"))
        // .with_src(format!("{cur_crate_dir}/../rats-rs/src/tee/claims.rs"))
        .with_config(config)
        .generate()
        .expect("Unable to generate bindings")
        .write_to_file("include/rats-rs.h");
}
