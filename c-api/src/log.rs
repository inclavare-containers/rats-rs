use ctor::ctor;
use log::info;
use shadow_rs::shadow;

shadow!(build);

#[ctor]
fn init_logger() {
    let env = env_logger::Env::default()
        .filter_or("RATS_RS_LOG_LEVEL", "debug")
        .write_style_or("RATS_RS_LOG_STYLE", "always"); // enable color
    env_logger::Builder::from_env(env).init();

    info!(
        "rats-rs c-api library version: v{}  commit: {}  buildtime: {}",
        build::PKG_VERSION,
        build::COMMIT_HASH,
        build::BUILD_TIME
    );
}

#[repr(C)]
pub enum LogLevel {
    Off = 0,
    Error = 1,
    Warn = 2,
    Info = 3,
    Debug = 4,
    Trace = 5,
}

#[allow(non_camel_case_types)]
pub type log_level_t = LogLevel;

/// Set log level of all log print in rats-rs, all of the supported levels can be found in `log_level_t`.
#[no_mangle]
pub extern "C" fn rats_rs_set_log_level(log_level: log_level_t) {
    log::set_max_level(match log_level {
        LogLevel::Off => log::LevelFilter::Off,
        LogLevel::Error => log::LevelFilter::Error,
        LogLevel::Warn => log::LevelFilter::Warn,
        LogLevel::Info => log::LevelFilter::Info,
        LogLevel::Debug => log::LevelFilter::Debug,
        LogLevel::Trace => log::LevelFilter::Trace,
    })
}
