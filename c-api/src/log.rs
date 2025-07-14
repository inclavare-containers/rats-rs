use ctor::ctor;
use log::{debug, info};
use once_cell::sync::OnceCell;
use shadow_rs::shadow;
use std::sync::{Mutex, Once};
use tracing_subscriber::reload::Handle;

shadow!(build);

static INIT: Once = Once::new();
static RELOAD_HANDLE: OnceCell<Mutex<Handle<tracing_subscriber::EnvFilter>>> = OnceCell::new();

#[ctor]
fn init_logger() {
    INIT.call_once(|| {
        let filter = tracing_subscriber::EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| "debug".into());
        let (filter_layer, reload_handle) = tracing_subscriber::reload::Layer::new(filter);

        RELOAD_HANDLE
            .set(Mutex::new(reload_handle))
            .expect("Failed to set RELOAD_HANDLE");

        tracing_subscriber::registry().with(filter_layer).init();
    });

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
    match std::env::var("RATS_RS_LOG_LEVEL") {
        Ok(v) if v != "" => {
            tracing::debug!(
                "The environment variable RATS_RS_LOG_LEVEL was set to value `{v}`, so rats_rs_set_log_level() will have no effect",
            );
        }
        _ => {
            let level_filter: tracing_subscriber::filter::LevelFilter = log_level.into();
            let env_filter = tracing_subscriber::EnvFilter::builder()
                .with_default_directive(level_filter.into())
                .from_env_lossy();

            if let Some(handle) = RELOAD_HANDLE.get() {
                handle
                    .lock()
                    .unwrap()
                    .modify(move |filter| {
                        *filter = env_filter;
                    })
                    .expect("Failed to update log level");
            } else {
                tracing::error!(
                    "Reload handle not found, maybe you forgot to call `init_logger()` first?"
                );
            }
        }
    }
}

use tracing_subscriber::filter::LevelFilter;

impl From<LogLevel> for LevelFilter {
    fn from(level: LogLevel) -> Self {
        match level {
            LogLevel::Off => LevelFilter::OFF,
            LogLevel::Error => LevelFilter::ERROR,
            LogLevel::Warn => LevelFilter::WARN,
            LogLevel::Info => LevelFilter::INFO,
            LogLevel::Debug => LevelFilter::DEBUG,
            LogLevel::Trace => LevelFilter::TRACE,
        }
    }
}
