use serde_yml::with;
use tracing_appender::{non_blocking::WorkerGuard, rolling};
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};


pub fn init_logger() -> WorkerGuard {
    let file_appender = rolling::never("logs", "app.log");
    let (non_blocking, guard) = tracing_appender::non_blocking(file_appender);

    let event_filter = EnvFilter::try_new("debug").unwrap_or_else(|_| EnvFilter::new("debug"));

    tracing_subscriber::registry()
        .with(event_filter)
        .with(
            fmt::layer()
                .with_ansi(true)
                .with_file(true)
                .with_line_number(true)
                .with_writer(std::io::stdout),
        )
        .with(
            fmt::layer()
                .with_ansi(false)
                .with_file(true)
                .with_line_number(true)
                .with_writer(non_blocking),
        )
        .init();

    guard
}