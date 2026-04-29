use clap::Parser;

use std::path::PathBuf;
use reports_filter::utils::{
    logging::init_logger,
    config::Config
};

#[derive(Debug, Parser)]
#[command(name = "reports-filter", about = "A tool to filter and analyze SAST reports")]
struct Args{
    #[arg(short, long, default_value = "config.yaml", help = "Path to the configuration file")]
    config_file: PathBuf,
}

fn main() {
    let _logger_guard = init_logger();
    tracing::info!("Application started");

    let args = Args::parse();
    tracing::info!("Using config file: {:?}", args.config_file);

    let confg = Config::from_yaml(args.config_file.to_str().unwrap());
    tracing::debug!("Config: {:?}", confg);
}
