use clap::Parser;
use rand::seq::SliceRandom;
use rand::{Rng, thread_rng};

use indicatif::ProgressIterator;

use std::collections::HashMap;
use std::path::PathBuf;
use reports_filter::codex::run_codex;
use reports_filter::parse::parse_sast_reports;
use reports_filter::utils::{
    checkout_project,
    logging::init_logger,
    config::Config,
};

#[derive(Debug, Parser)]
#[command(name = "reports-filter", about = "A tool to filter and analyze SAST reports")]
struct Args{
    #[arg(short, long, default_value = "config.yaml", help = "Path to the configuration file")]
    config_file: PathBuf,
}

fn main() {

    let args = Args::parse();
    tracing::info!("Using config file: {:?}", args.config_file);

    let config = Config::from_yaml(args.config_file.to_str().unwrap());
    tracing::debug!("Config: {:?}", config);
    
    let _logger_guard = init_logger(&config);

    let res = checkout_project(&config.repos_dir, &config.commit_id);
    if let Err(e) = res {
        tracing::error!("Failed to checkout project: {}", e);
        return;
    }

    let reports = parse_sast_reports(&config.results_file, &config.sast, &config.vul);
    if let Ok(data) = reports {
        let output_file = config.results_file.with_file_name(format!("validated_{}.json", config.results_file.file_stem().unwrap().to_str().unwrap()));
        let mut results: HashMap<String, String>= HashMap::new();
        tracing::info!("Successfully parsed SAST reports, total {} entries", data.len());
        tracing::info!("Output file will be: {:?}", output_file);
        let indexes = (0..data.len()).collect::<Vec<usize>>();
        let mut rng = thread_rng();
        // sample at most 100 reports
        let sample_size = ((data.len() as f64 * config.sample_ratio).ceil() as usize).min(300); 
        let sample_indexes = indexes.choose_multiple(&mut rng, sample_size);
        tracing::info!("Randomly sampled {} reports for Codex analysis", sample_size);
        for idx in sample_indexes.into_iter().progress() {
            let report = &data[*idx];
            let report_str = report.join("\n");
            tracing::debug!("Parsed SAST report:\n{}", report_str);
            // input to wait
            // std::io::stdin().read_line(&mut String::new()).unwrap();
            tracing::info!("Running Codex for report #{}...", idx);
            let res = run_codex(config.sast.to_string().as_str(), 
                &config.vul, 
                &report_str, 
                &config.repos_dir);
            if let Ok(response) = res {
                tracing::info!("Codex response:\n{}", response);
                results.insert(idx.to_string(), response);
            }else{
                tracing::error!("Failed to run Codex: {}", res.err().unwrap()); 
            }
        }
        serde_json::to_writer(std::fs::File::create(output_file).unwrap(), &results).unwrap();
    } else {
        tracing::error!("Failed to parse SAST reports: {:?}", reports.err());
    }
}
