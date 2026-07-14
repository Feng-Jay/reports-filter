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
    // We only print the pointer value, not dereference it.
    let args = Args::parse();
    tracing::info!("Using config file: {:?}", args.config_file);

    let config = Config::from_yaml(args.config_file.to_str().unwrap());
    tracing::debug!("Config: {:?}", config);
    
    let _logger_guard = init_logger(&config);

    let repo_to_commit_id: HashMap<String, String> = HashMap::from([
    ("OpenOLAT".to_string(), "df53b85db5c27935e7467b9d39eaac7aebf50d4a".to_string()),
    ("spark".to_string(), "1973e402f5d4c1442ad34a1d38ed0758079f7773".to_string()),
    ("DSpace".to_string(), "3b248012147da7cac7ac0fcd0b6b9ee0b07b5088".to_string()),

    ("xstream".to_string(), "a22d3af9e3938fcf33bff620fd08669993e203cf".to_string()),
    ("workflow-cps-plugin".to_string(), "e4b9517bd855657c900bd1b31cde09748c7a19a7".to_string()),
    ("tika".to_string(), "2b38ed18fa6df22a425cd96f2431b3a574044533".to_string()),

    ("xwiki-platform".to_string(), "fc734981c142b35c0ce97d0af7d29c904794ba46".to_string()),
    ("jenkins".to_string(), "69d5a542391a0dc5c1b2ed609447bc863e7e892d".to_string()),
    ("keycloak".to_string(), "4f55b9b6bd6dadfdd04cfd09eb532dfdd26d5607".to_string()),

    ("onedev".to_string(), "b8a4d7cdc212a488fd732a675f3d6f7fc755f5a3".to_string()),
    ("activemq".to_string(), "56ea235e6e481f7408f09101dec7ae77edb40ed1".to_string()),
    ("cron-utils".to_string(), "bac6e866caf5f53d695a9513fc1b938b8064eaeb".to_string()),

    ("sql2o".to_string(), "744b85b32bcea972c8d570483e1051cd0a25f0ba".to_string()),
    ("RxJava".to_string(), "f07765edac25ccc110802add8a879d77208f09b9".to_string()),
    ("jsoup".to_string(), "acafbcf3cb71ea0a04188c8f6257e3d395fa7c36".to_string()),

    ("linux".to_string(), "6093a688a07da07808f0122f9aa2a3eed250d853".to_string()),
    ("ImageMagick".to_string(), "3bf1076d748a5ec40073685ce71ca9222cf0b00c".to_string()),
    ("vim".to_string(), "8feaa94e774cd92039f5e35901a1340ac132163f".to_string()),
    ("gpac".to_string(), "c6a72c35aadadd9755d177c5ffc51b3e2b5f9268".to_string()),
    ("bitlbee".to_string(), "8af06ca5362445ff6379aca028b79c607ed77f90".to_string()),
    ]);

    let repo_name = config.repos_dir.file_name().unwrap().to_str().unwrap();
    if let Some(commit_id) = repo_to_commit_id.get(repo_name) {
        tracing::info!("Found commit ID {} for repo {}", commit_id, repo_name);
    } else {
        tracing::warn!("No commit ID found for repo {}, using commit ID from config: {:?}", repo_name, config.commit_id);
    }
    let commit_id = repo_to_commit_id.get(repo_name).unwrap();
    let res = checkout_project(&config.repos_dir, commit_id);
    if let Err(e) = res {
        tracing::error!("Failed to checkout project: {}", e);
        return;
    }

    let reports = parse_sast_reports(&config.results_file, &config.sast, &config.vul);
    if let Ok(data) = reports {
        // debug part
        // let file = File::create("reports.json").unwrap();
        // serde_json::to_writer_pretty(file, &data).unwrap();
        // return;
        let output_file = config.results_file.with_file_name(format!("validated_v3_{}.json", config.results_file.file_stem().unwrap().to_str().unwrap()));
        let mut results: HashMap<String, String>= HashMap::new();
        tracing::info!("Successfully parsed SAST reports, total {} entries", data.len());
        tracing::info!("Output file will be: {:?}", output_file);
        let indexes = (0..data.len()).collect::<Vec<usize>>();
        let mut rng = thread_rng();
        // sample at most 300 reports
        let sample_size = ((data.len() as f64 * config.sample_ratio).ceil() as usize).min(300); 
        let sample_indexes = indexes.choose_multiple(&mut rng, sample_size);
        tracing::info!("Randomly sampled {} reports for Codex analysis", sample_size);
        for idx in sample_indexes.into_iter().progress() {
            let report = &data[*idx];
            let report_str = report.join("\n");
            tracing::info!("Parsed SAST report:\n{}", report_str);
            // input to wait
            // std::io::stdin().read_line(&mut String::new()).unwrap();
            tracing::info!("Running Codex for report #{}...", idx);
            let res = run_codex(config.sast.to_string().as_str(), 
                &config.vul, 
                &report_str, 
                &config.repos_dir);
            if let Ok(response) = res {
                tracing::info!("Codex response:\n{}", response);
                let item: HashMap<String, String> = HashMap::from([
                    ("report".to_string(), report_str),
                    ("response".to_string(), response.clone()),
                ]);
                results.insert(idx.to_string(), serde_json::to_string_pretty(&item).unwrap());
            }else{
                tracing::error!("Failed to run Codex: {}", res.err().unwrap()); 
            }
        }
        serde_json::to_writer(std::fs::File::create(output_file).unwrap(), &results).unwrap();
    } else {
        tracing::error!("Failed to parse SAST reports: {:?}", reports.err());
    }
}
