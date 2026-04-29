use serde_yml;
use serde::{Serialize, Deserialize};

use std::path::PathBuf;
use std::fs;

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SAST {
    REPOAUDIT,
    KNIGHTER,
    LLMDFA,
    IRIS,
    INFERROI,
    CODEQL,
    SEMGREP,
    CSA,
    SPOTBUGS
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Config {
    pub log_level: String,
    pub log_file: PathBuf,
    pub sast: SAST,
    pub results_file: PathBuf,
}

impl Config {
    pub fn from_yaml(path: &str) -> Self {
        let config_str = fs::read_to_string(path);
        if let Ok(e) = config_str {
            let config: Config = serde_yml::from_str(&e).expect("Failed to parse config file");
            tracing::info!("Config loaded successfully from {}", path);
            config
        }else{
            tracing::error!("Failed to read config file: {}", path);
            panic!("Failed to read config file: {}", path);
        }
    }
}