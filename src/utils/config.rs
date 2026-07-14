use serde_yml;
use serde::{Serialize, Deserialize};

use std::fmt;
use std::path::PathBuf;
use std::fs;

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SAST {
    REPOAUDIT, // done
    KNIGHTER,
    LLMDFA, // done
    IRIS, // done
    INFERROI, // done
    CODEQL, // done
    SEMGREP, // done
    CSA,
    SPOTBUGS, // done
    Codex,
    ClaudeCode
}

impl fmt::Display for SAST {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            SAST::REPOAUDIT => "repoaudit",
            SAST::KNIGHTER => "knighter",
            SAST::LLMDFA => "llmdfa",
            SAST::IRIS => "iris",
            SAST::INFERROI => "inferroi",
            SAST::CODEQL => "codeql",
            SAST::SEMGREP => "semgrep",
            SAST::CSA => "csa",
            SAST::SPOTBUGS => "spotbugs",
            SAST::Codex => "codex",
            SAST::ClaudeCode => "claudecode"
        };
        write!(f, "{s}")
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Config {
    pub log_level: String,
    pub log_file: PathBuf,
    pub sast: SAST,
    pub vul: String,
    pub sample_ratio: f64,
    pub results_file: PathBuf,
    pub repos_dir: PathBuf,
    pub commit_id: Option<String>
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