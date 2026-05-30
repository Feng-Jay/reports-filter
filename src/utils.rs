use std::{path::PathBuf, process::Command};

pub mod logging;
pub mod config;

pub fn checkout_project(repo_path: &PathBuf, commit_id: &str) -> Result<(), Box<dyn std::error::Error>> {
    tracing::info!("Checking out project at path {:?} to commit ID {:?}", repo_path, commit_id);
    let mut cmd = Command::new("git");
    cmd.arg("checkout")
        .arg("-f")
        .arg(commit_id)
        .current_dir(repo_path);
    tracing::info!("Checkout done with command: {:?}", cmd);
    return Ok(());
}