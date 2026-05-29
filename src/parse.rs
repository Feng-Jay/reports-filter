use csv;
use roxmltree::Document;

use std::error::Error;
use std::io::SeekFrom::End;
use std::ops::Index;
use std::path::Path;
use crate::utils::config::SAST;

fn parse_codeql_csv_report(path: &Path) -> Result<Vec<Vec<String>>, Box<dyn Error>> {
    let headers = ["Rule Name", "Rule Description", "Severity", "Detailed Message", "Location-file", "Location-start-line", "Location-start-col", "Location-end-line", "Location-end-col"];
    let mut rdr = csv::ReaderBuilder::new().has_headers(false).from_path(path)?;
    let mut rows = Vec::new();
   
    for result in rdr.records(){
        let record = result?;
        let row: Vec<String> = headers
            .iter()
            .zip(record.iter())
            .map(|(header, value)| format!("{header}: {value}"))
            .collect();
        rows.push(row);
        // break; 
    }
    Ok(rows)
}

fn parse_sarif_report(path: &Path) -> Result<Vec<Vec<String>>, Box<dyn Error>> {
    // unimplemented!("SARIF report parsing is not implemented yet");
    let json_str = std::fs::read_to_string(path);
    if let Err(e) = json_str {
        tracing::error!("Failed to read SARIF report: {}", e);
        return Err(Box::new(e));
    }
    let json_str = json_str.unwrap();
    let json_value: serde_json::Value = serde_json::from_str(&json_str)?;
    let vul_reports = json_value.get("runs")
        .and_then(|runs| runs.as_array())
        .and_then(|runs| runs.get(0))
        .and_then(|run| run.get("results"))
        .and_then(|results| results.as_array());
    
    if let Some(vul_reports) = vul_reports {
        let mut rows = Vec::new();
        for vul_report in vul_reports {
            let rule_id = vul_report.get("ruleId").and_then(|v| v.as_str()).unwrap_or("");
            let message = vul_report.get("message").and_then(|m| m.get("text")).and_then(|t| t.as_str()).unwrap_or("");
            let locations = vul_report.get("locations").and_then(|l| l.as_array());
            let location_str = if let Some(locations) = locations {
                locations.iter().map(|loc| {
                    let file = loc.get("physicalLocation").and_then(|p| p.get("artifactLocation")).and_then(|a| a.get("uri")).and_then(|u| u.as_str()).unwrap_or("");
                    let start_line = loc.get("physicalLocation").and_then(|p| p.get("region")).and_then(|r| r.get("startLine")).and_then(|s| s.as_u64()).unwrap_or(0);
                    format!("{}:{}:{}", file, start_line, rule_id)
                }).collect::<Vec<String>>().join("; ")
            } else {
                "".to_string()
            };

            // optional codeFlows
            let mut code_flow_str = String::new();
            let code_flows = vul_report.get("codeFlows").and_then(|c| c.as_array());
            if let Some(code_flows) = code_flows {
                for code_flow in code_flows {
                    let thread_flows = code_flow.get("threadFlows").and_then(|t| t.as_array());
                    if let Some(thread_flows) = thread_flows {
                        for thread_flow in thread_flows {
                            let locations = thread_flow.get("locations").and_then(|l| l.as_array());
                            if let Some(locations) = locations {
                                for loc in locations {
                                    let file = loc.get("location").and_then(|l| l.get("physicalLocation")).and_then(|p| p.get("artifactLocation")).and_then(|a| a.get("uri")).and_then(|u| u.as_str()).unwrap_or("");
                                    
                                    let start_line = loc.get("location").and_then(|l| l.get("physicalLocation")).and_then(|p| p.get("region")).and_then(|r| r.get("startLine")).and_then(|s| s.as_u64()).unwrap_or(0);

                                    let step_message = loc.get("message").and_then(|m| m.get("text")).and_then(|t| t.as_str()).unwrap_or("");

                                    code_flow_str.push_str(&format!("{}:{} - {}\n", file, start_line, step_message));
                                    tracing::debug!("Code flow step: {}:{} - {}", file, start_line, step_message);
                                }
                            }
                        }
                    }
                }
            }
            if code_flow_str.is_empty() {
                rows.push(vec![format!("Rule ID: {}", rule_id), format!("Message: {}", message), format!("Location: {}", location_str)]);
            } else {
                rows.push(vec![format!("Rule ID: {}", rule_id), format!("Message: {}", message), format!("Location: {}", location_str), format!("Code Flow:\n{}", code_flow_str)]);
            }
        }
        tracing::info!("Successfully parsed SARIF report with {} vulnerability reports", rows.len());
        return Ok(rows);
    } else {
        tracing::error!("Failed to parse SARIF report: 'results' field is missing or not an array");
        return Err(Box::new(std::io::Error::new(std::io::ErrorKind::InvalidData, "Invalid SARIF report format")));
    }
}

fn parse_spotbugs_report(path: &Path) -> Result<Vec<Vec<String>>, Box<dyn Error>> {
    let xml_str = std::fs::read_to_string(path)?;
    let doc = Document::parse(&xml_str)?;
    let mut ret = Vec::new();
    for bug in doc.descendants().filter(|n| n.has_tag_name("BugInstance")) {
        let bug_type = bug.attribute("type").unwrap_or("?");
        // let priority = bug.attribute("priority").unwrap_or("?");
        // let rank = bug.attribute("rank").unwrap_or("?");
        let mut sources = Vec::new();
        let mut sinks = Vec::new();
        let mut lines = Vec::new();
        bug
        .children()
        .filter(|n| n.has_tag_name("String"))
        .for_each(|n| {
            if n.attribute("role") == Some("Sink method") {
                if let Some(value) = n.attribute("value") {
                    sinks.push(value.to_string());
                }
            }
            if n.attribute("role") == Some("Unknown source") {
                if let Some(value) = n.attribute("value") {
                    sources.push(value.to_string());
                }
            }
        });

        bug
        .children()
        .filter(|n| n.has_tag_name("SourceLine"))
        .for_each(|n| {
            let source_file = n.attribute("sourcefile").unwrap_or("?");
            let start_line = n.attribute("start").unwrap_or("?");
            let end_line = n.attribute("end").unwrap_or("?");
            lines.push(format!("{} from Line#{}-Line#{}", source_file, start_line, end_line));
        });

        println!("Lines: {:?}", lines);

        let buggy_line = lines.index(0).clone();
        lines.remove(0);
        let lines = lines.join("\n");
        let sources = if sources.is_empty() { "None".to_string() } else { sources.join("; ") };
        let sinks = if sinks.is_empty() { "None".to_string() } else { sinks.join("; ") };
        if !lines.is_empty() {
            ret.push(vec![format!("Reported Bug Type: {}", bug_type),format!("Buggy Line: {}", buggy_line), format!("Related Lines: {}", lines), format!("Sink methods: {}", sinks), format!("Source methods: {}", sources)]);
        }else{
            ret.push(vec![format!("Reported Bug Type: {}", bug_type),format!("Buggy Line: {}", buggy_line), format!("Sink methods: {}", sinks), format!("Source methods: {}", sources)]);
        }
    }
    return Ok(ret);
}

fn parse_repoaudit_report(path: &Path) -> Result<Vec<Vec<String>>, Box<dyn Error>> {
    unimplemented!("RepoAudit report parsing is not implemented yet");
}

fn parse_llmdfa_report(path: &Path) -> Result<Vec<Vec<String>>, Box<dyn Error>> {
    unimplemented!("LLMDFA report parsing is not implemented yet");
}

fn parse_inferroi_report(path: &Path) -> Result<Vec<Vec<String>>, Box<dyn Error>> {
    unimplemented!("InferROI report parsing is not implemented yet");
}

// Each bug report is formatted as a list of strings, where each string is a key-value pair in the format "key: value".
pub fn parse_sast_reports(reports_path: &Path, sast: &SAST, vul: &str) -> Result<Vec<Vec<String>>, String> {
    match sast {
        SAST::CODEQL => {
            let rows = parse_codeql_csv_report(reports_path);
            if let Ok(data) = rows {
                tracing::info!("Successfully parsed CodeQL report with {} rows", data.len());
                return Ok(data);
            } else {
                tracing::error!("Failed to parse CodeQL report {:?}:: {:?}", reports_path, rows.err());
                return Err(format!("Failed to parse CodeQL report"));
            }   
        },
        SAST::SEMGREP => {
            let rows = parse_sarif_report(reports_path);
            if let Ok(data) = rows {
                tracing::info!("Successfully parsed Semgrep SARIF report with {} vulnerability reports", data.len());
                return Ok(data);
            } else {
                tracing::error!("Failed to parse Semgrep SARIF report {:?}: {:?}", reports_path, rows.err());
                return Err(format!("Failed to parse Semgrep SARIF report"));
            }
        },
        SAST::SPOTBUGS => {
            let rows = parse_spotbugs_report(reports_path);
            if let Ok(data) = rows {
                tracing::info!("Successfully parsed SpotBugs XML report with {} bug instances", data.len());
                return Ok(data);
            } else {
                tracing::error!("Failed to parse SpotBugs XML report {:?}: {:?}", reports_path, rows.err());
                return Err(format!("Failed to parse SpotBugs XML report"));
            }
        },
        _ => {
            unimplemented!("SAST tool {:?} is not supported yet", sast);
        }
    }
}