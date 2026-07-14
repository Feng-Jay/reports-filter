use csv;
use roxmltree::Document;
use kuchiki::traits::*;
use kuchiki::NodeRef;
use serde_yml::modules::path;

use std::result;
use std::string::String;
use std::error::Error;
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
    let json_str = std::fs::read_to_string(path)?;
    let json_value: serde_json::Value = serde_json::from_str(&json_str)?;

    let mut ret = Vec::new();

    if let Some(vul_reports) = json_value.as_object(){
        for key in vul_reports.keys() {
            if let Some(vul_report) = vul_reports.get(key) {
                let vul_type = vul_report.get("bug_type").and_then(|v| v.as_str()).unwrap_or("");
                let buggy_value = vul_report.get("buggy_value").and_then(|v| v.as_str()).unwrap_or("");
                let relevant_values = vul_report.get("relevant_functions").and_then(|v| v.as_array()).map(Vec::as_slice).unwrap_or(&[]);
                let relevant_files = relevant_values.get(0).and_then(|v|v.as_array()).map(Vec::as_slice).unwrap_or(&[]);
                let relevant_funcs = relevant_values.get(1).and_then(|v|v.as_array()).map(Vec::as_slice).unwrap_or(&[]);
                let mut relevant_info = String::new();
                for (i, file) in relevant_files.iter().enumerate() {
                    let file = file.as_str().unwrap_or("");
                    let file = file.split("/data/projects/").last().unwrap_or("").split("/").skip(1).collect::<Vec<&str>>().join("/");
                    let func = relevant_funcs.get(i).and_then(|v| v.as_str()).unwrap_or("");
                    relevant_info.push_str(&format!("File path: {}, Func: {}\n", file.as_str(), func));
                }

                let explaination = vul_report.get("explanation").and_then(|v| v.as_str()).unwrap_or("");
                ret.push(vec![format!("Reported Bug Type: {}", vul_type), format!("Buggy Value: {}", buggy_value), format!("Relevant Code:\n{}", relevant_info), format!("Explaination: {}", explaination)]);
            }
        }
    }
    return Ok(ret);
}

fn parse_llmdfa_report(path: &Path) -> Result<Vec<Vec<String>>, Box<dyn Error>> {
    // llmdfa result is a list of str
    let json_str = std::fs::read_to_string(path)?;
    let json_value: serde_json::Value = serde_json::from_str(&json_str)?;
    let json_array = json_value.as_array().ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "Expected JSON array"))?;

    let mut ret = Vec::new();
    for item in json_array {
        ret.push(vec![format!("Vulnerability Report: {}", item)]);
    }
    return Ok(ret);
}

fn parse_inferroi_report(path: &Path) -> Result<Vec<Vec<String>>, Box<dyn Error>> {
    // the path feed to inferroi is a dictory, need iterate it.
    let mut ret = Vec::new();
    for json_file in path.read_dir()? {
        let json_file = json_file?;
        if json_file.path().extension().and_then(|s| s.to_str()) == Some("json") {
            let json_str = std::fs::read_to_string(json_file.path())?;
            let json_array = serde_json::from_str::<serde_json::Value>(&json_str)?;
            let json_array = json_array.as_array().map(Vec::as_slice).unwrap_or(&[]);
            let json_file_name = json_file.file_name();
            let json_file_name = json_file_name.to_str().unwrap_or("");
            for vul_report in json_array {
                let method_name = vul_report.get("method_name").and_then(|v| v.as_str()).unwrap_or("");
                let source_code = vul_report.get("source").and_then(|v| v.as_str()).unwrap_or("");
                let intensions = vul_report.get("intensions").and_then(|v| v.as_array()).map(Vec::as_slice).unwrap_or(&[]);
                // intensions
                let mut intensions_str = String::new();
                for intension in intensions {
                    if let Some(intension) = intension.as_array() {
                        intensions_str.push_str(&format!("Line: {}, {} resource, resource: {}, resource type: {}\n", intension[0].as_str().unwrap_or(""), intension[1].as_str().unwrap_or(""), intension[2].as_str().unwrap_or(""), intension[3].as_str().unwrap_or("")));
                    }
                }
                // leaks path
                let mut leaks_str = String::new();
                if let Some(leaks) = vul_report.get("leaks").and_then(|v| v.as_object()) {
                    for (leak_value, info) in leaks.iter() {
                        let leak_type = info.get("type").and_then(|v| v.as_str()).unwrap_or("");
                        let leak_path = info
                            .get("path")
                            .and_then(|v| v.as_array())
                            .map(|path| {
                                path.iter()
                                    .map(|v| v.as_str().unwrap_or(""))
                                    .collect::<Vec<&str>>()
                                    .join("\n")
                            })
                            .unwrap_or_default();
                        let leak_info = format!("Leak Value: {}, Leak Type: {}, Leak Path:\n{}", leak_value, leak_type, leak_path);
                        leaks_str.push_str(&leak_info);
                    }
                }
                ret.push(vec![format!("Report File: {}", json_file_name),format!("Method Name: {}", method_name), format!("Source Code:\n{}", source_code), format!("Intensions:\n{}", intensions_str), format!("Leaks:\n{}", leaks_str)]);
            }
        }
    }
    return Ok(ret);
}

fn get_attr(node: &NodeRef, name: &str) -> Option<String> {
    node.as_element()?
        .attributes
        .borrow()
        .get(name)
        .map(str::to_string)
}

fn has_class(node: &NodeRef, class: &str) -> bool {
    get_attr(node, "class")
        .unwrap_or_default()
        .split_whitespace()
        .any(|c| c == class)
}

fn parse_csa_html_report(path: &Path) -> Result<Vec<Vec<String>>, Box<dyn Error>> {
    let mut ret = Vec::new();

    for entry in path.read_dir()? {
        let entry = match entry {
            Ok(entry) => entry,
            Err(e) => {
                tracing::error!("Failed to read CSA report directory {:?}: {}", path, e);
                continue;
            }
        };

        let html_path = entry.path();

        if !html_path.is_file() {
            continue;
        }

        if html_path.file_stem().is_some_and(|stem| stem == "index") {
            continue;
        }

        if html_path.extension().is_some_and(|ext| ext != "html") {
            continue;
        }

        let html_str = match std::fs::read_to_string(&html_path) {
            Ok(s) => s,
            Err(e) => {
                tracing::error!("Failed to read CSA report file {:?}: {}", html_path, e);
                continue;
            }
        };

        let document = kuchiki::parse_html().one(html_str);

        let mut this_report = Vec::new();
        let mut path_events: Vec<(u32, String)> = Vec::new();

        if let Ok(rows) = document.select("table.simpletable tr") {
            for row in rows {
                let mut cells = match row.as_node().select("td") {
                    Ok(cells) => cells,
                    Err(e) => {
                        tracing::error!("Failed to select td cells: {:?}", e);
                        continue;
                    }
                };

                let Some(key_cell) = cells.next() else { continue };
                let Some(value_cell) = cells.next() else { continue };

                let key = key_cell.text_contents().trim().to_string();
                let value = value_cell.text_contents().trim().to_string();

                this_report.push(format!("{}: {}", key, value));
            }
        }

        let mut current_line: Option<String> = None;

        let code_lines = match document.select("table.code tr") {
            Ok(iter) => iter,
            Err(e) => {
                tracing::error!("Failed to select code lines: {:?}", e);
                continue;
            }
        };

        for line in code_lines {
            let line_node = line.as_node();

            if has_class(line_node, "codeline") {
                current_line = get_attr(line_node, "data-linenumber");
                continue;
            }

            let msgs = match line_node.select("div.msg") {
                Ok(iter) => iter,
                Err(e) => {
                    tracing::error!("Failed to select msg div: {:?}", e);
                    continue;
                }
            };

            for msg in msgs {
                let msg_node = msg.as_node();

                let index = match msg_node.select(".PathIndex") {
                    Ok(mut iter) => iter
                        .next()
                        .and_then(|n| n.text_contents().trim().parse::<u32>().ok()),
                    Err(e) => {
                        tracing::error!("Failed to select PathIndex: {:?}", e);
                        None
                    }
                };
                let Some(index) = index else { continue };
                let Some(line_num) = &current_line else { continue };

                let text = msg_node.text_contents();
                let text = text.trim();

                if !text.is_empty() {
                    path_events.push((
                        index,
                        format!("Path Index: {}, Line {}: {}", index, line_num, text),
                    ));
                }
            }
        }
        path_events.sort_by_key(|(index, _)| *index);
        this_report.extend(path_events.into_iter().map(|(_, text)| text));
        // println!("Report:\n{}", this_report.join("\n"));
        ret.push(this_report);
    }

    Ok(ret)
}

fn parse_iris_report(path: &Path) -> Result<Vec<Vec<String>>, Box<dyn Error>> {
    // iris use a json format
    let mut ret = Vec::new();
    let json_str = std::fs::read_to_string(path)?;
    let json_value: serde_json::Value = serde_json::from_str(&json_str)?;
    let json_value = json_value.as_array().ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "Expected JSON array"))?;

    for item in json_value{
        let item = item.as_object().ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "Expected JSON object"))?;
        
        let entry = item.get("entry").and_then(|v| v.as_object()).ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "Expected 'entry' field to be an object"))?;
        
        let result = entry.get("result").ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "Expected 'result' field to be an object"))?;

        if let Some(result) = result.as_object() {
            if result.get("is_vulnerable").and_then(|v| v.as_bool()).unwrap_or(false) {
                let path = entry.get("path").and_then(|v| v.as_array()).ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "Expected 'path' field to be an array"))?;
                let mut str = String::new();
                for item in path {
                    let item = item.as_object().ok_or_else(|| std::io::Error::new(std::io::ErrorKind::InvalidData, "Expected path item to be an object"))?;
                    let file = item.get("file_url").and_then(|v| v.as_str()).unwrap_or("");
                    let start_line = item.get("start_line").and_then(|v| v.as_u64()).unwrap_or(0);
                    let end_line = item.get("end_line").and_then(|v| v.as_u64()).unwrap_or(0);
                    let message = item.get("message").and_then(|v| v.as_str()).unwrap_or("");
                    str.push_str(&format!("{}:{}-{}: {}\n", file, start_line, end_line, message));
                }
                let explaination = result.get("explanation").and_then(|v| v.as_str()).unwrap_or("");
                ret.push(vec![format!("Vulnerability Path:\n{}", str), format!("Explaination: {}", explaination)]);
            }
        }
        
    }

    return Ok(ret)
}

fn parse_md_report(path: &Path) -> Result<Vec<Vec<String>>, Box<dyn Error>> {
    // split by ## report#xxx
    let mut ret = Vec::new();
    let md_str = std::fs::read_to_string(path)?;
    let reports: Vec<&str> = md_str.split("## Report#").collect();
    let reports = reports.into_iter().skip(1); // skip the first empty report
    for report in reports {
        let lines: Vec<String> = report.lines().map(|l| l.trim().to_string()).filter(|l| !l.is_empty()).collect();
        ret.push(lines);
    }
    return Ok(ret);
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
        SAST::REPOAUDIT => {
            let rows = parse_repoaudit_report(reports_path);
            if let Ok(data) = rows {
                tracing::info!("Successfully parsed RepoAudit JSON report with {} vulnerability reports", data.len());
                return Ok(data);
            } else {
                tracing::error!("Failed to parse RepoAudit JSON report {:?}: {:?}", reports_path, rows.err());
                return Err(format!("Failed to parse RepoAudit JSON report"));
            }
        },
        SAST::INFERROI => {
            let rows = parse_inferroi_report(reports_path);
            if let Ok(data) = rows {
                tracing::info!("Successfully parsed InferROI report with {} vulnerability reports", data.len());
                return Ok(data);
            } else {
                tracing::error!("Failed to parse InferROI report {:?}: {:?}", reports_path, rows.err());
                return Err(format!("Failed to parse InferROI report"));
            }
        },
        SAST::LLMDFA => {
            let rows = parse_llmdfa_report(reports_path);
            if let Ok(data) = rows {
                tracing::info!("Successfully parsed LLMDFA report with {} vulnerability reports", data.len());
                return Ok(data);
            } else {
                tracing::error!("Failed to parse LLMDFA report {:?}: {:?}", reports_path, rows.err());
                return Err(format!("Failed to parse LLMDFA report"));
            }
        },
        SAST::IRIS => {
            let rows = parse_iris_report(reports_path);
            if let Ok(data) = rows {
                tracing::info!("Successfully parsed IRIS SARIF report with {} vulnerability reports", data.len());
                return Ok(data);
            } else {
                tracing::error!("Failed to parse IRIS SARIF report {:?}: {:?}", reports_path, rows.err());
                return Err(format!("Failed to parse IRIS SARIF report"));
            }
        },
        SAST::KNIGHTER | SAST::CSA => {
            let rows = parse_csa_html_report(reports_path);
            if let Ok(data) = rows {
                tracing::info!("Successfully parsed CSA HTML report with {} vulnerability reports", data.len());
                return Ok(data);
            } else {
                tracing::error!("Failed to parse CSA HTML report {:?}: {:?}", reports_path, rows.err());
                return Err(format!("Failed to parse CSA HTML report"));
            }
        },
        SAST::ClaudeCode | SAST::Codex => {
            let rows = parse_md_report(reports_path);
            if let Ok(data) = rows {
                tracing::info!("Successfully parsed {} report with {} vulnerability reports", sast, data.len());
                return Ok(data);
            } else {
                tracing::error!("Failed to parse {} report {:?}: {:?}", sast, reports_path, rows.err());
                return Err(format!("Failed to parse {} report", sast));
            }
        },
        _ => {
            unimplemented!("SAST tool {:?} is not supported yet", sast);
        }
    }
}