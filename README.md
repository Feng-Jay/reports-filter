# reports-filter

`reports-filter` is the artifact pipeline used to normalize vulnerability reports from multiple static-analysis and LLM-based security tools and validate a sample of their findings with Codex. For each sampled report, Codex inspects the corresponding source repository, assigns a true-positive (`TP`) or false-positive (`FP`) label, records supporting evidence, and—when applicable—assigns the dominant false-positive reason from the taxonomy used in the paper.

The repository also contains the released validation results and benchmark metadata used in the paper.

## Pipeline overview

For one tool/project/CWE combination, the executable:

1. reads `config.yaml`;
2. parses the tool-specific report into a common textual representation;
3. randomly samples `ceil(number_of_reports * sample_ratio)` reports, capped at 300;
4. runs `codex exec` in the target project's source tree for each sampled report;
5. requires Codex to return a structured `TP`/`FP` judgment, analysis, evidence, and an FP-reason category;
6. writes the successful judgments to a JSON file next to the input report.

Each Codex call is retried up to three times if the process fails or its response does not contain the expected JSON object.

## Repository layout

```text
.
├── src/
│   ├── main.rs              # CLI, sampling, and experiment orchestration
│   ├── parse.rs             # parsers for the supported report formats
│   ├── codex.rs             # validation prompt and Codex CLI invocation
│   └── utils/               # YAML configuration and logging
├── config.yaml              # example experiment configurations
├── resources/real_world/
│   ├── c_projects.json      # C/C++ benchmark repositories and revisions
│   └── java_projects.json   # Java benchmark repositories and revisions
└── results_v3/              # released labels and aggregated paper artifacts
```

The most useful released artifacts are:

- `results_v3/<tool>/<project>.json`: per-tool, per-project Codex validation output;
- `results_v3/sampled_items_final.json`: consolidated sampled findings and judgments;
- `results_v3/sampled_items_fp_reason_final.json`: consolidated false positives grouped by reason.

The repository metadata files list the project URL, revision, CWE, and—where applicable—the analyzed subdirectory for every benchmark target.

## Supported report formats

Set `sast` in the configuration to one of the values below.

| `sast` value | Expected `results_file` |
| --- | --- |
| `codeql` | Headerless CSV file with nine CodeQL alert columns |
| `semgrep` | SARIF JSON file |
| `spotbugs` | SpotBugs XML file |
| `repoaudit` | RepoAudit JSON object |
| `inferroi` | Directory containing InferROI JSON files |
| `llmdfa` | JSON array of report strings |
| `iris` | IRIS JSON array containing `entry` objects |
| `knighter` | Directory containing Clang Static Analyzer-style HTML reports |
| `csa` | Directory containing Clang Static Analyzer HTML reports |
| `codex` | Markdown file whose findings begin with `## Report#` |
| `claudecode` | Markdown file whose findings begin with `## Report#` |

## Requirements

- Rust 1.85 or newer (the crate uses Rust 2024 edition)
- Git
- Codex CLI available as `codex` and authenticated
- Network/API access for Codex inference
- A local checkout of the source repository being inspected

For reference, the artifact was successfully built and tested with Rust 1.91.0, Cargo 1.91.0, and `codex-cli` 0.144.2. The exact model and credentials used by `codex exec` come from the user's Codex configuration; they are not selected by this program.

## Build

```bash
cd reports-filter
cargo build --release --locked
```

To verify the Rust crate:

```bash
cargo test --locked
```

The current crate contains no unit tests, so this command primarily verifies that the library and executable compile.

## Prepare a target repository

Clone the project that corresponds to the report being validated. The directory's basename must match one of the benchmark names in `resources/real_world/c_projects.json` or `resources/real_world/java_projects.json`, including capitalization (for example, `ImageMagick`, `RxJava`, or `OpenOLAT`).

Check out the revision recorded in the appropriate metadata file before running the pipeline:

```bash
git clone https://github.com/jhy/jsoup.git /path/to/projects/jsoup
git -C /path/to/projects/jsoup checkout --detach acafbcf3cb71ea0a04188c8f6257e3d395fa7c36
git -C /path/to/projects/jsoup status --short
```

Use a clean, disposable checkout. Codex runs with the project directory as its working directory and may inspect any files available there.

> **Revision-handling limitation:** the current `checkout_project` helper builds a `git checkout -f` command but does not execute it. In addition, the executable resolves revisions from an internal map keyed by repository basename and does not use the YAML `commit_id` as a fallback. Therefore, manually checking out the revision is required, and an unrecognized repository basename will cause the executable to stop.

## Configure an experiment

Create a YAML file such as `config.local.yaml`:

```yaml
log_level: info
log_file: ./logs/codeql-cwe-772-jsoup.log
sast: codeql
vul: CWE-772
sample_ratio: 1.0
results_file: /absolute/path/to/codeql-jsoup.csv
repos_dir: /absolute/path/to/projects/jsoup
commit_id: acafbcf3cb71ea0a04188c8f6257e3d395fa7c36
```

Configuration fields:

| Field | Meaning |
| --- | --- |
| `log_level` | `tracing` filter, such as `info` or `debug` |
| `log_file` | File receiving a copy of the run log; its parent directory must exist |
| `sast` | Parser/tool identifier from the supported-format table |
| `vul` | Target CWE identifier included in the validation prompt |
| `sample_ratio` | Fraction of parsed findings to sample; the final count is capped at 300 |
| `results_file` | Input report file or directory, depending on the selected parser |
| `repos_dir` | Local source checkout Codex will inspect |
| `commit_id` | Benchmark revision metadata; check it out manually as described above |

Create the log directory before running:

```bash
mkdir -p logs
```

`config.yaml` contains additional examples for the supported tools. Its paths are machine-specific and must be replaced with paths on your system.

## Run

```bash
cargo run --release --locked -- --config-file config.local.yaml
```

The short form is also supported:

```bash
cargo run --release --locked -- -c config.local.yaml
```

The progress bar advances once per sampled report. Detailed parser output, prompts, responses, and errors are written to standard output and `log_file`.

## Output format

For an input file named `/path/to/report.csv`, the executable writes:

```text
/path/to/validated_v3_report.json
```

The top-level object maps the original zero-based report index to a JSON-encoded string. Decoding that string yields the normalized report and Codex response:

```json
{
  "report": "Rule Name: ...\nDetailed Message: ...",
  "response": "{\n  \"judgement\": \"FP\", ...\n}"
}
```

The nested `response` string is itself JSON with this schema:

```json
{
  "judgement": "TP or FP",
  "analysis": "reasoning supporting the judgment",
  "FP_Reason": ["A1"],
  "evidence": "code and reachability evidence",
  "new_reason:": "optional newly observed FP reason"
}
```

`FP_Reason` is empty for true positives and contains the single dominant taxonomy category for false positives. The field name `new_reason:` includes a trailing colon in the current artifact schema.

With `jq`, one output entry can be decoded as follows:

```bash
jq 'to_entries[0].value | fromjson | .response | fromjson' \
  /path/to/validated_v3_report.json
```

Only successful Codex judgments are written. A finding is absent if all three attempts fail or return an invalid response.

## False-positive taxonomy

The validation prompt uses the following categories:

| Category | Description |
| --- | --- |
| `A1` | Truncated interprocedural or project context |
| `A2` | Theoretically unreachable control-flow construction |
| `B1` | Incorrect source or sink selection |
| `C1` | Deviation from the prompt or target CWE definition |
| `D1` | Missed checks, sanitizers, releases, or other key program points |
| `D2` | Misunderstood programming-language features |
| `D3` | Path-insensitive reasoning or runtime-infeasible flow |
| `D4` | Ignored type, structure, or class information |

The full operational definitions and decision order are embedded in `src/codex.rs`.

## Reproducibility notes

- Sampling uses an unseeded random-number generator. Re-running the program can select a different subset when `sample_ratio` does not include every report.
- The sample size is `ceil(N * sample_ratio)`, with a maximum of 300 findings.
- Codex behavior can vary with CLI/model versions and service-side updates. Record the output of `codex --version` and the active model configuration for new runs.
- The program does not persist a run manifest containing the model, prompt hash, random seed, or failed indexes.
- Paths in the example `config.yaml` and released raw report text reflect the original experiment environment and may need to be translated on another machine.
- Use the checked-in `results_v3/` files when evaluating the exact labels released with the paper; use the executable to reproduce the validation procedure on prepared inputs and source checkouts.

## Data and privacy

The report text and relevant source-code context are made available to the Codex process during validation. Do not run the pipeline on confidential reports or source trees unless the configured Codex deployment and data-handling policy are appropriate for that material.
