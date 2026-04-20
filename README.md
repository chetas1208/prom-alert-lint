# prom-alert-lint

A CLI tool that analyses Prometheus alerting rule YAML files and flags common quality issues, anti-patterns, and operational risks — with **cross-alert relationship analysis**, **autofix suggestions**, **configurable policy**, and **CI-friendly output**.

---

## Architectural Design

This project is built using a strong, deterministic, pipeline-based system design appropriate for a production CLI tool. The system explicitly separates configuration, file handling, parsing, rule validation, result aggregation, and output formatting.

### Pipeline Stages

The architecture follows a strict, one-way data flow pipeline:

```text
            CLI / Entrypoint (cli.py)
                       │
                       ▼
 ┌────────────── AnalyzerEngine (app.py) ───────────────┐
 │                                                      │
 │  1. Input Discovery (discovery.py)                   │
 │     Resolves files, directories, handles recursion   │
 │                                                      │
 │  2. Parsing (parser.py)                              │
 │     Reads YAML safely, extracts rules to AlertRule   │
 │     domain models                                    │
 │                                                      │
 │  3. Policy Loading (policy.py)                       │
 │     Loads and merges user policy config              │
 │                                                      │
 │  4. Analysis (checks/*)                              │
 │     Executes pure, side-effect free checks on        │
 │     the parsed objects, emitting Finding objects     │
 │                                                      │
 │  5. Result Assembly (app.py)                         │
 │     Sorts findings, computes summary, wraps in       │
 │     AnalysisResult                                   │
 └──────────────────────────────────────────────────────┘
                       │
                       ▼
            Reporter (reporter.py)
            Produces Text / JSON output
                       │
                       ▼
         Exit Code Decider (exit_codes.py)
      Computes POSIX return code based on fail-on
```

### Module Responsibilities

- **`models.py`**: The definitive standard shapes of data moving between modules (`AlertRule`, `Finding`, `Policy`, `ParseResult`, `AnalysisResult`). We deal strictly in objects, not raw nested dictionaries.
- **`app.py`**: The `AnalyzerEngine`. It coordinates the pipeline stages so the CLI remains exceptionally thin.
- **`checks/`**: Pluggable rules that execute logic over `AlertRule` objects and return standard `Finding` instances. They do no I/O, rely only on injected `Policy`, and are side-effect free.
- **`suggestions.py`**: Separation of the remediation suggestions mapping logic outside of check logic to keep concerns cleanly divided.
- **`cli.py`**: Adapts shell arguments into function parameters, invokes `AnalyzerEngine`, delegates to `reporter`, and exits based on `exit_codes`.

### Interview Tradeoffs

- **Pipeline over Ad-Hoc Scripts:** By dividing responsibilities structurally, it becomes trivially easy to add parallel processing (in discovery or check execution) or new output formats without untangling business logic.
- **Heuristics over full AST parser:** A full AST PromQL parser introduces an immense maintenance burden. Regex-based heuristics cover 95% of typical operational misconfigurations without creating "fake scale" bloat.
- **Checks are side-effect free:** Modifying files directly or having checks print their own output is brittle. Returning structured `Finding` objects allows a future feature like a `--fix` system to consume them deterministically, while reporting handles the rest.
- **Suggestive Autofix:** Instead of rewriting code automatically (which can break alignment or structure in YAML), the tool generates snippets as a human-readable bridge until a `--fix` capability guarantees format-preserving serialization.
- **Strict Config Policies:** Instead of unbounded CLI flags, using a well-defined `policy.yaml` allows teams to codify expectations locally without turning the core logic into complex "if" branches.

---

## Features

### 🔗 Cross-Alert Relationship Analysis

The tool doesn't just lint rules in isolation — it analyses the **full rule set** together:

- **Duplicate alert names** across files with conflict detection
- **Identical expressions** under different names (copy-paste detector)
- **Inverted warning/critical thresholds** (critical less severe than warning)
- **Critical fires before warning** (escalation ordering)
- **Overlapping alerts** with near-identical thresholds (redundant noise)
- **Conflicting definitions** (same name, different severity/runbook)

### 🔧 Autofix Suggestions

Every finding includes a clear explanation of **what's wrong**, **why it matters operationally**, and **how to fix it**. Many findings include a ready-to-use autofix snippet:

```
[WARNING] rules.yaml :: group=alerts :: alert=HighCPU
  check: STAB001
  confidence: high
  issue: Alert has no 'for' clause and may fire on transient spikes.
  why it matters: Without a stabilization window, a single-sample anomaly
    can trigger a page. This is the #1 source of alert fatigue.
  suggestion: Add 'for: 5m' to require persistence.
  autofix:
    for: 5m
```

### 📋 Configurable Policy

Teams have different conventions. The policy file lets you customise lint expectations without forking:

```bash
prom-alert-lint rules/ --policy policy.yaml
```

Override required labels, annotations, ephemeral label lists, minimum `for` durations, generic name patterns, and more. Ignore specific checks or alert names.

### 🤖 CI-Friendly Output

- `--format json` for machine-readable output
- `--fail-on error|warning|info` for exit code control
- Structured JSON with summary, severity counts, and detailed findings

---

## Installation

```bash
git clone https://github.com/yourorg/prom-alert-linter.git
cd prom-alert-linter
pip install -e ".[dev]"
```

**Requirements:** Python 3.11+

---

## Usage

```bash
# Lint a single file
prom-alert-lint rules.yaml

# Lint multiple files or a directory
prom-alert-lint rules/*.yml
prom-alert-lint ./rules-dir

# Recursive directory scan
prom-alert-lint ./rules-dir --recursive

# JSON output for CI
prom-alert-lint ./rules --format json

# Apply team policy
prom-alert-lint ./rules --policy policy.yaml

# Only show warnings and errors
prom-alert-lint ./rules --min-severity warning

# Fail CI only on errors
prom-alert-lint ./rules --fail-on error

# Disable colour (for log capture)
prom-alert-lint ./rules --no-color
```

### CLI Flags

| Flag | Default | Description |
|---|---|---|
| `--format`, `-f` | `text` | Output format: `text` or `json` |
| `--min-severity`, `-s` | `info` | Only show findings at or above this severity |
| `--fail-on` | `warning` | Exit non-zero if any finding meets this threshold |
| `--policy`, `-p` | *(none)* | Path to a YAML policy file |
| `--no-color` | `false` | Disable colour output |
| `--recursive`, `-r` | `false` | Recurse into subdirectories |
| `--verbose`, `-v` | `false` | Enable debug logging |

### Exit Codes

| Code | Meaning |
|---|---|
| `0` | No findings at or above `--fail-on` threshold |
| `1` | Findings exist at or above threshold |
| `2` | Usage error (invalid args, bad policy, no files found) |

---

## Check Reference

### Metadata Checks (META001–META006)

| ID | Title | Severity | Autofix | Description |
|---|---|---|---|---|
| META001 | `missing_severity_label` | error | ✅ | No severity label — breaks routing |
| META002 | `missing_summary_annotation` | warning | ✅ | No summary — on-call can't triage |
| META003 | `missing_description_annotation` | warning | ✅ | No description — no trigger context |
| META004 | `missing_runbook_url` | warning | ✅ | No runbook — no remediation guidance |
| META005 | `missing_ownership` | info | ✅ | No team/service label — can't route |
| META006 | `generic_alert_name` | info | — | Name like "Alert" or "Error" |

### Stability / Noise Checks (STAB001–STAB005)

| ID | Title | Severity | Autofix | Description |
|---|---|---|---|---|
| STAB001 | `missing_for_clause` | warning | ✅ | No `for` — fires on single sample |
| STAB002 | `short_for_duration` | info | ✅ | `for` below policy minimum |
| STAB003 | `irate_in_expr` | warning | ✅ | Uses `irate()` — too spiky for alerting |
| STAB004 | `instant_threshold_without_smoothing` | info | — | Raw metric threshold without windowing |
| STAB005 | `critical_fires_before_warning` | warning | ✅ | Critical `for` shorter than warning |

### Selector Quality Checks (SEL001–SEL004)

| ID | Title | Severity | Autofix | Description |
|---|---|---|---|---|
| SEL001 | `bare_metric_selector` | info | — | No label filters on metric |
| SEL002 | `broad_up_selector` | warning | ✅ | `up == 0` without scoping |
| SEL003 | `ephemeral_label_dependency` | warning | — | Equality-match on pod/instance |
| SEL004 | `overly_narrow_selector` | warning | ✅ | Pins to auto-generated pod name |

### Cross-Alert Relationship Checks (REL001–REL006)

| ID | Title | Severity | Autofix | Description |
|---|---|---|---|---|
| REL001 | `duplicate_alert_names` | warning | — | Same name in multiple locations |
| REL002 | `identical_expressions` | warning | — | Same expr under different names |
| REL003 | `likely_duplicate_alerts` | info | — | Same expr, different metadata |
| REL004 | `suspicious_threshold_ordering` | error | ✅ | Critical threshold less severe than warning |
| REL005 | `overlapping_alerts` | info | — | Near-identical thresholds on same metric |
| REL006 | `conflicting_definitions` | warning | — | Same name, different severity/runbook |

---

## Future Improvements

- **AST-backed PromQL parsing** — integrate a lightweight parser for precise semantic analysis
- **SARIF output** — for GitHub Code Scanning and security/quality tools
- **Safe file rewriting mode** — `--fix` flag that applies autofix snippets to files safely preserving yaml styling and comments.
- **Richer rule deduplication** — semantic similarity beyond exact expression matching

---

## License

MIT
