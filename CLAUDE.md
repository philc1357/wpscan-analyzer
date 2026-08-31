# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A single-script tool (`analyzer.py`) that takes a WPScan JSON scan result, enriches found CVEs with additional
details from the NVD API, sends everything to an LLM (via OpenRouter) for a German-language security assessment,
and writes the results to Markdown/JSON files. There is no package structure, no tests, and no build step — it's
one linear procedural script.

## Running

```bash
source venv/bin/activate
python analyzer.py
```

The script prompts interactively for the path to a WPScan JSON file (no CLI args). Dependencies are `requests`
and `python-dotenv`, installed in the committed `venv/` (no `requirements.txt` exists — if adding a new
dependency, install it into `venv` with `venv/bin/pip install <pkg>`).

### Required environment (`.env`, gitignored)

- `OPENROUTER_API_KEY` — required; used to call OpenRouter's `chat/completions` endpoint (model
  `openai/gpt-oss-20b:free`) for the LLM-generated assessment.
- `WPScan_API_Token` — optional; when present, the script queries the NVD API
  (`services.nvd.nist.gov`) for each CVE found in the scan to fetch richer CVSS/description data. Note this
  variable is misleadingly named: it doesn't authenticate to WPScan/NVD, it's just used as a flag gating the NVD
  enrichment step.

## Architecture (single file, top-to-bottom flow)

`analyzer.py` runs as a script (no `if __name__ == "__main__"` guard, no functions beyond a few
top-level helpers) in this order:

1. Load `.env`, prompt for and load the WPScan JSON file.
2. `extract_cves_from_scan()` — walks `scan_data["version"]`, `scan_data["main_theme"]`, and
   `scan_data["plugins"]` to pull out CVEs already present in the WPScan JSON (local extraction, no network).
3. `fetch_additional_cve_details()` — for each CVE ID found, queries the NVD API (rate-limited with
   `time.sleep(1)` per request) to get an up-to-date CVSS score/vector and description. Only runs if
   `WPScan_API_Token` is set.
4. `format_cve_list()` — merges local + NVD CVE data into a Markdown-formatted block for the LLM prompt.
5. A large German-language prompt is built embedding the full scan JSON plus the formatted CVE list, then sent
   to OpenRouter.
6. Output: three files are written per run, named from the domain extracted out of `scan_data["url"]`:
   - `wpscan_analysis_<domain>.md` — LLM analysis + raw scan JSON appended as an appendix
   - `wpscan_raw_<domain>.json` — the raw scan data, re-serialized
   - `cve_summary_<domain>.json` — structured summary of all local + NVD CVE data
   A condensed summary (WP version, theme, security-relevant `interesting_findings`, critical CVEs) is also
   printed to the console.

## Data files in the repo root

`.gitignore` excludes `.env`, `*.json`, and `*.md`, so the various `*.json` (raw WPScan scans) and `*.md`
(generated analysis reports) files sitting in the repo root are local scan artifacts/outputs from real target
sites — not tracked, not fixtures to rely on for tests.
