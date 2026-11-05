# AegisReview

**AI-powered security code review: Find. Fix. Fortify.**

AegisReview takes an application's source code (a folder, a ZIP file or a git URL), has Anthropic's Claude review it for security weaknesses, verifies every finding against the actual code, and writes a security assessment report with severity levels, code locations, explanations and secure code fixes.

Built for the CDF CyberSec Hackathon, *Intelligent Code Security Challenge*. It analyzes code generically: there are no hardcoded findings for any particular application.

## What it does

| Stage | What happens |
|---|---|
| **Find** | Multiple independent Claude review passes (injection and input handling; access control and data exposure; secrets and configuration) read the code with line numbers and cross-file context. |
| **Verify** | Each finding must quote evidence that exists at the cited file and line. Findings with fabricated or unverifiable evidence are dropped automatically, and line numbers are corrected from the real source. |
| **Review** | A lead-reviewer Claude pass merges duplicates, rejects speculative findings, and recalibrates severity, confidence and status (`confirmed` vs `needs_validation`). Rejections are listed in the report for transparency. |
| **Fix** | Each finding includes the risk in plain language, the impact, a root-cause remediation and a secure code snippet in the same language as the vulnerable code. |
| **Fortify** | Markdown, HTML and JSON reports with executive summary, severity counts, per-finding details, remediation table, overall assessment, and scope and limitations. The structure follows the hackathon's sample report template (same sections, order and field names). |

## Quick start

Requirements: Python 3.9 or newer (tested on 3.9 and 3.15) and an [Anthropic API key](https://console.anthropic.com/). Git is only needed for scanning git URLs.

```bash
git clone https://github.com/pateldarshil8/AegisReview.git
cd AegisReview
python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt

cp .env.example .env               # then edit .env and add your ANTHROPIC_API_KEY
python -m aegisreview check        # verifies the key and model
```

Analyze a codebase:

```bash
python -m aegisreview scan /path/to/app                 # a folder
python -m aegisreview scan app.zip                      # a ZIP file
python -m aegisreview scan https://github.com/org/repo  # a git URL (shallow clone)
```

Reports are written to `./reports/` as `<app>-security-report.md`, `.html` and `.json`. Open the HTML file in a browser (and print to PDF if you need one).

### Options

| Option | Meaning |
|---|---|
| `-o, --out DIR` | Output directory (default `reports`) |
| `--formats md,html,json` | Which reports to write |
| `--name NAME` | Application name shown in the report |
| `--model MODEL` | Override `ANTHROPIC_MODEL` |
| `--lenses a,b` | Choose review passes (default all three). Fewer passes use fewer API calls. |
| `--no-cache` | Do not reuse cached AI responses |
| `--no-ai` | Offline mode: pattern-based leads only. No code leaves your machine. |
| `--fail-on SEVERITY` | Exit code 1 if a finding at or above this severity exists (useful for CI) |
| `--env FILE` | Path to a `.env` file |

### Configuration (`.env`)

```
ANTHROPIC_API_KEY=your_key_here
ANTHROPIC_MODEL=claude-sonnet-5-5
# ANTHROPIC_FALLBACK_MODELS=claude-haiku-5-5   # optional: tried when the primary is overloaded
```

See `.env.example` for retry, rate-limit and timeout settings. Never commit `.env` (it is in `.gitignore`).

A normal scan makes 4 AI calls (3 review passes and 1 lead review) and takes about a minute. The client spaces requests out, retries on overload and rate limits, and can rotate to fallback models. Identical requests are cached in `.aegis-cache/`, so re-running the same scan on unchanged code is instant and free; use `--no-cache` to force fresh calls.

## For evaluators: running on an unseen codebase

The tool contains no rules or answers specific to any one application; it analyzes whatever code it is given (TypeScript/JavaScript, Python, Java, Go, Ruby, PHP, C#, Rust, SQL, shell, YAML, Dockerfiles and more).

1. Install as shown in [Quick start](#quick-start) and put an Anthropic API key in `.env` (`ANTHROPIC_API_KEY=...`). The tool needs this key because the analysis is done by Claude; a scan typically takes about a minute and costs a few cents.
2. Run `python -m aegisreview scan <folder | .zip | git URL> --name "<application name>"`.
3. Open `reports/<application-name>-security-report.html` (Markdown and JSON versions are written next to it).

Without a key, `--no-ai` still runs an offline pattern-based pass (no code leaves the machine), but findings from that mode are only unverified leads.

## AI model integration

- **Model:** Anthropic Claude through the official `anthropic` SDK (default `claude-sonnet-5-5`, configurable).
- **Where AI is used:** vulnerability discovery across files (including frontend, backend functions and SQL policies together), explanation, severity and confidence judgement, secure code generation, de-duplication and false-positive review, and the executive summary and overall assessment.
- **Structured output:** the prompts require a single JSON object; responses are parsed, validated and normalized in code, and malformed responses are retried.
- **Handling uncertainty:** every finding is `confirmed` (directly evident in the code) or `needs_validation` (depends on context the tool cannot see), with a confidence level and validation notes. Placeholder-looking credentials are never reported as confirmed leaks.
- **Grounding:** the code verifies quoted evidence against the file before a finding is accepted. The report shows the real lines from the source, not the model's paraphrase.
- **Pattern hints:** a small set of generic regex rules (for example `eval`, raw HTML sinks, always-true row-level-security policies, tables without RLS) provides unverified leads to the AI prompts. They are only reported directly in `--no-ai` mode or if the AI service is unreachable, and then labelled as pattern-based and needing validation.

## Security and privacy

- **Secrets are redacted before analysis.** Credential-like values (JWTs, cloud keys, tokens, private keys, `password = "..."` style assignments) are replaced with markers such as `<REDACTED:jwt:len=120:placeholder-like=no>` before any code is sent to the AI. Reports never contain the redacted values.
- **Source code is treated as untrusted data.** It is wrapped in delimiters, the prompts instruct the model to ignore instructions embedded in code, comments or file names, and the tool never executes the code it analyzes. Markdown files are not sent to the model.
- **ZIP input is extracted safely** (path traversal and size checks). Git URLs are cloned shallowly into a temporary directory that is deleted afterwards.
- Only analyze code you own or are authorized to share with an external AI provider. The tool prints a notice before sending code.

## Project layout

```
aegisreview/
  cli.py          command line interface (scan, check)
  collector.py    folder / ZIP / git input, file filtering
  redact.py       secret redaction
  hints.py        generic pattern hints
  prompts.py      review and lead-review prompts
  ai.py           Claude client (retries, throttling, model fallback, cache)
  analyzer.py     pipeline: review, evidence verification, consolidation
  report.py       Markdown / HTML / JSON report generation
tests/            unit tests (python -m unittest discover -s tests)
sample-report/    report generated for the provided CDF TaskFlow application
```

## Tests

```bash
python -m unittest discover -s tests
```

The tests cover redaction, input handling (including ZIP path traversal), evidence verification, JSON parsing, client settings and error handling, caching, the pattern hints and report rendering. They do not call the AI service.

## Dependencies and attribution

- Python standard library
- [`anthropic`](https://pypi.org/project/anthropic/) (MIT), the Anthropic Python SDK, and its transitive dependencies
- Anthropic Claude API (external service, subject to Anthropic's API terms)
- CDF TaskFlow, the intentionally vulnerable sample application provided by the hackathon organizers, is used only as an input for testing and for the sample report. It is not included in this repository.
- No other third-party code is reused. Everything in `aegisreview/` was written for this hackathon.

## Limitations

- Static analysis only: no runtime testing and no exploit execution.
- AI output is probabilistic. Treat findings marked `needs_validation` as leads, and review all findings before acting on them. Repeat runs may differ slightly.
- Very large codebases are split into batches, which reduces cross-batch reasoning.
- API rate limits and costs apply.

## License

MIT, see `LICENSE`.
