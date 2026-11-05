# AegisReview

**AI-powered security code review: Find. Fix. Fortify.**

AegisReview takes an application's source code (a folder, a ZIP file or a git URL), has an AI model review it for security weaknesses, verifies every finding against the actual code, and writes a security assessment report with severity levels, code locations, explanations and secure code fixes.

Built for the CDF CyberSec Hackathon, *Intelligent Code Security Challenge*. It analyzes code generically: there are no hardcoded findings for any particular application.

## What it does

| Stage | What happens |
|---|---|
| **Find** | Multiple independent AI review passes (injection and input handling; access control and data exposure; secrets and configuration) read the code with line numbers and cross-file context. |
| **Verify** | Each finding must quote evidence that exists at the cited file and line. Findings with fabricated or unverifiable evidence are dropped automatically, and line numbers are corrected from the real source. |
| **Review** | A lead-reviewer AI pass merges duplicates, rejects speculative findings, and recalibrates severity, confidence and status (`confirmed` vs `needs_validation`). Rejections are listed in the report for transparency. |
| **Fix** | Each finding includes the risk in plain language, the impact, a root-cause remediation and a secure code snippet in the same language as the vulnerable code. |
| **Fortify** | Markdown, HTML and JSON reports with executive summary, severity counts, per-finding details, remediation table, overall assessment, and scope and limitations. |

## Quick start

Requirements: Python 3.9+ and a Google AI Studio API key (free tier works). Git is only needed for scanning git URLs.

```bash
git clone https://github.com/pateldarshil8/AegisReview.git
cd AegisReview
python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt

cp .env.example .env               # then edit .env and add your key
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
| `--model MODEL` | Override `GEMINI_MODEL` |
| `--lenses a,b` | Choose review passes (default all three). Fewer passes use fewer API calls. |
| `--no-ai` | Offline mode: pattern-based leads only. No code leaves your machine. |
| `--fail-on SEVERITY` | Exit code 1 if a finding at or above this severity exists (useful for CI) |
| `--env FILE` | Path to a `.env` file |

### Configuration (`.env`)

```
GEMINI_API_KEY=your_key_here
GEMINI_MODEL=gemini-3.5-flash
AI_FALLBACK_MODELS=gemini-3-flash-preview      # optional: tried when the primary is overloaded
```

See `.env.example` for retry, rate-limit and timeout settings. Never commit `.env` (it is in `.gitignore`).

A normal scan makes 4 AI calls (3 review passes and 1 lead review). Free-tier Gemini keys have per-minute and per-day request limits, so the client spaces requests out, retries on overload and rotates to fallback models.

## AI model integration

- **Provider:** Google Gemini through the official `google-genai` SDK. The model is configurable; any Gemini model that supports JSON output works.
- **Where AI is used:** vulnerability discovery across files (including frontend, backend functions and SQL policies together), explanation, severity and confidence judgement, secure code generation, de-duplication and false-positive review, and the executive summary and overall assessment.
- **Structured output:** responses are requested as JSON and validated and normalized in code. Malformed responses are retried.
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
  ai.py           Gemini client (retries, throttling, model fallback)
  analyzer.py     pipeline: review, evidence verification, consolidation
  report.py       Markdown / HTML / JSON report generation
tests/            unit tests (python -m unittest discover -s tests)
sample-report/    report generated for the provided CDF TaskFlow application
```

## Tests

```bash
python -m unittest discover -s tests
```

The tests cover redaction, input handling (including ZIP path traversal), evidence verification, JSON parsing, the pattern hints and report rendering. They do not call the AI service.

## Dependencies and attribution

- Python standard library
- [`google-genai`](https://pypi.org/project/google-genai/) (Apache-2.0), the Google Gen AI SDK, and its transitive dependencies
- Google Gemini API (external service, subject to Google's API terms)
- CDF TaskFlow, the intentionally vulnerable sample application provided by the hackathon organizers, is used only as an input for testing and for the sample report. It is not included in this repository.
- No other third-party code is reused. Everything in `aegisreview/` was written for this hackathon.

## Limitations

- Static analysis only: no runtime testing and no exploit execution.
- AI output is probabilistic. Treat findings marked `needs_validation` as leads, and review all findings before acting on them.
- Very large codebases are split into batches, which reduces cross-batch reasoning.
- Free-tier API quotas limit how many scans can run per day.

## License

MIT, see `LICENSE`.
