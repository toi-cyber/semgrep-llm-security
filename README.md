# semgrep-llm-security

Static-analysis rules that catch insecure patterns in **LLM-powered application
code** — the glue around the model (prompts, tools, RAG, output rendering),
where most real LLM vulnerabilities actually live.

The model itself is rarely the hole. The holes are at the boundaries: untrusted
text reaching the trusted instruction channel, model output reaching a dangerous
sink, agents wired to shell/DB/HTTP with no guard. These rules find those
boundaries in source, before they ship.

Mapped to the [OWASP Top 10 for LLM Applications (2025)](https://genai.owasp.org/llm-top-10/).

## Why

Dynamic LLM red-teaming tools (garak, PyRIT, promptfoo) test a running system.
This pack works one step earlier — in the codebase and in CI — so insecure
wiring is caught at review time. It is small, opinionated, and dependency-light:
just [Semgrep](https://semgrep.dev/) rule files.

## Install & run

```bash
pip install semgrep
semgrep --config rules/ path/to/your/app
```

Add to CI (see `.github/workflows/ci.yml`) or pre-commit.

## Rules

| Rule ID | Severity | OWASP LLM | What it catches |
|---|---|---|---|
| `llm-output-to-code-execution` | ERROR | LLM05 / LLM06 | Model output into `eval`/`exec`/`os.system`/`shell=True`/`pickle.loads` → RCE |
| `llm-output-to-sql-query` | ERROR | LLM05 | Model output built into a SQL query string → SQLi |
| `llm-output-rendered-as-html` | WARNING | LLM05 | Model output rendered as raw HTML → XSS / Markdown-image exfiltration |
| `llm-output-to-server-side-request` | WARNING | LLM06 | Model output used as a URL → SSRF via indirect injection |
| `langchain-dangerous-tool-enabled` | ERROR | LLM06 | `PythonREPLTool`/`ShellTool`/`terminal` tool enabled → RCE |
| `langchain-allow-dangerous-flag` | ERROR | LLM06 | `allow_dangerous_*=True` disables a safety guard |
| `user-input-in-system-prompt` | WARNING | LLM01 | Runtime values spliced into the system prompt → prompt injection |

The output-handling rules use Semgrep **taint mode**: they fire only when data
that originates from an LLM call actually reaches the sink, which keeps false
positives low (e.g. parameterised SQL with a model value as a bound parameter
is *not* flagged — see `tests/`).

## Try it

```bash
semgrep --config rules/ examples/vulnerable_support_bot.py
```

`examples/vulnerable_support_bot.py` is an intentionally vulnerable demo bot that
trips four rules at once; use it as a target and as a before/after for write-ups.

## Develop

Each rule file has a paired fixture in `tests/` with `# ruleid:` / `# ok:`
annotations. Validate and test:

```bash
semgrep --validate --config rules/
semgrep --test --config rules/ tests/
```

## Scope & limits

These are *source-level heuristics*, not a guarantee. They catch common insecure
wiring; they do not prove an app is safe, and they will miss patterns phrased
differently from the shipped `pattern-sources`. Contributions that add sources
(other SDKs, frameworks) and sinks are welcome. See `docs/design-ja.md` for the
rationale behind each rule (日本語).

## License

MIT © toy
