# IPI MiniAgent lab

A ~150-line toy ReAct agent for reproducing **indirect prompt injection (IPI)**
and measuring which defenses block which payloads, entirely on a model you host
yourself.

- `ipi_lab.py` — the lab. All tools are mocked (log-only); the canary and
  sentinel are fictional; nothing leaves the machine.
- `results-qwen3-8b-n20.csv` — the raw ASR matrix (success count / N) measured
  with `qwen3:8b` via Ollama, N=20 per cell, temperature 0.2.

Full write-up (Japanese), including the 5×5 defense × payload matrix and the
analysis: [`../../blog/ipi-lab-ja.md`](../../blog/ipi-lab-ja.md).

## Run

```bash
export OPENAI_BASE_URL=http://localhost:11434/v1   # Ollama OpenAI-compat API
export OPENAI_API_KEY=dummy
export IPI_MODEL=qwen3:8b
export IPI_TRIALS=20
python ipi_lab.py
```

## Headline findings (qwen3:8b, N=20)

- A naive **input filter made every text attack worse**, not better — decoding
  Base64 / stripping zero-width "normalizes" the hidden instruction into clean
  plaintext (Base64 ASR 5% → 90%).
- An **action-layer monitor** (recipient allow-list on the sink) was the only
  defense that drove ASR to **0% across all payloads** — it never inspects the
  text, it constrains what the agent can *do*.

> Small-model, single-model pilot. Read it as a relative comparison of defenses,
> not as absolute numbers for frontier models.
