# SBOM → VEX Agent

> Automatically generate signed CycloneDX VEX documents from SBOMs using a secure multi-agent AI pipeline, built in accordance with the OWASP GenAI Security Project guidelines.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![OWASP](https://img.shields.io/badge/OWASP-GenAI%20Aligned-red)](https://genai.owasp.org)
[![CycloneDX](https://img.shields.io/badge/CycloneDX-1.6-green)](https://cyclonedx.org)
[![AutoGen](https://img.shields.io/badge/AutoGen-v0.4-purple)](https://microsoft.github.io/autogen)

---

## The Problem

Generating an SBOM surfaces hundreds of CVEs. In practice, over 90% are not exploitable in a specific product's runtime context. Without a Vulnerability Exploitability eXchange (VEX) document, every downstream tool — Dependency-Track, release gates, procurement checklists — drowns in false positives.

Manual VEX generation is time-consuming and does not scale. A skilled analyst can spend hours assessing a single component. A production SBOM may contain 500–2,000 components.

This project automates that reasoning pipeline — securely, without vendor lock-in, with all data remaining on your infrastructure.

> **Real-world motivation:** In 2024, security researcher Johanna Curiel documented exactly this problem while analysing the Kubernetes Java Client ([LinkedIn article](https://www.linkedin.com/pulse/analysing-supply-chain-vulnerabilities-kubernetes-java-curiel/)). The OSV scanner identified a high-risk CVE in `com.diffplug.spotless:spotless-maven-plugin 1.17.0` in seconds. Determining it was `not_affected` (build-time plugin, never executed at runtime) took hours of manual analysis. This project automates that reasoning step.

---

## Architecture

Four security zones. Nothing crosses a boundary without explicit validation.

```
┌─────────────────────────────────────────────────────────────────┐
│  ZONE 1 — Input ingestion (no LLM)                              │
│  SBOM upload → Schema validate → Sanitise → SHA-256 audit hash  │
└────────────────────────────┬────────────────────────────────────┘
                             │
┌────────────────────────────▼────────────────────────────────────┐
│  ZONE 2 — OWASP guardrail middleware                            │
│  Prompt guard (LLM01) · Output filter (LLM02/05)                │
│  Agency limiter (LLM06) · Token budget (LLM10)                  │
└────────────────────────────┬────────────────────────────────────┘
                             │
┌────────────────────────────▼────────────────────────────────────┐
│  ZONE 3 — Multi-agent pipeline (AutoGen AgentChat)              │
│                                                                  │
│  Orchestrator                                                    │
│       ├── CVE Analyst       NVD v2 + OSV + EPSS per component   │
│       ├── Exploit Reasoner  Call graph · LLM reasoning · RAG    │
│       └── VEX Writer        CycloneDX 1.6 schema-validated      │
│                                                                  │
│  Vector store (Qdrant) — signed past VEX decisions              │
└────────────────────────────┬────────────────────────────────────┘
                             │
┌────────────────────────────▼────────────────────────────────────┐
│  ZONE 4 — Output, signing, audit                                │
│  Human-in-the-loop gate → cosign/GPG sign → audit log           │
└─────────────────────────────────────────────────────────────────┘
```

---

## OWASP GenAI Compliance

This project is designed against the [OWASP Top 10 for LLM Applications 2025](https://genai.owasp.org/llm-top-10/) and the [OWASP Top 10 for Agentic Applications 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/).

| OWASP Risk | ID | Mitigation in this project |
|---|---|---|
| Prompt Injection | LLM01 | All SBOM fields sanitised before LLM injection; injection pattern blocklist |
| Sensitive Info Disclosure | LLM02 | PII scrubber on all agent outputs; internal path filter |
| Improper Output Handling | LLM05 | CycloneDX schema validation before signing; retry on failure |
| Excessive Agency | LLM06 | Read-only tools during analysis; HITL gate for all CVSS ≥ 7.0 rulings |
| System Prompt Leakage | LLM07 | Internal policies separated from system prompt |
| Vector / Embedding Weakness | LLM08 | Stored vectors signed; provenance checked before context injection |
| Unbounded Consumption | LLM10 | `MaxMessageTermination(20)`; per-component token budget; NVD timeout |

> **Human-in-the-loop is mandatory.** A VEX `not_affected` statement for a high-severity CVE is a legal-grade assertion. No VEX is signed without human reviewer approval. This is not configurable.

---

## Tech Stack

| Component | Tool | Notes |
|---|---|---|
| Agent orchestration | [AutoGen AgentChat v0.4](https://microsoft.github.io/autogen) | Multi-agent, tool-use, message hooks |
| LLM (recommended) | [Qwen2.5-Coder-32B](https://huggingface.co/Qwen/Qwen2.5-Coder-32B-Instruct) | Best structured JSON + security reasoning |
| LLM server | [vLLM](https://docs.vllm.ai) (prod) / [Ollama](https://ollama.com) (dev) | OpenAI-compatible API |
| CVE data | NVD v2 API + [OSV.dev](https://osv.dev) + [EPSS](https://api.first.org) | All free, no API key required |
| Vector store | [Qdrant](https://qdrant.tech) | Self-hosted, past VEX decisions |
| Embeddings | `all-MiniLM-L6-v2` (sentence-transformers) | Fully local |
| SBOM formats | CycloneDX 1.4–1.7 (JSON/XML), SPDX 2.3/3.0 | Schema-validated on ingest |
| VEX output | CycloneDX 1.6 VEX | Schema-validated before signing |
| Signing | [cosign](https://docs.sigstore.dev) (Sigstore keyless) | Timestamped, audit-logged |
| Audit log | PostgreSQL (append-only, pgaudit) | Every agent decision recorded |

Everything runs on-premises. No data leaves your infrastructure.

---

## Requirements

**Hardware (production):**
- 1× A100 80GB, or 2× RTX 3090 (48GB VRAM combined) for Qwen2.5-Coder-32B
- 16GB+ system RAM
- 100GB+ SSD for model weights and vector store

**Hardware (development / small SBOMs):**
- Any machine with 16GB RAM — use `llama3.1:8b` via Ollama

**Software:**
- Python 3.11+
- Docker + Docker Compose
- Node.js 18+ (for cosign tooling)

---

## Quick Start

### 1. Clone and install

```bash
git clone https://github.com/your-org/sbom-vex-agent
cd sbom-vex-agent
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

### 2. Start the LLM backend

```bash
# Development — Ollama (CPU/GPU, any laptop)
ollama pull llama3.1
ollama serve

# Production — vLLM (GPU required)
python -m vllm.entrypoints.openai.api_server \
  --model Qwen/Qwen2.5-Coder-32B-Instruct \
  --gpu-memory-utilization 0.90 \
  --host 0.0.0.0 --port 8000
```

### 3. Start supporting services

```bash
docker compose up -d   # starts Qdrant + PostgreSQL
```

### 4. Run the agent on an SBOM

```bash
python -m vex_agent analyse \
  --sbom path/to/your-sbom.cdx.json \
  --output path/to/output.vex.json
```

The pipeline will:
1. Validate and sanitise the SBOM
2. Look up CVEs for each component
3. Reason about exploitability
4. Present draft VEX to a human reviewer
5. Sign and emit the final document on approval

---

## Configuration

Copy `.env.example` to `.env` and set:

```env
# LLM backend
VLLM_BASE_URL=http://localhost:8000/v1    # or Ollama: http://localhost:11434/v1
LLM_MODEL=Qwen2.5-Coder-32B-Instruct     # or llama3.1 for dev

# Services
QDRANT_URL=http://localhost:6333
AUDIT_DB_URL=postgresql://audit:secret@localhost:5432/audit

# Signing (leave blank to use cosign keyless via Sigstore OIDC)
GPG_KEY_ID=                               # optional: use GPG instead
```

---

## Project Structure

```
sbom-vex-agent/
├── vex_agent/
│   ├── ingest.py          # Zone 1: SBOM validation and sanitisation
│   ├── guardrails.py      # Zone 2: OWASP middleware (GuardrailedAgent)
│   ├── agents/
│   │   ├── orchestrator.py
│   │   ├── cve_analyst.py
│   │   ├── exploit_reasoner.py
│   │   └── vex_writer.py
│   ├── tools/
│   │   ├── nvd.py         # NVD v2 API client
│   │   ├── osv.py         # OSV.dev client
│   │   └── epss.py        # EPSS scoring
│   ├── vector_store.py    # Qdrant integration + provenance signing
│   ├── hitl.py            # Human-in-the-loop review gate
│   └── sign.py            # Zone 4: cosign / GPG signing
├── schemas/
│   ├── cdx-1.6.schema.json
│   └── cdx-1.6-vex.schema.json
├── tests/
├── docker-compose.yml
├── .env.example
└── requirements.txt
```

---

## VEX Output Format

The agent produces CycloneDX 1.6 VEX documents. Example output for a single component:

```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "version": 1,
  "metadata": {
    "timestamp": "2026-04-26T10:00:00Z",
    "tools": [{ "name": "sbom-vex-agent", "version": "1.0.0" }]
  },
  "vulnerabilities": [
    {
      "id": "CVE-2021-37714",
      "affects": [{ "ref": "pkg:maven/com.diffplug.spotless/spotless-maven-plugin@1.17.0" }],
      "analysis": {
        "state": "not_affected",
        "justification": "vulnerable_code_not_in_execute_path",
        "detail": "Plugin executes only at build time; not present in deployed runtime."
      }
    }
  ]
}
```

Valid `state` values: `affected` · `not_affected` · `fixed` · `under_investigation`

Valid `justification` values (for `not_affected`):
- `component_not_present`
- `vulnerable_code_not_present`
- `vulnerable_code_not_in_execute_path`
- `vulnerable_code_cannot_be_controlled_by_adversary`
- `inline_mitigations_already_exist`

---

## Related Resources

- [OWASP GenAI Security Project](https://genai.owasp.org)
- [OWASP Top 10 for LLM Applications 2025](https://genai.owasp.org/llm-top-10/)
- [OWASP Top 10 for Agentic Applications 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
- [CycloneDX Specification](https://github.com/CycloneDX/specification)
- [AutoGen AgentChat v0.4](https://microsoft.github.io/autogen)
- [OSV Vulnerability Database](https://osv.dev)
- [EPSS Scoring API](https://api.first.org/data/v1/epss)
- [Sigstore / cosign](https://docs.sigstore.dev)
- Johanna Curiel — [Analysing Supply Chain Vulnerabilities in the Kubernetes Java Client Using SBOM and Generating VEX](https://www.linkedin.com/pulse/analysing-supply-chain-vulnerabilities-kubernetes-java-curiel/) (2024)

---

## Contributing

Contributions welcome. Please open an issue before submitting a pull request for significant changes.

Security issues should be reported privately — see [SECURITY.md](SECURITY.md).

---

## License

MIT — see [LICENSE](LICENSE).

---

*Built in alignment with the [OWASP GenAI Security Project](https://genai.owasp.org). Not an official OWASP project.*
