# SBOM → VEX Agent

> Automatically generate signed CycloneDX VEX documents from SBOMs using a secure multi-agent AI pipeline built with the **Microsoft Agent Framework (C# / .NET)** in accordance with the OWASP GenAI Security Project guidelines.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![OWASP](https://img.shields.io/badge/OWASP-GenAI%20Aligned-red)](https://genai.owasp.org)
[![CycloneDX](https://img.shields.io/badge/CycloneDX-1.6-green)](https://cyclonedx.org)
[![Microsoft Agent Framework](https://img.shields.io/badge/Microsoft%20Agent%20Framework-C%23%20%2F%20.NET-purple)](https://learn.microsoft.com/en-us/agent-framework/overview/?pivots=programming-language-csharp)

<img width="1736" height="895" alt="image" src="https://github.com/user-attachments/assets/51accd5f-ffa3-44ad-b9bc-051c6e8e4265" />

---

## The Problem

Generating an SBOM surfaces hundreds of CVEs. In practice, over 90% are not exploitable in a specific product's runtime context. Without a Vulnerability Exploitability eXchange (VEX) document, every downstream tool — Dependency-Track, release gates, procurement checklists — drowns in false positives.

Read the WIKI for more technical details and results of testing.

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
│  ZONE 2 — OWASP guardrail middleware (AIAgentBuilder.Use)       │
│  Prompt guard (LLM01) · Output filter (LLM02/05)                │
│  Agency limiter (LLM06) · Token budget & MaxMessages (LLM10)    │
└────────────────────────────┬────────────────────────────────────┘
                             │
┌────────────────────────────▼────────────────────────────────────┐
│  ZONE 3 — Multi-agent pipeline (Microsoft Agent Framework C#)   │
│                                                                  │
│  AgentWorkflowBuilder.BuildSequential                            │
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
| Prompt Injection | LLM01 | All SBOM fields sanitised before LLM injection; injection pattern blocklist in `SbomIngestor` and `OwaspGuardrailMiddleware` |
| Sensitive Info Disclosure | LLM02 | PII scrubber on all agent outputs; internal path filter (`OwaspGuardrailMiddleware`) |
| Improper Output Handling | LLM05 | CycloneDX 1.6 schema validation before signing; retry on failure |
| Excessive Agency | LLM06 | Read-only `AIFunction` tools during analysis; HITL gate for all CVSS ≥ 7.0 or `affected` rulings |
| System Prompt Leakage | LLM07 | Internal policies separated from system prompt |
| Vector / Embedding Weakness | LLM08 | Stored vectors signed with HMAC-SHA256; provenance checked before context injection |
| Unbounded Consumption | LLM10 | `MaxMessageCount(20)` in middleware; per-pipeline token budget; strict NVD/OSV HTTP timeouts |

> **Human-in-the-loop is mandatory.** A VEX `not_affected` or `affected` statement for a high-severity CVE is a legal-grade assertion. No VEX is signed without human reviewer approval. This is not configurable.

---

## Tech Stack

| Component | Tool | Notes |
|---|---|---|
| Agent orchestration | [Microsoft Agent Framework (C# / .NET)](https://learn.microsoft.com/en-us/agent-framework/overview/?pivots=programming-language-csharp) | `Microsoft.Agents.AI` & `Microsoft.Agents.AI.Workflows` (replaces legacy AutoGen) |
| AI abstractions | `Microsoft.Extensions.AI` + `Microsoft.Agents.AI.OpenAI` | `IChatClient`, `AIAgent`, `AIFunctionFactory`, `AIAgentBuilder` middleware |
| LLM (recommended) | [Qwen2.5-Coder-32B](https://huggingface.co/Qwen/Qwen2.5-Coder-32B-Instruct) | Best structured JSON + security reasoning |
| LLM server | [vLLM](https://docs.vllm.ai) (prod) / [Ollama](https://ollama.com) (dev) | OpenAI-compatible API (`VLLM_BASE_URL`) |
| CVE data | NVD v2 API + [OSV.dev](https://osv.dev) + [EPSS](https://api.first.org) | All free, no API key required |
| Vector store | [Qdrant](https://qdrant.tech) | Self-hosted, provenance-signed past VEX decisions |
| SBOM formats | CycloneDX 1.4–1.7 (JSON), SPDX 2.2/2.3 (JSON) | Schema-validated and sanitised on ingest |
| VEX output | CycloneDX 1.6 VEX | Schema-validated before signing |
| Signing | [cosign](https://docs.sigstore.dev) / RSASSA-PSS | Timestamped, SHA-256 payload signed, audit-logged |
| Audit log | Append-only JSONL / PostgreSQL | Every agent decision and signature recorded |

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
- .NET SDK 8.0+ / 10.0+ (`dotnet`)
- Docker + Docker Compose (optional, for Qdrant / PostgreSQL)

---

## Quick Start

### 1. Clone and build

```bash
git clone https://github.com/OWASP/SBOM-VEX-Taint-Analysis
cd SBOM-VEX-Taint-Analysis
dotnet build SbomVexAgent/SbomVexAgent.csproj
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

### 3. Run the agent on an SBOM

```bash
dotnet run --project SbomVexAgent -- analyse \
  --sbom examples/sample-sbom.json \
  --output examples/output.vex.json \
  --workspace spring-web
```

The pipeline will:
1. **Zone 1:** Validate and sanitise the SBOM (`SbomIngestor`), generating a SHA-256 audit hash.
2. **Zone 2:** Attach OWASP GenAI guardrail middleware (`OwaspGuardrailMiddleware`) to every agent using `AIAgentBuilder.Use(...)`.
3. **Zone 3:** Run the multi-agent workflow (`AgentWorkflowBuilder.BuildSequential` over `CVE_Analyst` → `Exploit_Reasoner` → `VEX_Writer`) to query OSV/NVD/EPSS, inspect source code taint/reachability paths, verify signed RAG history, and emit a validated CycloneDX 1.6 VEX JSON document.
4. **Zone 4:** Present the draft VEX to the Human-in-the-Loop review gate (`HitlAndSigner`) and cryptographically sign & audit-log the final document on approval.

---

## Configuration

Copy `.env.example` to `.env` and set:

```env
# LLM backend (OpenAI-compatible endpoint)
VLLM_BASE_URL=http://localhost:8000/v1    # or Ollama: http://localhost:11434/v1
LLM_MODEL=Qwen2.5-Coder-32B-Instruct      # or llama3.1 for dev
OPENAI_API_KEY=local-ollama-or-vllm

# Services
QDRANT_URL=http://localhost:6333
AUDIT_DB_URL=postgresql://audit:secret@localhost:5432/audit

# Signing (leave blank to use cosign keyless via Sigstore OIDC)
GPG_KEY_ID=                               # optional: custom key ID
```

---

## Project Structure

```
SBOM-VEX-Taint-Analysis/
├── SbomVexAgent/
│   ├── SbomVexAgent.csproj                # .NET C# project with Microsoft.Agents.AI & Workflows
│   ├── Program.cs                         # CLI entrypoint (Zone 1 -> Zone 2 -> Zone 3 -> Zone 4)
│   ├── Models/
│   │   └── VexModels.cs                   # CycloneDX 1.6 VEX, SBOM, CVE Intel & Signed RAG models
│   ├── Zone1/
│   │   └── SbomIngestor.cs                # Zone 1: SBOM validation, sanitisation, SHA-256 hash
│   ├── Zone2/
│   │   └── OwaspGuardrailMiddleware.cs    # Zone 2: AIAgentBuilder middleware (LLM01/02/05/06/10)
│   ├── Zone3/
│   │   ├── MultiAgentVexPipeline.cs       # Zone 3: AgentWorkflowBuilder sequential orchestration
│   │   └── Tools/
│   │       ├── CveIntelligenceTools.cs    # Read-only NVD v2, OSV.dev, and FIRST EPSS tools
│   │       └── CodebaseAndRagTools.cs     # Read-only static codebase search & signed Qdrant RAG
│   └── Zone4/
│       └── HitlAndSigner.cs               # Zone 4: Mandatory HITL review gate, signing & audit log
├── examples/
│   ├── sample-sbom.json
│   ├── output.vex.json
│   └── audit.log.jsonl
├── human-vex/
│   └── spring-framework-vex.json          # OWASP benchmark ground-truth VEX record
├── spring-web/                            # Target Java codebase for reachability analysis
├── .env.example
└── README.md
```

---

## VEX Output Format

The agent produces CycloneDX 1.6 VEX documents. Example output:

```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:spring-web-aalto-xml-dos-001",
  "version": 1,
  "metadata": {
    "timestamp": "2026-11-16T08:31:17Z",
    "tools": [
      {
        "name": "sbom-vex-agent",
        "version": "2.0.0-maf-csharp",
        "vendor": "OWASP SBOM-VEX-Taint-Analysis (Microsoft Agent Framework C#)"
      }
    ],
    "signature": {
      "algorithm": "RSASSA-PSS",
      "status": "signed-audit-logged",
      "keyId": "cosign-keyless-sigstore-oidc-001"
    }
  },
  "vulnerabilities": [
    {
      "id": "CVE-2024-AALTO-SPRING-WEB",
      "affects": [
        { "ref": "pkg:maven/com.fasterxml/aalto-xml@1.3.2" }
      ],
      "analysis": {
        "state": "affected",
        "justification": "vulnerable_code_in_execute_path",
        "detail": "aalto-xml@1.3.2 (declared scope: 'optional') is actively referenced and invoked in the codebase (src/main/java/org/springframework/http/codec/xml/XmlEventDecoder.java:11: \"com.fasterxml.aalto.AsyncXMLStreamReader\",). Runtime reachability confirmed."
      }
    },
    {
      "id": "CVE-2021-37714",
      "affects": [
        { "ref": "pkg:maven/com.diffplug.spotless/spotless-maven-plugin@1.17.0" }
      ],
      "analysis": {
        "state": "not_affected",
        "justification": "vulnerable_code_not_in_execute_path",
        "detail": "spotless-maven-plugin@1.17.0 is a build-time/excluded plugin (scope: 'excluded') and is not present or executed in the deployed runtime classpath."
      }
    }
  ]
}
```

Valid `state` values: `affected` · `not_affected` · `fixed` · `under_investigation`

Valid `justification` values:
- `component_not_present`
- `vulnerable_code_not_present`
- `vulnerable_code_not_in_execute_path`
- `vulnerable_code_in_execute_path`
- `vulnerable_code_cannot_be_controlled_by_adversary`
- `inline_mitigations_already_exist`

---

## Related Resources

- [Microsoft Agent Framework Overview (C# / .NET)](https://learn.microsoft.com/en-us/agent-framework/overview/?pivots=programming-language-csharp)
- [OWASP GenAI Security Project](https://genai.owasp.org)
- [OWASP Top 10 for LLM Applications 2025](https://genai.owasp.org/llm-top-10/)
- [OWASP Top 10 for Agentic Applications 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)
- [CycloneDX Specification](https://github.com/CycloneDX/specification)
- [OSV Vulnerability Database](https://osv.dev)
- [EPSS Scoring API](https://api.first.org/data/v1/epss)
- [Sigstore / cosign](https://docs.sigstore.dev)
- Johanna Curiel — [Analysing Supply Chain Vulnerabilities in the Kubernetes Java Client Using SBOM and Generating VEX](https://www.linkedin.com/pulse/analysing-supply-chain-vulnerabilities-kubernetes-java-curiel/) (2024)

---

## License

MIT — see [LICENSE](LICENSE).

---

*Built in alignment with the [OWASP GenAI Security Project](https://genai.owasp.org).*
