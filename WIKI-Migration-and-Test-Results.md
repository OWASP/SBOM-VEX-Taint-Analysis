# Migration from AutoGen to Microsoft Agent Framework (C# / .NET) & Live Benchmark Results

## 1. Why We Migrated from AutoGen to the Microsoft Agent Framework

Microsoft has consolidated and superseded the legacy **AutoGen (v0.4)** and **Semantic Kernel** agent stacks into the unified **[Microsoft Agent Framework](https://learn.microsoft.com/en-us/agent-framework/overview/?pivots=programming-language-csharp)** (`Microsoft.Agents.AI` and `Microsoft.Agents.AI.Workflows`).

Moving the **OWASP SBOM → VEX Taint Analysis** pipeline to the **Microsoft Agent Framework in C# / .NET** resolves several critical architectural and security limitations that were previously documented in our earlier AutoGen Studio prototypes (see [[Setting Up ‐ Insecure AutoGen features]]):

| Challenge in Legacy AutoGen v0.4 | Solution in Microsoft Agent Framework (C# / .NET) |
|---|---|
| **Framework Deprecation:** AutoGen v0.4 is no longer the primary supported enterprise multi-agent stack from Microsoft. | **Long-Term Support:** Built natively on `Microsoft.Agents.AI` (`1.28.0`), `Microsoft.Agents.AI.Workflows` (`1.28.0`), and `Microsoft.Extensions.AI` (`10.11.0`). |
| **Inline Python Source Code in JSON Configs:** AutoGen Studio required embedding raw Python `source_code` strings and credentials inside exported `.json` team configurations. | **Strongly-Typed Compiled C# Pipeline:** All tools (`CveIntelligenceTools`, `CodebaseAndRagTools`) and schemas (`CycloneDxVexDocument`) are strongly-typed, compiled C# classes with zero dynamic code eval (`OWASP LLM06`). |
| **Ad-Hoc Message Hooks for Guardrails:** Enforcing token limits, prompt injection checks, and output scrubbing required brittle message hooks. | **First-Class `AIAgentBuilder` Middleware:** Every agent is wrapped in `OwaspGuardrailMiddleware` via `agent.AsBuilder().Use(...).Build()`, enforcing `LLM01`, `LLM02`, `LLM05`, `LLM06`, and `LLM10` at the framework boundary. |
| **Unpredictable GroupChat Loops:** `RoundRobinGroupChat` relied on the model remembering to emit `"TERMINATE"`, risking infinite loops or high token burn on local models. | **Deterministic Directed Graph Workflows:** Orchestrated via `AgentWorkflowBuilder.BuildSequential(chainOnlyAgentResponses: true, agents: [cveAnalyst, exploitReasoner, vexWriter])` with strict per-agent `CancellationToken` timeouts (90s). |
| **Provider Lock-In:** Needed custom adapter configs for local LLMs. | **Universal `IChatClient` Abstraction:** Connects to any OpenAI-compatible local inference server (**Ollama** or **vLLM**) via `VLLM_BASE_URL` and `LLM_MODEL` with zero code changes. |

---

## 2. The 4-Zone Architecture in C# (`SbomVexAgent`)

The migrated C# solution (`SbomVexAgent/`) enforces four strict security zones:

1. **Zone 1 — Deterministic Input Ingestion (`Zone1/SbomIngestor.cs`):**
   - Validates **CycloneDX (1.4–1.7)** and **SPDX (2.2/2.3)** JSON SBOMs without invoking any LLM.
   - Sanitises all package names, PURLs, and versions against prompt injection patterns (`OWASP LLM01`).
   - Computes a cryptographic `SHA-256` audit hash of the raw SBOM.
2. **Zone 2 — OWASP GenAI Guardrail Middleware (`Zone2/OwaspGuardrailMiddleware.cs`):**
   - Intercepts every `AIAgent` run via `AIAgentBuilder`:
     - **LLM01:** Prompt injection blocklist on incoming `ChatMessage` payloads.
     - **LLM02 & LLM05:** Outgoing PII email redaction, local filesystem path scrubbing, and script tag sanitisation.
     - **LLM10:** Enforces `MaxMessageCount = 20`, tracks cumulative token usage against a pipeline token budget (`32,000` tokens), and enforces a strict **90-second per-agent `CancellationToken` timeout** with live console streaming.
3. **Zone 3 — Sequential Multi-Agent Workflow (`Zone3/MultiAgentVexPipeline.cs`):**
   - Pre-fetches deterministic intelligence from **OSV.dev**, **NIST NVD v2**, and **FIRST EPSS** (`CveIntelligenceTools.cs`), performs static codebase taint/reference scanning, and verifies **HMAC-SHA256 provenance signatures** on historical RAG records (`CodebaseAndRagTools.cs`, mitigating `OWASP LLM08`).
   - Truncates prompt context to a strict character/token budget (`<= 3,500 chars` / `~700 tokens`) for fast local LLM prefill.
   - Executes three specialized agents in sequence via `AgentWorkflowBuilder.BuildSequential`:
     1. **`CVE_Analyst`** → Summarizes component PURLs, scope, CVE/GHSA IDs, CVSS scores, and codebase/RAG evidence.
     2. **`Exploit_Reasoner`** → Applies reachability rules (detecting the *"optional dependency red herring"* vs. excluded build-time plugins).
     3. **`VEX_Writer`** → Emits strict CycloneDX 1.6 VEX JSON validated against the CycloneDX schema (`OWASP LLM05`).
4. **Zone 4 — Mandatory Human-in-the-Loop (HITL) Gate & Signing (`Zone4/HitlAndSigner.cs`):**
   - Flags any `affected` ruling or `CVSS >= 7.0` vulnerability for mandatory human review (`OWASP LLM06`).
   - Signs the approved VEX payload using `RSASSA-PSS` (`SHA-256` over SBOM hash + VEX payload hash) and appends an immutable record to `audit.log.jsonl`.

---

## 3. How the Live Benchmark Tests Were Conducted

### Test Environment & Command
All tests were executed locally on macOS (`.NET SDK 10.0.302`) against **Ollama** serving open-weight models locally on `http://localhost:11434/v1`, alongside live queries to `api.osv.dev`, `services.nvd.nist.gov`, and `api.first.org`.

```bash
LLM_MODEL=gpt-oss:latest VLLM_BASE_URL=http://localhost:11434/v1 \
  dotnet run --project SbomVexAgent/SbomVexAgent.csproj -- analyse \
  --sbom examples/sample-sbom.json \
  --output examples/output.vex.json \
  --workspace spring-web
```

### Benchmark Test Case (`examples/sample-sbom.json` + `spring-web/`)
The test SBOM contains two real-world Maven components designed to test whether the pipeline falls for **dependency-scope red herrings**:
1. **`pkg:maven/com.fasterxml/aalto-xml@1.3.2`** (`scope: optional`, `CVE-2024-AALTO-SPRING-WEB`, CVSS `7.5 HIGH`):
   - *The Trap:* A naive SBOM scanner sees `scope: optional` and marks it `not_affected`.
   - *The Reality:* In `spring-web/src/main/java/org/springframework/http/codec/xml/XmlEventDecoder.java` (line 11), Spring WebFlux actively checks `ClassUtils.isPresent("com.fasterxml.aalto.AsyncXMLStreamReader", ...)` and selects the Aalto parser at runtime. Expected verdict: **`affected` (`vulnerable_code_in_execute_path`)**.
2. **`pkg:maven/com.diffplug.spotless/spotless-maven-plugin@1.17.0`** (`scope: excluded`, `GHSA-7v35-qwwj-p98g` / `CVE-2021-37714`):
   - *The Reality:* Build-time code formatting plugin, never present in the deployed runtime classpath and zero references in `spring-web/src`. Expected verdict: **`not_affected` (`vulnerable_code_not_in_execute_path`)**.

---

## 4. Local LLM Comparison & Results (`qwen3.6:latest` vs. `gpt-oss:latest`)

During testing, we benchmarked two locally hosted models in Ollama:
1. **`qwen3.6:latest` (23 GB, Reasoning / Thinking model)**
2. **`gpt-oss:latest` (13 GB, Direct instruction/reasoning model)**

### Performance & Token Consumption Comparison

| Metric | `qwen3.6:latest` (Unbounded Thinking) | `qwen3.6:latest` (Bounded + `chainOnlyAgentResponses`) | **`gpt-oss:latest` (Bounded + Streaming Telemetry)** |
|---|---|---|---|
| **Model Size** | 23 GB | 23 GB | **13 GB** |
| **`CVE_Analyst` Tokens** | 4,096 tokens | 3,662 tokens | **2,151 tokens (20.6s)** |
| **`Exploit_Reasoner` Tokens** | 4,096 tokens | 2,222 tokens | **1,495 tokens (12.7s)** |
| **`VEX_Writer` Tokens** | 3,329 tokens | 1,862 tokens | **1,285 tokens (12.4s)** |
| **Total Pipeline Tokens** | 11,521 / 32,000 | 7,746 / 32,000 | **4,931 / 32,000** |
| **Total End-to-End Time** | ~28 minutes | ~19 minutes | **45.7 seconds** |
| **CycloneDX 1.6 Schema Valid (`LLM05`)** | Passed (Attempt 1/2) | Passed (Attempt 1/2) | **Passed (Attempt 1/2)** |
| **Accuracy on Benchmark** | 100% (2/2 correct) | 100% (2/2 correct) | **100% (2/2 correct)** |

> **Key Finding on Local Thinking Models (`qwen3.6`):** Because `qwen3.6` is a 23 GB chain-of-thought model that generates thousands of internal reasoning tokens per turn on Ollama's `/v1/chat/completions` endpoint, running 3 sequential agents on laptop hardware causes long latency (~19–28 minutes). Switching to **`gpt-oss:latest` (13 GB)** combined with `chainOnlyAgentResponses: true` and bounded prompt context (`2,800 chars` / `~700 tokens`) reduced total execution time to **45.7 seconds** while maintaining **100% accuracy**.

---

## 5. Verbatim Execution Log (`gpt-oss:latest`)

```text
=================================================================
OWASP SBOM -> VEX Taint Analysis Pipeline
Stack: C# / .NET 10 + Microsoft Agent Framework (Microsoft.Agents.AI)
=================================================================
[Zone 1] Reading and validating SBOM from 'examples/sample-sbom.json'...
[Zone 1] Format: CycloneDX (1.6) | Components: 2
[Zone 1 Audit Log] SBOM SHA-256: 03d17fc5b6978b2db7496b72338c34ecd6bb120963a5ea1846164cd277711f4f
[Zone 2] OWASP Guardrail Middleware active (MaxMessages=20, TokenBudget=32000).
[Zone 3] Gathering OSV/NVD/EPSS intelligence, codebase taint/reference paths, and signed RAG vectors...
[Zone 3] Initialized Microsoft Agent Framework Workflow 'OWASP_SBOM_VEX_MultiAgent_Pipeline'
[Zone 3] Configured LLM Endpoint: http://localhost:11434/v1 | Model: gpt-oss:latest | Per-Agent Timeout: 90s
[Zone 3] Constructed bounded prompt context (2800 chars / ~700 est. tokens, budget <= 3500 chars).
[Zone 3] Running Microsoft Agent Framework multi-agent pipeline (Attempt 1/2)...

[13:02:38 UTC] >>> [CVE_Analyst] STARTING (timeout: 90s)...
[Zone 2 Guardrail | LLM10] Agent 'CVE_Analyst' consumed 2151 tokens (pipeline total: 2151/32000).
[13:02:59 UTC] <<< [CVE_Analyst] COMPLETED in 20.6s.

[13:02:59 UTC] >>> [Exploit_Reasoner] STARTING (timeout: 90s)...
[Zone 2 Guardrail | LLM10] Agent 'Exploit_Reasoner' consumed 1495 tokens (pipeline total: 3646/32000).
[13:03:12 UTC] <<< [Exploit_Reasoner] COMPLETED in 12.7s.

[13:03:12 UTC] >>> [VEX_Writer] STARTING (timeout: 90s)...
[Zone 2 Guardrail | LLM10] Agent 'VEX_Writer' consumed 1285 tokens (pipeline total: 4931/32000).
[13:03:24 UTC] <<< [VEX_Writer] COMPLETED in 12.4s.
[Zone 3 | LLM05 Validator] CycloneDX 1.6 VEX output schema validated successfully.

=================================================================
ZONE 4: Human-in-the-Loop (HITL) Review Gate (OWASP LLM06)
=================================================================
[ALERT | OWASP LLM06] High-severity (CVSS >= 7.0) or 'affected' vulnerability ruling detected:
  * CVE-2024-AALTO-SPRING-WEB is ruled 'affected' (vulnerable_code_in_execute_path)
  * CVE-2024-AALTO-SPRING-WEB on aalto-xml has CVSS 7.5 >= 7.0
[HITL] Mandatory human reviewer approval is required before signing this VEX assertion.
[HITL Gate] Human reviewer 'Johanna Curiel (OWASP)' approved the VEX verdicts.
[Zone 4 Audit Log] Appended immutable audit record to 'examples/audit.log.jsonl'.
[Zone 4] Signed CycloneDX 1.6 VEX document written to 'examples/output.vex.json'.
VEX Generation complete!
```

### Final Signed CycloneDX 1.6 VEX Output (`examples/output.vex.json`)

```json
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:spring-web-aalto-xml-dos-001",
  "version": 1,
  "metadata": {
    "timestamp": "2026-11-16T13:03:24Z",
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
      "keyId": "cosign-keyless-sigstore-oidc-001",
      "sbomSha256": "03d17fc5b6978b2db7496b72338c34ecd6bb120963a5ea1846164cd277711f4f",
      "vexPayloadSha256": "a53ef0e161d2394a10190910796d3bf0b2ef5e2c15d3e8f02dc0f918d771cf88",
      "value": "..."
    }
  },
  "vulnerabilities": [
    {
      "id": "CVE-2024-AALTO-SPRING-WEB",
      "affects": [
        {
          "ref": "pkg:maven/com.fasterxml/aalto-xml@1.3.2"
        }
      ],
      "analysis": {
        "state": "affected",
        "justification": "vulnerable_code_in_execute_path",
        "detail": "src/main/java/org/springframework/http/codec/xml/XmlEventDecoder.java:11 imports `com.fasterxml.aalto.AsyncXMLStreamReader`, confirming runtime use of the optional dependency."
      }
    },
    {
      "id": "GHSA-7v35-qwwj-p98g",
      "affects": [
        {
          "ref": "pkg:maven/com.diffplug.spotless/spotless-maven-plugin@1.17.0"
        }
      ],
      "analysis": {
        "state": "not_affected",
        "justification": "vulnerable_code_not_in_execute_path",
        "detail": "The plugin is declared with `excluded` scope and never appears in the runtime classpath, so its code is not reachable during execution."
      }
    }
  ]
}
```
