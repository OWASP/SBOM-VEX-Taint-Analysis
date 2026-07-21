[article_sbom_vex_benchmark.md](https://github.com/user-attachments/files/30219208/article_sbom_vex_benchmark.md)

# Why Your Automated VEX Pipeline Is Probably Wrong: Lessons from an OWASP Benchmark

**Author:** Johanna Curiel, OWASP · with analysis by the SBOM-VEX-Taint-Analysis Project  
**Date:** July 2026

---

## Abstract

Software Bill of Materials (SBOM) documents are increasingly mandated by regulation and adopted across the software supply chain. Vulnerability Exploitability eXchange (VEX) documents — which annotate SBOMs with reachability and exploitability verdicts — are positioned as the mechanism that transforms a noisy vulnerability list into actionable intelligence. But how reliable are the automated pipelines that generate these verdicts?

We present a benchmark case from the OWASP SBOM-VEX-Taint-Analysis project that exposes a fundamental gap: **automated VEX pipelines that rely on SBOM-level analysis and string-matching codebase searches produce incorrect verdicts for optional dependencies that are actively selected at runtime.** Using the Spring Framework's handling of `aalto-xml` as a case study, we demonstrate that correct VEX analysis requires multi-file source code tracing, build system scope resolution, and structured reasoning that current automated approaches lack.

---

## 1. Introduction: The Promise and the Problem

The software industry has converged on a simple narrative: generate an SBOM, cross-reference it against vulnerability databases, and produce a VEX document that tells consumers which vulnerabilities actually matter. Tools like OSV.dev, the NVD, and EPSS scoring make the lookup step trivial. The harder question — *"Is this vulnerability actually reachable in my application?"* — is where pipelines diverge from reality.

Most automated VEX pipelines follow a predictable pattern:

1. **Parse** the SBOM (CycloneDX or SPDX)
2. **Query** vulnerability databases by package URL (purl)
3. **Search** the codebase for string references to the vulnerable component
4. **Conclude** based on whether a grep match was found

This pattern works for the easy cases. It fails catastrophically for the hard ones — and the hard ones are precisely the cases that matter most.

---

## 2. The Benchmark: aalto-xml in Spring Framework

### 2.1 Setup

The OWASP SBOM-VEX-Taint-Analysis project maintains a set of benchmark "triples" — (project, component, CVE) tuples with ground-truth verdicts produced by human expert analysis. Each triple is designed to test specific failure modes in automated pipelines.

The benchmark case examined here involves:

- **Project:** Spring Framework (`spring-web` module)
- **Component:** `com.fasterxml:aalto-xml` (an XML streaming parser)
- **Vulnerability:** A Denial of Service (DoS) triggered by malformed XML input
- **CVSS Score:** 7.5 (High) — Network-accessible, low complexity, no privileges required

The ground-truth verdict, established through expert human analysis, is **`affected`** with justification **`vulnerable_code_in_execute_path`**.

### 2.2 Why This Case Is Hard

This benchmark is classified as **difficulty: hard** for three reasons:

1. **Two sequential red herrings** precede the decisive finding
2. **Multi-file source code analysis** is required — the SBOM and build files alone are insufficient
3. **The correct verdict contradicts the obvious initial signal** from dependency scope

---

## 3. The Automated Pipeline's Verdict: Wrong

We ran an automated VEX pipeline built on the Google Antigravity SDK against an SPDX 2.3 SBOM generated from the Spring Framework repository. The pipeline:

1. Parsed the SBOM and extracted 15 packages
2. Queried OSV.dev for each package URL
3. Found 3 advisories for `fast-xml-parser@5.3.8` (a different component entirely)
4. Searched the workspace for string references using grep
5. Found matches only within the SBOM JSON file itself (circular evidence)
6. Concluded: **`not_affected`** — `vulnerable_code_not_in_execute_path`

The pipeline **missed `aalto-xml` entirely** because it does not appear as a direct dependency in the SPDX package list. It is an optional transitive dependency declared in Spring's Gradle build file — invisible to SBOM-level scanning.

Even if the pipeline had identified `aalto-xml` as a component, the grep-based codebase search would have found the `optional("com.fasterxml:aalto-xml")` declaration in `spring-web.gradle` and likely concluded `not_affected` — which, as we will show, is the wrong answer.

---

## 4. The Human Analysis: A Four-Step Evidence Chain

The human benchmark analysis follows a structured evidence chain that demonstrates why depth matters.

### Step 1 — Scope Signal (Red Herring #1)

| | |
|---|---|
| **Source** | `spring-web/spring-web.gradle` |
| **Evidence** | `optional("com.fasterxml:aalto-xml")` |
| **Initial signal** | `not_affected` |
| **Confidence** | High (deterministic) |

The `optional` scope in Gradle means `aalto-xml` is not transitively inherited by consuming applications. An automated pipeline that stops here — and most do — will conclude the vulnerable code is not present.

**Why it's misleading:** Optional does not mean *never present at runtime*. It means the consuming application must explicitly add the dependency. And many do, because `aalto-xml` offers superior XML streaming performance.

### Step 2 — Runtime Signal (Red Herring #2)

| | |
|---|---|
| **Source** | `spring-beans/.../DefaultDocumentLoader.java` |
| **Evidence** | `DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance()` |
| **Signal** | `not_affected` |
| **Confidence** | High (deterministic) |

Spring's internal XML loading for bean definitions uses JAXP — the standard Java XML API — not `aalto-xml`. A pipeline that searches for "XML processing in Spring" will find this code path and conclude that Spring uses JAXP, not the vulnerable parser.

**Why it's misleading:** Spring has **multiple XML processing paths** serving different purposes. The JAXP path handles application configuration; a completely separate path handles reactive HTTP codec processing. Generalizing from one XML path to all XML paths produces the wrong verdict.

### Step 3 — Code Path Signal (The Decisive Finding)

| | |
|---|---|
| **Source** | `spring-web/.../XmlEventDecoder.java` |
| **Evidence** | See below |
| **Signal** | **`affected`** |
| **Confidence** | High (deterministic) |

```java
private static final boolean AALTO_PRESENT = 
    ClassUtils.isPresent(
        "com.fasterxml.aalto.AsyncXMLStreamReader", 
        XmlEventDecoder.class.getClassLoader()
    );

boolean useAalto = AALTO_PRESENT;
// when useAalto is true, decode() uses AaltoDataBufferToXmlEvent
```

This is not passive classpath presence. Spring WebFlux's `XmlEventDecoder` **explicitly detects** `aalto-xml` at runtime using reflection-based class loading and **actively selects** the Aalto-based decoding path when the library is present. The vulnerable parser is not merely available — it is *preferred*.

### Step 4 — Context Signal (Exploitability Conditions)

The final step assesses four conditions that must co-occur for exploitation:

1. `aalto-xml` is present on the runtime classpath
2. The application uses Spring WebFlux (reactive stack) with XML media type support
3. `XmlEventDecoder` is active in the codec pipeline
4. The application accepts XML input from untrusted network sources

All four conditions are realistic and commonly co-occur in Spring WebFlux applications that expose XML REST APIs. The CVSS vector confirms: attack complexity is Low, no special privileges are required, and the attack surface is network-accessible.

**Verdict: `affected`** — with high confidence, context-dependent on consumer deployment.

---

## 5. Where Automated Pipelines Fail

The comparison reveals five structural failure modes in current automated VEX generation:

### 5.1 SBOM-Only Component Discovery

Automated pipelines analyze only the components listed in the SBOM. Optional and transitive dependencies that are not explicitly declared — but are actively used at runtime — are invisible. This is a fundamental limitation: **the SBOM describes what is declared, not what is executed.**

### 5.2 Grep Is Not Code Analysis

String-matching searches (`grep`, `ripgrep`) find textual references to package names. They cannot:

- Trace runtime class loading via reflection (`ClassUtils.isPresent()`)
- Distinguish between multiple code paths serving different purposes
- Identify conditional execution logic that selects between parser implementations
- Understand build system scope semantics (`optional`, `provided`, `test`)

### 5.3 No Red Herring Resilience

Automated pipelines have no mechanism to recognize that an initial finding may be misleading. They lack the ability to:

- Hold a preliminary verdict as tentative
- Continue searching for contradictory evidence
- Weight multiple signals against each other
- Backtrack when new evidence invalidates an earlier conclusion

### 5.4 Flat Evidence vs. Structured Chains

Automated pipelines produce a single verdict without documenting the reasoning path. The human benchmark analysis provides a four-step evidence chain with confidence levels, source attribution, and explicit documentation of why each step matters. This structure is essential for:

- **Auditability:** Regulators and consumers can trace how the verdict was reached
- **Reproducibility:** Another analyst can follow the same steps and verify the conclusion
- **Calibration:** The pipeline's accuracy can be measured against ground truth

### 5.5 Missing HITL Threshold Logic

The human analysis applies a policy rule: CVSS ≥ 7.0 requires human reviewer sign-off before the VEX is published. Automated pipelines that produce and publish verdicts without threshold-based human review gates create compliance and liability risks.

---

## 6. Implications for the Industry

### 6.1 Regulatory Risk

Regulations like the EU Cyber Resilience Act and US Executive Order 14028 increasingly reference SBOMs and VEX as compliance mechanisms. If automated VEX pipelines produce incorrect verdicts — particularly false negatives that mark affected components as `not_affected` — organizations face both security exposure and regulatory non-compliance.

### 6.2 False Sense of Security

A VEX document that says `not_affected` is a signal to deprioritize remediation. When that verdict is wrong, the vulnerability remains unpatched while the organization believes it has been triaged. The `aalto-xml` case demonstrates that this failure mode is not theoretical — it arises from common dependency patterns in widely-used frameworks.

### 6.3 The Benchmark Imperative

The OWASP SBOM-VEX-Taint-Analysis project exists precisely to surface these gaps. Without standardized benchmarks that include hard cases with red herrings, multi-file evidence chains, and known ground-truth verdicts, the industry has no way to evaluate whether automated VEX tools are trustworthy.

---

## 7. Toward More Reliable VEX Generation

Closing the gap between automated and human-quality VEX analysis requires advances in several areas:

### 7.1 Beyond SBOM: Runtime Reachability Analysis

VEX pipelines must incorporate static analysis or instrumented runtime analysis to determine whether vulnerable code paths are actually reachable. This means:

- **Abstract Syntax Tree (AST) analysis** to trace import chains and call graphs
- **Build system parsing** to resolve dependency scopes (`optional`, `provided`, `test`, `runtime`)
- **Reflection-aware analysis** to detect patterns like `ClassUtils.isPresent()`, `Class.forName()`, and `ServiceLoader`

### 7.2 Structured Evidence Chains

VEX documents should include not just the verdict but the evidence chain that produced it. The CycloneDX 1.6 specification supports rich `analysis.detail` fields — pipelines should populate them with traceable, step-by-step reasoning.

### 7.3 Red Herring Detection

Pipelines should implement multi-hypothesis reasoning: generate candidate verdicts from initial signals, then actively search for contradictory evidence before finalizing. A pipeline that can identify and document red herrings produces more trustworthy output than one that stops at the first plausible signal.

### 7.4 Human-in-the-Loop Gates

Automated pipelines should enforce policy-based thresholds for human review. Vulnerabilities above a configurable CVSS score, components with `optional` or `provided` scope, and cases where codebase evidence is ambiguous should route to human reviewers before VEX publication.

### 7.5 Benchmark-Driven Development

Every automated VEX tool should be evaluated against standardized benchmark suites that include:

- **Easy cases** (direct dependency, clear import, obvious verdict)
- **Medium cases** (transitive dependency, scope ambiguity)
- **Hard cases** (optional dependencies with runtime selection, multiple code paths, red herrings)

Without this calibration, tool accuracy claims are unsubstantiated.

---

## 8. Conclusion

The gap between automated VEX pipeline output and expert human analysis is not a minor discrepancy — it is a structural deficiency that produces wrong verdicts for precisely the cases that matter most. The `aalto-xml` benchmark case demonstrates that:

1. **SBOM-level analysis alone is insufficient** for optional dependencies that are actively selected at runtime
2. **String-matching codebase searches are not code analysis** and cannot trace runtime execution paths
3. **Red herrings are common** in real-world dependency graphs and current pipelines have no defense against them
4. **Correct VEX generation requires hybrid analysis** — deterministic code path tracing combined with semantic reasoning about exploitability conditions

The OWASP SBOM-VEX-Taint-Analysis project provides the benchmarks needed to measure and improve automated VEX tooling. Until pipelines can reliably handle hard cases, **human expert review remains essential** for high-stakes vulnerability triage.

> **Key Lesson:** An `optional` dependency that is actively preferred at runtime is the supply chain security equivalent of a locked door with the key taped to the frame. The SBOM shows the lock. Only source code analysis reveals the key.

---

## Acknowledgments

This analysis was conducted as part of the OWASP SBOM-VEX-Taint-Analysis project. The benchmark case was designed and annotated by Johanna Curiel (OWASP). The automated pipeline comparison was performed using the Antigravity SDK-based VEX agent developed within the same project.

---

*This article is published under CC-BY-4.0. The OWASP SBOM-VEX-Taint-Analysis project welcomes contributions of additional benchmark triples and pipeline evaluations at [github.com/OWASP/SBOM-VEX-Taint-Analysis](https://github.com/OWASP/SBOM-VEX-Taint-Analysis).*
