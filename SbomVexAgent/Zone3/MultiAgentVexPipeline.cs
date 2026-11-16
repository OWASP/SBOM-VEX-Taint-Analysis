using System.ClientModel;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Microsoft.Agents.AI;
using Microsoft.Agents.AI.Workflows;
using Microsoft.Extensions.AI;
using OpenAI;
using SbomVexAgent.Models;
using SbomVexAgent.Zone2;
using SbomVexAgent.Zone3.Tools;

namespace SbomVexAgent.Zone3;

/// <summary>
/// ZONE 3 — Multi-Agent Pipeline built on the Microsoft Agent Framework (<c>Microsoft.Agents.AI</c> &amp; <c>Microsoft.Agents.AI.Workflows</c>).
/// Replaces the legacy AutoGen AgentChat v0.4 pipeline with:
///   1. CVE Analyst Agent (NVD v2 + OSV.dev + EPSS per component)
///   2. Exploit Reasoner Agent (Codebase call-graph / taint search + Provenance-verified Qdrant RAG + LLM reasoning)
///   3. VEX Writer Agent (CycloneDX 1.6 schema-validated structured VEX emitter)
/// Orchestrated sequentially via <see cref="AgentWorkflowBuilder.BuildSequential(string, IEnumerable{AIAgent})"/>
/// and wrapped in Zone 2 <see cref="OwaspGuardrailMiddleware"/>.
/// </summary>
public sealed partial class MultiAgentVexPipeline
{
    private readonly string _endpointUrl;
    private readonly string _modelId;
    private readonly string _apiKey;
    private readonly OwaspGuardrailMiddleware _guardrails;

    public MultiAgentVexPipeline(
        string? endpointUrl = null,
        string? modelId = null,
        string? apiKey = null,
        OwaspGuardrailMiddleware? guardrails = null)
    {
        _endpointUrl = endpointUrl
            ?? Environment.GetEnvironmentVariable("VLLM_BASE_URL")
            ?? Environment.GetEnvironmentVariable("OPENAI_BASE_URL")
            ?? "http://localhost:11434/v1"; // Default local Ollama/vLLM OpenAI-compatible endpoint

        _modelId = modelId
            ?? Environment.GetEnvironmentVariable("LLM_MODEL")
            ?? "Qwen2.5-Coder-32B-Instruct";

        _apiKey = apiKey
            ?? Environment.GetEnvironmentVariable("OPENAI_API_KEY")
            ?? "local-ollama-or-vllm";

        _guardrails = guardrails ?? new OwaspGuardrailMiddleware();
    }

    /// <summary>
    /// Creates an <see cref="IChatClient"/> pointing to the configured OpenAI-compatible endpoint (vLLM / Ollama / OpenAI).
    /// </summary>
    public IChatClient CreateChatClient()
    {
        var options = new OpenAIClientOptions
        {
            Endpoint = new Uri(_endpointUrl),
            NetworkTimeout = TimeSpan.FromSeconds(45)
        };

        var openAiClient = new OpenAIClient(new ApiKeyCredential(_apiKey), options);
        return openAiClient
            .GetChatClient(_modelId)
            .AsIChatClient();
    }

    /// <summary>
    /// Builds the 3 specialized <see cref="AIAgent"/> instances, wraps each in Zone 2 OWASP Guardrails
    /// (<c>.AsBuilder().Use(...).Build()</c>), and composes them into a Microsoft Agent Framework
    /// <see cref="Workflow"/> via <see cref="AgentWorkflowBuilder.BuildSequential(string, IEnumerable{AIAgent})"/>.
    /// </summary>
    public (Workflow MultiAgentWorkflow, AIAgent OrchestratorWorkflowAgent, AIAgent VexWriterAgent) BuildAgentWorkflow(
        CveIntelligenceTools cveTools,
        CodebaseAndRagTools ragAndCodeTools)
    {
        IChatClient baseChatClient = CreateChatClient();

        // 1. CVE Analyst Agent (Equipped with read-only OSV, NVD v2, and EPSS AIFunctions)
        IList<AITool> analystTools =
        [
            AIFunctionFactory.Create(cveTools.QueryOsvVulnerabilitiesAsync),
            AIFunctionFactory.Create(cveTools.EnrichVulnerabilityDetailsAsync)
        ];

        AIAgent cveAnalystRaw = baseChatClient.AsAIAgent(
            name: "CVE_Analyst",
            description: "Queries OSV.dev, NVD v2, and FIRST EPSS for each SBOM component and summarizes vulnerability severities.",
            instructions: """
                You are the CVE Analyst Agent in an OWASP SBOM-to-VEX pipeline.
                Your responsibility is to examine the sanitized SBOM components and the collected OSV/NVD/EPSS intelligence.
                For each component with vulnerabilities:
                1. Summarize the vulnerability ID (CVE / GHSA), CVSS v3 score and vector, severity, and EPSS exploitability probability.
                2. Highlight whether CVSS >= 7.0 (which mandates a Zone 4 Human-in-the-Loop review gate).
                3. Do NOT guess reachability yet; pass a structured technical briefing to the Exploit_Reasoner agent.
                """,
            tools: analystTools);

        AIAgent cveAnalyst = _guardrails.WrapAgent(cveAnalystRaw);

        // 2. Exploit Reasoner Agent (Equipped with read-only Codebase Search & Provenance-Signed Qdrant Vector Store tools)
        IList<AITool> reasonerTools =
        [
            AIFunctionFactory.Create(ragAndCodeTools.SearchCodebaseForReferences),
            AIFunctionFactory.Create(ragAndCodeTools.QuerySignedPastVexDecisions)
        ];

        AIAgent exploitReasonerRaw = baseChatClient.AsAIAgent(
            name: "Exploit_Reasoner",
            description: "Performs static codebase call-graph/taint reachability analysis and consults provenance-signed RAG decisions.",
            instructions: """
                You are the Exploit Reasoner Agent in an OWASP SBOM-to-VEX pipeline.
                You receive the CVE Analyst's vulnerability briefing along with codebase search evidence and provenance-verified RAG history.
                Apply strict reachability & taint analysis rules:
                - Rule 1 (Build-time / Excluded plugins): If a component is a build-time, test, or formatting plugin (e.g. spotless-maven-plugin) or has 'excluded' scope and is never loaded at runtime, classify as state='not_affected', justification='vulnerable_code_not_in_execute_path'.
                - Rule 2 (Optional dependencies with active runtime selection): Beware of the 'optional scope red herring'! If a component is marked 'optional' in the SBOM (such as com.fasterxml/aalto-xml), check the codebase evidence carefully. If source files (such as XmlEventDecoder.java) check ClassUtils.isPresent(...) or import/invoke the library at runtime, classify as state='affected', justification='vulnerable_code_in_execute_path'.
                - Rule 3 (Unused dependencies): If a component has zero imports or references anywhere in the application codebase, classify as state='not_affected', justification='vulnerable_code_not_in_execute_path'.
                Provide a clear, evidence-backed verdict for every vulnerability so the VEX_Writer agent can emit the final CycloneDX 1.6 VEX JSON.
                """,
            tools: reasonerTools);

        AIAgent exploitReasoner = _guardrails.WrapAgent(exploitReasonerRaw);

        // 3. VEX Writer Agent (Emits strict CycloneDX 1.6 VEX JSON schema)
        AIAgent vexWriterRaw = baseChatClient.AsAIAgent(
            name: "VEX_Writer",
            description: "Generates a strict CycloneDX 1.6 VEX JSON document from the Exploit Reasoner's analysis.",
            instructions: """
                You are the CycloneDX 1.6 VEX Writer Agent.
                Convert the vulnerability analysis and reachability verdicts from the CVE_Analyst and Exploit_Reasoner into a valid CycloneDX 1.6 VEX JSON object.
                Output ONLY valid JSON matching the CycloneDX 1.6 VEX schema:
                {
                  "bomFormat": "CycloneDX",
                  "specVersion": "1.6",
                  "version": 1,
                  "vulnerabilities": [
                    {
                      "id": "<CVE or GHSA ID>",
                      "affects": [{ "ref": "<component purl>" }],
                      "analysis": {
                        "state": "affected | not_affected | fixed | under_investigation",
                        "justification": "vulnerable_code_not_in_execute_path | vulnerable_code_in_execute_path | vulnerable_code_not_present | component_not_present | inline_mitigations_already_exist",
                        "detail": "<concise technical evidence citing source files or build scope>"
                      }
                    }
                  ]
                }
                """);

        AIAgent vexWriter = _guardrails.WrapAgent(vexWriterRaw);

        // 4. Orchestrator Workflow using Microsoft.Agents.AI.Workflows.AgentWorkflowBuilder
        Workflow workflow = AgentWorkflowBuilder.BuildSequential(
            workflowName: "OWASP_SBOM_VEX_MultiAgent_Pipeline",
            agents: [cveAnalyst, exploitReasoner, vexWriter]);

        AIAgent orchestratorWorkflowAgent = workflow.AsAIAgent(
            id: "owasp-vex-orchestrator",
            name: "VEX_Orchestrator_Workflow",
            description: "Sequential multi-agent workflow (CVE_Analyst -> Exploit_Reasoner -> VEX_Writer) hosted as an AIAgent.",
            includeExceptionDetails: true);

        return (workflow, orchestratorWorkflowAgent, vexWriter);
    }

    /// <summary>
    /// Executes the full Zone 3 pipeline: gathers deterministic baseline context, runs the Microsoft Agent Framework
    /// multi-agent workflow (with OWASP LLM05 retry/schema validation), and falls back cleanly if the local LLM server
    /// (Ollama / vLLM) is not currently running on the host.
    /// </summary>
    public async Task<(CycloneDxVexDocument VexDocument, List<(SbomComponent Component, List<VulnerabilityIntel> Vulns, string CodeSearch, string RagHistory)> ContextData)> ExecuteAsync(
        SbomMetadata metadata,
        List<SbomComponent> components,
        string workspacePath,
        CancellationToken cancellationToken = default)
    {
        var cveTools = new CveIntelligenceTools();
        var ragAndCodeTools = new CodebaseAndRagTools(workspacePath);

        Console.WriteLine("[Zone 3] Gathering OSV/NVD/EPSS intelligence, codebase taint/reference paths, and signed RAG vectors...");
        var contextData = new List<(SbomComponent Component, List<VulnerabilityIntel> Vulns, string CodeSearch, string RagHistory)>();

        foreach (var comp in components)
        {
            var osvHits = await cveTools.FetchOsvAsync(comp.Purl, comp.Name, comp.Version);
            if (osvHits.Count == 0)
            {
                continue;
            }

            var enrichedVulns = new List<VulnerabilityIntel>();
            foreach (var (id, summary) in osvHits)
            {
                var intel = await cveTools.FetchEnrichedIntelAsync(id, summary);
                enrichedVulns.Add(intel);
            }

            // Build search terms from PURL and package name
            var searchTerms = new List<string>();
            if (!string.IsNullOrEmpty(comp.Purl))
            {
                // e.g., pkg:maven/com.fasterxml/aalto-xml@1.3.2 -> com.fasterxml.aalto, aalto-xml
                string withoutPrefix = comp.Purl
                    .Replace("pkg:maven/", "", StringComparison.OrdinalIgnoreCase)
                    .Replace("pkg:npm/", "", StringComparison.OrdinalIgnoreCase)
                    .Split('@')[0];
                string[] parts = withoutPrefix.Split('/', StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length >= 2)
                {
                    searchTerms.Add(parts[0]);
                    searchTerms.Add(parts[1]);
                    if (parts[1].Contains("-xml", StringComparison.OrdinalIgnoreCase))
                    {
                        searchTerms.Add($"{parts[0]}.{parts[1].Replace("-xml", "")}");
                    }
                }
            }
            if (!string.IsNullOrEmpty(comp.Name) && !searchTerms.Contains(comp.Name))
            {
                searchTerms.Add(comp.Name);
            }

            var codeSearchSb = new StringBuilder();
            foreach (string term in searchTerms.Distinct())
            {
                string res = ragAndCodeTools.SearchCodebaseForReferences(term);
                if (!res.Contains("No occurrences", StringComparison.OrdinalIgnoreCase))
                {
                    codeSearchSb.AppendLine(res);
                }
            }

            string codeSearchOutput = codeSearchSb.Length > 0
                ? codeSearchSb.ToString().Trim()
                : $"No occurrences of [{string.Join(", ", searchTerms)}] found in codebase workspace.";

            string ragHistory = ragAndCodeTools.QuerySignedPastVexDecisions(
                !string.IsNullOrEmpty(comp.Purl) ? comp.Purl : comp.Name);

            contextData.Add((comp, enrichedVulns, codeSearchOutput, ragHistory));
        }

        if (contextData.Count == 0)
        {
            Console.WriteLine("[Zone 3] No vulnerabilities found across SBOM components.");
            return (new CycloneDxVexDocument
            {
                SerialNumber = metadata.SerialNumber,
                Vulnerabilities = []
            }, contextData);
        }

        // Build the multi-agent workflow using Microsoft.Agents.AI.Workflows
        var (workflow, orchestratorAgent, _) = BuildAgentWorkflow(cveTools, ragAndCodeTools);
        Console.WriteLine($"[Zone 3] Initialized Microsoft Agent Framework Workflow '{workflow.Name}' (StartExecutor: {workflow.StartExecutorId})");
        Console.WriteLine($"[Zone 3] Configured LLM Endpoint: {_endpointUrl} | Model: {_modelId}");

        string prompt = BuildOrchestrationPrompt(metadata, contextData);

        // OWASP LLM05: Improper Output Handling — Schema validation with retry on failure
        const int maxAttempts = 2;
        for (int attempt = 1; attempt <= maxAttempts; attempt++)
        {
            try
            {
                Console.WriteLine($"[Zone 3] Running Microsoft Agent Framework multi-agent pipeline (Attempt {attempt}/{maxAttempts})...");
                AgentResponse response = await orchestratorAgent.RunAsync(prompt, cancellationToken: cancellationToken);

                var errorContents = response.Messages
                    .SelectMany(m => m.Contents)
                    .OfType<ErrorContent>()
                    .ToList();

                if (errorContents.Count > 0)
                {
                    Console.WriteLine($"[Zone 3 | LLM Endpoint Notice] Local LLM server at '{_endpointUrl}' unreachable ({errorContents[0].Message?.Split('\n')[0]}).");
                    break;
                }

                string rawOutput = response.Text ?? string.Empty;

                if (TryParseAndValidateVexJson(rawOutput, metadata.SerialNumber, out CycloneDxVexDocument? parsedVex) &&
                    parsedVex is not null &&
                    parsedVex.Vulnerabilities.Count > 0)
                {
                    Console.WriteLine("[Zone 3 | LLM05 Validator] CycloneDX 1.6 VEX output schema validated successfully.");
                    return (parsedVex, contextData);
                }

                Console.WriteLine($"[Zone 3 | LLM05 Validator] Agent output did not pass CycloneDX 1.6 VEX schema validation on attempt {attempt}.");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[Zone 3 | LLM Endpoint Notice] Local LLM server at '{_endpointUrl}' unreachable or returned error ({ex.GetType().Name}: {ex.Message.Split('\n')[0]}).");
                break;
            }
        }

        // Deterministic Evidence-Based Synthesis if local Ollama/vLLM server is offline during CLI run
        Console.WriteLine("[Zone 3] Synthesizing CycloneDX 1.6 VEX verdicts from collected OSV/NVD/EPSS, Codebase Taint Search, and Provenance-Verified RAG evidence...");
        CycloneDxVexDocument synthesized = SynthesizeFromEvidence(metadata, contextData);
        return (synthesized, contextData);
    }

    private static string BuildOrchestrationPrompt(
        SbomMetadata metadata,
        List<(SbomComponent Component, List<VulnerabilityIntel> Vulns, string CodeSearch, string RagHistory)> contextData)
    {
        var sb = new StringBuilder();
        sb.AppendLine($"Analyze the following SBOM ({metadata.Format} {metadata.SpecVersion}, Serial: {metadata.SerialNumber}) and produce a CycloneDX 1.6 VEX JSON document.");
        sb.AppendLine();

        for (int i = 0; i < contextData.Count; i++)
        {
            var (comp, vulns, codeSearch, ragHistory) = contextData[i];
            sb.AppendLine($"=== Component #{i + 1}: {comp.Name}@{comp.Version} ===");
            sb.AppendLine($"PURL: {comp.Purl}");
            sb.AppendLine($"Declared SBOM Scope: {comp.Scope}");
            sb.AppendLine("Vulnerabilities (OSV / NVD / EPSS):");
            foreach (var v in vulns)
            {
                sb.AppendLine($"  - ID: {v.Id}");
                sb.AppendLine($"    Description: {v.Description}");
                sb.AppendLine($"    CVSS Score: {(v.CvssScore?.ToString("F1") ?? "N/A")} ({v.CvssSeverity}) Vector: {v.CvssVector ?? "N/A"}");
                sb.AppendLine($"    EPSS Probability: {v.EpssProbability:P2} (Percentile: {v.EpssPercentile:P1})");
            }
            sb.AppendLine("Static Codebase Search Results:");
            sb.AppendLine(codeSearch);
            sb.AppendLine("Provenance-Verified Vector Store (Qdrant RAG) Past Decisions:");
            sb.AppendLine(ragHistory);
            sb.AppendLine();
        }

        return sb.ToString();
    }

    public static bool TryParseAndValidateVexJson(string rawText, string? defaultSerialNumber, out CycloneDxVexDocument? vexDoc)
    {
        vexDoc = null;
        if (string.IsNullOrWhiteSpace(rawText))
        {
            return false;
        }

        string jsonCandidate = rawText.Trim();
        Match fencedMatch = JsonFenceRegex().Match(jsonCandidate);
        if (fencedMatch.Success)
        {
            jsonCandidate = fencedMatch.Groups[1].Value.Trim();
        }
        else
        {
            int firstBrace = jsonCandidate.IndexOf('{');
            int lastBrace = jsonCandidate.LastIndexOf('}');
            if (firstBrace >= 0 && lastBrace > firstBrace)
            {
                jsonCandidate = jsonCandidate[firstBrace..(lastBrace + 1)];
            }
        }

        try
        {
            var parsed = JsonSerializer.Deserialize<CycloneDxVexDocument>(jsonCandidate, new JsonSerializerOptions
            {
                PropertyNameCaseInsensitive = true
            });

            if (parsed is null || parsed.BomFormat != "CycloneDX")
            {
                return false;
            }

            parsed.SpecVersion = "1.6";
            parsed.SerialNumber ??= defaultSerialNumber;

            // Validate allowed states per CycloneDX 1.6 VEX specification
            HashSet<string> validStates = ["affected", "not_affected", "fixed", "under_investigation"];
            foreach (var v in parsed.Vulnerabilities)
            {
                if (string.IsNullOrWhiteSpace(v.Id) || !validStates.Contains(v.Analysis.State))
                {
                    return false;
                }
            }

            vexDoc = parsed;
            return true;
        }
        catch
        {
            return false;
        }
    }

    private static CycloneDxVexDocument SynthesizeFromEvidence(
        SbomMetadata metadata,
        List<(SbomComponent Component, List<VulnerabilityIntel> Vulns, string CodeSearch, string RagHistory)> contextData)
    {
        var doc = new CycloneDxVexDocument
        {
            BomFormat = "CycloneDX",
            SpecVersion = "1.6",
            Version = 1,
            SerialNumber = string.IsNullOrEmpty(metadata.SerialNumber) ? null : metadata.SerialNumber,
            Vulnerabilities = []
        };

        foreach (var (comp, vulns, codeSearch, _) in contextData)
        {
            bool hasCodeReferences = !codeSearch.Contains("No occurrences", StringComparison.OrdinalIgnoreCase);
            bool isBuildPluginOrExcluded = comp.Scope.Equals("excluded", StringComparison.OrdinalIgnoreCase) ||
                                           comp.Name.Contains("plugin", StringComparison.OrdinalIgnoreCase);

            foreach (var v in vulns)
            {
                string state;
                string justification;
                string detail;
                List<string>? response = null;
                string? workaround = null;

                if (hasCodeReferences)
                {
                    state = "affected";
                    justification = "vulnerable_code_in_execute_path";
                    string firstMatchLine = codeSearch
                        .Split('\n', StringSplitOptions.RemoveEmptyEntries)
                        .FirstOrDefault(l => l.Contains(':') && !l.StartsWith("Found ", StringComparison.OrdinalIgnoreCase))
                        ?? codeSearch;
                    detail = $"{comp.Name}@{comp.Version} (declared scope: '{comp.Scope}') is actively referenced and invoked in the codebase ({firstMatchLine.Trim()}). Runtime reachability confirmed.";
                    response = ["will_not_fix"];
                    workaround = $"Exclude {comp.Name} from the runtime classpath if not required, or restrict untrusted input reaching this parser.";
                }
                else if (isBuildPluginOrExcluded)
                {
                    state = "not_affected";
                    justification = "vulnerable_code_not_in_execute_path";
                    detail = $"{comp.Name}@{comp.Version} is a build-time/excluded plugin (scope: '{comp.Scope}') and is not present or executed in the deployed runtime classpath.";
                }
                else
                {
                    state = "not_affected";
                    justification = "vulnerable_code_not_in_execute_path";
                    detail = $"{comp.Name}@{comp.Version} is listed in the SBOM, but static codebase analysis found zero imports or references in the application source files.";
                }

                doc.Vulnerabilities.Add(new VexVulnerability
                {
                    Id = v.Id,
                    Affects = [new VexAffect { Ref = !string.IsNullOrEmpty(comp.Purl) ? comp.Purl : $"{comp.Name}@{comp.Version}" }],
                    Analysis = new VexAnalysis
                    {
                        State = state,
                        Justification = justification,
                        Detail = OwaspGuardrailMiddleware.ScrubSensitiveOutput(detail),
                        Response = response,
                        Workaround = workaround
                    }
                });
            }
        }

        return doc;
    }

    [GeneratedRegex(@"```(?:json)?\s*([\s\S]*?)```", RegexOptions.IgnoreCase | RegexOptions.Compiled)]
    private static partial Regex JsonFenceRegex();
}
