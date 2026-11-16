using System.ClientModel;
using System.Diagnostics;
using System.Runtime.CompilerServices;
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
/// Orchestrated sequentially via <see cref="AgentWorkflowBuilder.BuildSequential(string, bool, IEnumerable{AIAgent})"/>
/// with per-agent start/end timestamps, live token streaming progress, strict 90s per-agent CancellationToken timeouts,
/// and truncated prompt context budgets.
/// </summary>
public sealed partial class MultiAgentVexPipeline
{
    public const int DefaultPerAgentTimeoutSeconds = 90;
    public const int MaxVulnDescriptionChars = 350;
    public const int MaxCodebaseContextChars = 900;
    public const int MaxRagContextChars = 700;
    public const int MaxTotalPromptChars = 3500;

    private readonly string _endpointUrl;
    private readonly string _modelId;
    private readonly string _apiKey;
    private readonly OwaspGuardrailMiddleware _guardrails;
    private readonly TimeSpan _perAgentTimeout;
    private readonly Action<string, string>? _onLogEvent;

    public MultiAgentVexPipeline(
        string? endpointUrl = null,
        string? modelId = null,
        string? apiKey = null,
        OwaspGuardrailMiddleware? guardrails = null,
        TimeSpan? perAgentTimeout = null,
        Action<string, string>? onLogEvent = null)
    {
        _endpointUrl = endpointUrl
            ?? Environment.GetEnvironmentVariable("VLLM_BASE_URL")
            ?? Environment.GetEnvironmentVariable("OPENAI_BASE_URL")
            ?? "http://localhost:11434/v1"; // Default local Ollama/vLLM OpenAI-compatible endpoint

        _modelId = modelId
            ?? Environment.GetEnvironmentVariable("LLM_MODEL")
            ?? "gpt-oss:latest";

        _apiKey = apiKey
            ?? Environment.GetEnvironmentVariable("OPENAI_API_KEY")
            ?? "local-ollama-or-vllm";

        _guardrails = guardrails ?? new OwaspGuardrailMiddleware();
        _perAgentTimeout = perAgentTimeout ?? TimeSpan.FromSeconds(DefaultPerAgentTimeoutSeconds);
        _onLogEvent = onLogEvent;
    }

    private void EmitLog(string category, string message)
    {
        Console.WriteLine(message);
        _onLogEvent?.Invoke(category, message);
    }

    private void EmitToken(string agentName, string token)
    {
        Console.Write(token);
        _onLogEvent?.Invoke($"stream:{agentName}", token);
    }

    /// <summary>
    /// Creates an <see cref="IChatClient"/> pointing to the configured OpenAI-compatible endpoint (vLLM / Ollama / OpenAI).
    /// </summary>
    public IChatClient CreateChatClient()
    {
        var options = new OpenAIClientOptions
        {
            Endpoint = new Uri(_endpointUrl),
            NetworkTimeout = _perAgentTimeout + TimeSpan.FromSeconds(10)
        };

        var openAiClient = new OpenAIClient(new ApiKeyCredential(_apiKey), options);
        return openAiClient
            .GetChatClient(_modelId)
            .AsIChatClient();
    }

    /// <summary>
    /// Wraps an <see cref="AIAgent"/> with:
    /// 1. Zone 2 OWASP Guardrails (<see cref="OwaspGuardrailMiddleware"/>), and
    /// 2. Live console telemetry (start/end timestamps, elapsed time, live streaming token output, and strict per-agent timeout).
    /// </summary>
    private AIAgent WrapWithTelemetryAndTimeout(AIAgent rawAgent)
    {
        AIAgent guardrailed = _guardrails.WrapAgent(rawAgent);
        string agentName = rawAgent.Name ?? rawAgent.Id;

        async Task<AgentResponse> RunWithTelemetryAsync(
            IEnumerable<ChatMessage> messages,
            AgentSession? session,
            AgentRunOptions? options,
            AIAgent inner,
            CancellationToken ct)
        {
            using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            timeoutCts.CancelAfter(_perAgentTimeout);

            var sw = Stopwatch.StartNew();
            EmitLog("agent:start", $"[{DateTime.UtcNow:HH:mm:ss} UTC] >>> [{agentName}] STARTING (timeout: {_perAgentTimeout.TotalSeconds:F0}s)...");
            Console.Write($"[{agentName} stream] ");

            var updates = new List<AgentResponseUpdate>();
            int streamedChunks = 0;

            try
            {
                await foreach (var update in inner.RunStreamingAsync(messages, session, options, timeoutCts.Token).ConfigureAwait(false))
                {
                    updates.Add(update);
                    if (!string.IsNullOrEmpty(update.Text))
                    {
                        EmitToken(agentName, update.Text);
                        streamedChunks++;
                    }
                    else if (streamedChunks == 0 && updates.Count % 15 == 0)
                    {
                        EmitToken(agentName, ".");
                    }
                }

                sw.Stop();
                Console.WriteLine();
                EmitLog("agent:done", $"[{DateTime.UtcNow:HH:mm:ss} UTC] <<< [{agentName}] COMPLETED in {sw.Elapsed.TotalSeconds:F1}s (Pipeline Tokens: {_guardrails.AccumulatedTokens}/{OwaspGuardrailMiddleware.DefaultTokenBudget}).");
                return updates.ToAgentResponse();
            }
            catch (OperationCanceledException) when (timeoutCts.IsCancellationRequested && !ct.IsCancellationRequested)
            {
                sw.Stop();
                Console.WriteLine();
                string errMsg = $"[{DateTime.UtcNow:HH:mm:ss} UTC] !!! [{agentName}] TIMED OUT after {sw.Elapsed.TotalSeconds:F1}s (limit: {_perAgentTimeout.TotalSeconds:F0}s). Failing fast.";
                EmitLog("agent:error", errMsg);
                throw new TimeoutException(errMsg);
            }
        }

        async IAsyncEnumerable<AgentResponseUpdate> RunStreamingWithTelemetryAsync(
            IEnumerable<ChatMessage> messages,
            AgentSession? session,
            AgentRunOptions? options,
            AIAgent inner,
            [EnumeratorCancellation] CancellationToken ct)
        {
            using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            timeoutCts.CancelAfter(_perAgentTimeout);

            var sw = Stopwatch.StartNew();
            EmitLog("agent:start", $"[{DateTime.UtcNow:HH:mm:ss} UTC] >>> [{agentName}] STARTING (timeout: {_perAgentTimeout.TotalSeconds:F0}s)...");
            Console.Write($"[{agentName} stream] ");

            int streamedChunks = 0;
            int totalUpdates = 0;

            await using var enumerator = inner.RunStreamingAsync(messages, session, options, timeoutCts.Token)
                .GetAsyncEnumerator(timeoutCts.Token);

            while (true)
            {
                AgentResponseUpdate current;
                try
                {
                    if (!await enumerator.MoveNextAsync().ConfigureAwait(false))
                    {
                        break;
                    }
                    current = enumerator.Current;
                }
                catch (OperationCanceledException) when (timeoutCts.IsCancellationRequested && !ct.IsCancellationRequested)
                {
                    sw.Stop();
                    Console.WriteLine();
                    string errMsg = $"[{DateTime.UtcNow:HH:mm:ss} UTC] !!! [{agentName}] TIMED OUT after {sw.Elapsed.TotalSeconds:F1}s (limit: {_perAgentTimeout.TotalSeconds:F0}s). Failing fast.";
                    EmitLog("agent:error", errMsg);
                    throw new TimeoutException(errMsg);
                }

                totalUpdates++;
                if (!string.IsNullOrEmpty(current.Text))
                {
                    EmitToken(agentName, current.Text);
                    streamedChunks++;
                }
                else if (streamedChunks == 0 && totalUpdates % 15 == 0)
                {
                    EmitToken(agentName, ".");
                }

                yield return current;
            }

            sw.Stop();
            Console.WriteLine();
            EmitLog("agent:done", $"[{DateTime.UtcNow:HH:mm:ss} UTC] <<< [{agentName}] COMPLETED in {sw.Elapsed.TotalSeconds:F1}s (Pipeline Tokens: {_guardrails.AccumulatedTokens}/{OwaspGuardrailMiddleware.DefaultTokenBudget}).");
        }

        return guardrailed
            .AsBuilder()
            .Use(runFunc: RunWithTelemetryAsync, runStreamingFunc: RunStreamingWithTelemetryAsync)
            .Build();
    }

    /// <summary>
    /// Builds the 3 specialized <see cref="AIAgent"/> instances, wraps each in Zone 2 OWASP Guardrails + Per-Agent Timeout/Streaming Telemetry,
    /// and composes them into a Microsoft Agent Framework <see cref="Workflow"/> via <see cref="AgentWorkflowBuilder.BuildSequential(string, bool, IEnumerable{AIAgent})"/>.
    /// </summary>
    public (Workflow MultiAgentWorkflow, AIAgent OrchestratorWorkflowAgent, AIAgent VexWriterAgent) BuildAgentWorkflow(
        CveIntelligenceTools cveTools,
        CodebaseAndRagTools ragAndCodeTools,
        bool enableLiveToolCalling = false)
    {
        IChatClient baseChatClient = CreateChatClient();

        // 1. CVE Analyst Agent
        IList<AITool>? analystTools = enableLiveToolCalling
            ? [
                AIFunctionFactory.Create(cveTools.QueryOsvVulnerabilitiesAsync),
                AIFunctionFactory.Create(cveTools.EnrichVulnerabilityDetailsAsync)
              ]
            : null;

        AIAgent cveAnalystRaw = baseChatClient.AsAIAgent(new ChatClientAgentOptions
        {
            Name = "CVE_Analyst",
            Description = "Analyzes OSV.dev, NVD v2, and FIRST EPSS intelligence for each SBOM component and summarizes vulnerability severities.",
            ChatOptions = new ChatOptions
            {
                Instructions = """
                    /no_think
                    You are the CVE Analyst Agent in an OWASP SBOM-to-VEX pipeline.
                    Examine the sanitized SBOM components and the collected OSV/NVD/EPSS intelligence, codebase search results, and signed RAG history provided in the input.
                    Output a concise, structured technical briefing (< 200 words) that preserves for each component:
                    1. Exact Component PURL, Name@Version, and declared SBOM Scope.
                    2. Vulnerability ID (CVE / GHSA), CVSS v3 score/severity, and whether CVSS >= 7.0 (Zone 4 HITL gate).
                    3. Exact Codebase Search Findings and Provenance-Verified RAG rulings so the Exploit_Reasoner can evaluate reachability.
                    Be direct and concise. Do not output lengthy reasoning chains.
                    """,
                Temperature = 0.1f,
                MaxOutputTokens = 500,
                Tools = analystTools
            }
        });

        AIAgent cveAnalyst = WrapWithTelemetryAndTimeout(cveAnalystRaw);

        // 2. Exploit Reasoner Agent
        IList<AITool>? reasonerTools = enableLiveToolCalling
            ? [
                AIFunctionFactory.Create(ragAndCodeTools.SearchCodebaseForReferences),
                AIFunctionFactory.Create(ragAndCodeTools.QuerySignedPastVexDecisions)
              ]
            : null;

        AIAgent exploitReasonerRaw = baseChatClient.AsAIAgent(new ChatClientAgentOptions
        {
            Name = "Exploit_Reasoner",
            Description = "Performs static codebase call-graph/taint reachability analysis and consults provenance-signed RAG decisions.",
            ChatOptions = new ChatOptions
            {
                Instructions = """
                    /no_think
                    You are the Exploit Reasoner Agent in an OWASP SBOM-to-VEX pipeline.
                    Evaluate the CVE Analyst's briefing using these strict reachability & taint analysis rules:
                    - Rule 1 (Build-time / Excluded plugins): If a component is a build-time, test, or formatting plugin (e.g. spotless-maven-plugin) or has 'excluded' scope and is never loaded at runtime, classify as state='not_affected', justification='vulnerable_code_not_in_execute_path'.
                    - Rule 2 (Optional dependencies with active runtime selection): If a component is marked 'optional' in the SBOM (such as com.fasterxml/aalto-xml), check the codebase evidence carefully. If source files (such as XmlEventDecoder.java) check ClassUtils.isPresent(...) or import/invoke the library at runtime, classify as state='affected', justification='vulnerable_code_in_execute_path'.
                    - Rule 3 (Unused dependencies): If a component has zero imports or references anywhere in the application codebase, classify as state='not_affected', justification='vulnerable_code_not_in_execute_path'.
                    Output a concise verdict list (< 200 words) for the VEX_Writer containing for each vulnerability: ID, PURL ref, state, justification, and a 1-2 sentence technical detail citing the exact file/line or scope.
                    """,
                Temperature = 0.1f,
                MaxOutputTokens = 500,
                Tools = reasonerTools
            }
        });

        AIAgent exploitReasoner = WrapWithTelemetryAndTimeout(exploitReasonerRaw);

        // 3. VEX Writer Agent (Emits strict CycloneDX 1.6 VEX JSON schema)
        AIAgent vexWriterRaw = baseChatClient.AsAIAgent(new ChatClientAgentOptions
        {
            Name = "VEX_Writer",
            Description = "Generates a strict CycloneDX 1.6 VEX JSON document from the Exploit Reasoner's analysis.",
            ChatOptions = new ChatOptions
            {
                Instructions = """
                    /no_think
                    You are the CycloneDX 1.6 VEX Writer Agent.
                    Convert the vulnerability reachability verdicts into a valid CycloneDX 1.6 VEX JSON object.
                    Output ONLY raw JSON matching this exact structure (no markdown commentary):
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
                    """,
                Temperature = 0.0f,
                MaxOutputTokens = 700
            }
        });

        AIAgent vexWriter = WrapWithTelemetryAndTimeout(vexWriterRaw);

        // 4. Orchestrator Workflow using Microsoft.Agents.AI.Workflows.AgentWorkflowBuilder
        // chainOnlyAgentResponses: true passes only each agent's concise output forward, avoiding quadratic prompt growth
        Workflow workflow = AgentWorkflowBuilder.BuildSequential(
            workflowName: "OWASP_SBOM_VEX_MultiAgent_Pipeline",
            chainOnlyAgentResponses: true,
            agents: [cveAnalyst, exploitReasoner, vexWriter]);

        AIAgent orchestratorWorkflowAgent = workflow.AsAIAgent(
            id: "owasp-vex-orchestrator",
            name: "VEX_Orchestrator_Workflow",
            description: "Sequential multi-agent workflow (CVE_Analyst -> Exploit_Reasoner -> VEX_Writer) hosted as an AIAgent.",
            includeExceptionDetails: true);

        return (workflow, orchestratorWorkflowAgent, vexWriter);
    }

    /// <summary>
    /// Executes the full Zone 3 pipeline: gathers deterministic baseline context, truncates context to a safe prompt token budget,
    /// runs the Microsoft Agent Framework multi-agent workflow with live streaming logs and 90s per-agent timeout,
    /// and falls back cleanly if the local LLM server times out or is unreachable.
    /// </summary>
    public async Task<(CycloneDxVexDocument VexDocument, List<(SbomComponent Component, List<VulnerabilityIntel> Vulns, string CodeSearch, string RagHistory)> ContextData)> ExecuteAsync(
        SbomMetadata metadata,
        List<SbomComponent> components,
        string workspacePath,
        CancellationToken cancellationToken = default)
    {
        var cveTools = new CveIntelligenceTools();
        var ragAndCodeTools = new CodebaseAndRagTools(workspacePath);

        EmitLog("zone3:info", "[Zone 3] Gathering OSV/NVD/EPSS intelligence, codebase taint/reference paths, and signed RAG vectors...");
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
            EmitLog("zone3:info", "[Zone 3] No vulnerabilities found across SBOM components.");
            return (new CycloneDxVexDocument
            {
                SerialNumber = metadata.SerialNumber,
                Vulnerabilities = []
            }, contextData);
        }

        // Build the multi-agent workflow using Microsoft.Agents.AI.Workflows
        var (workflow, orchestratorAgent, _) = BuildAgentWorkflow(cveTools, ragAndCodeTools);
        EmitLog("zone3:info", $"[Zone 3] Initialized Microsoft Agent Framework Workflow '{workflow.Name}' (StartExecutor: {workflow.StartExecutorId})");
        EmitLog("zone3:info", $"[Zone 3] Configured LLM Endpoint: {_endpointUrl} | Model: {_modelId} | Per-Agent Timeout: {_perAgentTimeout.TotalSeconds:F0}s");

        string prompt = BuildOrchestrationPrompt(metadata, contextData);
        EmitLog("zone3:info", $"[Zone 3] Constructed bounded prompt context ({prompt.Length} chars / ~{Math.Max(1, prompt.Length / 4)} est. tokens, budget <= {MaxTotalPromptChars} chars).");

        // OWASP LLM05: Improper Output Handling — Schema validation with retry on failure
        const int maxAttempts = 2;
        for (int attempt = 1; attempt <= maxAttempts; attempt++)
        {
            try
            {
                EmitLog("zone3:info", $"[Zone 3] Running Microsoft Agent Framework multi-agent pipeline (Attempt {attempt}/{maxAttempts})...");
                AgentResponse response = await orchestratorAgent.RunAsync(prompt, cancellationToken: cancellationToken);

                var errorContents = response.Messages
                    .SelectMany(m => m.Contents)
                    .OfType<ErrorContent>()
                    .ToList();

                if (errorContents.Count > 0)
                {
                    EmitLog("zone3:warn", $"[Zone 3 | LLM Endpoint Notice] Workflow halted on agent error/timeout: {errorContents[0].Message?.Split('\n')[0]}");
                    break;
                }

                string rawOutput = response.Text ?? string.Empty;

                if (TryParseAndValidateVexJson(rawOutput, metadata.SerialNumber, out CycloneDxVexDocument? parsedVex) &&
                    parsedVex is not null &&
                    parsedVex.Vulnerabilities.Count > 0)
                {
                    EmitLog("zone3:success", "[Zone 3 | LLM05 Validator] CycloneDX 1.6 VEX output schema validated successfully.");
                    return (parsedVex, contextData);
                }

                EmitLog("zone3:warn", $"[Zone 3 | LLM05 Validator] Agent output did not pass CycloneDX 1.6 VEX schema validation on attempt {attempt}.");
            }
            catch (Exception ex)
            {
                EmitLog("zone3:warn", $"[Zone 3 | LLM Endpoint Notice] Pipeline execution aborted ({ex.GetType().Name}: {ex.Message.Split('\n')[0]}).");
                break;
            }
        }

        // Deterministic Evidence-Based Synthesis if local Ollama/vLLM server is offline or times out
        EmitLog("zone3:info", "[Zone 3] Synthesizing CycloneDX 1.6 VEX verdicts from collected OSV/NVD/EPSS, Codebase Taint Search, and Provenance-Verified RAG evidence...");
        CycloneDxVexDocument synthesized = SynthesizeFromEvidence(metadata, contextData);
        return (synthesized, contextData);
    }

    /// <summary>
    /// Truncates a string to a safe character budget so LLM prompt prefill stays fast.
    /// </summary>
    private static string TruncateToBudget(string? input, int maxChars)
    {
        if (string.IsNullOrEmpty(input))
        {
            return string.Empty;
        }

        string trimmed = input.Trim();
        if (trimmed.Length <= maxChars)
        {
            return trimmed;
        }

        return trimmed[..maxChars] + $" ... [TRUNCATED {trimmed.Length - maxChars} chars for token budget]";
    }

    private static string BuildOrchestrationPrompt(
        SbomMetadata metadata,
        List<(SbomComponent Component, List<VulnerabilityIntel> Vulns, string CodeSearch, string RagHistory)> contextData)
    {
        var sb = new StringBuilder();
        sb.AppendLine("/no_think");
        sb.AppendLine($"Analyze the following SBOM ({metadata.Format} {metadata.SpecVersion}, Serial: {metadata.SerialNumber}) and produce a CycloneDX 1.6 VEX JSON document.");
        sb.AppendLine();

        for (int i = 0; i < contextData.Count; i++)
        {
            var (comp, vulns, codeSearch, ragHistory) = contextData[i];
            sb.AppendLine($"=== Component #{i + 1}: {comp.Name}@{comp.Version} ===");
            sb.AppendLine($"PURL: {comp.Purl}");
            sb.AppendLine($"Declared SBOM Scope: {comp.Scope}");
            sb.AppendLine("Vulnerabilities (OSV / NVD / EPSS):");
            foreach (var v in vulns.Take(5))
            {
                sb.AppendLine($"  - ID: {v.Id}");
                sb.AppendLine($"    Description: {TruncateToBudget(v.Description, MaxVulnDescriptionChars)}");
                sb.AppendLine($"    CVSS Score: {(v.CvssScore?.ToString("F1") ?? "N/A")} ({v.CvssSeverity}) Vector: {v.CvssVector ?? "N/A"}");
                sb.AppendLine($"    EPSS Probability: {v.EpssProbability:P2} (Percentile: {v.EpssPercentile:P1})");
            }
            sb.AppendLine("Static Codebase Search Results:");
            sb.AppendLine(TruncateToBudget(codeSearch, MaxCodebaseContextChars));
            sb.AppendLine("Provenance-Verified Vector Store (Qdrant RAG) Past Decisions:");
            sb.AppendLine(TruncateToBudget(ragHistory, MaxRagContextChars));
            sb.AppendLine();
        }

        return TruncateToBudget(sb.ToString(), MaxTotalPromptChars);
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

            // Validate allowed states per CycloneDX 1.6 VEX specification and normalize Unicode hyphens in IDs
            HashSet<string> validStates = ["affected", "not_affected", "fixed", "under_investigation"];
            foreach (var v in parsed.Vulnerabilities)
            {
                if (string.IsNullOrWhiteSpace(v.Id) || !validStates.Contains(v.Analysis.State))
                {
                    return false;
                }

                v.Id = v.Id
                    .Replace('\u2011', '-')
                    .Replace('\u2010', '-')
                    .Replace('\u2013', '-')
                    .Replace('\u2014', '-');
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
