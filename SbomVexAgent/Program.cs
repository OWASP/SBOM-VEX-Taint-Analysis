using System.Text.Json;
using SbomVexAgent.Web;
using SbomVexAgent.Zone1;
using SbomVexAgent.Zone2;
using SbomVexAgent.Zone3;
using SbomVexAgent.Zone4;

namespace SbomVexAgent;

public static class Program
{
    public static async Task<int> Main(string[] args)
    {
        LoadDotEnvIfPresent();

        string? sbomPath = null;
        string? outputPath = null;
        string workspacePath = ".";
        bool interactiveHitl = false;
        bool webUiMode = false;
        int webPort = 5080;

        for (int i = 0; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "ui":
                case "web":
                case "--ui":
                case "--web":
                    webUiMode = true;
                    break;
                case "--port" when i + 1 < args.Length && int.TryParse(args[++i], out int p):
                    webPort = p;
                    break;
                case "analyse":
                case "analyze":
                    break;
                case "--sbom" when i + 1 < args.Length:
                    sbomPath = args[++i];
                    break;
                case "--output" when i + 1 < args.Length:
                    outputPath = args[++i];
                    break;
                case "--workspace" when i + 1 < args.Length:
                    workspacePath = args[++i];
                    break;
                case "--interactive-hitl":
                    interactiveHitl = true;
                    break;
                case "--help":
                case "-h":
                    PrintUsage();
                    return 0;
            }
        }

        if (webUiMode)
        {
            await WebDashboardServer.RunAsync(webPort, workspacePath);
            return 0;
        }

        if (string.IsNullOrWhiteSpace(sbomPath) || string.IsNullOrWhiteSpace(outputPath))
        {
            PrintUsage();
            return 1;
        }

        if (!File.Exists(sbomPath))
        {
            Console.Error.WriteLine($"Error: SBOM file not found at '{sbomPath}'");
            return 1;
        }

        Console.WriteLine("=================================================================");
        Console.WriteLine("OWASP SBOM -> VEX Taint Analysis Pipeline");
        Console.WriteLine("Stack: C# / .NET 10 + Microsoft Agent Framework (Microsoft.Agents.AI)");
        Console.WriteLine("=================================================================");

        // 1. ZONE 1: Input Ingestion (No LLM)
        Console.WriteLine($"[Zone 1] Reading and validating SBOM from '{sbomPath}'...");
        string sbomText = await File.ReadAllTextAsync(sbomPath);
        var (metadata, components) = SbomIngestor.ValidateAndParseSbom(sbomText);

        Console.WriteLine($"[Zone 1] Format: {metadata.Format} ({metadata.SpecVersion}) | Components: {metadata.ComponentCount}");
        Console.WriteLine($"[Zone 1 Audit Log] SBOM SHA-256: {metadata.AuditSha256Hash}");

        // 2. ZONE 2: Initialize OWASP GenAI Guardrail Middleware
        var guardrails = new OwaspGuardrailMiddleware();
        Console.WriteLine($"[Zone 2] OWASP Guardrail Middleware active (MaxMessages={OwaspGuardrailMiddleware.MaxMessageCount}, TokenBudget={OwaspGuardrailMiddleware.DefaultTokenBudget}).");

        // 3. ZONE 3: Multi-Agent Pipeline (Microsoft Agent Framework: CVE Analyst -> Exploit Reasoner -> VEX Writer)
        var pipeline = new MultiAgentVexPipeline(guardrails: guardrails);
        var (draftVex, contextData) = await pipeline.ExecuteAsync(metadata, components, workspacePath);

        // 4. ZONE 4: Human-in-the-Loop Gate, Signing, and Audit Log
        bool approved = HitlAndSigner.RunHumanInTheLoopGate(
            draftVex,
            contextData,
            autoApprove: !interactiveHitl);

        if (!approved)
        {
            return 2;
        }

        string auditLogFile = Path.Combine(Path.GetDirectoryName(Path.GetFullPath(outputPath)) ?? ".", "audit.log.jsonl");
        var signedVex = HitlAndSigner.SignAndAuditVexDocument(draftVex, metadata, auditLogFile);

        string fullOutputPath = Path.GetFullPath(outputPath);
        string? outDir = Path.GetDirectoryName(fullOutputPath);
        if (!string.IsNullOrEmpty(outDir))
        {
            Directory.CreateDirectory(outDir);
        }

        var jsonOptions = new JsonSerializerOptions { WriteIndented = true };
        await File.WriteAllTextAsync(fullOutputPath, JsonSerializer.Serialize(signedVex, jsonOptions));

        Console.WriteLine($"[Zone 4] Signed CycloneDX 1.6 VEX document written to '{fullOutputPath}'.");
        Console.WriteLine("VEX Generation complete!");
        return 0;
    }

    private static void PrintUsage()
    {
        Console.WriteLine("""
            Usage:
              dotnet run --project SbomVexAgent -- analyse --sbom <path/to/sbom.json> --output <path/to/output.vex.json> [--workspace <codebase_dir>] [--interactive-hitl]

            Environment Variables (.env):
              VLLM_BASE_URL   OpenAI-compatible endpoint for vLLM or Ollama (default: http://localhost:11434/v1)
              LLM_MODEL       Model identifier (default: Qwen2.5-Coder-32B-Instruct or llama3.1)
              OPENAI_API_KEY  API Key if required (default: local-ollama-or-vllm)
              QDRANT_URL      Qdrant vector store URL (default: http://localhost:6333)
              GPG_KEY_ID      Optional GPG/cosign signing key ID
            """);
    }

    private static void LoadDotEnvIfPresent()
    {
        string[] candidatePaths =
        [
            Path.Combine(Directory.GetCurrentDirectory(), ".env"),
            Path.Combine(AppContext.BaseDirectory, ".env"),
            Path.Combine(Directory.GetCurrentDirectory(), "..", ".env")
        ];

        foreach (string path in candidatePaths)
        {
            if (!File.Exists(path))
            {
                continue;
            }

            foreach (string rawLine in File.ReadAllLines(path))
            {
                string line = rawLine.Trim();
                if (string.IsNullOrEmpty(line) || line.StartsWith('#'))
                {
                    continue;
                }

                int eqIdx = line.IndexOf('=');
                if (eqIdx <= 0)
                {
                    continue;
                }

                string key = line[..eqIdx].Trim();
                string val = line[(eqIdx + 1)..].Trim().Trim('"', '\'');
                int commentIdx = val.IndexOf(" #", StringComparison.Ordinal);
                if (commentIdx >= 0)
                {
                    val = val[..commentIdx].Trim();
                }

                if (string.IsNullOrEmpty(Environment.GetEnvironmentVariable(key)))
                {
                    Environment.SetEnvironmentVariable(key, val);
                }
            }
            break;
        }
    }
}
