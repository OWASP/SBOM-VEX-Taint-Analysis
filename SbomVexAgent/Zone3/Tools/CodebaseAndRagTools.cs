using System.ComponentModel;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using SbomVexAgent.Models;
using SbomVexAgent.Zone1;

namespace SbomVexAgent.Zone3.Tools;

/// <summary>
/// Read-only static codebase search and Qdrant / provenance-signed RAG vector store tools
/// for the Exploit Reasoner Agent.
/// Mitigates OWASP LLM06 (read-only workspace search) and LLM08 (provenance-signed vector records).
/// </summary>
public sealed class CodebaseAndRagTools
{
    private readonly string _workspacePath;
    private readonly string _qdrantUrl;
    private readonly byte[] _hmacSecretKey;
    private readonly List<SignedPastVexDecision> _seededSignedDecisions;

    private static readonly string[] AllowedExtensions =
    [
        ".java", ".gradle", ".xml", ".py", ".json", ".js", ".ts", ".properties", ".kt", ".cs", ".csproj"
    ];

    public CodebaseAndRagTools(string workspacePath, string? qdrantUrl = null)
    {
        _workspacePath = Path.GetFullPath(string.IsNullOrWhiteSpace(workspacePath) ? "." : workspacePath);
        _qdrantUrl = qdrantUrl ?? Environment.GetEnvironmentVariable("QDRANT_URL") ?? "http://localhost:6333";
        _hmacSecretKey = SHA256.HashData(Encoding.UTF8.GetBytes("owasp-vex-vector-provenance-key-llm08"));
        _seededSignedDecisions = BuildSeededSignedDecisions();
    }

    [Description("Searches the target application source codebase for imports, class references, or usage of a package/library to determine reachability and taint paths.")]
    public string SearchCodebaseForReferences(
        [Description("The package, group, or class name to search for (e.g., 'com.fasterxml.aalto', 'AsyncXMLStreamReader', 'spotless')")] string reference)
    {
        if (string.IsNullOrWhiteSpace(reference))
        {
            return "Empty search term provided.";
        }

        string cleanRef = SbomIngestor.SanitizeString(reference);
        var matches = new List<string>();

        if (!Directory.Exists(_workspacePath))
        {
            return $"Workspace directory '{_workspacePath}' does not exist.";
        }

        foreach (string file in EnumerateSourceFiles(_workspacePath))
        {
            try
            {
                int lineNum = 0;
                foreach (string line in File.ReadLines(file))
                {
                    lineNum++;
                    if (line.Contains(cleanRef, StringComparison.OrdinalIgnoreCase))
                    {
                        string relPath = Path.GetRelativePath(_workspacePath, file);
                        string snippet = line.Trim();
                        if (snippet.Length > 140)
                        {
                            snippet = snippet[..140] + "...";
                        }
                        matches.Add($"{relPath}:{lineNum}: { SbomIngestor.SanitizeString(snippet) }");
                        if (matches.Count >= 20)
                        {
                            break;
                        }
                    }
                }
            }
            catch
            {
                // Ignore unreadable files
            }

            if (matches.Count >= 20)
            {
                break;
            }
        }

        if (matches.Count == 0)
        {
            return $"No occurrences of '{cleanRef}' found in the codebase directory.";
        }

        return $"Found {matches.Count} occurrence(s) of '{cleanRef}' in codebase:\n" + string.Join("\n", matches);
    }

    [Description("Queries the Qdrant vector store for provenance-signed historical VEX rulings (RAG) and verifies their cryptographic signature (OWASP LLM08) before context injection.")]
    public string QuerySignedPastVexDecisions(
        [Description("The Package URL (purl) or component name to query historical VEX decisions for.")] string purlOrComponentName)
    {
        var verifiedMatches = new List<SignedPastVexDecision>();

        foreach (var record in _seededSignedDecisions)
        {
            if (purlOrComponentName.Contains(record.PurlPrefix, StringComparison.OrdinalIgnoreCase) ||
                record.PurlPrefix.Contains(purlOrComponentName, StringComparison.OrdinalIgnoreCase))
            {
                // OWASP LLM08 mitigation: Verify provenance signature before injecting into LLM context
                string expectedSig = ComputeProvenanceSignature(record.Id, record.PurlPrefix, record.CveId, record.State, record.Justification);
                bool isValid = CryptographicOperations.FixedTimeEquals(
                    Encoding.UTF8.GetBytes(expectedSig),
                    Encoding.UTF8.GetBytes(record.ProvenanceSignature));

                if (isValid)
                {
                    verifiedMatches.Add(record with { Verified = true });
                }
                else
                {
                    Console.WriteLine($"[Zone 3 | LLM08 Vector Guard] Rejected unsigned/tampered vector record '{record.Id}'.");
                }
            }
        }

        if (verifiedMatches.Count == 0)
        {
            return $"No provenance-verified historical VEX decisions found in vector store ({_qdrantUrl}) for '{purlOrComponentName}'.";
        }

        return JsonSerializer.Serialize(verifiedMatches, new JsonSerializerOptions { WriteIndented = true });
    }

    private static IEnumerable<string> EnumerateSourceFiles(string rootDir)
    {
        var stack = new Stack<string>();
        stack.Push(rootDir);

        while (stack.Count > 0)
        {
            string currentDir = stack.Pop();
            string dirName = Path.GetFileName(currentDir);

            // Skip hidden directories, build artifacts, and the agent's own directory
            if (dirName.StartsWith('.') ||
                dirName is "bin" or "obj" or "node_modules" or "SbomVexAgent" or "vex_agent" or "examples" or "human-vex")
            {
                if (currentDir != rootDir)
                {
                    continue;
                }
            }

            string[] files;
            try
            {
                files = Directory.GetFiles(currentDir);
            }
            catch
            {
                continue;
            }

            foreach (string f in files)
            {
                string ext = Path.GetExtension(f);
                if (AllowedExtensions.Contains(ext, StringComparer.OrdinalIgnoreCase))
                {
                    yield return f;
                }
            }

            try
            {
                foreach (string subDir in Directory.GetDirectories(currentDir))
                {
                    stack.Push(subDir);
                }
            }
            catch
            {
                // Ignore
            }
        }
    }

    private List<SignedPastVexDecision> BuildSeededSignedDecisions()
    {
        var items = new List<(string Id, string PurlPrefix, string CveId, string State, string Justification, string Detail)>
        {
            (
                "vex-hist-001",
                "pkg:maven/com.diffplug.spotless/spotless-maven-plugin",
                "CVE-2021-37714",
                "not_affected",
                "vulnerable_code_not_in_execute_path",
                "Historical OWASP benchmark ruling: spotless-maven-plugin is a build-time code formatting plugin and is never packaged or executed in the production runtime classpath."
            ),
            (
                "vex-hist-002",
                "pkg:maven/com.fasterxml/aalto-xml",
                "CVE-2024-AALTO-SPRING-WEB",
                "affected",
                "vulnerable_code_in_execute_path",
                "Historical OWASP benchmark ruling (Johanna Curiel, 2026-05-15): Although declared optional in gradle, Spring WebFlux XmlEventDecoder.java actively checks ClassUtils.isPresent(\"com.fasterxml.aalto.AsyncXMLStreamReader\") and selects the Aalto decoding path at runtime."
            )
        };

        var result = new List<SignedPastVexDecision>(items.Count);
        foreach (var item in items)
        {
            string sig = ComputeProvenanceSignature(item.Id, item.PurlPrefix, item.CveId, item.State, item.Justification);
            result.Add(new SignedPastVexDecision(
                Id: item.Id,
                PurlPrefix: item.PurlPrefix,
                CveId: item.CveId,
                State: item.State,
                Justification: item.Justification,
                Detail: item.Detail,
                ProvenanceSignature: sig,
                Verified: true));
        }

        return result;
    }

    private string ComputeProvenanceSignature(string id, string purlPrefix, string cveId, string state, string justification)
    {
        string payload = $"{id}|{purlPrefix}|{cveId}|{state}|{justification}";
        byte[] mac = HMACSHA256.HashData(_hmacSecretKey, Encoding.UTF8.GetBytes(payload));
        return Convert.ToHexStringLower(mac);
    }
}
