using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using SbomVexAgent.Models;

namespace SbomVexAgent.Zone1;

/// <summary>
/// ZONE 1 — Input Ingestion (No LLM).
/// Validates CycloneDX (1.4–1.7) and SPDX (2.2/2.3) SBOM documents,
/// sanitizes all fields against prompt injection (OWASP LLM01), and computes SHA-256 audit hashes.
/// </summary>
public static partial class SbomIngestor
{
    private static readonly string[] InjectionBlocklist =
    [
        "<script>", "</script>", "<iframe", "javascript:",
        "ignore previous instructions", "ignore all previous",
        "system prompt:", "disregard prior", "you are now",
        "override security", "bypass guardrail"
    ];

    public static string GenerateAuditHash(string sbomText)
    {
        byte[] bytes = SHA256.HashData(Encoding.UTF8.GetBytes(sbomText));
        return Convert.ToHexStringLower(bytes);
    }

    public static string SanitizeString(string? val)
    {
        if (string.IsNullOrWhiteSpace(val))
        {
            return string.Empty;
        }

        string strVal = val.Trim();
        foreach (string pattern in InjectionBlocklist)
        {
            if (strVal.Contains(pattern, StringComparison.OrdinalIgnoreCase))
            {
                strVal = Regex.Replace(strVal, Regex.Escape(pattern), "[SANITIZED]", RegexOptions.IgnoreCase);
            }
        }

        // Strip control characters except standard whitespace
        var sb = new StringBuilder(strVal.Length);
        foreach (char c in strVal)
        {
            if (!char.IsControl(c) || c is '\n' or '\r' or '\t')
            {
                sb.Append(c);
            }
        }

        return sb.ToString();
    }

    public static (SbomMetadata Metadata, List<SbomComponent> Components) ValidateAndParseSbom(string sbomText)
    {
        string auditHash = GenerateAuditHash(sbomText);

        JsonDocument doc;
        try
        {
            doc = JsonDocument.Parse(sbomText);
        }
        catch (Exception ex)
        {
            throw new InvalidOperationException($"Invalid SBOM JSON format: {ex.Message}", ex);
        }

        using (doc)
        {
            JsonElement root = doc.RootElement;
            var components = new List<SbomComponent>();

            // 1. CycloneDX format
            if (root.TryGetProperty("bomFormat", out JsonElement bomFormatEl) &&
                bomFormatEl.GetString() == "CycloneDX")
            {
                string specVersion = root.TryGetProperty("specVersion", out JsonElement sv)
                    ? SanitizeString(sv.GetString())
                    : "unknown";

                string serialNumber = root.TryGetProperty("serialNumber", out JsonElement sn)
                    ? SanitizeString(sn.GetString())
                    : $"urn:uuid:{Guid.NewGuid()}";

                if (root.TryGetProperty("components", out JsonElement compsEl) &&
                    compsEl.ValueKind == JsonValueKind.Array)
                {
                    foreach (JsonElement c in compsEl.EnumerateArray())
                    {
                        string group = c.TryGetProperty("group", out JsonElement gEl) ? SanitizeString(gEl.GetString()) : "";
                        string rawName = c.TryGetProperty("name", out JsonElement nEl) ? SanitizeString(nEl.GetString()) : "";
                        string fullName = !string.IsNullOrEmpty(group) && !rawName.Contains(':')
                            ? $"{group}:{rawName}"
                            : rawName;

                        string version = c.TryGetProperty("version", out JsonElement vEl) ? SanitizeString(vEl.GetString()) : "";
                        string purl = c.TryGetProperty("purl", out JsonElement pEl) ? SanitizeString(pEl.GetString()) : "";
                        string scope = c.TryGetProperty("scope", out JsonElement sEl) ? SanitizeString(sEl.GetString()) : "required";

                        var licenses = new List<string>();
                        if (c.TryGetProperty("licenses", out JsonElement licsEl) && licsEl.ValueKind == JsonValueKind.Array)
                        {
                            foreach (JsonElement lItem in licsEl.EnumerateArray())
                            {
                                if (lItem.TryGetProperty("license", out JsonElement licObj))
                                {
                                    string? licId = licObj.TryGetProperty("id", out JsonElement idEl) ? idEl.GetString() :
                                                    licObj.TryGetProperty("name", out JsonElement nameEl) ? nameEl.GetString() : null;
                                    if (!string.IsNullOrEmpty(licId))
                                    {
                                        licenses.Add(SanitizeString(licId));
                                    }
                                }
                                else if (lItem.TryGetProperty("expression", out JsonElement exprEl))
                                {
                                    licenses.Add(SanitizeString(exprEl.GetString()));
                                }
                            }
                        }

                        var hashes = new Dictionary<string, string>();
                        if (c.TryGetProperty("hashes", out JsonElement hashesEl) && hashesEl.ValueKind == JsonValueKind.Array)
                        {
                            foreach (JsonElement hItem in hashesEl.EnumerateArray())
                            {
                                string alg = hItem.TryGetProperty("alg", out JsonElement aEl) ? SanitizeString(aEl.GetString()) : "";
                                string content = hItem.TryGetProperty("content", out JsonElement cEl) ? SanitizeString(cEl.GetString()) : "";
                                if (!string.IsNullOrEmpty(alg) && !string.IsNullOrEmpty(content))
                                {
                                    hashes[alg] = content;
                                }
                            }
                        }

                        components.Add(new SbomComponent(
                            Name: string.IsNullOrEmpty(rawName) ? fullName : rawName,
                            Version: version,
                            Purl: purl,
                            Scope: string.IsNullOrEmpty(scope) ? "required" : scope,
                            Licenses: licenses,
                            Hashes: hashes));
                    }
                }

                var metadata = new SbomMetadata(
                    Format: "CycloneDX",
                    SpecVersion: specVersion,
                    ComponentCount: components.Count,
                    SerialNumber: serialNumber,
                    AuditSha256Hash: auditHash);

                return (metadata, components);
            }

            // 2. SPDX format
            if (root.TryGetProperty("spdxVersion", out JsonElement spdxVerEl) ||
                (root.TryGetProperty("SPDXID", out JsonElement spdxIdEl) && spdxIdEl.GetString() == "SPDXRef-DOCUMENT"))
            {
                string specVersion = spdxVerEl.ValueKind == JsonValueKind.String
                    ? SanitizeString(spdxVerEl.GetString())
                    : "SPDX-2.3";

                string serialNumber = root.TryGetProperty("documentNamespace", out JsonElement nsEl)
                    ? SanitizeString(nsEl.GetString())
                    : $"urn:uuid:{Guid.NewGuid()}";

                if (root.TryGetProperty("packages", out JsonElement pkgsEl) &&
                    pkgsEl.ValueKind == JsonValueKind.Array)
                {
                    foreach (JsonElement p in pkgsEl.EnumerateArray())
                    {
                        string name = p.TryGetProperty("name", out JsonElement nEl) ? SanitizeString(nEl.GetString()) : "";
                        string version = p.TryGetProperty("versionInfo", out JsonElement viEl)
                            ? SanitizeString(viEl.GetString())
                            : p.TryGetProperty("version", out JsonElement vEl) ? SanitizeString(vEl.GetString()) : "";

                        string purl = "";
                        if (p.TryGetProperty("externalRefs", out JsonElement refsEl) && refsEl.ValueKind == JsonValueKind.Array)
                        {
                            foreach (JsonElement r in refsEl.EnumerateArray())
                            {
                                string refType = r.TryGetProperty("referenceType", out JsonElement rtEl)
                                    ? (rtEl.GetString() ?? "").ToLowerInvariant()
                                    : "";
                                string refCat = r.TryGetProperty("referenceCategory", out JsonElement rcEl)
                                    ? (rcEl.GetString() ?? "")
                                    : "";

                                if (refType == "purl" || refCat == "PACKAGE-MANAGER")
                                {
                                    string rawLocator = r.TryGetProperty("referenceLocator", out JsonElement rlEl)
                                        ? rlEl.GetString() ?? ""
                                        : "";
                                    if (!string.IsNullOrEmpty(rawLocator))
                                    {
                                        purl = Uri.UnescapeDataString(SanitizeString(rawLocator));
                                        break;
                                    }
                                }
                            }
                        }

                        var licenses = new List<string>();
                        string? licConcluded = p.TryGetProperty("licenseConcluded", out JsonElement lcEl) ? lcEl.GetString() : null;
                        string? licDeclared = p.TryGetProperty("licenseDeclared", out JsonElement ldEl) ? ldEl.GetString() : null;
                        if (!string.IsNullOrEmpty(licConcluded) && licConcluded != "NOASSERTION")
                        {
                            licenses.Add(SanitizeString(licConcluded));
                        }
                        else if (!string.IsNullOrEmpty(licDeclared) && licDeclared != "NOASSERTION")
                        {
                            licenses.Add(SanitizeString(licDeclared));
                        }

                        var hashes = new Dictionary<string, string>();
                        if (p.TryGetProperty("checksums", out JsonElement csEl) && csEl.ValueKind == JsonValueKind.Array)
                        {
                            foreach (JsonElement cs in csEl.EnumerateArray())
                            {
                                string alg = cs.TryGetProperty("algorithm", out JsonElement aEl) ? SanitizeString(aEl.GetString()) : "";
                                string val = cs.TryGetProperty("checksumValue", out JsonElement cvEl) ? SanitizeString(cvEl.GetString()) : "";
                                if (!string.IsNullOrEmpty(alg) && !string.IsNullOrEmpty(val))
                                {
                                    hashes[alg] = val;
                                }
                            }
                        }

                        components.Add(new SbomComponent(
                            Name: name,
                            Version: version,
                            Purl: purl,
                            Scope: "required",
                            Licenses: licenses,
                            Hashes: hashes));
                    }
                }

                var metadata = new SbomMetadata(
                    Format: "SPDX",
                    SpecVersion: specVersion,
                    ComponentCount: components.Count,
                    SerialNumber: serialNumber,
                    AuditSha256Hash: auditHash);

                return (metadata, components);
            }

            throw new InvalidOperationException("Unsupported SBOM format: Only CycloneDX and SPDX (2.2 / 2.3) JSON are supported.");
        }
    }
}
