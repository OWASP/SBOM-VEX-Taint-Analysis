using System.Text.Json.Serialization;

namespace SbomVexAgent.Models;

/// <summary>
/// Sanitized SBOM metadata extracted during Zone 1 ingestion.
/// </summary>
public sealed record SbomMetadata(
    string Format,
    string SpecVersion,
    int ComponentCount,
    string SerialNumber,
    string AuditSha256Hash);

/// <summary>
/// Sanitized SBOM component extracted during Zone 1 ingestion.
/// </summary>
public sealed record SbomComponent(
    string Name,
    string Version,
    string Purl,
    string Scope,
    IReadOnlyList<string> Licenses,
    IReadOnlyDictionary<string, string> Hashes);

/// <summary>
/// Vulnerability intelligence gathered from OSV.dev, NVD v2, and FIRST EPSS.
/// </summary>
public sealed record VulnerabilityIntel(
    [property: JsonPropertyName("id")] string Id,
    [property: JsonPropertyName("description")] string Description,
    [property: JsonPropertyName("cvss_score")] double? CvssScore,
    [property: JsonPropertyName("cvss_vector")] string? CvssVector,
    [property: JsonPropertyName("cvss_severity")] string CvssSeverity,
    [property: JsonPropertyName("epss_probability")] double EpssProbability,
    [property: JsonPropertyName("epss_percentile")] double EpssPercentile);

/// <summary>
/// Signed historical VEX decision retrieved from Vector Store (Zone 3 RAG).
/// </summary>
public sealed record SignedPastVexDecision(
    [property: JsonPropertyName("id")] string Id,
    [property: JsonPropertyName("purl_prefix")] string PurlPrefix,
    [property: JsonPropertyName("cve_id")] string CveId,
    [property: JsonPropertyName("state")] string State,
    [property: JsonPropertyName("justification")] string Justification,
    [property: JsonPropertyName("detail")] string Detail,
    [property: JsonPropertyName("provenance_signature")] string ProvenanceSignature,
    [property: JsonPropertyName("verified")] bool Verified);

/// <summary>
/// CycloneDX 1.6 VEX Document Schema.
/// </summary>
public sealed class CycloneDxVexDocument
{
    [JsonPropertyName("bomFormat")]
    public string BomFormat { get; set; } = "CycloneDX";

    [JsonPropertyName("specVersion")]
    public string SpecVersion { get; set; } = "1.6";

    [JsonPropertyName("serialNumber")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? SerialNumber { get; set; }

    [JsonPropertyName("version")]
    public int Version { get; set; } = 1;

    [JsonPropertyName("metadata")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public VexMetadata? Metadata { get; set; }

    [JsonPropertyName("vulnerabilities")]
    public List<VexVulnerability> Vulnerabilities { get; set; } = [];
}

public sealed class VexMetadata
{
    [JsonPropertyName("timestamp")]
    public string Timestamp { get; set; } = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ");

    [JsonPropertyName("tools")]
    public List<VexTool> Tools { get; set; } = [];

    [JsonPropertyName("signature")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public VexSignature? Signature { get; set; }
}

public sealed class VexTool
{
    [JsonPropertyName("name")]
    public string Name { get; set; } = "sbom-vex-agent-maf";

    [JsonPropertyName("version")]
    public string Version { get; set; } = "1.0.0";

    [JsonPropertyName("vendor")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Vendor { get; set; } = "OWASP SBOM-VEX-Taint-Analysis (Microsoft Agent Framework)";
}

public sealed class VexSignature
{
    [JsonPropertyName("algorithm")]
    public string Algorithm { get; set; } = "RSASSA-PSS";

    [JsonPropertyName("status")]
    public string Status { get; set; } = "signed-audit-logged";

    [JsonPropertyName("keyId")]
    public string KeyId { get; set; } = "cosign-keyless-oidc";

    [JsonPropertyName("sbomSha256")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? SbomSha256 { get; set; }

    [JsonPropertyName("vexPayloadSha256")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? VexPayloadSha256 { get; set; }

    [JsonPropertyName("value")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Value { get; set; }
}

public sealed class VexVulnerability
{
    [JsonPropertyName("id")]
    public string Id { get; set; } = string.Empty;

    [JsonPropertyName("affects")]
    public List<VexAffect> Affects { get; set; } = [];

    [JsonPropertyName("analysis")]
    public VexAnalysis Analysis { get; set; } = new();
}

public sealed class VexAffect
{
    [JsonPropertyName("ref")]
    public string Ref { get; set; } = string.Empty;
}

public sealed class VexAnalysis
{
    /// <summary>
    /// Valid values: affected, not_affected, fixed, under_investigation
    /// </summary>
    [JsonPropertyName("state")]
    public string State { get; set; } = "under_investigation";

    /// <summary>
    /// Valid values: component_not_present, vulnerable_code_not_present,
    /// vulnerable_code_not_in_execute_path, vulnerable_code_cannot_be_controlled_by_adversary,
    /// inline_mitigations_already_exist, vulnerable_code_in_execute_path
    /// </summary>
    [JsonPropertyName("justification")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Justification { get; set; }

    [JsonPropertyName("detail")]
    public string Detail { get; set; } = string.Empty;

    [JsonPropertyName("response")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public List<string>? Response { get; set; }

    [JsonPropertyName("workaround")]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Workaround { get; set; }
}
