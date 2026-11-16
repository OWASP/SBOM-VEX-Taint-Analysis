using System.Text.Json;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using SbomVexAgent.Zone1;
using SbomVexAgent.Zone2;
using SbomVexAgent.Zone3;
using SbomVexAgent.Zone4;

namespace SbomVexAgent.Web;

/// <summary>
/// Interactive Web Dashboard for the OWASP SBOM -> VEX Taint Analysis Pipeline
/// powered by the Microsoft Agent Framework (C# / .NET).
/// Streams real-time Zone 1–4 events and live LLM agent tokens over Server-Sent Events (SSE).
/// </summary>
public static class WebDashboardServer
{
    public static async Task RunAsync(int port = 5080, string defaultWorkspace = ".")
    {
        var builder = WebApplication.CreateBuilder();
        builder.Logging.ClearProviders();
        builder.WebHost.UseUrls($"http://localhost:{port}");

        var app = builder.Build();
        string repoRoot = Path.GetFullPath(defaultWorkspace);

        app.MapGet("/", async context =>
        {
            context.Response.ContentType = "text/html; charset=utf-8";
            await context.Response.WriteAsync(GetDashboardHtml());
        });

        app.MapGet("/api/sample-sbom", async context =>
        {
            string type = context.Request.Query["type"].ToString();
            string samplePath = type == "spdx"
                ? Path.Combine(repoRoot, "examples", "user-spdx-sbom.json")
                : Path.Combine(repoRoot, "examples", "sample-sbom.json");

            if (!File.Exists(samplePath))
            {
                samplePath = Path.Combine(Directory.GetCurrentDirectory(), "examples", type == "spdx" ? "user-spdx-sbom.json" : "sample-sbom.json");
            }

            if (File.Exists(samplePath))
            {
                context.Response.ContentType = "application/json";
                await context.Response.WriteAsync(await File.ReadAllTextAsync(samplePath));
            }
            else
            {
                context.Response.StatusCode = 404;
                await context.Response.WriteAsync("{\"error\":\"Sample SBOM file not found.\"}");
            }
        });

        app.MapPost("/api/analyze-stream", async context =>
        {
            context.Response.Headers.Append("Content-Type", "text/event-stream");
            context.Response.Headers.Append("Cache-Control", "no-cache");
            context.Response.Headers.Append("Connection", "keep-alive");

            using var reader = new StreamReader(context.Request.Body);
            string bodyText = await reader.ReadToEndAsync();
            using var reqDoc = JsonDocument.Parse(bodyText);
            string sbomJson = reqDoc.RootElement.TryGetProperty("sbom", out var sEl) ? sEl.GetString() ?? "" : "";
            string modelId = reqDoc.RootElement.TryGetProperty("model", out var mEl) ? mEl.GetString() ?? "gpt-oss:latest" : "gpt-oss:latest";
            string workspaceSubdir = reqDoc.RootElement.TryGetProperty("workspace", out var wEl) ? wEl.GetString() ?? "spring-web" : "spring-web";

            var writeLock = new SemaphoreSlim(1, 1);
            async Task SendSseAsync(string eventType, object payload)
            {
                await writeLock.WaitAsync();
                try
                {
                    string json = JsonSerializer.Serialize(new { type = eventType, data = payload });
                    await context.Response.WriteAsync($"data: {json}\n\n");
                    await context.Response.Body.FlushAsync();
                }
                finally
                {
                    writeLock.Release();
                }
            }

            try
            {
                // ZONE 1
                await SendSseAsync("log", new { zone = "Zone 1", message = "[Zone 1] Validating SBOM schema, sanitising fields (OWASP LLM01), and computing SHA-256 hash..." });
                var (metadata, components) = SbomIngestor.ValidateAndParseSbom(sbomJson);
                await SendSseAsync("zone1", new
                {
                    format = metadata.Format,
                    specVersion = metadata.SpecVersion,
                    componentCount = metadata.ComponentCount,
                    serialNumber = metadata.SerialNumber,
                    sha256 = metadata.AuditSha256Hash,
                    components = components.Select(c => new { c.Name, c.Version, c.Purl, c.Scope }).ToArray()
                });
                await SendSseAsync("log", new { zone = "Zone 1", message = $"[Zone 1] Validated {metadata.Format} ({metadata.SpecVersion}) | Components: {metadata.ComponentCount} | SHA-256: {metadata.AuditSha256Hash[..16]}..." });

                // ZONE 2
                var guardrails = new OwaspGuardrailMiddleware();
                await SendSseAsync("zone2", new
                {
                    maxMessages = OwaspGuardrailMiddleware.MaxMessageCount,
                    tokenBudget = OwaspGuardrailMiddleware.DefaultTokenBudget
                });
                await SendSseAsync("log", new { zone = "Zone 2", message = $"[Zone 2] OWASP Guardrail Middleware active (MaxMessages={OwaspGuardrailMiddleware.MaxMessageCount}, TokenBudget={OwaspGuardrailMiddleware.DefaultTokenBudget})." });

                // ZONE 3
                string targetWorkspace = Path.Combine(repoRoot, workspaceSubdir);
                if (!Directory.Exists(targetWorkspace))
                {
                    targetWorkspace = repoRoot;
                }

                var pipeline = new MultiAgentVexPipeline(
                    modelId: modelId,
                    guardrails: guardrails,
                    onLogEvent: (category, msg) =>
                    {
                        _ = SendSseAsync(category, new
                        {
                            message = msg,
                            tokensUsed = guardrails.AccumulatedTokens,
                            tokenBudget = OwaspGuardrailMiddleware.DefaultTokenBudget
                        });
                    });

                var (draftVex, contextData) = await pipeline.ExecuteAsync(metadata, components, targetWorkspace, context.RequestAborted);

                // ZONE 4
                string auditPath = Path.Combine(repoRoot, "examples", "audit.log.jsonl");
                var signedVex = HitlAndSigner.SignAndAuditVexDocument(draftVex, metadata, auditPath);
                string outFilePath = Path.Combine(repoRoot, "examples", "output.vex.json");
                await File.WriteAllTextAsync(outFilePath, JsonSerializer.Serialize(signedVex, new JsonSerializerOptions { WriteIndented = true }));

                await SendSseAsync("zone4", new
                {
                    vex = signedVex,
                    tokensUsed = guardrails.AccumulatedTokens,
                    tokenBudget = OwaspGuardrailMiddleware.DefaultTokenBudget
                });
                await SendSseAsync("log", new { zone = "Zone 4", message = "[Zone 4] HITL Gate approved & CycloneDX 1.6 VEX signed with RSASSA-PSS." });
            }
            catch (Exception ex)
            {
                await SendSseAsync("error", new { message = ex.Message });
            }
        });

        Console.WriteLine("=================================================================");
        Console.WriteLine($"OWASP SBOM -> VEX Web Dashboard running at: http://localhost:{port}");
        Console.WriteLine("Stack: C# / .NET 10 + Microsoft Agent Framework (Microsoft.Agents.AI)");
        Console.WriteLine("=================================================================");

        await app.RunAsync();
    }

    private static string GetDashboardHtml() => """
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>OWASP SBOM → VEX Taint Analysis | Microsoft Agent Framework (C#)</title>
  <style>
    :root {
      --bg: #0b0f19;
      --panel: #111827;
      --border: #1f2937;
      --accent: #6366f1;
      --accent-glow: rgba(99, 102, 241, 0.25);
      --green: #10b981;
      --red: #ef4444;
      --amber: #f59e0b;
      --text: #f3f4f6;
      --muted: #9ca3af;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      background: var(--bg);
      color: var(--text);
      padding: 20px 28px;
      line-height: 1.5;
    }
    header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding-bottom: 16px;
      border-bottom: 1px solid var(--border);
      margin-bottom: 20px;
    }
    .title-group h1 {
      font-size: 1.35rem;
      font-weight: 700;
      display: flex;
      align-items: center;
      gap: 10px;
    }
    .badge {
      font-size: 0.75rem;
      padding: 3px 10px;
      border-radius: 999px;
      background: rgba(99, 102, 241, 0.18);
      border: 1px solid var(--accent);
      color: #a5b4fc;
      font-weight: 600;
    }
    .badge-owasp {
      background: rgba(239, 68, 68, 0.15);
      border-color: var(--red);
      color: #fca5a5;
    }
    .zones-bar {
      display: grid;
      grid-template-columns: repeat(4, 1fr);
      gap: 12px;
      margin-bottom: 20px;
    }
    .zone-card {
      background: var(--panel);
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 12px 14px;
      transition: all 0.25s ease;
    }
    .zone-card.active {
      border-color: var(--accent);
      box-shadow: 0 0 16px var(--accent-glow);
    }
    .zone-card.done {
      border-color: var(--green);
    }
    .zone-title {
      font-size: 0.75rem;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      color: var(--muted);
      font-weight: 700;
    }
    .zone-name {
      font-size: 0.95rem;
      font-weight: 600;
      margin-top: 2px;
    }
    .zone-meta {
      font-size: 0.78rem;
      color: var(--muted);
      margin-top: 4px;
      font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
    }
    .main-grid {
      display: grid;
      grid-template-columns: 380px 1fr;
      gap: 18px;
    }
    .panel {
      background: var(--panel);
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 16px;
      display: flex;
      flex-direction: column;
      gap: 12px;
    }
    .panel h2 {
      font-size: 0.95rem;
      font-weight: 600;
      color: #e5e7eb;
      display: flex;
      justify-content: space-between;
      align-items: center;
    }
    textarea, select, input {
      width: 100%;
      background: #090d16;
      color: var(--text);
      border: 1px solid var(--border);
      border-radius: 6px;
      padding: 8px 10px;
      font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
      font-size: 0.8rem;
    }
    textarea {
      height: 250px;
      resize: vertical;
    }
    .btn-row {
      display: flex;
      gap: 8px;
    }
    button {
      cursor: pointer;
      border: none;
      border-radius: 6px;
      padding: 9px 14px;
      font-weight: 600;
      font-size: 0.85rem;
      transition: all 0.15s;
    }
    .btn-primary {
      background: var(--accent);
      color: white;
      width: 100%;
    }
    .btn-primary:hover { background: #4f46e5; }
    .btn-primary:disabled { opacity: 0.5; cursor: not-allowed; }
    .btn-secondary {
      background: #1f2937;
      color: var(--text);
      font-size: 0.76rem;
      padding: 6px 10px;
    }
    .btn-secondary:hover { background: #374151; }
    .agents-grid {
      display: grid;
      grid-template-columns: repeat(3, 1fr);
      gap: 12px;
    }
    .agent-box {
      background: #090d16;
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 10px 12px;
      display: flex;
      flex-direction: column;
      height: 230px;
    }
    .agent-box.running {
      border-color: var(--amber);
      box-shadow: 0 0 12px rgba(245, 158, 11, 0.2);
    }
    .agent-box.completed {
      border-color: var(--green);
    }
    .agent-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      font-size: 0.8rem;
      font-weight: 700;
      padding-bottom: 6px;
      border-bottom: 1px solid var(--border);
      margin-bottom: 6px;
    }
    .agent-stream {
      flex: 1;
      overflow-y: auto;
      font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
      font-size: 0.74rem;
      color: #d1d5db;
      white-space: pre-wrap;
    }
    .bottom-grid {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 12px;
      margin-top: 4px;
    }
    .code-view {
      background: #090d16;
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 10px 12px;
      height: 240px;
      overflow-y: auto;
      font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
      font-size: 0.75rem;
      white-space: pre-wrap;
    }
    .verdict-pill {
      display: inline-block;
      padding: 2px 8px;
      border-radius: 4px;
      font-size: 0.72rem;
      font-weight: 700;
      text-transform: uppercase;
    }
    .verdict-affected { background: rgba(239, 68, 68, 0.2); color: #fca5a5; border: 1px solid var(--red); }
    .verdict-not_affected { background: rgba(16, 185, 129, 0.2); color: #6ee7b7; border: 1px solid var(--green); }
  </style>
</head>
<body>
  <header>
    <div class="title-group">
      <h1>
        🛡️ OWASP SBOM → VEX Taint Analysis
        <span class="badge">Microsoft Agent Framework (C# / .NET 10)</span>
        <span class="badge badge-owasp">OWASP GenAI LLM01–LLM10</span>
      </h1>
    </div>
    <div id="tokenCounter" class="badge">Tokens: 0 / 32,000</div>
  </header>

  <div class="zones-bar">
    <div class="zone-card" id="zone1Card">
      <div class="zone-title">Zone 1 — Input Ingest</div>
      <div class="zone-name">Schema & Sanitiser (No LLM)</div>
      <div class="zone-meta" id="zone1Meta">Waiting for SBOM...</div>
    </div>
    <div class="zone-card" id="zone2Card">
      <div class="zone-title">Zone 2 — OWASP Guardrails</div>
      <div class="zone-name">AIAgentBuilder Middleware</div>
      <div class="zone-meta" id="zone2Meta">LLM01 · LLM02 · LLM05 · LLM10</div>
    </div>
    <div class="zone-card" id="zone3Card">
      <div class="zone-title">Zone 3 — Multi-Agent Workflow</div>
      <div class="zone-name">AgentWorkflowBuilder.BuildSequential</div>
      <div class="zone-meta" id="zone3Meta">CVE_Analyst → Exploit_Reasoner → VEX_Writer</div>
    </div>
    <div class="zone-card" id="zone4Card">
      <div class="zone-title">Zone 4 — HITL & Signing</div>
      <div class="zone-name">RSASSA-PSS / Cosign & Audit</div>
      <div class="zone-meta" id="zone4Meta">Mandatory Human Gate</div>
    </div>
  </div>

  <div class="main-grid">
    <div class="panel">
      <h2>
        <span>1. Input SBOM & Model Config</span>
        <div class="btn-row">
          <button class="btn-secondary" onclick="loadSample('cdx')">Load CycloneDX Sample</button>
          <button class="btn-secondary" onclick="loadSample('spdx')">Load SPDX Sample</button>
        </div>
      </h2>
      <label style="font-size:0.78rem;color:var(--muted);">Local Ollama / vLLM Model (`LLM_MODEL`):</label>
      <select id="modelSelect">
        <option value="gpt-oss:latest" selected>gpt-oss:latest (13 GB — Fast ~45s)</option>
        <option value="qwen3.6:latest">qwen3.6:latest (23 GB — Deep Thinking)</option>
      </select>
      <label style="font-size:0.78rem;color:var(--muted);">Target Codebase Workspace:</label>
      <input id="workspaceInput" value="spring-web" />
      <label style="font-size:0.78rem;color:var(--muted);">SBOM JSON Payload:</label>
      <textarea id="sbomInput" spellcheck="false"></textarea>
      <button id="runBtn" class="btn-primary" onclick="runPipeline()">▶ Run Multi-Agent VEX Pipeline</button>
    </div>

    <div class="panel">
      <h2>2. Live Multi-Agent Streaming Telemetry (`Microsoft.Agents.AI.Workflows`)</h2>
      <div class="agents-grid">
        <div class="agent-box" id="box_CVE_Analyst">
          <div class="agent-header">
            <span>🔎 1. CVE_Analyst</span>
            <span id="status_CVE_Analyst" style="color:var(--muted);font-weight:400;">Idle</span>
          </div>
          <div class="agent-stream" id="stream_CVE_Analyst">Waiting for workflow start...</div>
        </div>
        <div class="agent-box" id="box_Exploit_Reasoner">
          <div class="agent-header">
            <span>🧠 2. Exploit_Reasoner</span>
            <span id="status_Exploit_Reasoner" style="color:var(--muted);font-weight:400;">Idle</span>
          </div>
          <div class="agent-stream" id="stream_Exploit_Reasoner">Waiting for CVE_Analyst...</div>
        </div>
        <div class="agent-box" id="box_VEX_Writer">
          <div class="agent-header">
            <span>📝 3. VEX_Writer</span>
            <span id="status_VEX_Writer" style="color:var(--muted);font-weight:400;">Idle</span>
          </div>
          <div class="agent-stream" id="stream_VEX_Writer">Waiting for Exploit_Reasoner...</div>
        </div>
      </div>

      <div class="bottom-grid">
        <div>
          <h2 style="margin-bottom:6px;">3. Pipeline Audit & Guardrail Event Stream</h2>
          <div class="code-view" id="auditLog">Ready. Click "Run Multi-Agent VEX Pipeline" to begin.\n</div>
        </div>
        <div>
          <h2 style="margin-bottom:6px;">
            <span>4. Signed CycloneDX 1.6 VEX Output (Zone 4)</span>
            <span id="verdictBadges"></span>
          </h2>
          <div class="code-view" id="vexOutput">// Signed CycloneDX 1.6 VEX JSON will appear here</div>
        </div>
      </div>
    </div>
  </div>

  <script>
    async function loadSample(type) {
      const res = await fetch(`/api/sample-sbom?type=${type}`);
      const txt = await res.text();
      document.getElementById('sbomInput').value = txt;
    }

    function appendLog(line) {
      const el = document.getElementById('auditLog');
      el.textContent += line + "\n";
      el.scrollTop = el.scrollHeight;
    }

    async function runPipeline() {
      const runBtn = document.getElementById('runBtn');
      runBtn.disabled = true;
      runBtn.textContent = "⏳ Running Microsoft Agent Framework Pipeline...";

      ['CVE_Analyst', 'Exploit_Reasoner', 'VEX_Writer'].forEach(a => {
        document.getElementById(`stream_${a}`).textContent = "";
        document.getElementById(`status_${a}`).textContent = "Queued";
        document.getElementById(`box_${a}`).className = "agent-box";
      });
      ['zone1Card', 'zone2Card', 'zone3Card', 'zone4Card'].forEach(z => {
        document.getElementById(z).className = "zone-card";
      });
      document.getElementById('auditLog').textContent = "";
      document.getElementById('vexOutput').textContent = "// Generating CycloneDX 1.6 VEX...";
      document.getElementById('verdictBadges').innerHTML = "";

      const payload = {
        sbom: document.getElementById('sbomInput').value,
        model: document.getElementById('modelSelect').value,
        workspace: document.getElementById('workspaceInput').value
      };

      try {
        const response = await fetch('/api/analyze-stream', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload)
        });

        const reader = response.body.getReader();
        const decoder = new TextDecoder();
        let buffer = "";

        while (true) {
          const { value, done } = await reader.read();
          if (done) break;
          buffer += decoder.decode(value, { stream: true });
          const parts = buffer.split("\n\n");
          buffer = parts.pop();

          for (const part of parts) {
            if (!part.startsWith("data: ")) continue;
            const evt = JSON.parse(part.slice(6));
            handleEvent(evt.type, evt.data);
          }
        }
      } catch (err) {
        appendLog("[ERROR] " + err.message);
      } finally {
        runBtn.disabled = false;
        runBtn.textContent = "▶ Run Multi-Agent VEX Pipeline";
      }
    }

    function handleEvent(type, data) {
      if (data && data.tokensUsed !== undefined) {
        document.getElementById('tokenCounter').textContent = `Tokens: ${data.tokensUsed.toLocaleString()} / 32,000`;
      }

      if (type === "log" || type.startsWith("zone3:")) {
        appendLog(data.message);
      } else if (type === "zone1") {
        document.getElementById('zone1Card').className = "zone-card done";
        document.getElementById('zone1Meta').textContent = `${data.format} ${data.specVersion} (${data.componentCount} pkgs) | SHA256: ${data.sha256.slice(0,10)}...`;
      } else if (type === "zone2") {
        document.getElementById('zone2Card').className = "zone-card done";
        document.getElementById('zone3Card').className = "zone-card active";
      } else if (type === "agent:start") {
        appendLog(data.message);
        for (const a of ['CVE_Analyst', 'Exploit_Reasoner', 'VEX_Writer']) {
          if (data.message.includes(`[${a}]`)) {
            document.getElementById(`box_${a}`).className = "agent-box running";
            document.getElementById(`status_${a}`).textContent = "Streaming...";
          }
        }
      } else if (type === "agent:done") {
        appendLog(data.message);
        for (const a of ['CVE_Analyst', 'Exploit_Reasoner', 'VEX_Writer']) {
          if (data.message.includes(`[${a}]`)) {
            document.getElementById(`box_${a}`).className = "agent-box completed";
            document.getElementById(`status_${a}`).textContent = "Completed ✓";
          }
        }
      } else if (type.startsWith("stream:")) {
        const agentName = type.split(":")[1];
        const el = document.getElementById(`stream_${agentName}`);
        if (el) {
          el.textContent += data.message;
          el.scrollTop = el.scrollHeight;
        }
      } else if (type === "zone4") {
        document.getElementById('zone3Card').className = "zone-card done";
        document.getElementById('zone4Card').className = "zone-card done";
        document.getElementById('zone4Meta').textContent = `Signed (${data.vex.metadata.signature.algorithm}) ✓`;
        document.getElementById('vexOutput').textContent = JSON.stringify(data.vex, null, 2);

        const badgesHtml = (data.vex.vulnerabilities || []).map(v => {
          const st = v.analysis.state;
          return `<span class="verdict-pill verdict-${st}">${v.id}: ${st}</span>`;
        }).join(" ");
        document.getElementById('verdictBadges').innerHTML = badgesHtml;
      } else if (type === "error") {
        appendLog("[ERROR] " + data.message);
      }
    }

    // Load default CycloneDX sample on startup
    loadSample('cdx');
  </script>
</body>
</html>
""";
}
