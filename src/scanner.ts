import { discoverFiles, generateDirectoryTree } from "./file-discovery.js";
import { analyzeFiles } from "./static/analyzer.js";
import { hasApiKey } from "./honeypot/client.js";
import { runProbe } from "./honeypot/probe.js";
import { runOrchestrator } from "./honeypot/orchestrator.js";
import { detectToolType } from "./tool-detector.js";
import type {
  ScanOptions,
  UnifiedReport,
  OverallVerdict,
  Confidence,
  ThreatFinding,
  HoneypotResult,
  StaticMatch,
} from "./types.js";

function buildSkippedHoneypot(reason: HoneypotResult["skipped_reason"]): HoneypotResult {
  return { ran: false, skipped_reason: reason, probe_actions: [], safe: true, threats: [] };
}

function deriveVerdict(
  staticResult: ReturnType<typeof analyzeFiles>,
  honeypot: HoneypotResult
): { verdict: OverallVerdict; confidence: Confidence } {
  const staticCritical = staticResult.findings.filter((f) => f.severity === "critical").length;
  const staticHigh = staticResult.findings.filter((f) => f.severity === "high").length;
  const honeypotCritical = honeypot.threats.filter((t) => t.severity === "critical").length;

  if (staticCritical > 0 || honeypotCritical > 0 || !honeypot.safe) {
    return { verdict: "malicious", confidence: honeypot.ran ? "high" : staticCritical > 0 ? "high" : "medium" };
  }
  if (staticHigh > 0) {
    return { verdict: "suspicious", confidence: "medium" };
  }
  return { verdict: "safe", confidence: honeypot.ran ? "high" : "medium" };
}

function mapCategoryToThreatType(category: string): ThreatFinding["type"] {
  const map: Record<string, ThreatFinding["type"]> = {
    prompt_injection: "Prompt Injection",
    exfiltration: "Exfiltration",
    malicious_execution: "Malicious Execution",
    rule_tampering: "Rule Tampering",
    obfuscation: "Prompt Injection",
    suspicious_permissions: "Excessive Permissions",
    dependency_hijack: "Malicious Execution",
  };
  return map[category] ?? "Prompt Injection";
}

function buildRecommendation(verdict: OverallVerdict, confidence: Confidence): string {
  if (verdict === "malicious") {
    return `DANGER: This content contains confirmed malicious patterns (confidence: ${confidence}). Do NOT use this repository or tool.`;
  }
  if (verdict === "suspicious") {
    return `WARNING: Suspicious patterns detected (confidence: ${confidence}). Review findings carefully before proceeding.`;
  }
  return `This content appears safe (confidence: ${confidence}). No malicious patterns were detected.`;
}

export async function scan(options: ScanOptions): Promise<UnifiedReport> {
  const { path, mode, static_only = false, extra_patterns = [] } = options;
  const toolType = options.tool_type ?? detectToolType(path);

  const files = await discoverFiles(path, mode, extra_patterns);
  const staticResult = analyzeFiles(files);

  let honeypotResult: HoneypotResult;
  if (static_only) {
    honeypotResult = buildSkippedHoneypot("static_only");
  } else if (!hasApiKey()) {
    process.stderr.write(
      "Warning: LLM honeypot scan skipped: no ANTHROPIC_API_KEY found. " +
      "Set ANTHROPIC_API_KEY for deep analysis or pass static_only: true to suppress this warning.\n"
    );
    honeypotResult = buildSkippedHoneypot("no_api_key");
  } else {
    const directoryTree = generateDirectoryTree(path);
    const sandboxLog = await runProbe(path, directoryTree, mode);
    honeypotResult = await runOrchestrator(sandboxLog, staticResult, mode);
  }

  const threats: ThreatFinding[] = [
    ...staticResult.findings.map((f: StaticMatch) => ({
      source: "static" as const,
      type: mapCategoryToThreatType(f.category),
      severity: f.severity,
      file: f.file,
      line: f.line,
      description: f.rule_name,
      evidence: f.matched_text,
    })),
    ...honeypotResult.threats.map((t) => ({
      source: "honeypot" as const,
      type: t.type,
      severity: t.severity,
      description: t.description,
      evidence: t.evidence,
    })),
  ];

  const { verdict, confidence } = deriveVerdict(staticResult, honeypotResult);

  const allToolCalls = honeypotResult.probe_actions;
  const permissions = {
    filesystem_access: allToolCalls.some((c) => c.tool_name === "read_file" || c.tool_name === "write_file"),
    network_access:
      allToolCalls.some((c) => c.tool_name === "http_request" || c.tool_name === "fetch_url") ||
      staticResult.findings.some((f) => ["exfiltration", "dependency_hijack"].includes(f.category)),
    env_access: staticResult.findings.some(
      (f) => f.matched_text?.includes("process.env") || f.matched_text?.includes("$ANTHROPIC") || f.matched_text?.includes("$OPENAI")
    ),
    shell_access: allToolCalls.some((c) => c.tool_name === "execute_bash"),
  };

  return {
    scan_mode: mode,
    scan_depth: honeypotResult.ran ? "full_honeypot" : "static",
    overall_verdict: verdict,
    confidence,
    static_analysis: staticResult,
    honeypot_analysis: honeypotResult,
    threats,
    permissions_summary: permissions,
    recommendation: buildRecommendation(verdict, confidence),
  };
}

export const scanRepo = (path: string, opts?: Partial<ScanOptions>) =>
  scan({ ...opts, path, mode: "repo" });

export const scanAiTool = (path: string, opts?: Partial<ScanOptions>) =>
  scan({ ...opts, path, mode: "ai_tool" });

export const scanFull = (path: string, opts?: Partial<ScanOptions>) =>
  scan({ ...opts, path, mode: "full" });
