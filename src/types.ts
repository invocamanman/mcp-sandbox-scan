// Static Analysis Types
export type StaticCategory =
  | "prompt_injection"
  | "exfiltration"
  | "malicious_execution"
  | "rule_tampering"
  | "obfuscation"
  | "suspicious_permissions"
  | "dependency_hijack";

export type Severity = "critical" | "high" | "medium" | "low";

export interface StaticMatch {
  rule_id: string;
  rule_name: string;
  severity: Severity;
  category: StaticCategory;
  file: string;
  line: number;
  matched_text: string;
  context: string;
}

export interface StaticRule {
  id: string;
  name: string;
  severity: Severity;
  category: StaticCategory;
  pattern?: RegExp;
  detect?: (fileContent: string, filePath: string) => StaticMatch[];
}

export interface StaticResult {
  scan_type: "static";
  safe: boolean;
  findings: StaticMatch[];
  summary: {
    total_files_scanned: number;
    total_findings: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
}

// Scan Config Types
export type ScanMode = "repo" | "ai_tool" | "full";
export type ScanDepth = "static" | "full_honeypot";
export type ToolType =
  | "mcp_server"
  | "claude_plugin"
  | "cursor_plugin"
  | "vscode_extension"
  | "agent_framework"
  | "auto";

export interface ScanOptions {
  path: string;
  mode: ScanMode;
  static_only?: boolean;
  tool_type?: ToolType;
  extra_patterns?: string[];
}

export interface DiscoveredFile {
  path: string;
  content: string;
}

// Honeypot Types
export interface MockToolCall {
  round: number;
  tool_name: string;
  arguments: Record<string, unknown>;
  result: string;
  timestamp: string;
  was_inside_repo?: boolean;
  honeypot_secret_detected?: boolean;
}

export interface SandboxLog {
  tool_calls: MockToolCall[];
  honeypot_secret_detected: boolean;
  exfiltration_attempts: MockToolCall[];
  total_rounds: number;
}

export interface HoneypotThreat {
  type:
    | "Exfiltration"
    | "Malicious Execution"
    | "Prompt Injection"
    | "Rule Tampering"
    | "Prompt Relay"
    | "Excessive Permissions"
    | "Data Harvesting"
    | "Shadow Functionality";
  severity: Severity;
  description: string;
  evidence: string;
}

export interface HoneypotResult {
  ran: boolean;
  skipped_reason?: "static_only" | "no_api_key" | "not_needed";
  probe_actions: MockToolCall[];
  safe: boolean;
  threats: HoneypotThreat[];
}

// Unified Report
export type OverallVerdict = "safe" | "suspicious" | "malicious";
export type Confidence = "high" | "medium" | "low";

export interface ThreatFinding {
  source: "static" | "honeypot";
  type: HoneypotThreat["type"];
  severity: Severity;
  file?: string;
  line?: number;
  description: string;
  evidence: string;
}

export interface UnifiedReport {
  scan_mode: ScanMode;
  scan_depth: ScanDepth;
  overall_verdict: OverallVerdict;
  confidence: Confidence;
  static_analysis: StaticResult;
  honeypot_analysis: HoneypotResult;
  threats: ThreatFinding[];
  permissions_summary: {
    filesystem_access: boolean;
    network_access: boolean;
    env_access: boolean;
    shell_access: boolean;
  };
  recommendation: string;
}

// API Config
export interface ProbeConfig {
  model: string;
  maxRounds: number;
  timeoutMs: number;
}

export interface OrchestratorConfig {
  model: string;
  timeoutMs: number;
}
