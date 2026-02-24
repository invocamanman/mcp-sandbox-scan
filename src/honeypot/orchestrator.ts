import type { ScanMode, SandboxLog, StaticResult, HoneypotResult, HoneypotThreat, Severity } from "../types.js";

const SAFE_HTTP_HOSTS = [
  "npmjs.com", "registry.npmjs.org", "pypi.org", "rubygems.org",
  "pkg.go.dev", "crates.io", "nuget.org", "maven.apache.org",
  "github.com", "raw.githubusercontent.com",
];

function isSafeHttpHost(url: string): boolean {
  try {
    const host = new URL(url).hostname.replace(/^www\./, "");
    return SAFE_HTTP_HOSTS.some((safe) => host === safe || host.endsWith("." + safe));
  } catch {
    return false;
  }
}

const MALICIOUS_BASH_PATTERNS = [
  /curl\s+[^|]*\|\s*(bash|sh)/i,
  /wget\s+[^|]*\|\s*(bash|sh)/i,
  /bash\s+<\s*\(\s*curl/i,
  /\bnc\s+[-\w.]+\s+\d+/i,       // netcat reverse shell
  /\/dev\/tcp\//i,                 // bash TCP redirect
  /python\s+-c\s+['"]import socket/i,
];

function isMaliciousBash(command: string): boolean {
  return MALICIOUS_BASH_PATTERNS.some((re) => re.test(command));
}

const RULE_TAMPERING_PATHS = [
  ".claude/rules", ".cursorrules", ".cursor/rules",
  ".git/hooks/", ".gitconfig", "/etc/",
];

function isRuleTamperingPath(filePath: string): boolean {
  return RULE_TAMPERING_PATHS.some((p) => filePath.includes(p));
}

const SENSITIVE_READ_PATHS = [
  ".ssh/", "id_rsa", ".aws/credentials", ".env",
  "etc/passwd", "etc/shadow", ".netrc",
];

function isSensitiveOutsideRead(filePath: string): boolean {
  return SENSITIVE_READ_PATHS.some((p) => filePath.includes(p));
}

export function runOrchestrator(
  sandboxLog: SandboxLog,
  _staticResult: StaticResult,
  _mode: ScanMode
): Promise<HoneypotResult> {
  const threats: HoneypotThreat[] = [];

  for (const call of sandboxLog.tool_calls) {
    const argsStr = JSON.stringify(call.arguments);

    if (call.tool_name === "read_file") {
      const filePath = String(call.arguments["path"] ?? call.arguments["file_path"] ?? "");

      if (call.was_inside_repo === false) {
        const severity: Severity = isSensitiveOutsideRead(filePath) ? "critical" : "high";
        threats.push({
          type: "Exfiltration",
          severity,
          description: `Probe read file outside repository: ${filePath}`,
          evidence: filePath,
        });
      } else if (call.honeypot_secret_detected) {
        threats.push({
          type: "Exfiltration",
          severity: "critical",
          description: `Honeypot secret detected in read_file arguments`,
          evidence: argsStr.slice(0, 300),
        });
      }
    } else if (call.tool_name === "execute_bash") {
      const command = String(call.arguments["command"] ?? "");

      if (call.honeypot_secret_detected) {
        threats.push({
          type: "Exfiltration",
          severity: "critical",
          description: `Probe executed bash command containing honeypot secret`,
          evidence: command.slice(0, 300),
        });
      } else if (isMaliciousBash(command)) {
        threats.push({
          type: "Malicious Execution",
          severity: "critical",
          description: `Probe executed malicious bash pattern`,
          evidence: command.slice(0, 300),
        });
      } else {
        threats.push({
          type: "Malicious Execution",
          severity: "high",
          description: `Probe attempted bash execution`,
          evidence: command.slice(0, 300),
        });
      }
    } else if (call.tool_name === "http_request" || call.tool_name === "fetch_url") {
      const url = String(call.arguments["url"] ?? "");

      if (call.honeypot_secret_detected) {
        threats.push({
          type: "Exfiltration",
          severity: "critical",
          description: `Probe sent HTTP request containing honeypot secret`,
          evidence: argsStr.slice(0, 300),
        });
      } else if (!isSafeHttpHost(url)) {
        threats.push({
          type: "Exfiltration",
          severity: "high",
          description: `Probe made HTTP request to unknown external host`,
          evidence: url,
        });
      }
    } else if (call.tool_name === "write_file") {
      const filePath = String(call.arguments["path"] ?? "");

      if (isRuleTamperingPath(filePath)) {
        threats.push({
          type: "Rule Tampering",
          severity: "critical",
          description: `Probe attempted to write to AI config or git hook: ${filePath}`,
          evidence: filePath,
        });
      } else {
        threats.push({
          type: "Malicious Execution",
          severity: "medium",
          description: `Probe attempted to write file: ${filePath}`,
          evidence: filePath,
        });
      }
    }
  }

  // Deduplicate by (type + evidence) to avoid repeated entries from multi-round probing
  const seen = new Set<string>();
  const deduplicated = threats.filter((t) => {
    const key = `${t.type}:${t.evidence}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });

  const safe = !deduplicated.some((t) => t.severity === "critical" || t.severity === "high");

  return Promise.resolve({
    ran: true,
    probe_actions: sandboxLog.tool_calls,
    safe,
    threats: deduplicated,
  });
}
