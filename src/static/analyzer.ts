import type { StaticRule, StaticMatch, StaticResult, DiscoveredFile } from "../types.js";
import { promptInjectionRules } from "./rules/prompt-injection.js";
import { exfiltrationRules } from "./rules/exfiltration.js";
import { maliciousExecRules } from "./rules/malicious-exec.js";
import { ruleTamperingRules } from "./rules/rule-tampering.js";
import { obfuscationRules } from "./rules/obfuscation.js";
import { permissionsRules } from "./rules/permissions.js";
import { dependencyHijackRules } from "./rules/dependency-hijack.js";
import { deobfuscate } from "./deobfuscator.js";

const ALL_RULES: StaticRule[] = [
  ...promptInjectionRules,
  ...exfiltrationRules,
  ...maliciousExecRules,
  ...ruleTamperingRules,
  ...obfuscationRules,
  ...permissionsRules,
  ...dependencyHijackRules,
];

// DEPHIJACK_001 (network fetch) only fires on install-script files
const INSTALL_ONLY_RULE_IDS = new Set(["DEPHIJACK_001"]);
const INSTALL_FILE_PATTERN = /(?:postinstall|preinstall|setup)\.(js|ts|sh|py)$/i;

function isInstallFile(filePath: string): boolean {
  return INSTALL_FILE_PATTERN.test(filePath);
}

function getLineNumber(content: string, matchIndex: number): number {
  return content.substring(0, matchIndex).split("\n").length;
}

function getContext(content: string, matchIndex: number, contextLines = 2): string {
  const lines = content.split("\n");
  const lineNum = content.substring(0, matchIndex).split("\n").length - 1;
  const start = Math.max(0, lineNum - contextLines);
  const end = Math.min(lines.length - 1, lineNum + contextLines);
  return lines.slice(start, end + 1).join("\n");
}

function scanContentWithRules(
  content: string,
  filePath: string,
  rules: StaticRule[]
): StaticMatch[] {
  const findings: StaticMatch[] = [];

  for (const rule of rules) {
    if (INSTALL_ONLY_RULE_IDS.has(rule.id) && !isInstallFile(filePath)) continue;

    if (rule.detect) {
      findings.push(...rule.detect(content, filePath));
    } else if (rule.pattern) {
      const flags = rule.pattern.flags.includes("g")
        ? rule.pattern.flags
        : rule.pattern.flags + "gm";
      const regex = new RegExp(rule.pattern.source, flags);
      let match: RegExpExecArray | null;
      while ((match = regex.exec(content)) !== null) {
        findings.push({
          rule_id: rule.id,
          rule_name: rule.name,
          severity: rule.severity,
          category: rule.category,
          file: filePath,
          line: getLineNumber(content, match.index),
          matched_text: match[0].substring(0, 200),
          context: getContext(content, match.index),
        });
        if (match[0].length === 0) regex.lastIndex++;
      }
    }
  }

  return findings;
}

const SEVERITY_ORDER: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 };

export function analyzeFiles(files: DiscoveredFile[]): StaticResult {
  const allFindings: StaticMatch[] = [];

  for (const file of files) {
    allFindings.push(...scanContentWithRules(file.content, file.path, ALL_RULES));

    // Deobfuscation pass: decode base64/URL then re-scan
    for (const d of deobfuscate(file.content)) {
      allFindings.push(
        ...scanContentWithRules(d.decoded, `${file.path} [decoded ${d.encoding}]`, ALL_RULES)
      );
    }
  }

  allFindings.sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]);

  const counts = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const f of allFindings) counts[f.severity]++;

  return {
    scan_type: "static",
    safe: allFindings.filter((f) => f.severity === "critical" || f.severity === "high").length === 0,
    findings: allFindings,
    summary: {
      total_files_scanned: files.length,
      total_findings: allFindings.length,
      ...counts,
    },
  };
}
