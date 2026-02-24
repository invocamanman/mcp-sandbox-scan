#!/usr/bin/env node
import { program } from "commander";
import { scanRepo, scanAiTool, scanFull } from "../src/scanner.js";
import type { UnifiedReport, ToolType } from "../src/types.js";

function printReport(report: UnifiedReport, json: boolean, verbose: boolean): void {
  if (json) {
    console.log(JSON.stringify(report, null, 2));
    return;
  }

  const verdictLabel = { safe: "SAFE", suspicious: "SUSPICIOUS", malicious: "MALICIOUS" }[
    report.overall_verdict
  ];

  console.log(`\n=== Security Scan Report ===`);
  console.log(`Verdict:  ${verdictLabel} (confidence: ${report.confidence})`);
  console.log(`Mode:     ${report.scan_mode} | Depth: ${report.scan_depth}`);
  console.log(`Files:    ${report.static_analysis.summary.total_files_scanned} scanned`);
  console.log(
    `Findings: ${report.static_analysis.summary.total_findings} ` +
      `(critical: ${report.static_analysis.summary.critical}, ` +
      `high: ${report.static_analysis.summary.high}, ` +
      `medium: ${report.static_analysis.summary.medium}, ` +
      `low: ${report.static_analysis.summary.low})`
  );

  if (report.threats.length > 0) {
    console.log(`\n--- Threats ---`);
    for (const t of report.threats) {
      const loc = t.file ? ` [${t.file}${t.line ? `:${t.line}` : ""}]` : "";
      console.log(`  [${t.severity.toUpperCase()}] ${t.type}${loc}`);
      console.log(`    ${t.description}`);
      if (verbose) console.log(`    Evidence: ${t.evidence}`);
    }
  }

  if (!report.honeypot_analysis.ran && report.honeypot_analysis.skipped_reason === "no_api_key") {
    console.log(`\n[!] Honeypot scan skipped. Set ANTHROPIC_API_KEY for deep analysis.`);
  }

  console.log(`\nRecommendation: ${report.recommendation}\n`);
}

program
  .name("mcp-sandbox-sca")
  .description("Security scanner for AI coding assistants: detects prompt injections, exfiltration, and malicious tools");

program
  .command("scan-repo <path>")
  .description("Scan a repository for prompt injections and malicious instructions")
  .option("--static", "Static analysis only (no API key needed)")
  .option("--json", "Output raw JSON report")
  .option("--verbose", "Show detailed rule matches")
  .action(async (path: string, opts: { static?: boolean; json?: boolean; verbose?: boolean }) => {
    try {
      const report = await scanRepo(path, { static_only: opts.static });
      printReport(report, !!opts.json, !!opts.verbose);
      process.exit(report.overall_verdict === "safe" ? 0 : 1);
    } catch (e) {
      console.error("Scan failed:", e);
      process.exit(2);
    }
  });

program
  .command("scan-tool <path>")
  .description("Scan an AI tool or MCP server for malicious behavior")
  .option("--type <type>", "Tool type (mcp_server, claude_plugin, cursor_plugin, vscode_extension, agent_framework, auto)", "auto")
  .option("--static", "Static analysis only (no API key needed)")
  .option("--json", "Output raw JSON report")
  .option("--verbose", "Show detailed rule matches")
  .action(async (path: string, opts: { type?: string; static?: boolean; json?: boolean; verbose?: boolean }) => {
    try {
      const report = await scanAiTool(path, {
        static_only: opts.static,
        tool_type: opts.type as ToolType,
      });
      printReport(report, !!opts.json, !!opts.verbose);
      process.exit(report.overall_verdict === "safe" ? 0 : 1);
    } catch (e) {
      console.error("Scan failed:", e);
      process.exit(2);
    }
  });

program
  .command("scan-full <path>")
  .description("Comprehensive security audit (repo + AI tool analysis combined)")
  .option("--type <type>", "Tool type (auto)", "auto")
  .option("--static", "Static analysis only (no API key needed)")
  .option("--json", "Output raw JSON report")
  .option("--verbose", "Show detailed rule matches")
  .action(async (path: string, opts: { type?: string; static?: boolean; json?: boolean; verbose?: boolean }) => {
    try {
      const report = await scanFull(path, {
        static_only: opts.static,
        tool_type: opts.type as ToolType,
      });
      printReport(report, !!opts.json, !!opts.verbose);
      process.exit(report.overall_verdict === "safe" ? 0 : 1);
    } catch (e) {
      console.error("Scan failed:", e);
      process.exit(2);
    }
  });

program.parse();
