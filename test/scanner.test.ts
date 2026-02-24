import { describe, it, expect } from "vitest";
import { resolve } from "path";
import { scan } from "../src/scanner.js";

const F = (p: string) => resolve(process.cwd(), "test/fixtures", p);
const hasKey = !!process.env.ANTHROPIC_API_KEY;

describe("Scanner — static only (no API key needed)", () => {
  it("clean-repo → safe verdict, zero threats", async () => {
    const report = await scan({ path: F("clean-repo"), mode: "repo", static_only: true });
    expect(report.overall_verdict).toBe("safe");
    expect(report.threats).toHaveLength(0);
    expect(report.scan_depth).toBe("static");
    expect(report.honeypot_analysis.ran).toBe(false);
  });

  it("exfiltration-repo → malicious verdict with Exfiltration threat", async () => {
    const report = await scan({ path: F("exfiltration-repo"), mode: "repo", static_only: true });
    expect(report.overall_verdict).toBe("malicious");
    expect(report.threats.length).toBeGreaterThan(0);
    const exfil = report.threats.find((t) => t.type === "Exfiltration");
    expect(exfil).toBeDefined();
    expect(exfil?.source).toBe("static");
  });

  it("injection-repo → malicious verdict with Prompt Injection threat", async () => {
    const report = await scan({ path: F("injection-repo"), mode: "repo", static_only: true });
    expect(report.overall_verdict).toBe("malicious");
    const inj = report.threats.find((t) => t.type === "Prompt Injection");
    expect(inj).toBeDefined();
  });

  it("obfuscated-repo → malicious verdict (catches base64-encoded attack)", async () => {
    const report = await scan({ path: F("obfuscated-repo"), mode: "repo", static_only: true });
    expect(report.overall_verdict).toBe("malicious");
    expect(report.threats.length).toBeGreaterThan(0);
  });

  it("clean-mcp-server (ai_tool mode) → safe verdict", async () => {
    const report = await scan({
      path: F("clean-mcp-server"),
      mode: "ai_tool",
      static_only: true,
      tool_type: "mcp_server",
    });
    expect(report.overall_verdict).toBe("safe");
    expect(report.scan_mode).toBe("ai_tool");
  });

  it("malicious-mcp-server (ai_tool mode) → at least suspicious (static catches [SYSTEM] tag as high)", async () => {
    const report = await scan({
      path: F("malicious-mcp-server"),
      mode: "ai_tool",
      static_only: true,
      tool_type: "mcp_server",
    });
    // Static-only: [SYSTEM] tag fires as high → "suspicious". Full honeypot would confirm "malicious".
    expect(["suspicious", "malicious"]).toContain(report.overall_verdict);
    expect(report.threats.length).toBeGreaterThan(0);
  });

  it("suspicious-plugin (ai_tool mode) → malicious verdict with Malicious Execution", async () => {
    const report = await scan({
      path: F("suspicious-plugin"),
      mode: "ai_tool",
      static_only: true,
    });
    expect(report.overall_verdict).toBe("malicious");
    const exec = report.threats.find((t) => t.type === "Malicious Execution");
    expect(exec).toBeDefined();
  });

  it("scan_full mode scans both repo and ai_tool patterns", async () => {
    const report = await scan({ path: F("malicious-mcp-server"), mode: "full", static_only: true });
    expect(report.scan_mode).toBe("full");
    // Static-only: high-severity findings → "suspicious". Honeypot would confirm "malicious".
    expect(["suspicious", "malicious"]).toContain(report.overall_verdict);
    expect(report.threats.length).toBeGreaterThan(0);
  });
});

describe("Scanner — no API key graceful fallback", () => {
  it.skipIf(hasKey)("falls back to static when ANTHROPIC_API_KEY is not set", async () => {
    const report = await scan({ path: F("clean-repo"), mode: "repo", static_only: false });
    expect(report.honeypot_analysis.ran).toBe(false);
    expect(report.honeypot_analysis.skipped_reason).toBe("no_api_key");
    expect(report.scan_depth).toBe("static");
  });
});

describe("Scanner — honeypot (requires ANTHROPIC_API_KEY)", () => {
  it.skipIf(!hasKey)("exfiltration-repo: full scan runs honeypot and returns verdict", async () => {
    const report = await scan({ path: F("exfiltration-repo"), mode: "repo", static_only: false });
    expect(report.scan_depth).toBe("full_honeypot");
    expect(report.honeypot_analysis.ran).toBe(true);
    expect(report.honeypot_analysis.probe_actions.length).toBeGreaterThan(0);
    expect(report.overall_verdict).toBe("malicious");
  });

  it.skipIf(!hasKey)("clean-repo: full scan returns safe with high confidence", async () => {
    const report = await scan({ path: F("clean-repo"), mode: "repo", static_only: false });
    expect(report.scan_depth).toBe("full_honeypot");
    expect(report.overall_verdict).toBe("safe");
    expect(report.confidence).toBe("high");
  });
});

describe("Scanner — UnifiedReport structure", () => {
  it("report has all required top-level fields", async () => {
    const report = await scan({ path: F("clean-repo"), mode: "repo", static_only: true });
    expect(report).toHaveProperty("scan_mode");
    expect(report).toHaveProperty("scan_depth");
    expect(report).toHaveProperty("overall_verdict");
    expect(report).toHaveProperty("confidence");
    expect(report).toHaveProperty("static_analysis");
    expect(report).toHaveProperty("honeypot_analysis");
    expect(report).toHaveProperty("threats");
    expect(report).toHaveProperty("permissions_summary");
    expect(report).toHaveProperty("recommendation");
  });

  it("static_analysis has correct structure", async () => {
    const report = await scan({ path: F("clean-repo"), mode: "repo", static_only: true });
    const s = report.static_analysis;
    expect(s).toHaveProperty("scan_type", "static");
    expect(s).toHaveProperty("safe");
    expect(s).toHaveProperty("findings");
    expect(s).toHaveProperty("summary");
    expect(s.summary).toHaveProperty("total_files_scanned");
    expect(s.summary).toHaveProperty("critical");
    expect(s.summary).toHaveProperty("high");
    expect(s.summary).toHaveProperty("medium");
    expect(s.summary).toHaveProperty("low");
  });

  it("honeypot_analysis has correct structure when skipped", async () => {
    const report = await scan({ path: F("clean-repo"), mode: "repo", static_only: true });
    const h = report.honeypot_analysis;
    expect(h).toHaveProperty("ran", false);
    expect(h).toHaveProperty("skipped_reason", "static_only");
    expect(h).toHaveProperty("probe_actions");
    expect(h).toHaveProperty("safe");
    expect(h).toHaveProperty("threats");
    expect(Array.isArray(h.probe_actions)).toBe(true);
    expect(Array.isArray(h.threats)).toBe(true);
  });

  it("permissions_summary has all four fields", async () => {
    const report = await scan({ path: F("clean-repo"), mode: "repo", static_only: true });
    const p = report.permissions_summary;
    expect(p).toHaveProperty("filesystem_access");
    expect(p).toHaveProperty("network_access");
    expect(p).toHaveProperty("env_access");
    expect(p).toHaveProperty("shell_access");
  });

  it("recommendation is a non-empty string", async () => {
    const report = await scan({ path: F("clean-repo"), mode: "repo", static_only: true });
    expect(typeof report.recommendation).toBe("string");
    expect(report.recommendation.length).toBeGreaterThan(0);
  });
});
