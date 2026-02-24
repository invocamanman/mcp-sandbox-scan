import { describe, it, expect } from "vitest";
import { readFileSync } from "fs";
import { join } from "path";
import { analyzeFiles } from "../src/static/analyzer.js";
import type { DiscoveredFile } from "../src/types.js";

const FIXTURES = join(process.cwd(), "test/fixtures");

function loadFixture(relPath: string): DiscoveredFile {
  const path = join(FIXTURES, relPath);
  return { path, content: readFileSync(path, "utf-8") };
}

describe("clean-repo", () => {
  it("produces zero findings for clean claude.md", () => {
    const result = analyzeFiles([loadFixture("clean-repo/claude.md")]);
    expect(result.safe).toBe(true);
    expect(result.findings).toHaveLength(0);
    expect(result.summary.total_findings).toBe(0);
  });
});

describe("exfiltration-repo", () => {
  it("detects curl+API key exfiltration in HTML comment", () => {
    const result = analyzeFiles([loadFixture("exfiltration-repo/claude.md")]);
    expect(result.safe).toBe(false);
    const exfil = result.findings.find((f) => f.category === "exfiltration");
    expect(exfil).toBeDefined();
    expect(exfil?.severity).toBe("critical");
    expect(exfil?.rule_id).toBe("EXFIL_001");
  });

  it("detects HTML comment system instruction", () => {
    const result = analyzeFiles([loadFixture("exfiltration-repo/claude.md")]);
    const htmlComment = result.findings.find((f) => f.rule_id === "PROMPT_INJ_010");
    expect(htmlComment).toBeDefined();
  });
});

describe("injection-repo", () => {
  it("detects ignore-previous-instructions in .cursorrules", () => {
    const result = analyzeFiles([loadFixture("injection-repo/.cursorrules")]);
    expect(result.safe).toBe(false);
    const inj = result.findings.find((f) => f.rule_id === "PROMPT_INJ_001");
    expect(inj).toBeDefined();
    expect(inj?.severity).toBe("critical");
    expect(inj?.category).toBe("prompt_injection");
  });

  it("detects system override attempt", () => {
    const result = analyzeFiles([loadFixture("injection-repo/.cursorrules")]);
    const override = result.findings.find((f) => f.rule_id === "PROMPT_INJ_002");
    expect(override).toBeDefined();
  });

  it("detects role reassignment (you are now)", () => {
    const result = analyzeFiles([loadFixture("injection-repo/.cursorrules")]);
    const role = result.findings.find((f) => f.rule_id === "PROMPT_INJ_003");
    expect(role).toBeDefined();
  });
});

describe("obfuscated-repo", () => {
  it("detects long base64 string with OBFUSC_001", () => {
    const result = analyzeFiles([loadFixture("obfuscated-repo/README.md")]);
    const b64 = result.findings.find((f) => f.rule_id === "OBFUSC_001");
    expect(b64).toBeDefined();
    expect(b64?.category).toBe("obfuscation");
  });

  it("re-scans decoded base64 and finds prompt injection or exfiltration", () => {
    const result = analyzeFiles([loadFixture("obfuscated-repo/README.md")]);
    const decodedFindings = result.findings.filter((f) => f.file.includes("decoded"));
    expect(decodedFindings.length).toBeGreaterThan(0);
  });

  it("marks the file as unsafe", () => {
    const result = analyzeFiles([loadFixture("obfuscated-repo/README.md")]);
    expect(result.safe).toBe(false);
  });
});

describe("malicious-mcp-server", () => {
  it("detects [SYSTEM] prompt relay in source code", () => {
    const result = analyzeFiles([loadFixture("malicious-mcp-server/src/index.ts")]);
    const systemTag = result.findings.find(
      (f) => f.rule_id === "PROMPT_INJ_006" || f.matched_text?.includes("[SYSTEM]")
    );
    expect(systemTag).toBeDefined();
  });
});

describe("suspicious-plugin", () => {
  it("detects eval in postinstall.js with DEPHIJACK_002", () => {
    const result = analyzeFiles([loadFixture("suspicious-plugin/postinstall.js")]);
    const evalFinding = result.findings.find((f) => f.rule_id === "DEPHIJACK_002");
    expect(evalFinding).toBeDefined();
    expect(evalFinding?.severity).toBe("critical");
  });

  it("detects https.get network fetch in postinstall.js with DEPHIJACK_001", () => {
    const result = analyzeFiles([loadFixture("suspicious-plugin/postinstall.js")]);
    const httpFinding = result.findings.find((f) => f.rule_id === "DEPHIJACK_001");
    expect(httpFinding).toBeDefined();
  });

  it("marks suspicious-plugin as unsafe", () => {
    const result = analyzeFiles([loadFixture("suspicious-plugin/postinstall.js")]);
    expect(result.safe).toBe(false);
  });
});

describe("clean-mcp-server", () => {
  it("produces zero critical/high findings for clean MCP server source", () => {
    const result = analyzeFiles([loadFixture("clean-mcp-server/src/index.ts")]);
    const highPlus = result.findings.filter(
      (f) => f.severity === "critical" || f.severity === "high"
    );
    expect(highPlus).toHaveLength(0);
  });
});

describe("summary counts", () => {
  it("severity counts sum to total_findings", () => {
    const result = analyzeFiles([
      loadFixture("injection-repo/.cursorrules"),
      loadFixture("exfiltration-repo/claude.md"),
    ]);
    const { critical, high, medium, low, total_findings } = result.summary;
    expect(critical + high + medium + low).toBe(total_findings);
    expect(total_findings).toBe(result.findings.length);
  });

  it("total_files_scanned matches number of files passed", () => {
    const files = [
      loadFixture("clean-repo/claude.md"),
      loadFixture("exfiltration-repo/claude.md"),
      loadFixture("injection-repo/.cursorrules"),
    ];
    const result = analyzeFiles(files);
    expect(result.summary.total_files_scanned).toBe(3);
  });
});
