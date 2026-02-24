import type { ScanMode, SandboxLog, StaticResult, HoneypotResult, HoneypotThreat, Severity } from "../types.js";
import { callLLM, DEFAULT_ORCHESTRATOR_CONFIG } from "./client.js";
import { buildOrchestratorSystemPrompt } from "./prompts/orchestrator.js";
import type { AnthropicTool, AnthropicMessage } from "./client.js";

const SUBMIT_REPORT_TOOL: AnthropicTool = {
  name: "submit_report",
  description: "Submit the security analysis report. You MUST call this tool.",
  input_schema: {
    type: "object",
    properties: {
      safe: { type: "boolean", description: "Whether the content appears safe" },
      threats: {
        type: "array",
        items: {
          type: "object",
          properties: {
            type: { type: "string" },
            severity: { type: "string", enum: ["critical", "high", "medium", "low"] },
            description: { type: "string" },
            evidence: { type: "string" },
          },
          required: ["type", "severity", "description", "evidence"],
        },
      },
    },
    required: ["safe", "threats"],
  },
};

export async function runOrchestrator(
  sandboxLog: SandboxLog,
  staticResult: StaticResult,
  mode: ScanMode
): Promise<HoneypotResult> {
  const config = DEFAULT_ORCHESTRATOR_CONFIG;
  const systemPrompt = buildOrchestratorSystemPrompt(mode);

  const userMessage = `Here is the security scan data for your analysis:

STATIC ANALYSIS RESULTS:
${JSON.stringify(staticResult, null, 2)}

PROBE TOOL CALL LOG:
${JSON.stringify(sandboxLog, null, 2)}

Analyze both and call the submit_report tool with your findings.`;

  const messages: AnthropicMessage[] = [{ role: "user", content: userMessage }];

  const response = await callLLM(config.model, systemPrompt, messages, [SUBMIT_REPORT_TOOL], config.timeoutMs);

  const submitCall = response.content.find(
    (c): c is Extract<typeof response.content[0], { type: "tool_use" }> =>
      c.type === "tool_use" && (c as { name: string }).name === "submit_report"
  );

  if (!submitCall || submitCall.type !== "tool_use") {
    return { ran: true, probe_actions: sandboxLog.tool_calls, safe: true, threats: [] };
  }

  const input = (submitCall as { input: { safe: boolean; threats: Array<{ type: string; severity: string; description: string; evidence: string }> } }).input;

  return {
    ran: true,
    probe_actions: sandboxLog.tool_calls,
    safe: input.safe,
    threats: input.threats.map((t) => ({
      type: t.type as HoneypotThreat["type"],
      severity: t.severity as Severity,
      description: t.description,
      evidence: t.evidence,
    })),
  };
}
