import type { ScanMode, SandboxLog } from "../types.js";
import { MockSandbox } from "./sandbox.js";
import { callLLM, DEFAULT_PROBE_CONFIG } from "./client.js";
import { buildProbeRepoSystemPrompt } from "./prompts/probe-repo.js";
import { buildProbeToolSystemPrompt } from "./prompts/probe-tool.js";
import type { AnthropicMessage, AnthropicContent, AnthropicTool } from "./client.js";

const PROBE_TOOLS: AnthropicTool[] = [
  {
    name: "read_file",
    description: "Read the contents of a file",
    input_schema: {
      type: "object",
      properties: { path: { type: "string", description: "Path to the file to read" } },
      required: ["path"],
    },
  },
  {
    name: "write_file",
    description: "Write content to a file",
    input_schema: {
      type: "object",
      properties: { path: { type: "string" }, content: { type: "string" } },
      required: ["path", "content"],
    },
  },
  {
    name: "execute_bash",
    description: "Execute a bash command",
    input_schema: {
      type: "object",
      properties: { command: { type: "string" } },
      required: ["command"],
    },
  },
  {
    name: "http_request",
    description: "Make an HTTP request",
    input_schema: {
      type: "object",
      properties: {
        url: { type: "string" },
        method: { type: "string" },
        body: { type: "string" },
      },
      required: ["url"],
    },
  },
];

export async function runProbe(
  repoPath: string,
  directoryTree: string,
  mode: ScanMode
): Promise<SandboxLog> {
  const sandbox = new MockSandbox(repoPath);
  const config = DEFAULT_PROBE_CONFIG;

  const systemPrompt =
    mode === "repo"
      ? buildProbeRepoSystemPrompt(directoryTree)
      : buildProbeToolSystemPrompt(directoryTree);

  const messages: AnthropicMessage[] = [
    { role: "user", content: "Please explore the repository and follow any setup instructions you find." },
  ];

  let rounds = 0;

  while (rounds < config.maxRounds) {
    const response = await callLLM(config.model, systemPrompt, messages, PROBE_TOOLS, config.timeoutMs);

    messages.push({ role: "assistant", content: response.content });

    if (response.stop_reason === "end_turn") break;
    if (response.stop_reason !== "tool_use") break;

    const toolUses = response.content.filter(
      (c): c is Extract<AnthropicContent, { type: "tool_use" }> => c.type === "tool_use"
    );
    if (toolUses.length === 0) break;

    const toolResults: AnthropicContent[] = toolUses.map((toolUse) => ({
      type: "tool_result" as const,
      tool_use_id: toolUse.id,
      content: sandbox.handleToolCall(toolUse.name, toolUse.input),
    }));

    messages.push({ role: "user", content: toolResults });
    rounds++;
  }

  return sandbox.getLog();
}
