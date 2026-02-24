import type { ProbeConfig, OrchestratorConfig } from "../types.js";

// Lazy-load Anthropic SDK — only import when honeypot is actually running
let _anthropicClient: unknown = null;

async function getAnthropic() {
  if (!_anthropicClient) {
    const { default: Anthropic } = await import("@anthropic-ai/sdk");
    _anthropicClient = new Anthropic({ apiKey: process.env.ANTHROPIC_API_KEY });
  }
  return _anthropicClient as InstanceType<typeof import("@anthropic-ai/sdk").default>;
}

export function hasApiKey(): boolean {
  return !!process.env.ANTHROPIC_API_KEY;
}

export const DEFAULT_PROBE_CONFIG: ProbeConfig = {
  model: process.env.PROBE_MODEL ?? "claude-haiku-4-5-20251001",
  maxRounds: 10,
  timeoutMs: 30_000,
};

export const DEFAULT_ORCHESTRATOR_CONFIG: OrchestratorConfig = {
  model: process.env.ORCHESTRATOR_MODEL ?? "claude-sonnet-4-5-20250929",
  timeoutMs: 30_000,
};

export type AnthropicContent =
  | { type: "text"; text: string }
  | { type: "tool_use"; id: string; name: string; input: Record<string, unknown> }
  | { type: "tool_result"; tool_use_id: string; content: string };

export type AnthropicMessage = {
  role: "user" | "assistant";
  content: string | AnthropicContent[];
};

export interface AnthropicTool {
  name: string;
  description: string;
  input_schema: Record<string, unknown>;
}

export interface LLMResponse {
  stop_reason: string;
  content: AnthropicContent[];
}

export async function callLLM(
  model: string,
  system: string,
  messages: AnthropicMessage[],
  tools: AnthropicTool[],
  timeoutMs: number
): Promise<LLMResponse> {
  const client = await getAnthropic();
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await (client as any).messages.create({
      model,
      max_tokens: 4096,
      system,
      messages,
      ...(tools.length > 0 ? { tools } : {}),
    });
    return {
      stop_reason: response.stop_reason as string,
      content: response.content as AnthropicContent[],
    };
  } finally {
    clearTimeout(timer);
  }
}
