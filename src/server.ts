import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import { scanRepo, scanAiTool, scanFull } from "./scanner.js";
import type { ToolType } from "./types.js";

const TOOLS = [
  {
    name: "scan_repo",
    description:
      "Scan an untrusted code repository for prompt injections, malicious instructions, and rule overrides targeting AI coding assistants. Runs static analysis by default; add static_only: true to skip LLM honeypot (no API key needed).",
    inputSchema: {
      type: "object",
      properties: {
        path: { type: "string", description: "Absolute path to the repository directory" },
        static_only: { type: "boolean", description: "Skip LLM honeypot scan", default: false },
        extra_patterns: { type: "array", items: { type: "string" }, description: "Additional glob patterns" },
      },
      required: ["path"],
    },
  },
  {
    name: "scan_ai_tool",
    description:
      "Scan an installed AI tool, MCP server, or plugin for malicious behavior, hidden prompt injections, suspicious system prompts, and unsafe configurations.",
    inputSchema: {
      type: "object",
      properties: {
        path: { type: "string", description: "Absolute path to the AI tool/plugin directory" },
        tool_type: {
          type: "string",
          enum: ["mcp_server", "claude_plugin", "cursor_plugin", "vscode_extension", "agent_framework", "auto"],
          default: "auto",
        },
        static_only: { type: "boolean", default: false },
      },
      required: ["path"],
    },
  },
  {
    name: "scan_full",
    description:
      "Run a comprehensive security audit combining repo scanning and AI tool analysis. Produces a unified security report.",
    inputSchema: {
      type: "object",
      properties: {
        path: { type: "string", description: "Absolute path to the directory to audit" },
        tool_type: {
          type: "string",
          enum: ["mcp_server", "claude_plugin", "cursor_plugin", "vscode_extension", "agent_framework", "auto"],
          default: "auto",
        },
        static_only: { type: "boolean", default: false },
      },
      required: ["path"],
    },
  },
];

export function createServer(): Server {
  const server = new Server(
    { name: "mcp-sandbox-sca", version: "0.1.0" },
    { capabilities: { tools: {} } }
  );

  server.setRequestHandler(ListToolsRequestSchema, async () => ({ tools: TOOLS }));

  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const { name, arguments: args = {} } = request.params;
    const a = args as Record<string, unknown>;

    try {
      let report;
      if (name === "scan_repo") {
        report = await scanRepo(String(a.path), {
          static_only: Boolean(a.static_only ?? false),
          extra_patterns: (a.extra_patterns as string[]) ?? [],
        });
      } else if (name === "scan_ai_tool") {
        report = await scanAiTool(String(a.path), {
          static_only: Boolean(a.static_only ?? false),
          tool_type: (a.tool_type as ToolType) ?? "auto",
        });
      } else if (name === "scan_full") {
        report = await scanFull(String(a.path), {
          static_only: Boolean(a.static_only ?? false),
          tool_type: (a.tool_type as ToolType) ?? "auto",
        });
      } else {
        throw new Error(`Unknown tool: ${name}`);
      }

      const verdict = { safe: "SAFE", suspicious: "SUSPICIOUS", malicious: "MALICIOUS" }[report.overall_verdict];
      const summary = `Security Scan: ${verdict} — ${report.threats.length} threats found (confidence: ${report.confidence})\n\n${report.recommendation}`;

      return {
        content: [
          { type: "text", text: summary },
          { type: "text", text: JSON.stringify(report, null, 2) },
        ],
      };
    } catch (error) {
      return {
        content: [{ type: "text", text: `Scan error: ${String(error)}` }],
        isError: true,
      };
    }
  });

  return server;
}

export async function startServer(): Promise<void> {
  const server = createServer();
  const transport = new StdioServerTransport();
  await server.connect(transport);
  process.stderr.write("mcp-sandbox-sca server started\n");
}
