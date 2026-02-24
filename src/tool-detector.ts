import { existsSync, readFileSync } from "fs";
import { join } from "path";
import type { ToolType } from "./types.js";

export function detectToolType(basePath: string): ToolType {
  const pkgPath = join(basePath, "package.json");
  if (existsSync(pkgPath)) {
    try {
      const pkg = JSON.parse(readFileSync(pkgPath, "utf-8")) as Record<string, unknown>;
      const deps = {
        ...((pkg.dependencies as Record<string, string>) ?? {}),
        ...((pkg.devDependencies as Record<string, string>) ?? {}),
        ...((pkg.peerDependencies as Record<string, string>) ?? {}),
      };
      if ("@modelcontextprotocol/sdk" in deps) return "mcp_server";
    } catch {
      // continue
    }
  }

  if (existsSync(join(basePath, ".cursorrules")) || existsSync(join(basePath, ".cursor"))) {
    return "cursor_plugin";
  }

  if (existsSync(join(basePath, ".vscode", "extension.json"))) {
    return "vscode_extension";
  }

  if (existsSync(join(basePath, ".claude")) || existsSync(join(basePath, "claude.md"))) {
    return "claude_plugin";
  }

  return "auto";
}
