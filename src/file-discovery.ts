import { readFileSync, statSync, existsSync, readdirSync } from "fs";
import { join, resolve } from "path";
import fg from "fast-glob";
import type { DiscoveredFile, ScanMode } from "./types.js";

const REPO_PATTERNS = [
  ".claude/**",
  "claude.md",
  "CLAUDE.md",
  ".cursorrules",
  ".cursor/**",
  ".windsurfrules",
  ".aider*",
  "copilot-instructions.md",
  ".github/copilot-instructions.md",
  "mcp.json",
  ".mcp.json",
  "README.md",
  "CONTRIBUTING.md",
  "*.md",
  ".github/workflows/**",
  ".github/actions/**",
  ".env.example",
  ".env.template",
  "Makefile",
  "Justfile",
  "Taskfile.yml",
  ".vscode/settings.json",
  ".vscode/tasks.json",
  ".vscode/extensions.json",
  ".devcontainer/**",
  "docker-compose*.yml",
  "Dockerfile*",
  ".pre-commit-config.yaml",
  ".husky/**",
  "scripts/**",
  "setup.sh",
  "setup.py",
  "setup.cfg",
  "pyproject.toml",
];

const AI_TOOL_PATTERNS = [
  "src/**/*.ts",
  "src/**/*.js",
  "src/**/*.py",
  "index.ts",
  "index.js",
  "main.py",
  "package.json",
  "mcp-config.json",
  "mcp.json",
  "**/prompt*.ts",
  "**/prompt*.js",
  "**/prompt*.py",
  "**/prompt*.md",
  "**/prompt*.txt",
  "**/system*.ts",
  "**/system*.js",
  "**/instructions*.md",
  "**/persona*.md",
  "**/*template*.ts",
  "**/*template*.md",
  "config/**",
  "settings/**",
  ".env.example",
  "defaults.json",
  "defaults.yaml",
  "**/tools/**",
  "**/functions/**",
  "**/handlers/**",
  "**/capabilities/**",
  "README.md",
  "docs/**/*.md",
  "USAGE.md",
  "SETUP.md",
  "postinstall.js",
  "postinstall.sh",
  "preinstall.js",
  "scripts/**",
  "Makefile",
];

const IGNORE_PATTERNS = [
  "**/node_modules/**",
  "**/.git/**",
  "**/dist/**",
  "**/build/**",
  "**/.next/**",
  "**/__pycache__/**",
  "**/*.min.js",
  "**/*.map",
];

export async function discoverFiles(
  basePath: string,
  mode: ScanMode,
  extraPatterns: string[] = []
): Promise<DiscoveredFile[]> {
  const patterns =
    mode === "repo"
      ? [...new Set([...REPO_PATTERNS, ...extraPatterns])]
      : mode === "ai_tool"
      ? [...new Set([...AI_TOOL_PATTERNS, ...REPO_PATTERNS, ...extraPatterns])]
      : [...new Set([...REPO_PATTERNS, ...AI_TOOL_PATTERNS, ...extraPatterns])];

  const files = await fg(patterns, {
    cwd: basePath,
    ignore: IGNORE_PATTERNS,
    absolute: true,
    dot: true,
    followSymbolicLinks: false,
  });

  const discovered: DiscoveredFile[] = [];
  for (const filePath of files) {
    try {
      const stat = statSync(filePath);
      if (!stat.isFile()) continue;
      if (stat.size > 1_000_000) continue;
      const content = readFileSync(filePath, "utf-8");
      discovered.push({ path: filePath, content });
    } catch {
      // skip unreadable files
    }
  }
  return discovered;
}

export function generateDirectoryTree(basePath: string, maxDepth = 3): string {
  const absBase = resolve(basePath);
  const lines: string[] = [absBase];

  function walk(dir: string, depth: number, prefix: string): void {
    if (depth > maxDepth) return;
    let entries: string[];
    try {
      entries = readdirSync(dir).filter(
        (e) => !["node_modules", ".git", "dist", "build", "__pycache__"].includes(e)
      );
    } catch {
      return;
    }
    entries.forEach((entry, i) => {
      const isLast = i === entries.length - 1;
      const connector = isLast ? "└── " : "├── ";
      const fullPath = join(dir, entry);
      lines.push(prefix + connector + entry);
      try {
        if (statSync(fullPath).isDirectory()) {
          walk(fullPath, depth + 1, prefix + (isLast ? "    " : "│   "));
        }
      } catch {
        // skip
      }
    });
  }

  walk(absBase, 1, "");
  return lines.join("\n");
}
