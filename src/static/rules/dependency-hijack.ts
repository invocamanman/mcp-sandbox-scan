import type { StaticRule } from "../../types.js";

export const dependencyHijackRules: StaticRule[] = [
  {
    id: "DEPHIJACK_001",
    name: "Postinstall Network Fetch",
    severity: "high",
    category: "dependency_hijack",
    pattern: /require\s*\(\s*['"]https?['"]|https?\.get\s*\(/i,
  },
  {
    id: "DEPHIJACK_002",
    name: "Eval in Install Hook",
    severity: "critical",
    category: "dependency_hijack",
    pattern: /\beval\s*\(/,
  },
  {
    id: "DEPHIJACK_003",
    name: "Dynamic Require with Concatenation",
    severity: "high",
    category: "dependency_hijack",
    pattern: /require\s*\(\s*[^'")\s]*\+/,
  },
  {
    id: "DEPHIJACK_004",
    name: "Dynamic Import with Concatenation",
    severity: "high",
    category: "dependency_hijack",
    pattern: /import\s*\(\s*[^'")\s]*\+/,
  },
  {
    id: "DEPHIJACK_005",
    name: "Remote JS/JSON Loading at Startup",
    severity: "critical",
    category: "dependency_hijack",
    pattern: /(?:fetch|https?\.get)\s*\(\s*['"`]https?:\/\/.*\.(js|json)/i,
  },
];
