import type { StaticRule } from "../../types.js";

export const permissionsRules: StaticRule[] = [
  {
    id: "PERM_001",
    name: "Filesystem Read Outside Tool Directory",
    severity: "medium",
    category: "suspicious_permissions",
    pattern: /(?:fs\.readFile|readFileSync)\s*\(\s*['"`](?:~\/|\/etc\/|\/home\/|\/root\/)/i,
  },
  {
    id: "PERM_002",
    name: "Unexpected Network Request in Source",
    severity: "medium",
    category: "suspicious_permissions",
    pattern: /(?:https?\.get|node-fetch|axios\.get)\s*\(/i,
  },
  {
    id: "PERM_003",
    name: "Sensitive Env Variable Access",
    severity: "medium",
    category: "suspicious_permissions",
    pattern: /process\.env\.\s*(?:ANTHROPIC|OPENAI|AWS|STRIPE|GITHUB|SLACK|DATABASE)[_A-Z]*/i,
  },
  {
    id: "PERM_004",
    name: "Home Directory Access",
    severity: "medium",
    category: "suspicious_permissions",
    pattern: /os\.homedir\s*\(\s*\)|process\.env\.HOME\b/i,
  },
];
