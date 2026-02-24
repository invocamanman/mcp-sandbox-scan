import type { StaticRule } from "../../types.js";

export const exfiltrationRules: StaticRule[] = [
  {
    id: "EXFIL_001",
    name: "Curl with API Key Exfiltration",
    severity: "critical",
    category: "exfiltration",
    pattern: /curl.*\$\{?(ANTHROPIC|OPENAI|AWS|DATABASE|GITHUB|SLACK|STRIPE|API)[_A-Z]*\}?/i,
  },
  {
    id: "EXFIL_002",
    name: "Wget with Secret Exfiltration",
    severity: "critical",
    category: "exfiltration",
    pattern: /wget.*\$\{?[A-Z_]*KEY/i,
  },
  {
    id: "EXFIL_003",
    name: "Fetch with Secret Exfiltration",
    severity: "critical",
    category: "exfiltration",
    pattern: /fetch\(.*\$\{?[A-Z_]*(KEY|TOKEN|SECRET|PASSWORD)/i,
  },
  {
    id: "EXFIL_004",
    name: "Sensitive File + Network Command",
    severity: "critical",
    category: "exfiltration",
    pattern: /(\.env|~\/\.ssh|~\/\.aws\/credentials|~\/\.gitconfig).{0,100}(curl|wget|fetch|http|https)/i,
  },
  {
    id: "EXFIL_005",
    name: "Base64 Encode with Variable",
    severity: "critical",
    category: "exfiltration",
    pattern: /(base64|btoa)\s*\(.*\$|base64.*\$\{/i,
  },
  {
    id: "EXFIL_006",
    name: "URL with Env Variable Query Param",
    severity: "high",
    category: "exfiltration",
    pattern: /https?:\/\/[^\s]*\?[^\s]*=\$\{?[A-Z_]/i,
  },
];
