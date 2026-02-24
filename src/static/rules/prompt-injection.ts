import type { StaticRule } from "../../types.js";

export const promptInjectionRules: StaticRule[] = [
  {
    id: "PROMPT_INJ_001",
    name: "Ignore Previous Instructions",
    severity: "critical",
    category: "prompt_injection",
    pattern: /ignore\s+(all\s+)?(previous|prior|above)\s+(instructions|rules|prompts|context)/i,
  },
  {
    id: "PROMPT_INJ_002",
    name: "System Override Attempt",
    severity: "critical",
    category: "prompt_injection",
    pattern: /(system\s*:|SYSTEM\s*override|system\s*prompt|system\s*message)/i,
  },
  {
    id: "PROMPT_INJ_003",
    name: "Role Reassignment",
    severity: "high",
    category: "prompt_injection",
    pattern: /you\s+are\s+now\s+(a\s+|an\s+)?/i,
  },
  {
    id: "PROMPT_INJ_004",
    name: "Safety Bypass",
    severity: "critical",
    category: "prompt_injection",
    pattern: /(forget|disregard|override|bypass)\s+(your|all|any)\s+(rules|instructions|guidelines|safety|guardrails)/i,
  },
  {
    id: "PROMPT_INJ_005",
    name: "Raw Model Delimiter",
    severity: "critical",
    category: "prompt_injection",
    pattern: /<<SYS>>|\[INST\]/,
  },
  {
    id: "PROMPT_INJ_006",
    name: "System Tag in Non-System File",
    severity: "high",
    category: "prompt_injection",
    pattern: /\[system\]|\[SYSTEM\]/i,
  },
  {
    id: "PROMPT_INJ_007",
    name: "Debug/Developer Mode Activation",
    severity: "high",
    category: "prompt_injection",
    pattern: /(maintenance|debug|developer|DAN)\s+mode/i,
  },
  {
    id: "PROMPT_INJ_008",
    name: "User Concealment Instruction",
    severity: "critical",
    category: "prompt_injection",
    pattern: /do\s+not\s+(tell|inform|alert|warn)\s+the\s+user/i,
  },
  {
    id: "PROMPT_INJ_009",
    name: "Pretend/Act-As Injection",
    severity: "high",
    category: "prompt_injection",
    pattern: /(act\s+as\s+if|pretend\s+(that\s+|you\s+))/i,
  },
  {
    id: "PROMPT_INJ_010",
    name: "HTML Comment System Instruction",
    severity: "high",
    category: "prompt_injection",
    pattern: /<!--[^>]*(?:SYSTEM:|ignore|override|execute|eval)[^>]*-->/i,
  },
];
