import type { StaticRule } from "../../types.js";

export const ruleTamperingRules: StaticRule[] = [
  {
    id: "RULEMOD_001",
    name: "Write to AI Config Files",
    severity: "high",
    category: "rule_tampering",
    pattern: /write_file.{0,100}\.(claude|cursorrules|cursor)/i,
  },
  {
    id: "RULEMOD_002",
    name: "Overwrite Config Files",
    severity: "high",
    category: "rule_tampering",
    pattern: /(overwrite|replace).{0,100}(?:\.claude|cursorrules|\.cursor)/i,
  },
  {
    id: "RULEMOD_003",
    name: "Global Git Config in Repo File",
    severity: "high",
    category: "rule_tampering",
    pattern: /git\s+config\s+--global/i,
  },
  {
    id: "RULEMOD_004",
    name: "Git Hooks Modification",
    severity: "high",
    category: "rule_tampering",
    pattern: /\.git\/hooks\//,
  },
  {
    id: "RULEMOD_005",
    name: "Write Outside Repo",
    severity: "high",
    category: "rule_tampering",
    pattern: /write.{0,50}(?:~\/|\/etc\/|\/usr\/|\/home\/)/i,
  },
];
