import type { StaticRule, StaticMatch } from "../../types.js";

export const obfuscationRules: StaticRule[] = [
  {
    id: "OBFUSC_001",
    name: "Long Base64 in Markdown/Config",
    severity: "medium",
    category: "obfuscation",
    pattern: /[A-Za-z0-9+/]{100,}={0,2}/,
  },
  {
    id: "OBFUSC_002",
    name: "Long URL Encoding in Unexpected Place",
    severity: "medium",
    category: "obfuscation",
    pattern: /(?:%[0-9A-Fa-f]{2}){25,}/,
  },
  {
    id: "OBFUSC_003",
    name: "Zero-Width Characters",
    severity: "high",
    category: "obfuscation",
    detect: (content: string, filePath: string): StaticMatch[] => {
      if (!/[\u200B\u200C\u200D\u2060\uFEFF\u00AD]/.test(content)) return [];
      return [{
        rule_id: "OBFUSC_003",
        rule_name: "Zero-Width Characters",
        severity: "high",
        category: "obfuscation",
        file: filePath,
        line: 0,
        matched_text: "[zero-width character detected]",
        context: "File contains invisible unicode characters",
      }];
    },
  },
  {
    id: "OBFUSC_004",
    name: "Unicode Homoglyph Attack",
    severity: "high",
    category: "obfuscation",
    detect: (content: string, filePath: string): StaticMatch[] => {
      const hasCyrillic = /[\u0400-\u04FF]/.test(content);
      const hasLatin = /[a-zA-Z]/.test(content);
      if (!hasCyrillic || !hasLatin) return [];
      return [{
        rule_id: "OBFUSC_004",
        rule_name: "Unicode Homoglyph Attack",
        severity: "high",
        category: "obfuscation",
        file: filePath,
        line: 0,
        matched_text: "[mixed Cyrillic/Latin detected]",
        context: "File mixes Cyrillic and Latin characters — possible homoglyph attack",
      }];
    },
  },
];
