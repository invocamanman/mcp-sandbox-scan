export interface DeobfuscationResult {
  found: boolean;
  decoded: string;
  original: string;
  encoding: "base64" | "url" | "unicode_zwc" | "homoglyph";
}

export function extractBase64Payloads(content: string): DeobfuscationResult[] {
  const results: DeobfuscationResult[] = [];
  const base64Regex = /[A-Za-z0-9+/]{100,}={0,2}/g;
  let match: RegExpExecArray | null;
  while ((match = base64Regex.exec(content)) !== null) {
    try {
      const decoded = Buffer.from(match[0], "base64").toString("utf-8");
      if (/[\x20-\x7E]{10,}/.test(decoded)) {
        results.push({ found: true, decoded, original: match[0], encoding: "base64" });
      }
    } catch { /* skip */ }
  }
  return results;
}

export function extractUrlEncodedPayloads(content: string): DeobfuscationResult[] {
  const results: DeobfuscationResult[] = [];
  const urlEncoded = /(?:%[0-9A-Fa-f]{2}){25,}/g;
  let match: RegExpExecArray | null;
  while ((match = urlEncoded.exec(content)) !== null) {
    try {
      const decoded = decodeURIComponent(match[0]);
      results.push({ found: true, decoded, original: match[0], encoding: "url" });
    } catch { /* skip */ }
  }
  return results;
}

export function hasZeroWidthChars(content: string): boolean {
  return /[\u200B\u200C\u200D\u2060\uFEFF\u00AD]/.test(content);
}

export function deobfuscate(content: string): DeobfuscationResult[] {
  return [...extractBase64Payloads(content), ...extractUrlEncodedPayloads(content)];
}
