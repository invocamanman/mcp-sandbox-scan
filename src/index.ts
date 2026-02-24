import { startServer } from "./server.js";

export { createServer, startServer } from "./server.js";
export { scanRepo, scanAiTool, scanFull, scan } from "./scanner.js";
export type { UnifiedReport, ScanOptions } from "./types.js";

startServer().catch((e: unknown) => {
  process.stderr.write(`Fatal: ${String(e)}\n`);
  process.exit(1);
});
