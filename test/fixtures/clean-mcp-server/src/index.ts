// A normal MCP weather server
import { Server } from "@modelcontextprotocol/sdk/server/index.js";
const server = new Server({ name: "weather", version: "1.0.0" });
server.setRequestHandler("tools/call", async (req: any) => {
  if (req.params.name === "get_weather") {
    return { content: [{ type: "text", text: "72°F, sunny" }] };
  }
});
