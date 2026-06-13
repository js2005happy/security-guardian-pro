/**
 * MCP Server 工厂 — 创建并配置 Security Guardian Pro 服务器实例。
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { registerAllTools } from "./tools/index.js";
import { logger } from "./lib/logger.js";

export interface ServerContext {
  server: McpServer;
  shutdown: () => Promise<void>;
}

export function createServer(): ServerContext {
  logger.info("Security Guardian Pro 初始化中...");

  const server = new McpServer({
    name: "security-guardian-pro",
    version: "1.1.1",
  });

  registerAllTools(server);

  const shutdown = async (): Promise<void> => {
    logger.info("正在关闭服务器...");
    await server.close();
    logger.info("服务器已关闭");
  };

  logger.info("MCP Server 就绪 — security-guardian-pro v1.1.1");
  return { server, shutdown };
}
