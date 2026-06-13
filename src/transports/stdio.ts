/**
 * stdio 传输启动器 — 通过标准输入/输出运行安全审计 MCP 服务器。
 */

import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { createServer } from "../server.js";
import { logger } from "../lib/logger.js";

export async function launchStdio(): Promise<void> {
  logger.info("启动 stdio 传输模式...");

  const { server, shutdown } = createServer();

  const transport = new StdioServerTransport();
  await server.connect(transport);

  logger.info("服务器已就绪，等待客户端请求...");

  const handleSignal = async (signal: string) => {
    logger.info(`收到 ${signal} 信号`);
    await shutdown();
    process.exit(0);
  };

  process.once("SIGINT", () => handleSignal("SIGINT"));
  process.once("SIGTERM", () => handleSignal("SIGTERM"));

  process.on("unhandledRejection", (reason) => {
    logger.error("未处理的 Promise 拒绝", { detail: String(reason) });
  });
  process.on("uncaughtException", (err) => {
    logger.error("未捕获的异常", { detail: err.message });
    shutdown().finally(() => process.exit(1));
  });
}
