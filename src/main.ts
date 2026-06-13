#!/usr/bin/env node
/**
 * Security Guardian Pro — 企业级全栈安全审计 MCP Server
 *
 * 用法:
 *   node dist/main.js         # stdio 模式（默认，用于 Claude Desktop 集成）
 *   npx security-guardian-pro # 通过 npm 包名直接启动
 */

import { logger } from "./lib/logger.js";

async function main(): Promise<void> {
  const transport = process.argv[2] || "stdio";

  switch (transport) {
    case "stdio": {
      const { launchStdio } = await import("./transports/stdio.js");
      await launchStdio();
      break;
    }
    default:
      logger.error(`未知传输模式: ${transport}`);
      process.stderr.write("用法: security-guardian-pro [stdio]\n");
      process.exit(1);
  }
}

main().catch((err) => {
  logger.error("启动失败", { detail: err instanceof Error ? err.message : String(err) });
  process.exit(1);
});
