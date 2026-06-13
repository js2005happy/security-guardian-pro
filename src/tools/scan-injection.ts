/**
 * scan_injection — 注入类漏洞专项检测。
 */

import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";
import { z } from "zod";
import { RULES_BY_CATEGORY } from "../lib/rules.js";
import { runScan } from "../lib/scanner.js";
import { logger } from "../lib/logger.js";
import { resolve } from "node:path";

const InjInput = z.object({
  target_path: z.string().min(1).describe("目标项目根目录的绝对路径"),
});

const CONFIG = {
  title: "注入漏洞扫描",
  description:
    "专项扫描 SQL 注入、OS 命令注入、模板注入 (SSTI)、日志注入 (CRLF) 四类注入漏洞。" +
    "检测字符串拼接构造查询、危险系统调用、模板引擎未转义使用等模式。",
  inputSchema: InjInput,
  annotations: {
    readOnlyHint: true,
    destructiveHint: false,
    idempotentHint: true,
    openWorldHint: false,
  },
};

export function registerScanInjection(server: McpServer): void {
  server.registerTool("scan_injection", CONFIG, async (args): Promise<CallToolResult> => {
    const { target_path } = InjInput.parse(args);
    const resolved = resolve(target_path);
    logger.info(`scan_injection 启动: ${resolved}`);

    const scan = await runScan({
      target: resolved,
      rules: RULES_BY_CATEGORY["injection"] ?? [],
    });

    return {
      content: [{
        type: "text",
        text: JSON.stringify({
          target: resolved,
          scan_time: scan.scanTime,
          duration_ms: scan.durationMs,
          files_scanned: scan.totalFiles,
          total_injections: scan.totalMatches,
          by_severity: scan.bySeverity,
          findings: scan.matches,
        }, null, 2),
      }],
    };
  });
}
