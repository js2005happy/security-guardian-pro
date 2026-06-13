/**
 * 工具注册汇总 — 安全审计工具集注册入口。
 *
 * 新增工具时在此文件中导入并调用 register 函数即可。
 */

import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { registerSecurityAudit } from "./security-audit.js";
import { registerScanSecrets } from "./scan-secrets.js";
import { registerScanInjection } from "./scan-injection.js";

export function registerAllTools(server: McpServer): void {
  registerSecurityAudit(server);
  registerScanSecrets(server);
  registerScanInjection(server);
}
