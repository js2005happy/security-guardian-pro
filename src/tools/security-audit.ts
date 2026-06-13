/**
 * security_audit — 全量安全审计工具。
 * 按 OWASP Top 10 + CWE Top 25 规则库对目标目录执行全类别扫描并生成报告。
 */

import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { CallToolResult } from "@modelcontextprotocol/sdk/types.js";
import { z } from "zod";
import { ALL_RULES, RULES_BY_CATEGORY } from "../lib/rules.js";
import { runScan } from "../lib/scanner.js";
import { generateReport } from "../lib/reporter.js";
import { logger } from "../lib/logger.js";
import { resolve } from "node:path";

// ---------------------------------------------------------------------------
// Schema
// ---------------------------------------------------------------------------

const AuditInput = z.object({
  target_path: z.string().min(1).describe("目标项目根目录的绝对路径"),
  categories: z.string().optional().describe(
    "扫描类别，逗号分隔。可选: injection, access_control, crypto, misconfiguration, secrets, misc。留空=全量"
  ),
});

// ---------------------------------------------------------------------------
// 配置
// ---------------------------------------------------------------------------

const CONFIG = {
  title: "全栈安全审计",
  description:
    "对目标项目执行 OWASP Top 10 + CWE Top 25 全类别安全审计。" +
    "内置 17 条检测规则，覆盖注入、访问控制、加密失效、安全配置、敏感信息泄露、反序列化六大类别。" +
    "返回结构化审计报告，含安全评分、详细发现、CWE 编号、整改建议及优先级。",
  inputSchema: AuditInput,
  annotations: {
    readOnlyHint: true,
    destructiveHint: false,
    idempotentHint: true,
    openWorldHint: false,
  },
};

// ---------------------------------------------------------------------------
// 注册
// ---------------------------------------------------------------------------

export function registerSecurityAudit(server: McpServer): void {
  server.registerTool("security_audit", CONFIG, async (args): Promise<CallToolResult> => {
    const { target_path, categories } = AuditInput.parse(args);

    const resolved = resolve(target_path);
    logger.info(`security_audit 启动: ${resolved}${categories ? ` (${categories})` : ""}`);

    // 选择规则集
    let rules;
    if (categories) {
      rules = categories
        .split(",")
        .map((c) => c.trim().toLowerCase())
        .filter((c) => c in RULES_BY_CATEGORY)
        .flatMap((c) => RULES_BY_CATEGORY[c] ?? []);
      if (rules.length === 0) {
        return {
          content: [{
            type: "text",
            text: JSON.stringify({
              error: `无效类别: ${categories}。可选: ${Object.keys(RULES_BY_CATEGORY).join(", ")}`,
            }, null, 2),
          }],
        };
      }
    } else {
      rules = ALL_RULES;
    }

    // 扫描
    const scan = await runScan({ target: resolved, rules });

    // 生成报告
    const projectName = resolved.split(/[/\\]/).pop() ?? "unknown";
    const report = generateReport(projectName, scan);

    logger.info(`security_audit 完成: ${scan.totalMatches} 个发现, 评分 ${report.score}/10`);

    return {
      content: [{
        type: "text",
        text: JSON.stringify(report, null, 2),
      }],
    };
  });
}
