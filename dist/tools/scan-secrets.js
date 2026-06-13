/**
 * scan_secrets — 敏感信息检测工具。
 * 内置 AWS/GitHub/Slack/JWT 等密钥模式匹配及硬编码凭据检测。
 */
import { z } from "zod";
import { RULES_BY_CATEGORY } from "../lib/rules.js";
import { runScan } from "../lib/scanner.js";
import { logger } from "../lib/logger.js";
import { resolve } from "node:path";
const SecretInput = z.object({
    target_path: z.string().min(1).describe("目标项目根目录的绝对路径"),
});
const CONFIG = {
    title: "敏感凭据扫描",
    description: "扫描目标目录中是否存在硬编码密钥、Token、私钥等敏感凭据。" +
        "覆盖 AWS (AKIA), GitHub Token (ghp_), Slack Token (xox), JWT, OpenAI/Stripe (sk-), " +
        "私钥块 (PEM), 密码变量等多种模式。" +
        "检测到真实凭据时自动掩码，报告中仅显示类型和位置。",
    inputSchema: SecretInput,
    annotations: {
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: false,
    },
};
export function registerScanSecrets(server) {
    server.registerTool("scan_secrets", CONFIG, async (args) => {
        const { target_path } = SecretInput.parse(args);
        const resolved = resolve(target_path);
        logger.info(`scan_secrets 启动: ${resolved}`);
        const rules = [
            ...(RULES_BY_CATEGORY["secrets"] ?? []),
            ...(RULES_BY_CATEGORY["crypto"]?.filter((r) => r.id === "CRY-002") ?? []),
        ];
        const scan = await runScan({ target: resolved, rules });
        // 对结果做掩码处理
        const safe = scan.matches.map((m) => ({
            ...m,
            snippet: m.snippet.replace(/[A-Za-z0-9\-_=]{20,}/g, (s) => s.slice(0, 4) + "***" + s.slice(-4)),
        }));
        return {
            content: [{
                    type: "text",
                    text: JSON.stringify({
                        target: resolved,
                        scan_time: scan.scanTime,
                        duration_ms: scan.durationMs,
                        files_scanned: scan.totalFiles,
                        total_secrets: scan.totalMatches,
                        findings: safe,
                    }, null, 2),
                }],
        };
    });
}
//# sourceMappingURL=scan-secrets.js.map