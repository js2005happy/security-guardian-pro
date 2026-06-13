/**
 * 扫描引擎 — 基于规则库对文件内容执行模式匹配。
 *
 * 设计原则：
 * - 纯 JS 实现，不依赖外部 CLI 工具
 * - 逐行扫描，规则并行匹配
 * - 结果上限 500 条防止内存溢出
 */
import { readFile } from "node:fs/promises";
import { readdir } from "node:fs/promises";
import { join, relative, resolve } from "node:path";
import { logger } from "./logger.js";
const SCAN_LIMIT = 500;
// ---------------------------------------------------------------------------
// 文件发现
// ---------------------------------------------------------------------------
/** 可扫描的文本文件扩展名 */
const TEXT_EXTENSIONS = new Set([
    ".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs",
    ".py", ".pyi", ".pyx",
    ".java", ".kt", ".groovy", ".scala",
    ".go",
    ".rb",
    ".php", ".phtml",
    ".c", ".cpp", ".h", ".hpp", ".cc",
    ".rs",
    ".swift",
    ".yaml", ".yml",
    ".json",
    ".xml", ".html", ".htm",
    ".env", ".ini", ".conf", ".cfg", ".toml",
    ".sh", ".bash", ".zsh",
    ".sql",
    ".dockerfile", ".dockerignore",
    ".md",
]);
const SKIP_DIRS = new Set(["node_modules", ".git", "dist", "build", "__pycache__",
    ".next", ".nuxt", "target", "vendor", ".venv", "venv", ".pytest_cache"]);
const MAX_FILES = 200;
async function* walkFiles(dir) {
    let yielded = 0;
    const stack = [dir];
    while (stack.length > 0) {
        const current = stack.pop();
        let entries;
        try {
            entries = await readdir(current, { withFileTypes: true });
        }
        catch {
            continue;
        }
        for (const e of entries) {
            const full = join(current, e.name);
            if (e.isDirectory()) {
                if (!SKIP_DIRS.has(e.name))
                    stack.push(full);
            }
            else if (e.isFile()) {
                const ext = e.name.slice(e.name.lastIndexOf(".")).toLowerCase();
                if (TEXT_EXTENSIONS.has(ext) || TEXT_EXTENSIONS.has(e.name.toLowerCase())) {
                    if (yielded++ >= MAX_FILES)
                        return;
                    yield full;
                }
            }
        }
    }
}
// ---------------------------------------------------------------------------
// 行扫描
// ---------------------------------------------------------------------------
/**
 * 对单行内容匹配所有规则，返回命中的 RuleMatch 列表。
 * 片段截取 100 字符。
 */
function scanLine(filePath, lineNo, content, rules) {
    const hits = [];
    for (const rule of rules) {
        for (const pat of rule.patterns) {
            pat.lastIndex = 0; // 重置 regex（带 g 标志的）
            if (pat.test(content)) {
                hits.push({
                    ruleId: rule.id,
                    category: rule.category,
                    cwe: rule.cwe,
                    severity: rule.severity,
                    file: filePath,
                    line: lineNo,
                    snippet: content.trim().slice(0, 100),
                    description: rule.description,
                    remediation: rule.remediation,
                });
                break; // 同规则每行只命中一次
            }
        }
        if (hits.length >= SCAN_LIMIT)
            break;
    }
    return hits;
}
// ---------------------------------------------------------------------------
// 文件扫描
// ---------------------------------------------------------------------------
async function scanFile(filePath, rules) {
    const results = [];
    let content;
    try {
        content = await readFile(filePath, "utf-8");
    }
    catch {
        return results; // 跳过不可读文件
    }
    const lines = content.split("\n");
    for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        if (line.trim().length === 0)
            continue;
        results.push(...scanLine(filePath, i + 1, line, rules));
        if (results.length >= SCAN_LIMIT)
            break;
    }
    return results;
}
/**
 * 对目标目录执行完整安全扫描。
 */
export async function runScan(opts) {
    const start = Date.now();
    const rules = opts.rules ?? [];
    const resolvedTarget = resolve(opts.target);
    logger.info(`扫描开始: ${resolvedTarget}, 规则数=${rules.length}`);
    const allResults = [];
    let fileCount = 0;
    for await (const filePath of walkFiles(resolvedTarget)) {
        const relPath = relative(resolvedTarget, filePath);
        const hits = await scanFile(filePath, rules);
        if (hits.length > 0) {
            allResults.push(...hits);
        }
        fileCount++;
        if (allResults.length >= SCAN_LIMIT) {
            logger.warn(`达到扫描上限 ${SCAN_LIMIT} 条，提前终止`);
            break;
        }
    }
    // 统计
    const bySeverity = {};
    const byCategory = {};
    for (const m of allResults) {
        bySeverity[m.severity] = (bySeverity[m.severity] ?? 0) + 1;
        byCategory[m.category] = (byCategory[m.category] ?? 0) + 1;
    }
    const elapsed = Date.now() - start;
    logger.info(`扫描完成: ${fileCount} 文件, ${allResults.length} 发现, ${elapsed}ms`);
    return {
        target: opts.target,
        scanTime: new Date().toISOString(),
        durationMs: elapsed,
        totalFiles: fileCount,
        totalMatches: allResults.length,
        matches: allResults,
        bySeverity,
        byCategory,
    };
}
//# sourceMappingURL=scanner.js.map