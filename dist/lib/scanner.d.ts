/**
 * 扫描引擎 — 基于规则库对文件内容执行模式匹配。
 *
 * 设计原则：
 * - 纯 JS 实现，不依赖外部 CLI 工具
 * - 逐行扫描，规则并行匹配
 * - 结果上限 500 条防止内存溢出
 */
import type { SecurityRule, RuleMatch } from "./rules.js";
export interface ScanOptions {
    /** 待扫描的目录路径 */
    target: string;
    /** 要应用的规则集，默认全部 */
    rules?: SecurityRule[];
    /** 限制扫描文件数 */
    maxFiles?: number;
}
export interface ScanResult {
    target: string;
    scanTime: string;
    durationMs: number;
    totalFiles: number;
    totalMatches: number;
    matches: RuleMatch[];
    /** 按严重等级统计 */
    bySeverity: Record<string, number>;
    /** 按类别统计 */
    byCategory: Record<string, number>;
}
/**
 * 对目标目录执行完整安全扫描。
 */
export declare function runScan(opts: ScanOptions): Promise<ScanResult>;
//# sourceMappingURL=scanner.d.ts.map