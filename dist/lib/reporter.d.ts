/**
 * 安全审计报告生成器 — 按 CVSS/CWE 标准格式输出结构化报告。
 */
import type { ScanResult } from "./scanner.js";
export interface AuditReport {
    title: string;
    project: string;
    auditTime: string;
    durationMs: number;
    score: number;
    summary: {
        critical: number;
        high: number;
        medium: number;
        low: number;
        info: number;
        total: number;
    };
    findings: FormattedFinding[];
    remediationPlan: {
        urgent: string[];
        highPriority: string[];
        backlog: string[];
    };
    appendix: {
        rulesApplied: number;
        filesScanned: number;
        cweCoverage: string[];
    };
}
interface FormattedFinding {
    rank: number;
    severity: string;
    ruleId: string;
    category: string;
    cwe: string;
    file: string;
    line: number;
    description: string;
    snippet: string;
    remediation: string;
}
export declare function generateReport(projectName: string, scan: ScanResult): AuditReport;
export {};
//# sourceMappingURL=reporter.d.ts.map