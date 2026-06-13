/**
 * 安全检测规则引擎 — 基于 references/rules.md 编译的 OWASP Top 10 + CWE Top 25 模式库。
 *
 * 每条规则定义：id / category / cwe / severity / patterns (grep 正则) / description / fix
 */
export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
export interface SecurityRule {
    id: string;
    category: string;
    cwe: string;
    severity: Severity;
    /** 用于 Grep 的正则数组 */
    patterns: RegExp[];
    /** 多语言模式变体 */
    description: string;
    remediation: string;
}
export interface RuleMatch {
    ruleId: string;
    category: string;
    cwe: string;
    severity: Severity;
    file: string;
    line: number;
    snippet: string;
    description: string;
    remediation: string;
}
export declare const ALL_RULES: SecurityRule[];
/** 按类别分组 */
export declare const RULES_BY_CATEGORY: Record<string, SecurityRule[]>;
//# sourceMappingURL=rules.d.ts.map