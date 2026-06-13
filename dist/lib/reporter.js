/**
 * 安全审计报告生成器 — 按 CVSS/CWE 标准格式输出结构化报告。
 */
// ---------------------------------------------------------------------------
// 评分算法
// ---------------------------------------------------------------------------
function computeScore(matches) {
    const severities = matches.map((m) => m.severity);
    let penalty = 0;
    for (const s of severities) {
        switch (s) {
            case "CRITICAL":
                penalty += 3;
                break;
            case "HIGH":
                penalty += 2;
                break;
            case "MEDIUM":
                penalty += 1;
                break;
            case "LOW":
                penalty += 0.5;
                break;
            default: penalty += 0.25;
        }
    }
    return Math.max(0, Math.round((10 - penalty) * 10) / 10);
}
// ---------------------------------------------------------------------------
// 报告生成
// ---------------------------------------------------------------------------
export function generateReport(projectName, scan) {
    const findings = scan.matches.map((m, i) => ({
        rank: i + 1,
        severity: m.severity,
        ruleId: m.ruleId,
        category: m.category,
        cwe: m.cwe,
        file: m.file,
        line: m.line,
        description: m.description,
        snippet: m.snippet,
        remediation: m.remediation,
    }));
    // 按严重度排序
    const order = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 };
    findings.sort((a, b) => (order[a.severity] ?? 5) - (order[b.severity] ?? 5));
    // 整改分组
    const urgent = findings
        .filter((f) => f.severity === "CRITICAL")
        .map((f) => `${f.file}:${f.line} — ${f.description}`);
    const highPriority = findings
        .filter((f) => f.severity === "HIGH")
        .map((f) => `${f.file}:${f.line} — ${f.description}`);
    const backlog = findings
        .filter((f) => f.severity === "MEDIUM" || f.severity === "LOW")
        .map((f) => `${f.file}:${f.line} — ${f.description}`);
    const cwes = [...new Set(findings.map((f) => f.cwe))];
    return {
        title: `安全审计报告 — ${projectName}`,
        project: projectName,
        auditTime: scan.scanTime,
        durationMs: scan.durationMs,
        score: computeScore(scan.matches),
        summary: {
            critical: scan.bySeverity["CRITICAL"] ?? 0,
            high: scan.bySeverity["HIGH"] ?? 0,
            medium: scan.bySeverity["MEDIUM"] ?? 0,
            low: scan.bySeverity["LOW"] ?? 0,
            info: scan.bySeverity["INFO"] ?? 0,
            total: scan.totalMatches,
        },
        findings,
        remediationPlan: {
            urgent: urgent.slice(0, 20),
            highPriority: highPriority.slice(0, 30),
            backlog: backlog.slice(0, 50),
        },
        appendix: {
            rulesApplied: scan.matches.length > 0
                ? [...new Set(scan.matches.map((m) => m.ruleId))].length
                : 0,
            filesScanned: scan.totalFiles,
            cweCoverage: cwes,
        },
    };
}
//# sourceMappingURL=reporter.js.map