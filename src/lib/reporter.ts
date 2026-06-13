/**
 * 安全审计报告生成器 — 按 CVSS/CWE 标准格式输出结构化报告。
 */

import type { RuleMatch } from "./rules.js";
import type { ScanResult } from "./scanner.js";

// ---------------------------------------------------------------------------
// 类型
// ---------------------------------------------------------------------------

export interface AuditReport {
  title: string;
  project: string;
  auditTime: string;
  durationMs: number;
  score: number;                    // 0–10 安全评分
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
    urgent: string[];               // 24h 内
    highPriority: string[];         // 本迭代
    backlog: string[];              // 后续
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

// ---------------------------------------------------------------------------
// 评分算法
// ---------------------------------------------------------------------------

function computeScore(matches: RuleMatch[]): number {
  const severities = matches.map((m) => m.severity);
  let penalty = 0;
  for (const s of severities) {
    switch (s) {
      case "CRITICAL": penalty += 3; break;
      case "HIGH":     penalty += 2; break;
      case "MEDIUM":   penalty += 1; break;
      case "LOW":      penalty += 0.5; break;
      default:         penalty += 0.25;
    }
  }
  return Math.max(0, Math.round((10 - penalty) * 10) / 10);
}

// ---------------------------------------------------------------------------
// 报告生成
// ---------------------------------------------------------------------------

export function generateReport(
  projectName: string,
  scan: ScanResult,
): AuditReport {
  const findings: FormattedFinding[] = scan.matches.map((m, i) => ({
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
  const order: Record<string, number> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 };
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
