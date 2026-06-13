/**
 * 规则引擎单元测试
 */

import { describe, it, expect } from "vitest";
import { ALL_RULES, RULES_BY_CATEGORY } from "../src/lib/rules.js";

describe("规则库完整性", () => {
  it("所有规则应有唯一 ID", () => {
    const ids = ALL_RULES.map((r) => r.id);
    expect(new Set(ids).size).toBe(ids.length);
  });

  it("每条规则至少有 1 个匹配模式", () => {
    for (const rule of ALL_RULES) {
      expect(rule.patterns.length).toBeGreaterThan(0);
    }
  });

  it("每条规则有描述和修复建议", () => {
    for (const rule of ALL_RULES) {
      expect(rule.description.length).toBeGreaterThan(0);
      expect(rule.remediation.length).toBeGreaterThan(0);
    }
  });

  it("每条规则有合法 CWE 编号", () => {
    for (const rule of ALL_RULES) {
      expect(rule.cwe).toMatch(/^CWE-\d+$/);
    }
  });

  it("严重等级为合法值", () => {
    const valid = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];
    for (const rule of ALL_RULES) {
      expect(valid).toContain(rule.severity);
    }
  });
});

describe("规则分类", () => {
  it("所有类别应覆盖全部规则", () => {
    const categorized = Object.values(RULES_BY_CATEGORY).flat();
    expect(categorized.length).toBe(ALL_RULES.length);
  });

  it("每个类别至少含 1 条规则", () => {
    for (const [cat, rules] of Object.entries(RULES_BY_CATEGORY)) {
      expect(rules.length, `类别 ${cat} 为空`).toBeGreaterThan(0);
    }
  });
});

describe("模式匹配正确性", () => {
  it("SQL 注入规则应检测到拼接查询", () => {
    const sql = RULES_BY_CATEGORY["injection"]?.find((r) => r.id === "INJ-001");
    expect(sql).toBeDefined();
    const hit = sql!.patterns.some((p) => p.test('\' + "SELECT * FROM users"'));
    expect(hit).toBe(true);
  });

  it("硬编码密钥规则应检测到 secret_key", () => {
    const key = RULES_BY_CATEGORY["crypto"]?.find((r) => r.id === "CRY-002");
    expect(key).toBeDefined();
    const hit = key!.patterns.some((p) =>
      p.test('secret_key = "sk-abcdefghijklmnop"')
    );
    expect(hit).toBe(true);
  });

  it("CORS 规则应检测到 Allow-Origin: *", () => {
    const cors = RULES_BY_CATEGORY["access_control"]?.find((r) => r.id === "ACC-003");
    expect(cors).toBeDefined();
    const hit = cors!.patterns.some((p) =>
      p.test("Access-Control-Allow-Origin: *")
    );
    expect(hit).toBe(true);
  });

  it("ECB 模式规则应检测到 AES.MODE_ECB", () => {
    const ecb = RULES_BY_CATEGORY["crypto"]?.find((r) => r.id === "CRY-003");
    expect(ecb).toBeDefined();
    const hit = ecb!.patterns.some((p) => p.test("AES.MODE_ECB"));
    expect(hit).toBe(true);
  });
});
