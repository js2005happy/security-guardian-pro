# Security Guardian Pro（安全卫士·专业版）

> 适用于 Claude Code 的企业级全栈安全审计技能 —— 覆盖 OWASP Top 10、供应链安全、云原生安全、敏感数据泄露、合规风险，一次对话完成全流程审计。

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Claude Code](https://img.shields.io/badge/Claude%20Code-Skill-orange)](https://claude.ai/code)

[English](README.md)

---

## 这是什么？

一个 Claude Code 技能文件，将 Claude 转变为**拥有 15 年经验的应用安全架构师**。它按照严格的四阶段漏洞挖掘方法论，自动执行侦察、静态分析、手动测试点枚举和结构化报告输出。

**一句话触发，全量审计，可落地的报告。**

## 功能覆盖

| 类别 | 检测内容 |
|------|----------|
| **注入类** | SQL 注入、命令注入、模板注入（SSTI）、日志注入、XSS |
| **访问控制** | IDOR、中间件缺失、CORS 配置错误 |
| **加密失效** | 弱哈希、硬编码密钥、ECB 模式、弱随机数 |
| **不安全设计** | 缺少速率限制、密码重置令牌可预测、批量赋值 |
| **配置错误** | 调试模式开启、默认凭据、安全头缺失 |
| **供应链** | 依赖 CVE 查询、过期组件检测 |
| **敏感信息** | AWS 密钥、GitHub Token、私钥、通用凭证正则匹配 |
| **SSRF** | 用户可控 URL 追踪、内网暴露 |
| **云原生/K8s** | 特权容器、Docker socket 挂载、root 用户运行 |
| **框架专项** | JS 原型污染、Python pickle、Java XXE、Go 模板注入 |

## 快速开始

### 1. 安装

```bash
# 克隆仓库到 Claude Code skills 目录
git clone https://github.com/YOUR_USERNAME/security-guardian-pro.git
cp security-guardian-pro/security-guardian-pro.md ~/.claude/skills/
```

或直接复制到项目中：

```bash
mkdir -p .claude/skills
cp security-guardian-pro.md .claude/skills/
```

### 2. 触发

在 Claude Code 对话中直接说：

```
安全审计
security review
帮我检查漏洞
全面安全扫描
dependency scan
hardcoded secrets
```

## 四阶段审计流程

```
侦察 → 扫描 → 验证 → 报告
```

| 阶段 | 活动 | 工具 |
|------|------|------|
| **1. 侦察** | 技术栈识别、依赖映射、危险模式搜索 | Glob、Grep、gitleaks |
| **2. 扫描** | 自动化 SAST + 手动测试点枚举 | semgrep、输入点追踪 |
| **3. 验证** | 为每个可疑点生成可复现的安全测试用例 | curl / 请求模板 |
| **4. 报告** | 结构化报告：评分、优先级、合规映射 | 内置模板 |

## 报告示例

```
🔒 安全审计报告
项目：my-web-app
审查范围：src/
总体安全评分：6/10（需改进）

发现汇总
🔴 严重：2个
🟠 高危：3个
🟡 中危：5个
🟢 低危：4个
✅ 通过项：12个

每个发现包含：
  [风险等级] 标题
  文件/位置：auth/login.ts:42
  问题描述：...
  攻击场景：...
  修复方案：（diff 格式）
  CWE 参考：CWE-89

整改摘要
  紧急（24h内）：[严重项]
  高优（本迭代）：[高危项]
  中低优（backlog）：[中低危项]

附录：可复现测试用例
```

## 检查规则库

内置 **9 大类 50+ 项检查模式**：

1. **注入类** — 参数化查询、命令转义、模板自动转义
2. **访问控制** — 中间件缺失、IDOR、CORS 凭证泄露
3. **加密失效** — MD5/SHA1、ECB、Math.random()
4. **不安全设计** — 速率限制、令牌熵值、错误信息泄露
5. **配置错误** — debug 标志、默认账号、CSP/HSTS 缺失
6. **供应链** — `npm audit` / `pip audit`、CVE 查询
7. **敏感信息** — AWS/GitHub/私钥/通用凭证正则
8. **SSRF** — URL 参数追踪、白名单检查
9. **框架专项** — JS 原型污染、Python 反序列化、Java XXE、Docker socket

## 可选依赖

在系统 PATH 中安装以下工具可获得最佳效果：

| 工具 | 用途 |
|------|------|
| [semgrep](https://semgrep.dev) | 多语言 SAST 扫描 |
| [gitleaks](https://gitleaks.io) | 硬编码凭证检测 |
| `npm audit` / `pip-audit` | 依赖扫描 |

不安装也能用 —— 会自动回退到手动的 Grep/Glob 分析。

## 安全边界

本技能严格遵循**防御性披露**原则：

- 绝不生成可用的攻击代码、exploit 或恶意脚本
- 检出真实凭证时仅显示掩码（如 `AKIA****`）
- 攻击场景仅以伪代码说明原理
- 拒绝未授权的渗透测试请求

## License

MIT © 2026
