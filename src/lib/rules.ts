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

// ---------------------------------------------------------------------------
// 一、注入类 (Injection)
// ---------------------------------------------------------------------------

const SQL_INJECTION: SecurityRule = {
  id: "INJ-001",
  category: "SQL 注入",
  cwe: "CWE-89",
  severity: "CRITICAL",
  description: "SQL 查询拼接用户输入，未使用参数化查询",
  remediation: "使用参数化查询 (PreparedStatement / ? placeholder) 或 ORM 安全 API",
  patterns: [
    /(["']\s*\+.*SELECT.*FROM|SELECT.*FROM.*\+.*["'])/i,
    /(cursor\.execute\s*\(\s*["'].*%|execute\s*\(\s*["'].*\{)/i,
    /(`SELECT\s+\*\s+FROM.*\$\{|"SELECT\s+\*\s+FROM.*\$\{)/i,
    /(\.raw\s*\(\s*["'].*SELECT)/i,
  ],
};

const OS_COMMAND: SecurityRule = {
  id: "INJ-002",
  category: "OS 命令注入",
  cwe: "CWE-78",
  severity: "CRITICAL",
  description: "用户输入拼接到系统命令中执行",
  remediation: "使用参数数组形式传递命令参数 (spawn(cmd, [args]))，避免 shell 拼接",
  patterns: [
    /\b(system\s*\(\s*["'].*\+|exec\s*\(\s*["'].*\+)/i,
    /\b(popen\s*\(\s*["'].*\+|subprocess\.call\s*\(\s*["'].*\+)/i,
    /\b(Runtime\.exec\s*\(\s*["'].*\+|os\.system\s*\(\s*["'].*\+)/i,
    /\b(eval\s*\(\s*.*\+)/,
  ],
};

const TEMPLATE_INJECTION: SecurityRule = {
  id: "INJ-003",
  category: "模板注入 (SSTI)",
  cwe: "CWE-94",
  severity: "HIGH",
  description: "用户输入传入模板引擎且未转义",
  remediation: "对用户输入进行 HTML 实体编码，启用模板引擎自动转义，避免使用 env.from_string()",
  patterns: [
    /(env\.from_string\s*\(|\.render\s*\(.*request\.)/i,
    /(<%-?\s*=?\s*.*user|<\?=.*eval)/i,
    /(template\.HTML\s*\(|text\/template.*Execute)/i,
  ],
};

const LOG_INJECTION: SecurityRule = {
  id: "INJ-004",
  category: "日志注入 / CRLF",
  cwe: "CWE-117",
  severity: "MEDIUM",
  description: "用户输入直接写入日志，未过滤换行符",
  remediation: "对写入日志的用户输入进行换行符清理 (\\n → _)，或使用结构化日志框架",
  patterns: [/log(ger)?\.\w+\s*\(\s*.*req\.(query|body|params)/i],
};

// ---------------------------------------------------------------------------
// 二、访问控制 (Access Control)
// ---------------------------------------------------------------------------

const MISSING_AUTH: SecurityRule = {
  id: "ACC-001",
  category: "缺失认证中间件",
  cwe: "CWE-306",
  severity: "CRITICAL",
  description: "敏感路由未挂载认证中间件",
  remediation: "在路由定义链中添加 authMiddleware / passport.authenticate()",
  patterns: [
    /(app\.(get|post|put|delete)\s*\(\s*["']\/api\/(?!login|health))/i,
    /(router\.(get|post)\s*\(\s*["']\/admin)/i,
    /(@GetMapping|@PostMapping.*(?!@PreAuthorize))/i,
  ],
};

const IDOR_RISK: SecurityRule = {
  id: "ACC-002",
  category: "IDOR / 越权",
  cwe: "CWE-639",
  severity: "HIGH",
  description: "资源操作仅靠 ID 鉴权，未校验归属关系",
  remediation: "服务端校验资源的 owner_id === current_user_id，不可仅依赖前端隐藏",
  patterns: [
    /(\/api\/\w+\/\$\{.*id\}|\/user\/\d+\/\w+)/i,
    /(findById\s*\(\s*req\.(params|query)\.id)/i,
  ],
};

const CORS_MISCONFIG: SecurityRule = {
  id: "ACC-003",
  category: "CORS 配置错误",
  cwe: "CWE-942",
  severity: "HIGH",
  description: "CORS 允许任意 Origin 且携带凭据",
  remediation: "Access-Control-Allow-Origin 设为白名单域名，禁止 * 与 credentials 共存",
  patterns: [
    /(Access-Control-Allow-Origin\s*:\s*\*)/i,
    /(cors\s*\(\s*\{\s*origin\s*:\s*["']\*["'])/i,
    /(allowCredentials\s*:\s*true)/i,
  ],
};

// ---------------------------------------------------------------------------
// 三、加密失效 (Cryptographic Failures)
// ---------------------------------------------------------------------------

const WEAK_HASH: SecurityRule = {
  id: "CRY-001",
  category: "弱哈希算法",
  cwe: "CWE-328",
  severity: "HIGH",
  description: "使用 MD5 / SHA1 做密码哈希",
  remediation: "使用 bcrypt / scrypt / Argon2 进行密码哈希",
  patterns: [
    /\b(MD5\s*\(|md5\s*\(\s*["'])/i,
    /\b(SHA1\s*\(|sha1\s*\(\s*["']|digest\s*\(\s*["']sha1)/i,
    /(hashers\.MD5|django\.contrib\.auth\.hashers\.MD5)/i,
  ],
};

const HARDCODED_KEY: SecurityRule = {
  id: "CRY-002",
  category: "硬编码密钥",
  cwe: "CWE-798",
  severity: "CRITICAL",
  description: "密钥/Token/私钥直接写在源码中",
  remediation: "通过环境变量 / KMS / Vault 管理密钥，代码中仅引用 process.env.XXX",
  patterns: [
    /(secret_key\s*=\s*["'][\w\-+=\/]{16,}["'])/i,
    /(API_KEY\s*=\s*["'][\w\-+=\/]{16,}["'])/i,
    /(-----BEGIN\s+(RSA|EC|DSA|OPENSSH)\s+PRIVATE\s+KEY-----)/,
    /\b(password\s*=\s*["'][\w\-+=\/]{6,}["'])/i,
  ],
};

const ECB_MODE: SecurityRule = {
  id: "CRY-003",
  category: "ECB 加密模式",
  cwe: "CWE-327",
  severity: "HIGH",
  description: "AES 使用 ECB 模式（不安全的块加密模式）",
  remediation: "切换为 GCM / CBC + HMAC 模式",
  patterns: [/AES\.MODE_ECB|Cipher\.getInstance\s*\(\s*["']AES\/ECB/i],
};

const WEAK_RNG: SecurityRule = {
  id: "CRY-004",
  category: "不安全随机数",
  cwe: "CWE-338",
  severity: "HIGH",
  description: "安全令牌使用 Math.random() / rand() 生成",
  remediation: "使用 crypto.randomBytes() / secrets.token_urlsafe() / SecureRandom",
  patterns: [
    /Math\.random\s*\(\)\s*.*token/i,
    /\brand\s*\(\)\s*.*password/i,
    /(random\.randint|Math\.random).*(token|key|secret)/i,
  ],
};

// ---------------------------------------------------------------------------
// 四、安全配置错误 (Security Misconfiguration)
// ---------------------------------------------------------------------------

const DEBUG_MODE: SecurityRule = {
  id: "CFG-001",
  category: "调试模式开启",
  cwe: "CWE-489",
  severity: "HIGH",
  description: "生产环境未关闭调试模式",
  remediation: "部署前设置 DEBUG=False / NODE_ENV=production / spring.profiles.active=prod",
  patterns: [
    /\b(DEBUG\s*=\s*True|DEBUG\s*=\s*true)/,
    /\b(NODE_ENV\s*=\s*["']development["'])/,
    /(spring\.profiles\.active\s*=\s*dev)/i,
  ],
};

const DEFAULT_CREDS: SecurityRule = {
  id: "CFG-002",
  category: "默认凭据",
  cwe: "CWE-1392",
  severity: "HIGH",
  description: "代码中出现疑似默认账号密码",
  remediation: "移除所有硬编码默认凭据，首次运行时强制修改",
  patterns: [
    /\b(admin\s*[:=]\s*["']admin["'])/i,
    /\b(root\s*[:=]\s*["']root["'])/i,
    /(username\s*=\s*["']admin["'].*password\s*=\s*["']admin["'])/i,
  ],
};

const MISSING_HEADERS: SecurityRule = {
  id: "CFG-003",
  category: "安全头缺失",
  cwe: "CWE-693",
  severity: "MEDIUM",
  description: "HTTP 响应可能缺少关键安全头",
  remediation: "配置 helmet() (Express) / SecurityHeadersMiddleware，添加 CSP/HSTS/X-Frame-Options",
  patterns: [
    /(app\s*\(\s*\)|createApp\s*\(\s*\))/i, // 检测初始化但无 helmet
  ],
};

// ---------------------------------------------------------------------------
// 五、敏感信息泄露 (Sensitive Data Exposure)
// ---------------------------------------------------------------------------

const SECRET_PATTERNS: SecurityRule = {
  id: "SEN-001",
  category: "敏感凭据泄露",
  cwe: "CWE-200",
  severity: "CRITICAL",
  description: "检测到疑似 AWS/GitHub/Slack/JWT 密钥模式",
  remediation: "立即轮换泄露的凭据，将其移至环境变量或密钥管理服务",
  patterns: [
    /AKIA[0-9A-Z]{16}/,                              // AWS Access Key
    /ghp_[0-9a-zA-Z]{36}/,                            // GitHub Personal Token
    /xox[baprs]-[0-9a-zA-Z-]{10,}/,                   // Slack Token
    /eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*/, // JWT
    /sk-[a-zA-Z0-9]{32,}/,                            // OpenAI / Stripe sk-
  ],
};

// ---------------------------------------------------------------------------
// 六、反序列化 & 其他 (Deserialization & Misc)
// ---------------------------------------------------------------------------

const DESERIALIZATION: SecurityRule = {
  id: "MSC-001",
  category: "不安全反序列化",
  cwe: "CWE-502",
  severity: "CRITICAL",
  description: "反序列化不可信数据源",
  remediation: "避免反序列化用户输入；若必须，使用安全库 (ysoserial 白名单)",
  patterns: [
    /\b(pickle\.loads\s*\(|pickle\.load\s*\(\s*request)/i,
    /\b(yaml\.load\s*\(|ObjectInputStream)/i,
    /\b(JSON\.parse\s*\(\s*req\.|unserialize\s*\(\s*)/i,
  ],
};

const PROTOTYPE: SecurityRule = {
  id: "MSC-002",
  category: "原型污染 (JS)",
  cwe: "CWE-1321",
  severity: "HIGH",
  description: "Object.assign / _.merge 接收用户可控对象",
  remediation: "使用 Object.create(null) 或 lodash _.merge({}, safeInput) 并白名单过滤 __proto__",
  patterns: [
    /(_\.merge\s*\(\s*\{\}\s*,\s*req\.(body|query|params))/i,
    /(Object\.assign\s*\(\s*\{\}\s*,\s*req\.body)/i,
  ],
};

// ---------------------------------------------------------------------------
// 全部规则汇总
// ---------------------------------------------------------------------------

export const ALL_RULES: SecurityRule[] = [
  SQL_INJECTION,
  OS_COMMAND,
  TEMPLATE_INJECTION,
  LOG_INJECTION,
  MISSING_AUTH,
  IDOR_RISK,
  CORS_MISCONFIG,
  WEAK_HASH,
  HARDCODED_KEY,
  ECB_MODE,
  WEAK_RNG,
  DEBUG_MODE,
  DEFAULT_CREDS,
  MISSING_HEADERS,
  SECRET_PATTERNS,
  DESERIALIZATION,
  PROTOTYPE,
];

/** 按类别分组 */
export const RULES_BY_CATEGORY: Record<string, SecurityRule[]> = {
  injection: [SQL_INJECTION, OS_COMMAND, TEMPLATE_INJECTION, LOG_INJECTION],
  access_control: [MISSING_AUTH, IDOR_RISK, CORS_MISCONFIG],
  crypto: [WEAK_HASH, HARDCODED_KEY, ECB_MODE, WEAK_RNG],
  misconfiguration: [DEBUG_MODE, DEFAULT_CREDS, MISSING_HEADERS],
  secrets: [SECRET_PATTERNS],
  misc: [DESERIALIZATION, PROTOTYPE],
};
