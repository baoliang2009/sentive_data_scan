use crate::model::Severity;

/// Declarative definition of a built-in detection rule.
pub struct RuleSpec {
    pub id: &'static str,
    pub name: &'static str,
    pub category: &'static str,
    pub severity: Severity,
    pub pattern: &'static str,
    pub keywords: &'static [&'static str],
    pub validators: &'static str,
    pub description: &'static str,
}

/// Built-in sensitive data rules. Adding a rule is a one-line change here.
///
/// 关于边界：Rust 的 `\b` 默认按 Unicode 单词字符判断，中文属于单词字符，
/// 因此 `身份证1101...` 之间没有边界，必须改用 `(?-u:\b)`（仅 ASCII 单词
/// 边界），否则中文紧邻号码时会整条漏检。同理，号码内部允许分隔符时统一
/// 用 `(?:^|[^0-9])` 做左边界，避免把长数字串截断后误报。
pub const BUILTIN_RULES: &[RuleSpec] = &[
    RuleSpec {
        id: "cn_id_card",
        name: "中国大陆居民身份证号",
        category: "identity",
        severity: Severity::High,
        // 6 位地址码 + 8 位生日 + 3 位顺序码 + 校验位，生日与地址码先粗筛，
        // 精确度再交给 cn_id 校验器（地区码/日期/GB 11643 校验位）。
        pattern: r"(?-u:\b)([1-9][0-9]{5}(?:18|19|20)[0-9]{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12][0-9]|3[01])[0-9]{3}[0-9Xx])(?-u:\b)",
        keywords: &[],
        validators: "cn_id",
        description: "18 位身份证号，校验行政区划、出生日期与 GB 11643 校验位",
    },
    RuleSpec {
        id: "cn_id_card_15",
        name: "一代居民身份证号（15 位）",
        category: "identity",
        severity: Severity::Medium,
        // 15 位没有校验位，靠地址码 + 生日收敛；地址码必须在真实行政区划内。
        pattern: r"(?-u:\b)([1-9][0-9]{5}[0-9]{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12][0-9]|3[01])[0-9]{3})(?-u:\b)",
        keywords: &[],
        validators: "cn_id_15",
        description: "15 位老身份证号，校验行政区划与出生日期",
    },
    RuleSpec {
        id: "cn_social_security",
        name: "社会保障卡号",
        category: "identity",
        severity: Severity::High,
        // 社保卡号各地规则不一（常见 9 位，也有 8/10/12/14 位），没有统一
        // 校验位，必须依赖“社保卡号/医保编号”等中文标签就近限定，否则任意
        // 8-14 位数字都会命中。社会保障号码本身即身份证号，由 cn_id_card 负责。
        pattern: r"(?:社会保障卡号|社保卡号|社保卡编号|社保编号|医保卡号|医保编号|社保个人编号|个人社保编号)\s*[:：=]?\s*([0-9](?:[ -]?[0-9]){7,13})(?-u:\b)",
        keywords: &[],
        validators: "social_security",
        description: "带“社保卡号/医保编号”等标签的 8-14 位社保卡号（社会保障号码即身份证号）",
    },
    RuleSpec {
        id: "cn_mobile",
        name: "中国大陆手机号",
        category: "contact",
        severity: Severity::Medium,
        // 号段收敛到 13x-19x，校验器再排除 140-144、154 等未分配号段与连号。
        pattern: r"(?:^|[^0-9])(?:\+?86[ -]?)?(1[3-9][0-9](?:[ -]?[0-9]){8})(?-u:\b)",
        keywords: &[],
        validators: "phone",
        description: "11 位手机号，支持 +86 与空格/连字符分隔，过滤未分配号段与连号",
    },
    RuleSpec {
        id: "cn_landline",
        name: "固定电话",
        category: "contact",
        severity: Severity::Low,
        pattern: r"(?:^|[^0-9])(0[0-9]{2,3}[ -]?[0-9]{7,8})(?-u:\b)",
        // 座机号与流水号、内部编码天然混淆（如 02023112412），而单独一串
        // 座机的数据价值有限，因此额外要求附近出现电话相关词，换取精度。
        keywords: &[
            "电话",
            "座机",
            "固话",
            "传真",
            "联系方式",
            "联系电话",
            "tel",
            "phone",
            "fax",
        ],
        validators: "landline",
        description: "带区号的固定电话，区号必须在真实区号表内，且附近需有电话相关词",
    },
    RuleSpec {
        id: "email",
        name: "电子邮箱",
        category: "contact",
        severity: Severity::Medium,
        pattern: r"(?-u:\b)([A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,24})(?-u:\b)",
        keywords: &[],
        validators: "placeholder",
        description: "邮箱地址，过滤 example/test 等占位值",
    },
    RuleSpec {
        id: "bank_card",
        name: "银行卡号",
        category: "financial",
        severity: Severity::High,
        // 先广撒网抓 12-19 位数字，再由 bank_card 校验器做 Luhn + BIN 号段
        // + 卡号长度的三重校验，避免只靠 Luhn 把 13-19 位数字串大面积误报。
        pattern: r"(?-u:\b)([1-9][0-9]{11,18})(?-u:\b)",
        keywords: &[],
        validators: "bank_card",
        description: "银行卡号，Luhn + 银联/国际卡组织 BIN 号段 + 卡号长度三重校验",
    },
    RuleSpec {
        id: "bank_card_formatted",
        name: "银行卡号（分组格式）",
        category: "financial",
        severity: Severity::High,
        // 4 位一组、空格或连字符分隔；覆盖 16 位（4-4-4-4）与 19 位
        // （4-4-4-4-3）等常见排版。最后一段限制 1-3 位，避免把后面紧跟的
        // 年份等 4 位数字吞进卡号。
        pattern: r"(?-u:\b)([0-9]{4}(?:[ -][0-9]{4}){2,3}(?:[ -][0-9]{1,3})?)(?-u:\b)",
        keywords: &[],
        validators: "bank_card",
        description: "4 位一组书写、带空格或连字符的卡号，同样做 BIN 与 Luhn 校验",
    },
    RuleSpec {
        id: "password_assignment",
        name: "密码配置项",
        category: "credential",
        severity: Severity::High,
        pattern: r#"(?i)(?:password|passwd|pwd|密码|口令)\s*[:=：]\s*["']?([^\s"',;，；}]{6,128})"#,
        keywords: &[],
        validators: "entropy:2.0,placeholder",
        description: "password= / 密码： 等赋值语句后的口令",
    },
    RuleSpec {
        id: "generic_secret",
        name: "通用密钥/令牌",
        category: "credential",
        severity: Severity::High,
        pattern: r#"(?i)(?:api[_-]?key|secret(?:[_-]?key)?|token|access[_-]?key|private[_-]?key|client[_-]?secret|密钥|秘钥|令牌)\s*[:=：]\s*["']?([A-Za-z0-9_\-./+=]{16,128})"#,
        keywords: &[],
        validators: "entropy:3.2,placeholder",
        description: "高熵 API Key / Token / Secret 赋值",
    },
    RuleSpec {
        id: "private_key",
        name: "PEM/OpenSSH 私钥",
        category: "crypto",
        severity: Severity::Critical,
        pattern: r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----",
        keywords: &[],
        validators: "none",
        description: "私钥文件头，出现即视为严重风险",
    },
    RuleSpec {
        id: "aws_access_key",
        name: "AWS Access Key ID",
        category: "credential",
        severity: Severity::Critical,
        pattern: r"(?-u:\b)(AKIA[0-9A-Z]{16})(?-u:\b)",
        keywords: &[],
        validators: "none",
        description: "AWS 访问密钥 ID（AKIA 前缀）",
    },
    RuleSpec {
        id: "aws_secret_key",
        name: "AWS Secret Access Key",
        category: "credential",
        severity: Severity::Critical,
        pattern: r#"(?i)aws_?secret_?access_?key\s*[:=]\s*["']?([A-Za-z0-9/+=]{40})"#,
        keywords: &[],
        validators: "entropy:3.5,placeholder",
        description: "AWS 秘密访问密钥赋值",
    },
    RuleSpec {
        id: "github_token",
        name: "GitHub Token",
        category: "credential",
        severity: Severity::Critical,
        pattern: r"(?-u:\b)(gh[pousr]_[A-Za-z0-9]{36,255})(?-u:\b)",
        keywords: &[],
        validators: "placeholder",
        description: "GitHub 个人访问令牌 / OAuth Token",
    },
    RuleSpec {
        id: "google_api_key",
        name: "Google API Key",
        category: "credential",
        severity: Severity::High,
        pattern: r"(?-u:\b)(AIza[0-9A-Za-z_\-]{35})(?-u:\b)",
        keywords: &[],
        validators: "entropy:3.0,placeholder",
        description: "Google API Key（AIza 前缀）",
    },
    RuleSpec {
        id: "slack_token",
        name: "Slack Token",
        category: "credential",
        severity: Severity::High,
        pattern: r"(?-u:\b)(xox[baprs]-[0-9A-Za-z\-]{10,})(?-u:\b)",
        keywords: &[],
        validators: "placeholder",
        description: "Slack Bot/User/App Token",
    },
    RuleSpec {
        id: "stripe_key",
        name: "Stripe Live Key",
        category: "credential",
        severity: Severity::Critical,
        pattern: r"(?-u:\b)((?:sk|rk)_live_[0-9A-Za-z]{20,})(?-u:\b)",
        keywords: &[],
        validators: "placeholder",
        description: "Stripe 生产环境密钥",
    },
    RuleSpec {
        id: "openai_key",
        name: "OpenAI API Key",
        category: "credential",
        severity: Severity::High,
        pattern: r"(?-u:\b)(sk-(?:proj-)?[A-Za-z0-9_\-]{20,})(?-u:\b)",
        keywords: &[],
        validators: "placeholder",
        description: "OpenAI API Key",
    },
    RuleSpec {
        id: "jwt",
        name: "JSON Web Token",
        category: "credential",
        severity: Severity::Medium,
        pattern: r"(?-u:\b)(eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,})(?-u:\b)",
        keywords: &[],
        validators: "placeholder",
        description: "三段式 JWT，可能携带身份信息或权限",
    },
    RuleSpec {
        id: "bearer_token",
        name: "Authorization Bearer Token",
        category: "credential",
        severity: Severity::High,
        pattern: r#"(?i)authorization\s*[:=]\s*["']?bearer\s+([A-Za-z0-9\-._~+/]{16,})"#,
        keywords: &[],
        validators: "entropy:3.0,placeholder",
        description: "HTTP Authorization Bearer 凭据",
    },
    RuleSpec {
        id: "cn_passport",
        name: "中国护照号",
        category: "identity",
        severity: Severity::Medium,
        // 普通护照 E/G + 8 位；2017 年后 E + 字母（不含 I/O）+ 7 位；
        // 公务/外交护照 DE/SE/PE + 7 位。
        pattern: r"(?i)(?-u:\b)((?:E[A-HJ-NP-Z]|E|G|DE|SE|PE)[0-9]{7,8})(?-u:\b)",
        keywords: &[],
        validators: "passport",
        description: "中国护照号，区分普通护照与公务/外交护照的号码规则",
    },
];
