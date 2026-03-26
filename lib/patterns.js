/**
 * Deterministic security patterns — 30+ regex checks.
 * Ported from gitlab-security-agent/src/scanners/deterministic.js
 */

export const PATTERNS = [
  // === SECRETS & CREDENTIALS ===
  { id: 'secret-aws-key', name: 'AWS Access Key', regex: /(?:AWS_ACCESS_KEY_ID|aws_access_key_id|AKIA)[=:\s'"]*([A-Z0-9]{16,})/, severity: 'critical', category: 'hardcoded_secret', message: 'AWS access key detected. Remove immediately and rotate the key.' },
  { id: 'secret-aws-secret', name: 'AWS Secret Key', regex: /(?:AWS_SECRET_ACCESS_KEY|aws_secret_access_key)[=:\s'"]*([A-Za-z0-9/+=]{30,})/, severity: 'critical', category: 'hardcoded_secret', message: 'AWS secret key detected. Remove and rotate immediately.' },
  { id: 'secret-generic-api-key', name: 'Generic API Key', regex: /(?:api[_-]?key|apikey|api[_-]?secret|api[_-]?token)[=:\s'"]+[A-Za-z0-9_\-]{20,}/i, severity: 'high', category: 'hardcoded_secret', message: 'Possible hardcoded API key. Use environment variables instead.' },
  { id: 'secret-private-key', name: 'Private Key', regex: /-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/, severity: 'critical', category: 'hardcoded_secret', message: 'Private key embedded in source code. Remove and rotate immediately.' },
  { id: 'secret-password-assign', name: 'Hardcoded Password', regex: /(?:password|passwd|pwd|secret)\s*[:=]\s*['"][^'"]{8,}['"]/i, severity: 'high', category: 'hardcoded_secret', message: 'Possible hardcoded password. Use a secrets manager or environment variables.' },
  { id: 'secret-jwt-token', name: 'JWT Token', regex: /eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/, severity: 'high', category: 'hardcoded_secret', message: 'JWT token found in source code. Tokens should not be committed.' },
  { id: 'secret-connection-string', name: 'Database Connection String', regex: /(?:mongodb|postgres|mysql|redis|amqp):\/\/[^\s'"]+:[^\s'"]+@[^\s'"]+/i, severity: 'critical', category: 'hardcoded_secret', message: 'Database connection string with credentials detected. Use environment variables.' },

  // === SQL INJECTION ===
  { id: 'sqli-fstring', name: 'SQL Injection (f-string)', regex: /f["'](?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE)\s.*\{[^}]+\}/i, severity: 'high', category: 'sql_injection', languages: ['python'], message: 'SQL query with f-string interpolation. Use parameterized queries.' },
  { id: 'sqli-concat', name: 'SQL Injection (concatenation)', regex: /["'](?:SELECT|INSERT|UPDATE|DELETE|DROP)\s[^"']*["']\s*\+\s*(?!['"])/i, severity: 'high', category: 'sql_injection', message: 'SQL query built with string concatenation. Use parameterized queries.' },
  { id: 'sqli-template-literal', name: 'SQL Injection (template literal)', regex: /`(?:SELECT|INSERT|UPDATE|DELETE|DROP)\s[^`]*\$\{[^}]+\}/i, severity: 'high', category: 'sql_injection', languages: ['javascript', 'typescript'], message: 'SQL query with template literal interpolation. Use parameterized queries.' },
  { id: 'sqli-format', name: 'SQL Injection (.format)', regex: /["'](?:SELECT|INSERT|UPDATE|DELETE|DROP)\s.*(?:\.format\(|%\s)/i, severity: 'high', category: 'sql_injection', languages: ['python'], message: 'SQL query with .format() or % formatting. Use parameterized queries.' },

  // === COMMAND INJECTION ===
  { id: 'cmdi-exec', name: 'Command Injection (exec)', regex: /(?:exec|execSync|spawn|spawnSync|child_process)\s*\(\s*(?:`[^`]*\$\{|['"][^'"]*['"]\s*\+)/i, severity: 'critical', category: 'command_injection', languages: ['javascript', 'typescript'], message: 'Command execution with dynamic input. Use argument arrays instead of string interpolation.' },
  { id: 'cmdi-os-system', name: 'Command Injection (os.system)', regex: /os\.(?:system|popen)\s*\(\s*f?["'].*[\{+]/, severity: 'critical', category: 'command_injection', languages: ['python'], message: 'os.system/popen with dynamic input. Use subprocess with argument list.' },
  { id: 'cmdi-subprocess-shell', name: 'Command Injection (subprocess shell)', regex: /subprocess\.(?:call|run|Popen)\s*\([^)]*shell\s*=\s*True/, severity: 'high', category: 'command_injection', languages: ['python'], message: 'subprocess with shell=True. Use shell=False with argument list.' },
  { id: 'cmdi-eval', name: 'Code Injection (eval)', regex: /\beval\s*\(\s*(?!['"](?:true|false|null|undefined)['"])/, severity: 'critical', category: 'command_injection', message: 'eval() usage detected. Avoid eval() — use safe alternatives.' },

  // === XSS ===
  { id: 'xss-innerhtml', name: 'XSS (innerHTML)', regex: /\.innerHTML\s*=\s*(?!['"]<)/, severity: 'high', category: 'xss', languages: ['javascript', 'typescript'], message: 'Direct innerHTML assignment. Use textContent or sanitize input first.' },
  { id: 'xss-dangerously', name: 'XSS (dangerouslySetInnerHTML)', regex: /dangerouslySetInnerHTML\s*=\s*\{\s*\{\s*__html:/, severity: 'medium', category: 'xss', languages: ['javascript', 'typescript'], message: 'dangerouslySetInnerHTML usage. Ensure input is sanitized (e.g., DOMPurify).' },
  { id: 'xss-document-write', name: 'XSS (document.write)', regex: /document\.write\s*\(/, severity: 'high', category: 'xss', languages: ['javascript', 'typescript'], message: 'document.write() is vulnerable to XSS. Use DOM manipulation methods.' },

  // === PATH TRAVERSAL ===
  { id: 'path-traversal', name: 'Path Traversal', regex: /(?:readFile|readFileSync|open|createReadStream)\s*\([^)]*(?:\+|`\$\{|\bformat\()/, severity: 'high', category: 'path_traversal', message: 'File operation with dynamic path. Validate and sanitize the path.' },

  // === WEAK CRYPTO ===
  { id: 'crypto-md5', name: 'Weak Hash (MD5)', regex: /(?:createHash\s*\(\s*['"]md5['"]|hashlib\.md5|\.md5\s*\(|MD5\s*\()/i, severity: 'medium', category: 'weak_crypto', message: 'MD5 is cryptographically broken. Use SHA-256 or bcrypt for passwords.' },
  { id: 'crypto-sha1', name: 'Weak Hash (SHA-1)', regex: /(?:createHash|hashlib\.sha1)\s*\(['"]?sha1['"]?\s*\)?/i, severity: 'medium', category: 'weak_crypto', message: 'SHA-1 is deprecated. Use SHA-256 or stronger.' },
  { id: 'crypto-math-random', name: 'Insecure Random', regex: /Math\.random\s*\(\)/, severity: 'medium', category: 'weak_crypto', languages: ['javascript', 'typescript'], message: 'Math.random() is not cryptographically secure. Use crypto.randomBytes() or crypto.getRandomValues().' },

  // === AUTH ISSUES ===
  { id: 'auth-jwt-none', name: 'JWT Algorithm None', regex: /algorithm['":\s]*['"]?none['"]?/i, severity: 'critical', category: 'jwt_misconfigured', message: 'JWT with "none" algorithm allows forged tokens. Always specify a strong algorithm.' },
  { id: 'auth-jwt-no-verify', name: 'JWT Verify Disabled', regex: /verify\s*[:=]\s*false|algorithms\s*:\s*\[\s*\]/i, severity: 'critical', category: 'jwt_misconfigured', message: 'JWT verification disabled. Always verify tokens with a strong algorithm.' },
  { id: 'auth-cors-wildcard', name: 'CORS Wildcard', regex: /(?:Access-Control-Allow-Origin|cors)\s*[(:={]\s*[{(]?\s*(?:origin\s*:\s*)?['"]?\*['"]?/i, severity: 'medium', category: 'auth_bypass', message: 'CORS wildcard allows any origin. Restrict to specific trusted domains.' },

  // === SSRF ===
  { id: 'ssrf-user-url', name: 'Potential SSRF', regex: /(?:fetch|axios|request|http\.get|urllib|requests\.get)\s*\(\s*(?:req\.|request\.|params\.|query\.|body\.|args\.)/, severity: 'high', category: 'ssrf', message: 'HTTP request with user-controlled URL. Validate and allowlist target hosts.' },

  // === DESERIALIZATION ===
  { id: 'deser-pickle', name: 'Insecure Deserialization (pickle)', regex: /pickle\.(?:loads?|Unpickler)\s*\(/, severity: 'high', category: 'insecure_deserialization', languages: ['python'], message: 'pickle deserialization can execute arbitrary code. Use json or a safe alternative.' },
  { id: 'deser-yaml-load', name: 'Insecure YAML Load', regex: /yaml\.(?:load|unsafe_load)\s*\(/, severity: 'high', category: 'insecure_deserialization', languages: ['python'], message: 'yaml.load() can execute arbitrary code. Use yaml.safe_load() instead.' },

  // === OPEN REDIRECT ===
  { id: 'redirect-unvalidated', name: 'Open Redirect', regex: /(?:redirect|location\.href|window\.location)\s*=\s*(?:req\.|request\.|params\.|query\.)/, severity: 'medium', category: 'open_redirect', message: 'Redirect using user-controlled input. Validate against an allowlist.' },
];

export const COMPLIANCE_MAP = {
  sql_injection:     { soc2: 'CC6.1', gdpr: 'Art.32', pci: '6.5.1', owasp: 'A03:2021' },
  xss:              { soc2: 'CC6.1', gdpr: 'Art.32', pci: '6.5.7', owasp: 'A03:2021' },
  command_injection: { soc2: 'CC6.1', gdpr: 'Art.32', pci: '6.5.1', owasp: 'A03:2021' },
  path_traversal:    { soc2: 'CC6.1', gdpr: 'Art.32', pci: '6.5.8', owasp: 'A01:2021' },
  hardcoded_secret:  { soc2: 'CC6.1', gdpr: 'Art.32', pci: '2.1',   owasp: 'A07:2021' },
  weak_crypto:       { soc2: 'CC6.1', gdpr: 'Art.32', pci: '4.1',   owasp: 'A02:2021' },
  auth_bypass:       { soc2: 'CC6.1', gdpr: 'Art.32', pci: '6.5.10',owasp: 'A01:2021' },
  insecure_deserialization: { soc2: 'CC6.1', gdpr: 'Art.32', pci: '6.5.1', owasp: 'A08:2021' },
  jwt_misconfigured: { soc2: 'CC6.1', gdpr: 'Art.32', pci: '6.5.10',owasp: 'A07:2021' },
  insecure_cookie:   { soc2: 'CC6.1', gdpr: 'Art.32', pci: '6.5.10',owasp: 'A05:2021' },
  ssrf:              { soc2: 'CC6.1', gdpr: 'Art.32', pci: '6.5.1', owasp: 'A10:2021' },
  open_redirect:     { soc2: 'CC6.1', gdpr: 'Art.32', pci: '6.5.10',owasp: 'A01:2021' },
};

const LANG_MAP = {
  js: 'javascript', jsx: 'javascript', mjs: 'javascript', cjs: 'javascript',
  ts: 'typescript', tsx: 'typescript',
  py: 'python', pyw: 'python',
  rb: 'ruby', go: 'go', rs: 'rust', java: 'java',
  php: 'php', cs: 'csharp', swift: 'swift',
  sh: 'shell', bash: 'shell',
};

export function detectLanguage(filename) {
  const ext = filename?.split('.').pop()?.toLowerCase();
  return LANG_MAP[ext] || null;
}

/**
 * Run deterministic scan on code string.
 * Returns array of findings with line numbers.
 */
export function scanCode(code, filename = 'input.js') {
  const lang = detectLanguage(filename);
  const lines = code.split('\n');
  const findings = [];

  for (let i = 0; i < lines.length; i++) {
    const lineContent = lines[i];
    for (const pattern of PATTERNS) {
      if (pattern.languages && lang && !pattern.languages.includes(lang)) continue;
      if (pattern.regex.test(lineContent)) {
        findings.push({
          id: pattern.id,
          name: pattern.name,
          file: filename,
          line: i + 1,
          snippet: lineContent.trim(),
          severity: pattern.severity,
          category: pattern.category,
          message: pattern.message,
          compliance: COMPLIANCE_MAP[pattern.category] || {},
          confidence: 0.9,
          source: 'deterministic',
        });
      }
    }
  }

  return findings;
}
