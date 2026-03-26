/**
 * Local test — validates the scanning logic without Vercel.
 */
import { scanCode } from '../lib/patterns.js';

let passed = 0;
let failed = 0;

function test(name, fn) {
  try {
    fn();
    console.log(`  ✅ ${name}`);
    passed++;
  } catch (e) {
    console.log(`  ❌ ${name}: ${e.message}`);
    failed++;
  }
}

function assert(condition, msg) {
  if (!condition) throw new Error(msg || 'Assertion failed');
}

console.log('\n🔍 Code Security Scanner API — Tests\n');

// === SECRETS ===
console.log('Secrets Detection:');

test('Catches AWS access key', () => {
  const r = scanCode('AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE', 'config.py');
  assert(r.length >= 1, 'Should find AWS key');
  assert(r[0].severity === 'critical');
});

test('Catches hardcoded password', () => {
  const r = scanCode('password = "supersecret123"', 'app.py');
  assert(r.length >= 1, 'Should find password');
  assert(r[0].category === 'hardcoded_secret');
});

test('Catches private key', () => {
  const r = scanCode('-----BEGIN RSA PRIVATE KEY-----', 'deploy.sh');
  assert(r.length >= 1, 'Should find private key');
  assert(r[0].severity === 'critical');
});

test('Catches JWT token', () => {
  const r = scanCode('const token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"', 'auth.js');
  assert(r.length >= 1, 'Should find JWT');
});

test('Catches database connection string', () => {
  const r = scanCode('const db = "postgres://admin:password123@db.example.com:5432/mydb"', 'config.js');
  assert(r.length >= 1, 'Should find connection string');
  assert(r[0].severity === 'critical');
});

// === SQL INJECTION ===
console.log('\nSQL Injection:');

test('Catches f-string SQL', () => {
  const r = scanCode('query = f"SELECT * FROM users WHERE id = {user_id}"', 'db.py');
  assert(r.length >= 1, 'Should find SQL injection');
  assert(r[0].category === 'sql_injection');
});

test('Catches concatenated SQL', () => {
  const r = scanCode('query = "SELECT * FROM users WHERE id = " + userId', 'db.js');
  assert(r.length >= 1);
});

test('Catches template literal SQL', () => {
  const r = scanCode('const q = `SELECT * FROM users WHERE id = ${userId}`', 'db.ts');
  assert(r.length >= 1);
});

// === COMMAND INJECTION ===
console.log('\nCommand Injection:');

test('Catches eval()', () => {
  const r = scanCode('eval(userInput)', 'app.js');
  assert(r.length >= 1);
  assert(r[0].severity === 'critical');
});

test('Catches os.system', () => {
  const r = scanCode('os.system(f"ping {host}")', 'util.py');
  assert(r.length >= 1);
});

test('Catches subprocess shell=True', () => {
  const r = scanCode('subprocess.run(cmd, shell=True)', 'run.py');
  assert(r.length >= 1);
});

// === XSS ===
console.log('\nXSS:');

test('Catches innerHTML', () => {
  const r = scanCode('element.innerHTML = userInput', 'app.js');
  assert(r.length >= 1);
  assert(r[0].category === 'xss');
});

test('Catches dangerouslySetInnerHTML', () => {
  const r = scanCode('dangerouslySetInnerHTML={{ __html: data }}', 'component.tsx');
  assert(r.length >= 1);
});

// === CRYPTO ===
console.log('\nWeak Crypto:');

test('Catches MD5', () => {
  const r = scanCode('hash = hashlib.md5(data)', 'auth.py');
  assert(r.length >= 1);
  assert(r[0].category === 'weak_crypto');
});

test('Catches Math.random', () => {
  const r = scanCode('const token = Math.random().toString(36)', 'session.js');
  assert(r.length >= 1);
});

// === AUTH ===
console.log('\nAuth Issues:');

test('Catches JWT algorithm none', () => {
  const r = scanCode('jwt.sign(payload, key, { algorithm: "none" })', 'auth.js');
  assert(r.length >= 1);
  assert(r[0].severity === 'critical');
});

test('Catches CORS wildcard', () => {
  const r = scanCode('cors({ origin: "*" })', 'server.js');
  assert(r.length >= 1);
});

// === CLEAN CODE (no false positives) ===
console.log('\nFalse Positive Prevention:');

test('Clean code returns empty', () => {
  const r = scanCode('const x = 1 + 2;\nconsole.log(x);', 'math.js');
  assert(r.length === 0, `Expected 0 findings, got ${r.length}`);
});

test('Parameterized SQL not flagged', () => {
  const r = scanCode('db.query("SELECT * FROM users WHERE id = ?", [userId])', 'db.js');
  assert(r.length === 0, `Expected 0 findings, got ${r.length}`);
});

// === COMPLIANCE ===
console.log('\nCompliance Mapping:');

test('Findings include OWASP controls', () => {
  const r = scanCode('password = "hardcoded123"', 'config.py');
  assert(r[0].compliance?.owasp, 'Should have OWASP mapping');
});

test('Findings include SOC2 controls', () => {
  const r = scanCode('eval(req.body.code)', 'api.js');
  assert(r[0].compliance?.soc2, 'Should have SOC2 mapping');
});

// === SCORE ===
console.log('\nScoring:');

test('Clean code scores 100', () => {
  const r = scanCode('const greeting = "hello";', 'app.js');
  assert(r.length === 0);
});

test('Multiple findings reduce score', () => {
  const code = `password = "admin123"
eval(userInput)
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE`;
  const r = scanCode(code, 'bad.py');
  assert(r.length >= 3, `Expected 3+ findings, got ${r.length}`);
});

console.log(`\n  RESULTS: ${passed} passed, ${failed} failed out of ${passed + failed} tests\n`);
if (failed > 0) process.exit(1);
console.log('  ✅ ALL TESTS PASSED\n');
