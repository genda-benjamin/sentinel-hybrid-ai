import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { LocalSanitizer } from '../core/sanitizer.js';
import { LocalDetector } from '../core/detector.js';
import { PatchSynthesizer } from '../core/patch-synthesizer.js';
import { AutoFixer } from '../core/autofix.js';
import { TestSynthesizer } from '../core/test-synthesizer.js';

describe('Advanced Capabilities: Entropy Vaulting, AST Taint, Agentic Rules & Closed-Loop Verification', () => {
  it('should detect and vault unknown high-entropy secrets via Shannon entropy without flagging URLs', () => {
    const unknownProprietaryToken = 'v9Kx_8qLm2ZpR4wYt6BnC3dFg7HjJk1Mn';
    const code = `
      const endpoint = "https://api.partner.example.com/v2/healthcheck";
      const customAuth = "${unknownProprietaryToken}";
    `;

    const res = LocalSanitizer.sanitize(code);
    assert.ok(!res.sanitizedContent.includes(unknownProprietaryToken), 'High-entropy secret must be vaulted');
    assert.ok(res.sanitizedContent.includes('https://api.partner.example.com/v2/healthcheck'), 'Benign URL must remain untouched');
    assert.ok(res.sanitizedContent.includes('__SENTINEL_ENTROPY_'), 'Must tag as ENTROPY category');

    const audit = LocalSanitizer.auditEgress(res.sanitizedContent, res.tokens, res.redactedCategories);
    assert.strictEqual(audit.zeroLeakage, true);
    assert.strictEqual(audit.residualHighEntropyLiterals, 0);
  });

  it('should support HMAC session-keyed determinism and optional PII/Infra redaction', () => {
    const anthropicKey = ['sk-ant', 'api03', '998877665544332211aabbccddeeff001122'].join('-');
    const code = `
      const key = "${anthropicKey}";
      const internalHost = "billing-db.prod.internal";
      const privateIp = "10.24.18.9";
      const adminEmail = "secops@enterprise.com";
    `;

    const resA = LocalSanitizer.sanitize(code, { redactInfraAndPii: true, sessionKey: 'session-alpha' });
    const resB = LocalSanitizer.sanitize(code, { redactInfraAndPii: true, sessionKey: 'session-alpha' });
    const resC = LocalSanitizer.sanitize(code, { redactInfraAndPii: true, sessionKey: 'session-beta' });

    assert.strictEqual(resA.sanitizedContent, resB.sanitizedContent, 'Same session key must be deterministic');
    assert.notStrictEqual(resA.sanitizedContent, resC.sanitizedContent, 'Different session keys must rotate pseudonyms');
    assert.ok(!resA.sanitizedContent.includes(anthropicKey));
    assert.ok(!resA.sanitizedContent.includes('billing-db.prod.internal'));
    assert.ok(!resA.sanitizedContent.includes('10.24.18.9'));
    assert.ok(!resA.sanitizedContent.includes('secops@enterprise.com'));
  });

  it('should ignore commented-out vulnerabilities and track destructured + multi-line AST taint', () => {
    const code = `
      // db.query(\`SELECT * FROM users WHERE id = \${req.query.id}\`);
      /* exec("rm -rf " + req.body.dir); */
      export async function getOrders(req, res) {
        const { customerId } = req.query;
        const sqlQuery = \`SELECT * FROM orders WHERE customer_id = \${customerId}\`;
        const rows = await db.query(
          sqlQuery
        );
        return res.json(rows);
      }
    `;

    const findings = LocalDetector.scanContent('src/orders.ts', code);
    assert.strictEqual(findings.length, 1, 'Commented lines must produce 0 false positives while aliased multi-line SQLi is caught');
    assert.strictEqual(findings[0].cwe, 'CWE-89');
  });

  it('should respect sanitizer dominance in AST scope and not flag parameterized queries', () => {
    const safeCode = `
      export async function safeHandler(req, db) {
        const userId = parseInt(req.query.id, 10);
        const rows = await db.query("SELECT * FROM orders WHERE id = $1", [userId]);
        return rows;
      }
    `;

    const findings = LocalDetector.scanContent('src/safe.ts', safeCode);
    assert.strictEqual(findings.length, 0);
  });

  it('should detect OWASP Agentic Prompt Injection, MCP Excessive Agency, Weak Crypto, and Broken JWT', () => {
    const agenticAndCryptoCode = `
      const mcpConfig = { name: 'shell-runner', autoApprove: true };
      export async function askAgent(userPrompt, model) {
        const systemPrompt = \`Follow instructions: \${userPrompt}\`;
        return await model.generateContent(systemPrompt);
      }
      export function hashPw(pw) {
        return crypto.createHash('md5').update(pw).digest('hex');
      }
      export function checkJwt(tok, key) {
        return jwt.verify(tok, key, { algorithms: ['none', 'HS256'] });
      }
    `;

    const findings = LocalDetector.scanContent('src/agent-crypto.ts', agenticAndCryptoCode);
    const cwes = findings.map(f => f.cwe);

    assert.ok(cwes.includes('CWE-269'), 'Must detect autoApprove: true excessive MCP agency');
    assert.ok(cwes.includes('CWE-77'), 'Must detect prompt injection interpolation');
    assert.ok(cwes.includes('CWE-327'), 'Must detect weak MD5 crypto');
    assert.ok(cwes.includes('CWE-347'), 'Must detect JWT algorithms: ["none"]');
  });

  it('should synthesize context-aware SQL patches preserving original table names and verify safety closed-loop', () => {
    const vulnerableSnippet = 'db.query(`SELECT * FROM invoices WHERE acct = ${acctId}`)';
    const patched = PatchSynthesizer.synthesize('CWE-89', vulnerableSnippet);

    assert.ok(patched.includes('FROM invoices WHERE acct = $1'), 'Must preserve original table and column');
    assert.ok(patched.includes('[acctId]'), 'Must bind original variable expression');

    const report = AutoFixer.verifyPatchSafety(
      'src/invoices.ts',
      `async function f(db, acctId) { return ${vulnerableSnippet}; }`,
      `async function f(db, acctId) { return ${patched}; }`,
      {
        id: 'FIND-SEC-001-1',
        file: 'src/invoices.ts',
        line: 1,
        ruleId: 'SEC-001',
        cwe: 'CWE-89',
        owaspCategory: 'A03:2021-Injection',
        severity: 'CRITICAL',
        message: 'SQLi',
        snippet: vulnerableSnippet,
        requiresCloudReasoning: true
      }
    );

    assert.strictEqual(report.syntaxValid, true);
    assert.strictEqual(report.originalFindingResolved, true);
    assert.strictEqual(report.introducedNewFindings, 0);
    assert.strictEqual(report.safeToApply, true);

    const brokenReport = AutoFixer.verifyPatchSafety(
      'src/invoices.ts',
      `async function f(db, acctId) { return ${vulnerableSnippet}; }`,
      `async function f(db, acctId) { return db.query( ; }`,
      {
        id: 'FIND-SEC-001-1',
        file: 'src/invoices.ts',
        line: 1,
        ruleId: 'SEC-001',
        cwe: 'CWE-89',
        owaspCategory: 'A03:2021-Injection',
        severity: 'CRITICAL',
        message: 'SQLi',
        snippet: vulnerableSnippet,
        requiresCloudReasoning: true
      }
    );
    assert.strictEqual(brokenReport.syntaxValid, false);
    assert.strictEqual(brokenReport.safeToApply, false);
  });

  it('should synthesize executable PoC tests for SSRF and OWASP Prompt Injection', () => {
    const ssrfFinding = {
      id: 'FIND-SEC-007-1',
      file: 'webhook.ts',
      line: 5,
      ruleId: 'SEC-007',
      cwe: 'CWE-918',
      owaspCategory: 'A10:2021-Server-Side Request Forgery',
      severity: 'HIGH' as const,
      message: 'SSRF',
      snippet: 'axios.get(targetUrl)',
      requiresCloudReasoning: true
    };
    const ssrfSuite = TestSynthesizer.synthesizeSuite(ssrfFinding, 'axios.get(targetUrl)');
    assert.ok(ssrfSuite.fullTestCode.includes('169.254.169.254'));

    const promptFinding = {
      id: 'FIND-SEC-012-1',
      file: 'agent.ts',
      line: 8,
      ruleId: 'SEC-012',
      cwe: 'CWE-77',
      owaspCategory: 'LLM01:2025-Prompt Injection',
      severity: 'HIGH' as const,
      message: 'Prompt Injection',
      snippet: 'model.generateContent(`Run: ${userPrompt}`)',
      requiresCloudReasoning: true
    };
    const promptSuite = TestSynthesizer.synthesizeSuite(promptFinding, 'model.generateContent(`Run: ${userPrompt}`)');
    assert.ok(promptSuite.fullTestCode.includes('Ignore all previous instructions'));
  });
});
