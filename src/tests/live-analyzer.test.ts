import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { LiveCodeAnalyzer } from '../core/live-analyzer.js';

describe('Live Arbitrary-Code Execution Engine Tests (Days 5-9)', () => {
  it('should measure high-precision dynamic redaction timing with performance.now()', () => {
    const code = `const key = "sk-proj-1234567890abcdef1234567890abcdef";\nconst db = "postgres://root:password123@localhost:5432/app";`;
    const { sanitized, items, redactionTimeMs } = LiveCodeAnalyzer.vaultCredentials(code);

    assert.ok(redactionTimeMs > 0, 'Redaction timing must be positive dynamic measurement');
    assert.strictEqual(items.length, 2);
    assert.ok(sanitized.includes('[VAULT_TOKEN_001]'));
    assert.ok(sanitized.includes('[VAULT_TOKEN_002]'));
    assert.ok(!sanitized.includes('password123'), 'Plaintext password must be completely vaulted');
  });

  it('should dynamically analyze arbitrary SQL injection code and generate unified diff', () => {
    const arbitraryCode = `// User service endpoint
app.get('/search', async (req, res) => {
  const query = req.query.term;
  const items = await db.query("SELECT * FROM products WHERE name = '" + query + "'");
  res.json(items);
});`;

    const result = LiveCodeAnalyzer.analyze(arbitraryCode, 'searchController.ts');

    assert.strictEqual(result.detectedCwe, 'CWE-89');
    assert.strictEqual(result.severity, 'CRITICAL');
    assert.strictEqual(result.cvss, 9.8);
    assert.strictEqual(result.vulnerableLineNumber, 4);
    assert.ok(result.unifiedDiff.includes('--- a/searchController.ts'));
    assert.ok(result.unifiedDiff.includes('+++ b/searchController.ts'));
    assert.ok(result.unifiedDiff.includes('-  const items = await db.query'));
    assert.ok(result.unifiedDiff.includes('+  // REMEDIATION: Replace dynamic string concatenation'));
    assert.ok(result.exploitTestCode.includes("describe('Security Invariant Verification: SQL Injection (CWE-89)'"));
  });

  it('should dynamically analyze arbitrary command injection code', () => {
    const arbitraryCode = `import { exec } from 'node:child_process';
export function executeDiagnostics(target) {
  exec("traceroute " + target, (err, out) => console.log(out));
}`;

    const result = LiveCodeAnalyzer.analyze(arbitraryCode, 'diagnostics.ts');

    assert.strictEqual(result.detectedCwe, 'CWE-78');
    assert.strictEqual(result.cweTitle, 'OS Command Injection');
    assert.strictEqual(result.severity, 'CRITICAL');
    assert.strictEqual(result.vulnerableLineNumber, 3);
    assert.ok(result.remediatedLineText.includes('execFile'));
    assert.strictEqual(result.taintGraph.sink.file, 'diagnostics.ts');
  });

  it('should dynamically analyze arbitrary path traversal code', () => {
    const arbitraryCode = `import fs from 'node:fs';
export function downloadReport(req, res) {
  const userFile = req.params.filename;
  fs.readFile('/reports/' + userFile, (err, data) => res.send(data));
}`;

    const result = LiveCodeAnalyzer.analyze(arbitraryCode, 'reports.ts');

    assert.strictEqual(result.detectedCwe, 'CWE-22');
    assert.strictEqual(result.cweTitle, 'Path Traversal');
    assert.strictEqual(result.severity, 'HIGH');
    assert.strictEqual(result.vulnerableLineNumber, 4);
    assert.ok(result.remediatedLineText.includes('path.resolve'));
  });

  it('should dynamically analyze arbitrary SSRF code', () => {
    const arbitraryCode = `import axios from 'axios';
export async function proxyWebhook(targetUrl) {
  return (await axios.get(targetUrl)).data;
}`;

    const result = LiveCodeAnalyzer.analyze(arbitraryCode, 'webhook.ts');

    assert.strictEqual(result.detectedCwe, 'CWE-918');
    assert.strictEqual(result.cweTitle, 'Server-Side Request Forgery');
    assert.strictEqual(result.severity, 'HIGH');
    assert.ok(result.remediatedLineText.includes('ALLOWED_HOSTS'));
  });

  it('should dynamically verify safe clean code without reporting false positives', () => {
    const safeCode = `import express from 'express';
export function addNumbers(a, b) {
  return a + b;
}`;

    const result = LiveCodeAnalyzer.analyze(safeCode, 'math.ts');

    assert.strictEqual(result.detectedCwe, 'CWE-000');
    assert.strictEqual(result.cvss, 0.0);
    assert.strictEqual(result.severity, 'LOW');
    assert.ok(result.remediationExplanation.includes('zero detected vulnerabilities'));
  });

  it('should generate valid OASIS SARIF v2.1.0 finding object for arbitrary code', () => {
    const code = `const q = "SELECT * FROM users WHERE id = " + userId;`;
    const result = LiveCodeAnalyzer.analyze(code, 'query.ts');

    assert.strictEqual(result.sarifFinding.ruleId, 'SEC-089');
    assert.strictEqual(result.sarifFinding.level, 'error');
    assert.ok(result.sarifFinding.cwe.includes('CWE-89'));
  });
});
