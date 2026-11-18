/**
 * Sentinel-AI Web Studio & Client Bundle Verification Tests
 * Engineered for Google #BuildHybridAI 2026 Hackathon
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync } from 'node:fs';
import { resolve } from 'node:path';
import { LiveCodeAnalyzer } from '../core/live-analyzer.js';

describe('Web Studio Client Bundle & Dynamic DOM Engine Tests', () => {
  const rootDir = resolve(process.cwd());
  const docsHtmlPath = resolve(rootDir, 'docs', 'index.html');
  const docsAppJsPath = resolve(rootDir, 'docs', 'app.js');
  const webAppJsPath = resolve(rootDir, 'web', 'app.js');

  it('should verify deployment bundle exists and is synchronized across docs/ and web/', () => {
    assert.ok(existsSync(docsAppJsPath), 'docs/app.js must exist');
    assert.ok(existsSync(webAppJsPath), 'web/app.js must exist');

    const docsJs = readFileSync(docsAppJsPath, 'utf8');
    const webJs = readFileSync(webAppJsPath, 'utf8');
    assert.equal(docsJs, webJs, 'docs/app.js and web/app.js must be byte-for-byte identical');
    assert.ok(docsJs.length > 10000, 'app.js bundle must contain complete engine implementation');
  });

  it('should verify docs/index.html loads compiled app.js and has purged all static mocks', () => {
    assert.ok(existsSync(docsHtmlPath), 'docs/index.html must exist');
    const html = readFileSync(docsHtmlPath, 'utf8');

    // 1. Must load script src="app.js"
    assert.ok(html.includes('<script src="app.js"></script>'), 'docs/index.html must load app.js bundle');

    // 2. Must not contain hardcoded mock secrets in HTML
    assert.ok(!html.includes('postgres://root:SuperSecretPassword2026@cluster0.db.internal:5432/production ➔ [VAULT_TOKEN_001]'),
      'docs/index.html must NOT contain hardcoded mock credentials in DOM');

    // 3. Must not contain frozen static latency in HTML
    assert.ok(!html.includes('id="hudRedactTime">0.38 ms</div>'),
      'docs/index.html must NOT contain frozen 0.38 ms static latency metric');

    // 4. Must not contain hardcoded static diff in diffView
    assert.ok(!html.includes('<span class="diff-del">-  const userData = await db.query'),
      'docs/index.html diffView must not contain hardcoded static diff');

    // 5. Must contain loading spinner styling
    assert.ok(html.includes('.loading-spinner'), 'docs/index.html must include loading spinner styles');
    assert.ok(html.includes('.diff-loading-box'), 'docs/index.html must include diff loading container styles');
  });

  it('should dynamically execute arbitrary user code with live AST vaulting and real performance.now() timing', () => {
    const arbitraryUserCode = `
      import express from 'express';
      const app = express();
      const PROD_KEY = "sk-proj-test998877665544332211aabbccddee";
      app.get('/search', async (req, res) => {
        const query = req.query.q;
        const out = await db.query(\`SELECT * FROM inventory WHERE item = \${query}\`);
        res.json(out);
      });
    `;

    const result = LiveCodeAnalyzer.analyze(arbitraryUserCode, 'custom-input.ts', 'hybrid');

    // 1. Dynamic timing verification (> 0 ms, non-static)
    assert.ok(result.redactionTimeMs > 0, 'Redaction timing must be dynamically calculated');
    assert.ok(result.inferenceTimeMs > 0, 'Inference timing must be dynamically calculated');

    // 2. Secret vaulting
    assert.equal(result.vaultCount, 1);
    assert.ok(!result.sanitizedCode.includes('sk-proj-test998877665544332211aabbccddee'), 'Secret must be vaulted');
    assert.ok(result.sanitizedCode.includes('[VAULT_TOKEN_001]'), 'Vault token must replace secret');

    // 3. Dynamic vulnerability detection
    assert.equal(result.detectedCwe, 'CWE-89');
    assert.equal(result.severity, 'CRITICAL');
    assert.equal(result.cvss, 9.8);

    // 4. Dynamic unified diff
    assert.ok(result.unifiedDiff.startsWith('--- a/custom-input.ts\n+++ b/custom-input.ts'));
    assert.ok(result.unifiedDiff.includes('-  const out = await db.query'));
    assert.ok(result.unifiedDiff.includes('+  // REMEDIATION:'));

    // 5. Dynamic node:test suite
    assert.ok(result.exploitTestCode.includes('describe(\'Security Invariant Verification: SQL Injection (CWE-89)\''));
    assert.ok(result.exploitTestCode.includes('assert.ok('));

    // 6. Dynamic SARIF v2.1.0 finding
    assert.equal(result.sarifFinding.ruleId, 'SEC-089');
    assert.equal(result.sarifFinding.level, 'error');

    // 7. Dynamic Taint Graph
    assert.equal(result.taintGraph.source.name, 'query');
    assert.equal(result.taintGraph.airgap.vaultedCount, 1);
  });

  it('should dynamically detect command injection in arbitrary code with template literals', () => {
    const cmdCode = `
      import { exec } from 'node:child_process';
      export function ping(host) {
        exec(\`ping -c 1 \${host}\`, (err, stdout) => console.log(stdout));
      }
    `;

    const result = LiveCodeAnalyzer.analyze(cmdCode, 'ping-service.ts', 'on-device');
    assert.equal(result.detectedCwe, 'CWE-78');
    assert.equal(result.severity, 'CRITICAL');
    assert.ok(result.unifiedDiff.includes('child_process.execFile'));
    assert.equal(result.executionTier, 'on-device');
  });

  it('should dynamically report clean code with zero findings when no vulnerabilities exist', () => {
    const safeCode = `
      export function add(a: number, b: number): number {
        return a + b;
      }
    `;

    const result = LiveCodeAnalyzer.analyze(safeCode, 'math.ts', 'hybrid');
    assert.equal(result.detectedCwe, 'CWE-000');
    assert.equal(result.severity, 'LOW');
    assert.equal(result.cvss, 0.0);
    assert.equal(result.vaultCount, 0);
    assert.ok(result.unifiedDiff.includes('// Invariant Verified: Code conforms to OWASP Top 10 guidelines'));
  });
});
