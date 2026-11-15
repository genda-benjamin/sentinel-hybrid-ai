import { test, describe } from 'node:test';
import assert from 'node:assert';
import { writeFileSync, readFileSync, unlinkSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { AutoFixer } from '../core/autofix.js';
import type { LocalFinding, RehydratedRemediation } from '../cloud/types.js';

describe('AutoFixer Unit & Integration Tests', () => {
  test('should accurately replace vulnerable snippet with patch using exact and indented match', () => {
    const rawContent = `
import express from 'express';
const app = express();

app.get('/user', (req, res) => {
  const id = req.query.id;
  db.query("SELECT * FROM users WHERE id = " + id);
});
`.trim();

    const snippet = `db.query("SELECT * FROM users WHERE id = " + id);`;
    const patch = `db.query("SELECT * FROM users WHERE id = ?", [id]);`;

    const { updatedContent, replaced } = AutoFixer.applySnippetReplacement(
      rawContent,
      snippet,
      patch
    );

    assert.strictEqual(replaced, true);
    assert.ok(updatedContent.includes('db.query("SELECT * FROM users WHERE id = ?", [id]);'));
    assert.ok(!updatedContent.includes('"SELECT * FROM users WHERE id = " + id'));
  });

  test('should perform dry-run without writing to disk', () => {
    const tmpPath = join(tmpdir(), `sentinel-test-dryrun-${Date.now()}.js`);
    const originalCode = `const p = req.query.path; fs.readFileSync("/data/" + p);`;
    writeFileSync(tmpPath, originalCode, 'utf-8');

    const finding: LocalFinding = {
      id: 'FIND-001',
      file: tmpPath,
      line: 1,
      ruleId: 'PATH-TRAVERSAL',
      cwe: 'CWE-22',
      owaspCategory: 'A01:2021',
      severity: 'HIGH',
      message: 'Unvalidated path concatenation',
      snippet: 'fs.readFileSync("/data/" + p);',
      requiresCloudReasoning: true
    };

    const remediation: RehydratedRemediation = {
      findingId: 'FIND-001',
      rehydratedPatch: 'fs.readFileSync(path.resolve("/data", path.basename(p)));',
      verifiedLocalPass: true,
      explanation: 'Mitigates path traversal via path.basename sanitization',
      cvssScore: 7.5,
      engineUsed: 'meta-muse-spark'
    };

    const diffs = AutoFixer.remediateFile(tmpPath, [finding], [remediation], { dryRun: true });

    assert.strictEqual(diffs.length, 1);
    assert.strictEqual(diffs[0].applied, false);

    // Verify file on disk remained completely untouched
    const diskContent = readFileSync(tmpPath, 'utf-8');
    assert.strictEqual(diskContent, originalCode);

    unlinkSync(tmpPath);
  });

  test('should apply changes to disk and create .bak backup when requested', () => {
    const tmpPath = join(tmpdir(), `sentinel-test-apply-${Date.now()}.js`);
    const originalCode = `const cmd = req.query.cmd; execSync("ping " + cmd);`;
    writeFileSync(tmpPath, originalCode, 'utf-8');

    const finding: LocalFinding = {
      id: 'FIND-002',
      file: tmpPath,
      line: 1,
      ruleId: 'COMMAND-INJECTION',
      cwe: 'CWE-78',
      owaspCategory: 'A03:2021',
      severity: 'CRITICAL',
      message: 'Direct command execution from untrusted input',
      snippet: 'execSync("ping " + cmd);',
      requiresCloudReasoning: true
    };

    const remediation: RehydratedRemediation = {
      findingId: 'FIND-002',
      rehydratedPatch: 'execFileSync("ping", [String(cmd).trim()]);',
      verifiedLocalPass: true,
      explanation: 'Replaced execSync with parameterized execFileSync',
      cvssScore: 9.8,
      engineUsed: 'hybrid-ensemble'
    };

    const diffs = AutoFixer.remediateFile(tmpPath, [finding], [remediation], {
      dryRun: false,
      createBackup: true
    });

    assert.strictEqual(diffs.length, 1);
    assert.strictEqual(diffs[0].applied, true);

    // Verify disk content was updated
    const updatedDisk = readFileSync(tmpPath, 'utf-8');
    assert.ok(updatedDisk.includes('execFileSync("ping", [String(cmd).trim()]);'));

    // Verify backup exists with original content
    const backupPath = `${tmpPath}.bak`;
    assert.strictEqual(existsSync(backupPath), true);
    assert.strictEqual(readFileSync(backupPath, 'utf-8'), originalCode);

    unlinkSync(tmpPath);
    unlinkSync(backupPath);
  });

  test('should generate structured enterprise PR Markdown with compliance mappings', () => {
    const finding: LocalFinding = {
      id: 'FIND-003',
      file: 'src/api/auth.ts',
      line: 42,
      ruleId: 'SQLI-RAW',
      cwe: 'CWE-89',
      owaspCategory: 'A03:2021',
      severity: 'CRITICAL',
      message: 'SQL Injection via query string',
      snippet: 'pool.query(`SELECT * FROM accounts WHERE token = "${tok}"`);',
      requiresCloudReasoning: true
    };

    const remediation: RehydratedRemediation = {
      findingId: 'FIND-003',
      rehydratedPatch: 'pool.query("SELECT * FROM accounts WHERE token = $1", [tok]);',
      verifiedLocalPass: true,
      explanation: 'Use parameterized PostgreSQL query',
      cvssScore: 9.6,
      engineUsed: 'meta-muse-spark'
    };

    const { title, body } = AutoFixer.generatePrMarkdown([finding], [remediation], ['src/api/auth.ts']);

    assert.ok(title.includes('fix(security): auto-remediate 1 vulnerabilities (CWE-89)'));
    assert.ok(body.includes('SOC 2 Type II (CC6.1)'));
    assert.ok(body.includes('GDPR Art. 32'));
    assert.ok(body.includes('CWE-89'));
    assert.ok(body.includes('Zero-Leakage Airgap'));
    assert.ok(body.includes('```diff'));
  });

  test('should synthesize self-healing PR payload with branch naming conventions', () => {
    const finding: LocalFinding = {
      id: 'FIND-004',
      file: 'src/server.ts',
      line: 10,
      ruleId: 'COMMAND-INJECTION',
      cwe: 'CWE-78',
      owaspCategory: 'A03:2021',
      severity: 'CRITICAL',
      message: 'Command injection',
      snippet: 'exec(cmd);',
      requiresCloudReasoning: true
    };

    const remediation: RehydratedRemediation = {
      findingId: 'FIND-004',
      rehydratedPatch: 'execFile(cmd, []);',
      verifiedLocalPass: true,
      explanation: 'Parameterized command invocation',
      cvssScore: 9.0
    };

    const result = AutoFixer.createSelfHealingPR({
      repoDir: tmpdir(),
      modifiedFiles: ['src/server.ts'],
      findings: [finding],
      remediations: [remediation],
      branchPrefix: 'sentinel/security-patch'
    });

    assert.ok(result.branchCreated?.startsWith('sentinel/security-patch-'));
    assert.strictEqual(result.prPayload?.base, 'main');
    assert.ok(result.prPayload?.title.includes('CWE-78'));
    assert.ok(result.prPayload?.body.includes('Sentinel-AI Autonomous Security Remediation'));
  });
});
