import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, unlinkSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { TestSynthesizer } from '../core/test-synthesizer.js';
import type { LocalFinding } from '../cloud/types.js';

describe('TestSynthesizer Unit & Integration Tests', () => {
  const mockFindingSql: LocalFinding = {
    id: 'FINDING-SQL-01',
    file: 'sample/vulnerable-app.ts',
    line: 14,
    ruleId: 'SEC-SQL-INJECTION',
    cwe: 'CWE-89: Improper Neutralization of Special Elements used in an SQL Command',
    severity: 'CRITICAL',
    message: 'Direct concatenation into database query permits SQL injection.',
    snippet: 'db.query("SELECT * FROM users WHERE id = " + userId)',
    owaspCategory: 'A03:2021-Injection',
    requiresCloudReasoning: true
  };

  const mockFindingCmd: LocalFinding = {
    id: 'FINDING-CMD-01',
    file: 'sample/admin.ts',
    line: 22,
    ruleId: 'SEC-COMMAND-INJECTION',
    cwe: 'CWE-78: Improper Neutralization of Special Elements used in an OS Command',
    severity: 'CRITICAL',
    message: 'OS command execution with unsanitized user argument.',
    snippet: 'exec("ping -c 1 " + host)',
    owaspCategory: 'A03:2021-Injection',
    requiresCloudReasoning: true
  };

  const mockFindingPath: LocalFinding = {
    id: 'FINDING-PATH-01',
    file: 'sample/file-server.ts',
    line: 35,
    ruleId: 'SEC-PATH-TRAVERSAL',
    cwe: 'CWE-22: Improper Limitation of a Pathname to a Restricted Directory',
    severity: 'HIGH',
    message: 'Relative pathname permits directory traversal.',
    snippet: 'fs.readFileSync(baseDir + "/" + filename)',
    owaspCategory: 'A01:2021-Broken Access Control',
    requiresCloudReasoning: true
  };

  it('should generate tailored attack and benign payloads per CWE category', () => {
    const sqlPayloads = TestSynthesizer.getPayloadsForCwe(mockFindingSql.cwe);
    assert.match(sqlPayloads.exploitPayload, /OR '1'='1'/);
    assert.strictEqual(sqlPayloads.benignPayload, '42');

    const cmdPayloads = TestSynthesizer.getPayloadsForCwe(mockFindingCmd.cwe);
    assert.match(cmdPayloads.exploitPayload, /__VULN_EXPLOITED__/);

    const pathPayloads = TestSynthesizer.getPayloadsForCwe(mockFindingPath.cwe);
    assert.match(pathPayloads.exploitPayload, /\.\.\//);
  });

  it('should synthesize complete node:test suite with 3 distinct verification phases', () => {
    const rawCode = `const key = "sk-live-secret12345"; db.query("SELECT * FROM users WHERE id = " + userId);`;
    const suite = TestSynthesizer.synthesizeSuite(mockFindingSql, rawCode, undefined, 'node:test');

    assert.strictEqual(suite.findingId, 'FINDING-SQL-01');
    assert.strictEqual(suite.framework, 'node:test');
    assert.strictEqual(suite.testCases.length, 3);
    assert.strictEqual(suite.testCases[0].type, 'exploit_poc');
    assert.strictEqual(suite.testCases[1].type, 'regression_verification');
    assert.strictEqual(suite.testCases[2].type, 'benign_invariant');

    // Assert zero leakage of the raw key into test code
    assert.strictEqual(suite.fullTestCode.includes('sk-live-secret12345'), false);
    assert.match(suite.fullTestCode, /node:test/);
    assert.match(suite.fullTestCode, /node:assert\/strict/);
  });

  it('should format Jest and Mocha suites accurately according to framework conventions', () => {
    const rawCode = `exec("ping -c 1 " + host);`;
    const jestSuite = TestSynthesizer.synthesizeSuite(mockFindingCmd, rawCode, undefined, 'jest');
    assert.match(jestSuite.fullTestCode, /expect\(isVulnerable/);

    const mochaSuite = TestSynthesizer.synthesizeSuite(mockFindingCmd, rawCode, undefined, 'mocha');
    assert.match(mochaSuite.fullTestCode, /import { describe, it } from 'mocha'/);
  });

  it('should write test suite to disk and execute live mathematical verification with node:test', () => {
    const rawCode = `db.query("SELECT * FROM users WHERE id = " + userId);`;
    const suite = TestSynthesizer.synthesizeSuite(mockFindingSql, rawCode, undefined, 'node:test');
    
    const tempDir = join('tests', 'scratch_security_test');
    const writtenFile = TestSynthesizer.writeTestSuite(suite, tempDir);

    assert.strictEqual(existsSync(writtenFile), true);

    // Live verification execution using node --test
    const verification = TestSynthesizer.verifyTestSuite(writtenFile);
    assert.strictEqual(verification.passed, true, `Verification failed with output: ${verification.output}`);
    assert.strictEqual(verification.failedTests, 0);
    assert.strictEqual(verification.passedTests >= 3, true);

    // Cleanup
    try {
      rmSync(tempDir, { recursive: true, force: true });
    } catch {}
  });
});
