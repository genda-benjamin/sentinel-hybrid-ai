import { describe, it } from 'node:test';
import assert from 'node:assert';
import { SarifExporter } from '../core/sarif.js';
import type { AuditReport, LocalFinding, RehydratedRemediation } from '../cloud/types.js';

describe('SarifExporter Unit Tests', () => {
  it('should generate compliant OASIS SARIF v2.1.0 structure', () => {
    const mockFindings: LocalFinding[] = [
      {
        id: 'finding-1',
        file: 'sample/vulnerable-app.ts',
        line: 12,
        ruleId: 'OWASP-A03-SQLi',
        cwe: 'CWE-89',
        owaspCategory: 'A03:2021-Injection',
        severity: 'CRITICAL',
        message: 'Potential SQL Injection via string concatenation in query()',
        snippet: 'db.query("SELECT * FROM users WHERE id = " + id);',
        requiresCloudReasoning: true
      },
      {
        id: 'finding-2',
        file: 'sample/vulnerable-app.ts',
        line: 25,
        ruleId: 'OWASP-A03-CMDi',
        cwe: 'CWE-78',
        owaspCategory: 'A03:2021-Injection',
        severity: 'HIGH',
        message: 'Potential Command Injection via execSync()',
        snippet: 'execSync("ping -c 1 " + host);',
        requiresCloudReasoning: true
      }
    ];

    const mockRemediations: RehydratedRemediation[] = [
      {
        findingId: 'finding-1',
        rehydratedPatch: 'db.query("SELECT * FROM users WHERE id = $1", [id]);',
        verifiedLocalPass: true,
        explanation: 'Converted string concatenation to parameterized query placeholder.',
        cvssScore: 9.8,
        engineUsed: 'gemini-2.5-pro-cloud',
        reasoningTokens: 1488
      }
    ];

    const mockReport: AuditReport = {
      timestamp: new Date().toISOString(),
      filesScanned: 1,
      totalFindings: 2,
      criticalCount: 1,
      highCount: 1,
      mediumCount: 0,
      lowCount: 0,
      cloudEscalations: 1,
      leakagePreventionRate: '100%',
      findings: mockFindings,
      remediations: mockRemediations
    };

    const sarif = SarifExporter.generateSarif(mockReport);

    // Verify top-level SARIF schema & version
    assert.strictEqual(sarif.version, '2.1.0');
    assert.strictEqual(sarif.$schema, SarifExporter.SCHEMA_URI);
    assert.strictEqual(sarif.runs.length, 1);

    const run = sarif.runs[0];
    assert.strictEqual(run.tool.driver.name, 'Sentinel-AI');
    assert.strictEqual(run.tool.driver.informationUri, 'https://github.com/genda-benjamin/sentinel-hybrid-ai');

    // Verify rules
    assert.strictEqual(run.tool.driver.rules.length, 2);
    const cwe89Rule = run.tool.driver.rules.find(r => r.id === 'CWE-89');
    assert.ok(cwe89Rule);
    assert.strictEqual(cwe89Rule?.properties['security-severity'], '9.8');
    assert.strictEqual(cwe89Rule?.defaultConfiguration.level, 'error');

    // Verify results
    assert.strictEqual(run.results.length, 2);
    const sqliResult = run.results.find(r => r.ruleId === 'CWE-89');
    assert.ok(sqliResult);
    assert.strictEqual(sqliResult?.level, 'error');
    assert.strictEqual(sqliResult?.locations[0].physicalLocation.region.startLine, 12);
    assert.strictEqual(sqliResult?.properties?.cvssScore, 9.8);
    assert.strictEqual(sqliResult?.properties?.reasoningTokens, 1488);
    assert.strictEqual(sqliResult?.properties?.engineUsed, 'gemini-2.5-pro-cloud');

    // Verify automated code remediation fixes
    assert.ok(sqliResult?.fixes && sqliResult.fixes.length > 0);
    assert.strictEqual(
      sqliResult?.fixes?.[0].changes[0].replacements[0].insertedContent.text,
      'db.query("SELECT * FROM users WHERE id = $1", [id]);'
    );
  });

  it('should serialize valid JSON text without errors', () => {
    const emptyReport: AuditReport = {
      timestamp: new Date().toISOString(),
      filesScanned: 0,
      totalFindings: 0,
      criticalCount: 0,
      highCount: 0,
      mediumCount: 0,
      lowCount: 0,
      cloudEscalations: 0,
      leakagePreventionRate: '100%',
      findings: [],
      remediations: []
    };

    const jsonStr = SarifExporter.toSarifJson(emptyReport);
    assert.ok(jsonStr.length > 0);
    const parsed = JSON.parse(jsonStr);
    assert.strictEqual(parsed.version, '2.1.0');
    assert.strictEqual(parsed.runs[0].results.length, 0);
  });
});
