import { describe, it } from 'node:test';
import assert from 'node:assert';
import { LocalSanitizer } from '../core/sanitizer.js';
import { LocalDetector } from '../core/detector.js';
import { HybridClassifier } from '../core/classifier.js';
import { MetaMuseSparkClient } from '../cloud/muse-spark.js';

describe('Meta Muse Spark 1.3 Security Reasoning Tests', () => {
  it('should generate offline deterministic remediation plan with compliance mappings', async () => {
    const rawCode = `const result = db.query(\`SELECT * FROM users WHERE id = \${req.params.id}\`);`;
    const findings = LocalDetector.scanContent('api/users.ts', rawCode);
    const sqlFinding = findings.find(f => f.cwe === 'CWE-89');
    assert.ok(sqlFinding, 'Must find CWE-89');

    const plan = await MetaMuseSparkClient.analyzeAndRemediate(sqlFinding, sqlFinding.snippet);
    assert.strictEqual(plan.engineUsed, 'meta-muse-spark');
    assert.ok(plan.cvssScore >= 8.0, 'CVSS score for SQLi should be high/critical');
    assert.ok(plan.complianceImpact.soc2Controls.length > 0, 'SOC 2 controls mapped');
    assert.ok(plan.complianceImpact.gdprArticles.length > 0, 'GDPR articles mapped');
    assert.ok(plan.sanitizedPatch.includes('$1'), 'Must parameterize SQL query');
  });

  it('should execute end-to-end secret redaction -> Muse Spark reasoning -> rehydration with 0 leakage', async () => {
    const vulnerableCode = `
      const apiKey = "sk-proj-abc123XYZ999000111222333444555666777";
      const out = exec(\`ping -c 4 \${req.body.ip}\`);
    `;

    // 1. Sanitize
    const sanitized = LocalSanitizer.sanitize(vulnerableCode);
    assert.strictEqual(sanitized.vaultTokenCount, 1);
    assert.strictEqual(sanitized.sanitizedContent.includes('sk-proj-abc123XYZ999000111222333444555666777'), false);

    // 2. Detect & Triage
    const findings = LocalDetector.scanContent('server/ping.ts', sanitized.sanitizedContent);
    const triage = HybridClassifier.triage(findings);
    const cmdFinding = triage.cloudEscalated.find(f => f.cwe === 'CWE-78');
    assert.ok(cmdFinding, 'Must identify CWE-78 command injection');

    // 3. Reason via Muse Spark
    const plan = await MetaMuseSparkClient.analyzeAndRemediate(cmdFinding, cmdFinding.snippet);
    assert.strictEqual(plan.engineUsed, 'meta-muse-spark');
    assert.ok(plan.cvssScore >= 9.0, 'Command injection CVSS is critical');

    // 4. Rehydrate
    const rehydrated = LocalSanitizer.rehydrate(plan.sanitizedPatch, sanitized.tokens);
    assert.strictEqual(rehydrated.includes('__SENTINEL_'), false, 'All placeholders rehydrated cleanly');
    assert.strictEqual(LocalSanitizer.verifyZeroLeakage(rehydrated), true);
  });
});
