import { describe, it } from 'node:test';
import assert from 'node:assert';
import { LocalSanitizer } from '../core/sanitizer.js';
import { LocalDetector } from '../core/detector.js';
import { HybridClassifier } from '../core/classifier.js';
import { FirebaseAILogic } from '../cloud/firebase-ai.js';

describe('End-to-End Hybrid AI Security Workflow', () => {
  it('should execute full sanitize -> detect -> cloud remediate -> rehydrate loop with zero secrets leakage', async () => {
    // Sensitive code with BOTH an embedded database credential AND a SQL injection flaw
    const rawVulnerableCode = `
      const dbPass = "SuperSecretDBPassword!99";
      const user = db.query(\`SELECT * FROM users WHERE id = \${req.params.id}\`);
    `;

    // 1. Local Edge: Sanitize & Vault Secrets
    const sanitized = LocalSanitizer.sanitize(rawVulnerableCode);
    assert.strictEqual(sanitized.vaultTokenCount >= 1, true);
    assert.strictEqual(sanitized.sanitizedContent.includes('SuperSecretDBPassword!99'), false);
    assert.strictEqual(LocalSanitizer.verifyZeroLeakage(sanitized.sanitizedContent), true);

    // 2. Local Edge: Detect Vulnerabilities
    const findings = LocalDetector.scanContent('controllers/user.ts', sanitized.sanitizedContent);
    assert.strictEqual(findings.length >= 1, true);

    // 3. Local Edge: Hybrid Triage
    const triage = HybridClassifier.triage(findings);
    const sqlFinding = triage.cloudEscalated.find(f => f.cwe === 'CWE-89');
    assert.ok(sqlFinding, 'SQL injection finding must be flagged for cloud reasoning');

    // 4. Cloud Tier: Firebase AI Logic / Gemini Reasoning
    // Sends ONLY the sanitized snippet
    const cloudPlan = await FirebaseAILogic.analyzeAndRemediate(sqlFinding, sqlFinding.snippet);
    assert.strictEqual(cloudPlan.cvssScore, 8.8);
    assert.ok(cloudPlan.sanitizedPatch.includes('$1'), 'Remediation must be parameterized');

    // 5. Local Tier: Re-hydrate Original Secrets
    const finalPatch = LocalSanitizer.rehydrate(cloudPlan.sanitizedPatch, sanitized.tokens);

    // 6. Verification
    assert.ok(finalPatch.length > 0);
    assert.strictEqual(finalPatch.includes('__SENTINEL_'), false, 'All placeholders must be cleanly rehydrated');
  });
});
