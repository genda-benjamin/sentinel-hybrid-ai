import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { FirebaseAILogic } from '../cloud/firebase-ai.js';
import { LocalSanitizer } from '../core/sanitizer.js';
import type { LocalFinding } from '../cloud/types.js';

describe('Firebase AI Logic Hybrid Routing Tests', () => {
  it('should generate on-device remediation plan with Gemini Nano execution tier', async () => {
    const sqlFinding: LocalFinding = {
      id: 'test-sql-001',
      file: 'app.ts',
      line: 12,
      ruleId: 'SQL_INJECTION',
      cwe: 'CWE-89',
      owaspCategory: 'A03:2021-Injection',
      severity: 'CRITICAL',
      message: 'SQL injection via string concatenation',
      snippet: 'db.query("SELECT * FROM users WHERE id = " + userId)',
      requiresCloudReasoning: false
    };
    const plan = await FirebaseAILogic.analyzeAndRemediate(sqlFinding, sqlFinding.snippet);
    assert.strictEqual(plan.engineUsed, 'gemini-nano-on-device');
    assert.strictEqual(plan.executionTier, 'on-device');
    assert.ok(plan.cvssScore >= 8.0);
    assert.ok(plan.explanation.length > 10);
    assert.ok(plan.complianceImpact.owaspTop10.includes('Injection'));
  });

  it('should execute end-to-end secret redaction -> Firebase AI Logic reasoning -> rehydration with 0 leakage', async () => {
    const rawCode = `
      const ADMIN_KEY = "sk-live_SuperSecretAdminKey2026_production";
      exec("rm -rf " + userInput);
    `;
    // 1. Sanitize
    const sanitized = LocalSanitizer.sanitize(rawCode);
    assert.ok(sanitized.vaultTokenCount >= 1);
    assert.ok(LocalSanitizer.verifyZeroLeakage(sanitized.sanitizedContent));

    // 2. Detect
    const cmdFinding: LocalFinding = {
      id: 'test-cmd-001',
      file: 'deploy.ts',
      line: 3,
      ruleId: 'COMMAND_INJECTION',
      cwe: 'CWE-78',
      owaspCategory: 'A03:2021-Injection',
      severity: 'CRITICAL',
      message: 'Command injection via exec()',
      snippet: 'exec("rm -rf " + userInput)',
      requiresCloudReasoning: false
    };

    // 3. Reason via Firebase AI Logic (Gemini Nano on-device)
    const plan = await FirebaseAILogic.analyzeAndRemediate(cmdFinding, cmdFinding.snippet);
    assert.strictEqual(plan.engineUsed, 'gemini-nano-on-device');
    assert.strictEqual(plan.executionTier, 'on-device');

    // 4. Rehydrate
    const rehydrated = LocalSanitizer.rehydrate(plan.sanitizedPatch, sanitized.tokens);
    assert.ok(typeof rehydrated === 'string');
  });

  it('should escalate to cloud Gemini 2.5 Pro when finding requires cloud reasoning', async () => {
    const complexFinding: LocalFinding = {
      id: 'test-taint-001',
      file: 'service.ts',
      line: 42,
      ruleId: 'SQL_INJECTION',
      cwe: 'CWE-89',
      owaspCategory: 'A03:2021-Injection',
      severity: 'CRITICAL',
      message: 'Cross-service SQL injection via tainted data flow',
      snippet: 'db.query("SELECT * FROM orders WHERE customer = " + req.body.id)',
      requiresCloudReasoning: true
    };

    const plan = await FirebaseAILogic.analyzeAndRemediate(complexFinding, complexFinding.snippet);
    assert.strictEqual(plan.engineUsed, 'gemini-2.5-pro-cloud');
    assert.strictEqual(plan.executionTier, 'cloud');
    assert.ok(plan.escalationReason);
    assert.ok(plan.escalationReason!.includes('Gemini 2.5 Pro'));
  });
});
