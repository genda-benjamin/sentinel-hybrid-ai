import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { FirebaseAILogic } from '../cloud/firebase-ai.js';
import type { LocalFinding } from '../cloud/types.js';

describe('Firebase App Check Initialization & Telemetry Tests', () => {
  it('should generate a valid cryptographic debug App Check attestation for hackathon evaluation', () => {
    const attestation = FirebaseAILogic.generateDebugAppCheckToken();
    assert.ok(attestation.token.startsWith(FirebaseAILogic.DEBUG_TOKEN_PREFIX));
    assert.strictEqual(attestation.provider, 'debug');
    assert.strictEqual(attestation.verified, true);
    assert.strictEqual(attestation.appId, 'sentinel-hybrid-ai');
    assert.ok(new Date(attestation.expiresAt).getTime() > new Date(attestation.issuedAt).getTime());
  });

  it('should verify valid debug and JWT-style App Check tokens', () => {
    const debugAttestation = FirebaseAILogic.generateDebugAppCheckToken();
    const result1 = FirebaseAILogic.verifyAppCheckToken(debugAttestation.token);
    assert.strictEqual(result1.valid, true);
    assert.strictEqual(result1.provider, 'debug');

    const result2 = FirebaseAILogic.verifyAppCheckToken('eyJhbGciOiJSUzI1NiJ9.eyJhcHBJZCI6InNlbnRpbmVsIn0.signature');
    assert.strictEqual(result2.valid, true);
    assert.strictEqual(result2.provider, 'recaptcha-enterprise');

    const result3 = FirebaseAILogic.verifyAppCheckToken('');
    assert.strictEqual(result3.valid, false);

    const result4 = FirebaseAILogic.verifyAppCheckToken('invalid-garbage-token');
    assert.strictEqual(result4.valid, false);
  });

  it('should automatically attach verified App Check attestation on cloud escalations', async () => {
    const finding: LocalFinding = {
      id: 'test-cloud-finding',
      file: 'service.ts',
      line: 10,
      ruleId: 'SQL_INJECTION',
      cwe: 'CWE-89',
      owaspCategory: 'A03:2021-Injection',
      severity: 'CRITICAL',
      message: 'Critical SQL Injection',
      snippet: 'db.query("SELECT * FROM u WHERE id = " + id)',
      requiresCloudReasoning: true
    };

    const plan = await FirebaseAILogic.analyzeAndRemediate(finding, finding.snippet);
    assert.strictEqual(plan.executionTier, 'cloud');
    assert.strictEqual(plan.engineUsed, 'gemini-2.5-pro-cloud');
    assert.ok(plan.appCheckAttestation, 'Cloud plan must include App Check attestation');
    assert.strictEqual(plan.appCheckAttestation?.verified, true);
    assert.strictEqual(plan.appCheckAttestation?.provider, 'debug');
  });

  it('should allow custom valid App Check token to be supplied and verified', async () => {
    const finding: LocalFinding = {
      id: 'test-custom-token',
      file: 'api.ts',
      line: 20,
      ruleId: 'COMMAND_INJECTION',
      cwe: 'CWE-78',
      owaspCategory: 'A03:2021-Injection',
      severity: 'CRITICAL',
      message: 'Command injection',
      snippet: 'exec(cmd)',
      requiresCloudReasoning: true
    };

    const customToken = 'eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJhcHAtY2hlY2stcHJvZCIsImFwcElkIjoic2VudGluZWwifQ.fake_signature_for_test';
    const plan = await FirebaseAILogic.analyzeAndRemediate(finding, finding.snippet, {
      appCheckToken: customToken
    });

    assert.ok(plan.appCheckAttestation);
    assert.strictEqual(plan.appCheckAttestation?.token, customToken);
    assert.strictEqual(plan.appCheckAttestation?.provider, 'recaptcha-enterprise');
    assert.strictEqual(plan.appCheckAttestation?.verified, true);
  });

  it('should reject cloud escalation with error when strictAppCheck is enabled and token is invalid', async () => {
    const finding: LocalFinding = {
      id: 'test-strict-appcheck',
      file: 'db.ts',
      line: 30,
      ruleId: 'PATH_TRAVERSAL',
      cwe: 'CWE-22',
      owaspCategory: 'A01:2021-Broken Access Control',
      severity: 'HIGH',
      message: 'Path traversal',
      snippet: 'readFile(p)',
      requiresCloudReasoning: true
    };

    await assert.rejects(
      async () => {
        await FirebaseAILogic.analyzeAndRemediate(finding, finding.snippet, {
          strictAppCheck: true,
          appCheckToken: 'malformed_invalid_token'
        });
      },
      /Firebase App Check attestation failed/
    );
  });

  it('should not require App Check attestation for on-device Gemini Nano execution', async () => {
    const finding: LocalFinding = {
      id: 'test-on-device',
      file: 'client.ts',
      line: 5,
      ruleId: 'SQL_INJECTION',
      cwe: 'CWE-89',
      owaspCategory: 'A03:2021-Injection',
      severity: 'HIGH',
      message: 'Simple SQL Injection',
      snippet: 'db.query("SELECT * FROM u WHERE id = " + id)',
      requiresCloudReasoning: false
    };

    const plan = await FirebaseAILogic.analyzeAndRemediate(finding, finding.snippet, {
      preferOnDevice: true
    });
    assert.strictEqual(plan.executionTier, 'on-device');
    assert.strictEqual(plan.engineUsed, 'gemini-nano-on-device');
    assert.strictEqual(plan.appCheckAttestation, undefined);
  });
});
