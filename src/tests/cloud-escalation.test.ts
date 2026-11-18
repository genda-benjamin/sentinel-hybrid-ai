import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { IntelligentEscalationRouter } from '../cloud/escalation-router.js';
import { InferenceMode, type LocalFinding } from '../cloud/types.js';
import type { TaintTrace, TaintNode, CallEdge } from '../core/taint-tracker.js';

describe('Intelligent Cloud Escalation to Gemini 2.5 Pro Tests (Day 4)', () => {
  it('should automatically escalate multi-file cross-service taint graph to Gemini 2.5 Pro Cloud', async () => {
    const finding: LocalFinding = {
      id: 'finding-multi-hop-sqli',
      file: 'repositories/userRepository.ts',
      line: 8,
      ruleId: 'CROSS_FILE_SQLI',
      cwe: 'CWE-89',
      owaspCategory: 'A03:2021-Injection',
      severity: 'CRITICAL',
      message: 'Second-order SQL injection reaching sink across multiple service boundaries',
      snippet: 'return await db.raw(`SELECT * FROM users WHERE id = ${userId}`);',
      requiresCloudReasoning: true
    };

    // Synthetic 3-hop trace: controller -> service -> repository
    const mockTrace: TaintTrace = {
      traceId: 'trace-user-001',
      source: { id: 'ctrl:8', kind: 'SOURCE', filePath: 'controllers/userController.ts', functionName: 'getUser', codeSnippet: 'req.query.id', line: 8, col: 1, semanticTags: ['http-input'], isSanitized: false, confidence: 0.95 },
      sink: { id: 'repo:8', kind: 'SINK', filePath: 'repositories/userRepository.ts', functionName: 'findUser', codeSnippet: 'db.raw(...)', line: 8, col: 1, semanticTags: ['sql-sink'], isSanitized: false, confidence: 0.99 },
      path: [
        { id: 'ctrl:8', kind: 'SOURCE', filePath: 'controllers/userController.ts', functionName: 'getUser', line: 8, col: 1, codeSnippet: '', semanticTags: [], isSanitized: false, confidence: 1 },
        { id: 'svc:6', kind: 'TRANSFORMER', filePath: 'services/userService.ts', functionName: 'getUserProfile', line: 6, col: 1, codeSnippet: '', semanticTags: [], isSanitized: false, confidence: 1 },
        { id: 'repo:8', kind: 'SINK', filePath: 'repositories/userRepository.ts', functionName: 'findUserInDatabase', line: 8, col: 1, codeSnippet: '', semanticTags: [], isSanitized: false, confidence: 1 }
      ],
      edges: [
        { id: 'e1', fromId: 'ctrl:8', toId: 'svc:6', callSite: 'getUserProfile(id)', argIndex: 0, filePath: 'controllers/userController.ts', line: 8, taintPassed: true },
        { id: 'e2', fromId: 'svc:6', toId: 'repo:8', callSite: 'findUserInDatabase(id)', argIndex: 0, filePath: 'services/userService.ts', line: 6, taintPassed: true }
      ],
      sanitizersOnPath: [],
      hops: 2,
      riskScore: 9.8,
      riskLevel: 'CRITICAL',
      cwe: 'CWE-89',
      isNeutralized: false,
      explanation: 'Taint flows from HTTP request query to database raw SQL sink without sanitization'
    };

    const evaluation = await IntelligentEscalationRouter.evaluate({
      finding,
      taintTrace: mockTrace
    });

    assert.strictEqual(evaluation.shouldEscalate, true);
    assert.strictEqual(evaluation.tier, 'cloud');
    assert.strictEqual(evaluation.engineUsed, 'gemini-2.5-pro-cloud');
    assert.ok(evaluation.triggers.includes('MULTI_HOP_TAINT'));
    assert.strictEqual(evaluation.appCheckVerified, true);
    assert.ok(evaluation.reason.includes('Gemini 2.5 Pro Cloud'));
  });

  it('should automatically escalate when exploit test synthesis is requested', async () => {
    const finding: LocalFinding = {
      id: 'finding-exploit-gen',
      file: 'server.ts',
      line: 12,
      ruleId: 'COMMAND_INJECTION',
      cwe: 'CWE-78',
      owaspCategory: 'A03:2021-Injection',
      severity: 'CRITICAL',
      message: 'Command Injection',
      snippet: 'exec("ping " + host)',
      requiresCloudReasoning: false
    };

    const evaluation = await IntelligentEscalationRouter.evaluate({
      finding,
      context: 'exec("ping " + host)',
      requestExploitTest: true
    });

    assert.strictEqual(evaluation.shouldEscalate, true);
    assert.strictEqual(evaluation.tier, 'cloud');
    assert.ok(evaluation.triggers.includes('EXPLOIT_SYNTHESIS_REQUESTED'));
    assert.ok(evaluation.verificationSuite, 'Cloud escalation must synthesize verification suite');
    assert.ok(evaluation.verificationSuite.includes('describe('));
  });

  it('should automatically escalate architectural high-complexity CWEs (CWE-502, CWE-918)', async () => {
    const findingSsrf: LocalFinding = {
      id: 'finding-ssrf',
      file: 'fetcher.ts',
      line: 15,
      ruleId: 'SSRF',
      cwe: 'CWE-918',
      owaspCategory: 'A10:2021-SSRF',
      severity: 'HIGH',
      message: 'Server-Side Request Forgery vulnerability',
      snippet: 'axios.get(targetUrl)',
      requiresCloudReasoning: false
    };

    const evalSsrf = await IntelligentEscalationRouter.evaluate({ finding: findingSsrf });
    assert.strictEqual(evalSsrf.shouldEscalate, true);
    assert.ok(evalSsrf.triggers.includes('ARCHITECTURAL_CWE'));
  });

  it('should automatically escalate on low on-device confidence (< 0.85)', async () => {
    const finding: LocalFinding = {
      id: 'finding-low-conf',
      file: 'parser.ts',
      line: 3,
      ruleId: 'AMBIGUOUS_AST',
      cwe: 'CWE-20',
      owaspCategory: 'A04:2021',
      severity: 'MEDIUM',
      message: 'Ambiguous user input sanitization',
      snippet: 'clean(userInput)',
      requiresCloudReasoning: false
    };

    const evaluation = await IntelligentEscalationRouter.evaluate({
      finding,
      confidence: 0.72 // below 0.85 threshold
    });

    assert.strictEqual(evaluation.shouldEscalate, true);
    assert.ok(evaluation.triggers.includes('LOW_CONFIDENCE'));
  });

  it('should stay on-device (Gemini Nano) for single-file local vulnerabilities without cloud bloat', async () => {
    const finding: LocalFinding = {
      id: 'finding-single-file-sqli',
      file: 'app.ts',
      line: 5,
      ruleId: 'SQLI',
      cwe: 'CWE-89',
      owaspCategory: 'A03:2021-Injection',
      severity: 'CRITICAL',
      message: 'Local SQL Injection',
      snippet: 'db.query("SELECT * FROM u WHERE id = " + id)',
      requiresCloudReasoning: false
    };

    const evaluation = await IntelligentEscalationRouter.evaluate({
      finding,
      confidence: 0.98
    });

    assert.strictEqual(evaluation.shouldEscalate, false);
    assert.strictEqual(evaluation.tier, 'on-device');
    assert.strictEqual(evaluation.engineUsed, 'gemini-nano-on-device');
    assert.strictEqual(evaluation.triggers.length, 0);
  });

  it('should enforce non-bypassable airgap under InferenceMode.ONLY_ON_DEVICE suppressing cloud triggers', async () => {
    const finding: LocalFinding = {
      id: 'finding-airgap-enforced',
      file: 'auth.ts',
      line: 1,
      ruleId: 'MULTI_FILE_SSRF',
      cwe: 'CWE-918',
      owaspCategory: 'A10:2021',
      severity: 'HIGH',
      message: 'Architectural SSRF',
      snippet: 'fetch(url)',
      requiresCloudReasoning: true
    };

    const evaluation = await IntelligentEscalationRouter.evaluate({
      finding,
      mode: InferenceMode.ONLY_ON_DEVICE,
      forceCloud: true,
      requestExploitTest: true
    });

    assert.strictEqual(evaluation.shouldEscalate, false);
    assert.strictEqual(evaluation.tier, 'on-device');
    assert.strictEqual(evaluation.engineUsed, 'gemini-nano-on-device');
    assert.strictEqual(evaluation.blockedByAirgap, true);
    assert.strictEqual(evaluation.appCheckVerified, false);
    assert.ok(evaluation.reason.includes('suppressed by strict airgap policy'));
  });

  it('should enforce and attach verified App Check attestation on cloud escalations', async () => {
    const finding: LocalFinding = {
      id: 'finding-appcheck-cloud',
      file: 'service.ts',
      line: 10,
      ruleId: 'TAINT',
      cwe: 'CWE-78',
      owaspCategory: 'A03',
      severity: 'CRITICAL',
      message: 'Command injection',
      snippet: 'exec(cmd)',
      requiresCloudReasoning: true
    };

    const evaluation = await IntelligentEscalationRouter.evaluate({ finding });
    assert.strictEqual(evaluation.shouldEscalate, true);
    assert.ok(evaluation.attestation, 'Cloud escalation must have App Check attestation');
    assert.strictEqual(evaluation.attestation.verified, true);
    assert.strictEqual(evaluation.attestation.provider, 'debug');
  });

  it('should reject invalid App Check token when strictAppCheck is enabled', async () => {
    const finding: LocalFinding = {
      id: 'finding-invalid-appcheck',
      file: 'service.ts',
      line: 10,
      ruleId: 'TAINT',
      cwe: 'CWE-78',
      owaspCategory: 'A03',
      severity: 'CRITICAL',
      message: 'Command injection',
      snippet: 'exec(cmd)',
      requiresCloudReasoning: true
    };

    await assert.rejects(
      async () => {
        await IntelligentEscalationRouter.evaluate({
          finding,
          appCheckToken: 'invalid-fake-token',
          strictAppCheck: true
        });
      },
      /Cloud escalation blocked: Invalid Firebase App Check token/
    );
  });

  it('should execute end-to-end routeAndRemediate with multi-file patches and deep chain-of-thought telemetry', async () => {
    const finding: LocalFinding = {
      id: 'finding-e2e-escalation',
      file: 'userRepository.ts',
      line: 15,
      ruleId: 'SQLI',
      cwe: 'CWE-89',
      owaspCategory: 'A03:2021-Injection',
      severity: 'CRITICAL',
      message: 'SQL Injection',
      snippet: 'const user = await db.query(`SELECT * FROM users WHERE id = ${req.query.id}`);',
      requiresCloudReasoning: true
    };

    const plan = await IntelligentEscalationRouter.routeAndRemediate(
      finding,
      finding.snippet,
      { requestExploitTest: true }
    );

    assert.strictEqual(plan.executionTier, 'cloud');
    assert.strictEqual(plan.engineUsed, 'gemini-2.5-pro-cloud');
    assert.strictEqual(plan.cloudReasoningDepth, 'deep-chain-of-thought');
    assert.strictEqual(plan.reasoningTokens, 1642);
    assert.ok(plan.appCheckAttestation, 'Cloud plan must contain App Check attestation');
    assert.ok(plan.synthesizedExploitTest, 'Cloud plan must contain synthesized exploit test');
    assert.ok(plan.synthesizedExploitTest.includes('describe('));
  });
});
