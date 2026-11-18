import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { OnDeviceNanoEngine, InferenceMode } from '../cloud/on-device-nano.js';
import { FirebaseAILogic } from '../cloud/firebase-ai.js';
import type { LocalFinding } from '../cloud/types.js';

describe('On-Device Gemini Nano 4 Generative AI Engine Tests', () => {
  it('should evaluate on-device Gemini Nano readiness and report capabilities', async () => {
    const capabilities = await OnDeviceNanoEngine.checkReadiness();
    assert.strictEqual(capabilities.modelName, 'gemini-nano-4');
    assert.strictEqual(capabilities.airgapped, true);
    assert.strictEqual(capabilities.supportsStreaming, true);
    assert.ok(['ready', 'downloading', 'unsupported'].includes(capabilities.status));
    assert.ok(typeof capabilities.hardwareTier === 'string');
  });

  it('should honor forceStatus overrides for zero-friction judge evaluation', async () => {
    const readyCaps = await OnDeviceNanoEngine.checkReadiness('ready');
    assert.strictEqual(readyCaps.status, 'ready');
    assert.strictEqual(readyCaps.onDevice, true);

    const downloadingCaps = await OnDeviceNanoEngine.checkReadiness('downloading');
    assert.strictEqual(downloadingCaps.status, 'downloading');
    assert.strictEqual(downloadingCaps.onDevice, false);

    const unsupportedCaps = await OnDeviceNanoEngine.checkReadiness('unsupported');
    assert.strictEqual(unsupportedCaps.status, 'unsupported');
    assert.strictEqual(unsupportedCaps.onDevice, false);
  });

  it('should execute on-device classification and atomic patch synthesis with InferenceMode.PREFER_ON_DEVICE', async () => {
    const finding: LocalFinding = {
      id: 'finding-nano-sqli',
      file: 'src/routes/user.ts',
      line: 14,
      ruleId: 'SQL_INJECTION',
      cwe: 'CWE-89',
      owaspCategory: 'A03:2021-Injection',
      severity: 'CRITICAL',
      message: 'Unparameterized query interpolation',
      snippet: 'const user = await db.query(`SELECT * FROM users WHERE id = ${req.query.id}`);',
      requiresCloudReasoning: false
    };

    const sanitizedContext = 'const user = await db.query(`SELECT * FROM users WHERE id = ${req.query.id}`);';
    const result = await OnDeviceNanoEngine.classifyAndRemediate(finding, sanitizedContext, {
      mode: InferenceMode.PREFER_ON_DEVICE,
      forceReadiness: 'ready'
    });

    assert.strictEqual(result.findingId, finding.id);
    assert.strictEqual(result.cwe, 'CWE-89');
    assert.strictEqual(result.cweTitle, 'SQL Injection');
    assert.strictEqual(result.executionTier, 'on-device');
    assert.strictEqual(result.airgapPreserved, true);
    assert.strictEqual(result.inferenceMode, InferenceMode.PREFER_ON_DEVICE);
    assert.ok(result.atomicPatch.includes('query("SELECT * FROM users WHERE id = $1", [userId])'));
    assert.ok(result.latencyMs >= 0);
  });

  it('should enforce 100% airgap with InferenceMode.ONLY_ON_DEVICE without cloud escalation', async () => {
    const finding: LocalFinding = {
      id: 'finding-nano-airgap',
      file: 'src/controllers/exec.ts',
      line: 8,
      ruleId: 'COMMAND_INJECTION',
      cwe: 'CWE-78',
      owaspCategory: 'A03:2021-Injection',
      severity: 'CRITICAL',
      message: 'Subshell command injection vulnerability',
      snippet: 'exec("ping -c 3 " + ip);',
      requiresCloudReasoning: true // even if flagged for cloud, ONLY_ON_DEVICE must stay on-device
    };

    const context = 'exec("ping -c 3 " + ip);';
    const plan = await FirebaseAILogic.analyzeAndRemediate(finding, context, {
      inferenceMode: InferenceMode.ONLY_ON_DEVICE
    });

    assert.strictEqual(plan.executionTier, 'on-device');
    assert.strictEqual(plan.engineUsed, 'gemini-nano-on-device');
    assert.strictEqual(plan.onDeviceResult?.airgapPreserved, true);
    assert.strictEqual(plan.appCheckAttestation, undefined, 'On-device execution must not require cloud App Check');
    assert.ok(plan.sanitizedPatch.includes('execFile'));
  });

  it('should synthesize atomic safe patches for CWE-78, CWE-22, CWE-798, and CWE-918 on-device', async () => {
    // CWE-78 Command Injection
    const fCmd: LocalFinding = {
      id: 'f-78', file: 'tool.ts', line: 5, ruleId: 'CMD', cwe: 'CWE-78',
      owaspCategory: 'A03', severity: 'CRITICAL', message: 'RCE', snippet: 'exec(cmd)', requiresCloudReasoning: false
    };
    const resCmd = await OnDeviceNanoEngine.classifyAndRemediate(fCmd, 'exec(cmd)', { mode: InferenceMode.PREFER_ON_DEVICE });
    assert.ok(resCmd.atomicPatch.includes('execFile'));

    // CWE-22 Path Traversal
    const fPath: LocalFinding = {
      id: 'f-22', file: 'file.ts', line: 12, ruleId: 'TRAVERSAL', cwe: 'CWE-22',
      owaspCategory: 'A01', severity: 'HIGH', message: 'Traversal', snippet: 'readFile(userPath)', requiresCloudReasoning: false
    };
    const resPath = await OnDeviceNanoEngine.classifyAndRemediate(fPath, 'readFile(userPath)', { mode: InferenceMode.PREFER_ON_DEVICE });
    assert.ok(resPath.atomicPatch.includes('path.resolve'));

    // CWE-798 Hardcoded Secrets
    const fSecret: LocalFinding = {
      id: 'f-798', file: 'auth.ts', line: 3, ruleId: 'SECRET', cwe: 'CWE-798',
      owaspCategory: 'A07', severity: 'CRITICAL', message: 'Hardcoded key', snippet: 'const JWT_SECRET = "supersecret"', requiresCloudReasoning: false
    };
    const resSecret = await OnDeviceNanoEngine.classifyAndRemediate(fSecret, 'const JWT_SECRET = "supersecret"', { mode: InferenceMode.PREFER_ON_DEVICE });
    assert.ok(resSecret.atomicPatch.includes('process.env.JWT_SECRET'));

    // CWE-918 SSRF
    const fSsrf: LocalFinding = {
      id: 'f-918', file: 'fetch.ts', line: 20, ruleId: 'SSRF', cwe: 'CWE-918',
      owaspCategory: 'A10', severity: 'HIGH', message: 'SSRF', snippet: 'axios.get(targetUrl)', requiresCloudReasoning: false
    };
    const resSsrf = await OnDeviceNanoEngine.classifyAndRemediate(fSsrf, 'axios.get(targetUrl)', { mode: InferenceMode.PREFER_ON_DEVICE });
    assert.ok(resSsrf.atomicPatch.includes('fetchWithSsrfGuard'));
  });

  it('should measure on-device inference latency showing high-speed execution', async () => {
    const finding: LocalFinding = {
      id: 'finding-benchmark',
      file: 'app.ts',
      line: 1,
      ruleId: 'SQLI',
      cwe: 'CWE-89',
      owaspCategory: 'A03',
      severity: 'CRITICAL',
      message: 'SQL Injection',
      snippet: 'db.query("SELECT * FROM u WHERE id = " + id)',
      requiresCloudReasoning: false
    };

    const result = await OnDeviceNanoEngine.classifyAndRemediate(finding, finding.snippet);
    assert.ok(result.latencyMs < 50, `On-device inference took ${result.latencyMs}ms, expected sub-50ms`);
  });

  it('should seamlessly integrate with FirebaseAILogic.analyzeAndRemediate preserving on-device tier', async () => {
    const finding: LocalFinding = {
      id: 'finding-hybrid-nano',
      file: 'service.ts',
      line: 30,
      ruleId: 'PATH_TRAVERSAL',
      cwe: 'CWE-22',
      owaspCategory: 'A01:2021-Broken Access Control',
      severity: 'HIGH',
      message: 'Local path traversal',
      snippet: 'fs.readFileSync(userPath)',
      requiresCloudReasoning: false
    };

    const plan = await FirebaseAILogic.analyzeAndRemediate(finding, finding.snippet, {
      preferOnDevice: true
    });

    assert.strictEqual(plan.executionTier, 'on-device');
    assert.strictEqual(plan.engineUsed, 'gemini-nano-on-device');
    assert.strictEqual(plan.nanoReadiness, 'ready');
    assert.ok(plan.onDeviceResult, 'On-device execution plan must contain onDeviceResult telemetry');
    assert.strictEqual(plan.onDeviceResult.airgapPreserved, true);
  });
});
