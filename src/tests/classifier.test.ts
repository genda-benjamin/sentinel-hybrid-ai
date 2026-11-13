import { describe, it } from 'node:test';
import assert from 'node:assert';
import { HybridClassifier } from '../core/classifier.js';
import type { LocalFinding } from '../cloud/types.js';

describe('HybridClassifier Unit Tests', () => {
  it('should partition findings between local deterministic rules and cloud reasoning', () => {
    const mockFindings: LocalFinding[] = [
      {
        id: '1',
        file: 'test.ts',
        line: 10,
        ruleId: 'SEC-001',
        cwe: 'CWE-89',
        owaspCategory: 'Injection',
        severity: 'CRITICAL',
        message: 'SQLi',
        snippet: 'db.query(`SELECT ... ${val}`)',
        requiresCloudReasoning: true
      },
      {
        id: '2',
        file: 'test.ts',
        line: 25,
        ruleId: 'SEC-004',
        cwe: 'CWE-1321',
        owaspCategory: 'Components',
        severity: 'HIGH',
        message: 'Prototype Pollution',
        snippet: 'Object.assign({}, req.body)',
        requiresCloudReasoning: false
      }
    ];

    const decision = HybridClassifier.triage(mockFindings);
    assert.strictEqual(decision.cloudEscalated.length, 1);
    assert.strictEqual(decision.localRemediable.length, 1);
    assert.strictEqual(decision.costAvoidanceUsd, 0.005);
    assert.strictEqual(decision.privacyPreservedRate, 50.0);
  });
});
