import type { LocalFinding } from '../cloud/types.js';

export interface TriageDecision {
  localRemediable: LocalFinding[];
  cloudEscalated: LocalFinding[];
  costAvoidanceUsd: number;
  privacyPreservedRate: number;
}

export class HybridClassifier {
  /**
   * Intelligently routes security findings between local deterministic remediation
   * and Cloud Gemini deep semantic reasoning.
   */
  public static triage(findings: LocalFinding[]): TriageDecision {
    const localRemediable: LocalFinding[] = [];
    const cloudEscalated: LocalFinding[] = [];

    for (const finding of findings) {
      if (finding.requiresCloudReasoning) {
        cloudEscalated.push(finding);
      } else {
        localRemediable.push(finding);
      }
    }

    // Benchmark calculation: Each locally handled rule saves ~0.005 USD in API compute and ~150ms in latency
    const costAvoidanceUsd = localRemediable.length * 0.005;
    const privacyPreservedRate = findings.length > 0 ? (localRemediable.length / findings.length) * 100 : 100;

    return {
      localRemediable,
      cloudEscalated,
      costAvoidanceUsd: Number(costAvoidanceUsd.toFixed(4)),
      privacyPreservedRate: Number(privacyPreservedRate.toFixed(1))
    };
  }
}
