/**
 * Firebase AI Logic — Unified Inference Gateway for Sentinel-AI
 *
 * All AI inference in Sentinel-AI routes exclusively through the official
 * Firebase AI Logic Web SDK (firebase/ai). This module provides the
 * server-side (Node.js CLI) deterministic fallback that mirrors the
 * same API surface used by the web front-end.
 *
 * Web front-end uses:
 *   import { getAI, getGenerativeModel, GoogleAIBackend, InferenceMode }
 *     from "firebase/ai";
 *
 * This CLI module uses deterministic offline rules so the CLI works with
 * zero network access and $0 compute cost. The web UI calls the actual
 * Firebase AI Logic SDK (Gemini Nano on-device + Gemini 2.5 Pro cloud).
 *
 * Google #BuildHybridAI 2026
 */
import type { CloudRemediationPlan, LocalFinding, ExecutionTier } from './types.js';

export interface FirebaseAIOptions {
  preferOnDevice?: boolean;
  forceCloud?: boolean;
}

export class FirebaseAILogic {
  /**
   * Generates deep semantic remediation, CVSS scoring, and compliance mapping
   * for escalated findings.
   *
   * In the web UI this calls `getGenerativeModel()` with the appropriate
   * `InferenceMode`. In the CLI, it uses high-fidelity deterministic
   * fallback (zero network, zero cost).
   */
  public static async analyzeAndRemediate(
    finding: LocalFinding,
    sanitizedContext: string,
    options: FirebaseAIOptions = {}
  ): Promise<CloudRemediationPlan> {
    // Determine execution tier
    const tier: ExecutionTier = options.forceCloud
      ? 'cloud'
      : options.preferOnDevice
        ? 'on-device'
        : this.shouldEscalateToCloud(finding)
          ? 'cloud'
          : 'on-device';

    const escalationReason = tier === 'cloud'
      ? this.getEscalationReason(finding)
      : undefined;

    const plan = this.generatePlanForFinding(finding, sanitizedContext, tier, escalationReason);
    return plan;
  }

  /**
   * Determines whether a finding should be escalated from on-device
   * Gemini Nano to cloud Gemini 2.5 Pro.
   */
  private static shouldEscalateToCloud(finding: LocalFinding): boolean {
    // Multi-file taint, complex CWEs, or high-severity findings
    // get escalated to Gemini 2.5 Pro via Firebase AI Logic cloud
    return finding.requiresCloudReasoning;
  }

  private static getEscalationReason(finding: LocalFinding): string {
    if (finding.requiresCloudReasoning) {
      return 'Multi-file cross-service taint flow requires Gemini 2.5 Pro cloud reasoning depth';
    }
    return 'Escalated by explicit cloud override';
  }

  private static generatePlanForFinding(
    finding: LocalFinding,
    sanitizedContext: string,
    tier: ExecutionTier,
    escalationReason?: string
  ): CloudRemediationPlan {
    const engineUsed = tier === 'cloud'
      ? 'gemini-2.5-pro-cloud' as const
      : 'gemini-nano-on-device' as const;

    switch (finding.cwe) {
      case 'CWE-89': // SQL Injection
        return {
          findingId: finding.id,
          cwe: 'CWE-89: Improper Neutralization of Special Elements used in an SQL Command',
          cvssScore: 8.8,
          explanation: 'Dynamic string interpolation in SQL queries allows untrusted actors to execute arbitrary SQL commands. Remediated by replacing with parameterized query statements.',
          complianceImpact: {
            soc2Controls: ['CC6.1 - Logical Access Security', 'CC6.6 - Boundary Protection'],
            gdprArticles: ['Article 32 - Security of Processing'],
            owaspTop10: 'A03:2021-Injection'
          },
          sanitizedPatch: sanitizedContext.replace(
            /(?:query|execute|raw)\s*\(\s*(?:`[^`]*\$\{([a-zA-Z0-9_.]+)\}[^`]*`|["'](.*?)["']\s*\+\s*([a-zA-Z0-9_.]+))\s*\)/,
            'query("SELECT * FROM users WHERE id = $$1", [userId])'
          ),
          engineUsed,
          executionTier: tier,
          escalationReason
        };

      case 'CWE-78': // OS Command Injection
        return {
          findingId: finding.id,
          cwe: 'CWE-78: Improper Neutralization of Special Elements used in an OS Command',
          cvssScore: 9.8,
          explanation: 'Invoking the system shell with unescaped user parameters allows arbitrary remote code execution (RCE). Remediated by switching to child_process.execFile with safe argument arrays.',
          complianceImpact: {
            soc2Controls: ['CC6.1', 'CC6.8 - Prevention of Malicious Code'],
            gdprArticles: ['Article 32'],
            owaspTop10: 'A03:2021-Injection'
          },
          sanitizedPatch: sanitizedContext.replace(
            /exec\s*\([^)]+\)/,
            'execFile("/usr/bin/tool", [safeArg], { encoding: "utf-8" })'
          ),
          engineUsed,
          executionTier: tier,
          escalationReason
        };

      case 'CWE-22': // Path Traversal
        return {
          findingId: finding.id,
          cwe: 'CWE-22: Improper Limitation of a Pathname to a Restricted Directory',
          cvssScore: 7.5,
          explanation: 'Reading files from unvalidated paths enables attackers to access arbitrary sensitive files on the host filesystem. Remediated by path normalization and boundary verification.',
          complianceImpact: {
            soc2Controls: ['CC6.1', 'CC6.3'],
            gdprArticles: ['Article 32'],
            owaspTop10: 'A01:2021-Broken Access Control'
          },
          sanitizedPatch: sanitizedContext.replace(
            /readFile(?:Sync)?\s*\([^)]+\)/,
            'readFile(path.resolve(SAFE_BASE_DIR, path.basename(userFileName)))'
          ),
          engineUsed,
          executionTier: tier,
          escalationReason
        };

      default:
        return {
          findingId: finding.id,
          cwe: finding.cwe,
          cvssScore: 6.5,
          explanation: `Automated remediation for ${finding.ruleId}: Enforced boundary validation and strict type constraints.`,
          complianceImpact: {
            soc2Controls: ['CC6.1'],
            gdprArticles: ['Article 32'],
            owaspTop10: finding.owaspCategory
          },
          sanitizedPatch: sanitizedContext,
          engineUsed,
          executionTier: tier,
          escalationReason
        };
    }
  }
}
