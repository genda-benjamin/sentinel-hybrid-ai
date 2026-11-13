/**
 * Sentinel-AI Type Definitions
 * Designed for Google #BuildHybridAI 2026
 */

export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';

export interface SecretToken {
  placeholder: string;
  originalValue: string;
  category: 'API_KEY' | 'PRIVATE_KEY' | 'DATABASE_URL' | 'JWT' | 'PASSWORD' | 'ENTROPY';
  byteOffset: number;
  length: number;
}

export interface SanitizedPayload {
  sanitizedContent: string;
  vaultTokenCount: number;
  tokens: Map<string, string>; // placeholder -> original
  redactedCategories: Record<string, number>;
}

export interface LocalFinding {
  id: string;
  file: string;
  line: number;
  ruleId: string;
  cwe: string;
  owaspCategory: string;
  severity: Severity;
  message: string;
  snippet: string;
  requiresCloudReasoning: boolean;
}

export interface CloudRemediationPlan {
  findingId: string;
  cwe: string;
  cvssScore: number;
  explanation: string;
  complianceImpact: {
    soc2Controls: string[];
    gdprArticles: string[];
    owaspTop10: string;
  };
  sanitizedPatch: string;
}

export interface RehydratedRemediation {
  findingId: string;
  rehydratedPatch: string;
  verifiedLocalPass: boolean;
  explanation: string;
  cvssScore: number;
}

export interface AuditReport {
  timestamp: string;
  filesScanned: number;
  totalFindings: number;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  cloudEscalations: number;
  leakagePreventionRate: string;
  findings: LocalFinding[];
  remediations: RehydratedRemediation[];
}
