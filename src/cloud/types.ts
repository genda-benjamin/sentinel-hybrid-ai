/**
 * Sentinel-AI Type Definitions
 * Designed for Google #BuildHybridAI 2026
 * All inference routes exclusively through Firebase AI Logic SDK
 */

export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';

export type ExecutionTier = 'on-device' | 'cloud' | 'hybrid-fallback';

export enum InferenceMode {
  PREFER_ON_DEVICE = 'PREFER_ON_DEVICE',
  ONLY_ON_DEVICE = 'ONLY_ON_DEVICE',
  PREFER_CLOUD = 'PREFER_CLOUD',
  ONLY_CLOUD = 'ONLY_CLOUD'
}

export type NanoReadinessStatus = 'ready' | 'downloading' | 'unsupported';

export interface NanoModelCapabilities {
  status: NanoReadinessStatus;
  onDevice: boolean;
  airgapped: boolean;
  modelName: string;
  hardwareTier: string;
  supportsStreaming: boolean;
  latencyMs?: number;
}

export interface OnDeviceInferenceResult {
  findingId: string;
  cwe: string;
  cweTitle: string;
  severity: Severity;
  explanation: string;
  remediationGuidance: string;
  atomicPatch: string;
  inferenceMode: InferenceMode;
  readinessStatus: NanoReadinessStatus;
  executionTier: 'on-device';
  airgapPreserved: boolean;
  latencyMs: number;
  hardwareTier: string;
}

export interface AppCheckAttestation {
  token: string;
  provider: 'debug' | 'recaptcha-enterprise' | 'custom';
  verified: boolean;
  issuedAt: string;
  expiresAt: string;
  appId?: string;
}

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
  engineUsed?: 'gemini-nano-on-device' | 'gemini-2.5-pro-cloud' | 'gemini-hybrid-fallback';
  executionTier?: ExecutionTier;
  escalationReason?: string;
  reasoningTokens?: number;
  appCheckAttestation?: AppCheckAttestation;
  nanoReadiness?: NanoReadinessStatus;
  onDeviceResult?: OnDeviceInferenceResult;
}

export interface RehydratedRemediation {
  findingId: string;
  rehydratedPatch: string;
  verifiedLocalPass: boolean;
  explanation: string;
  cvssScore: number;
  engineUsed?: 'gemini-nano-on-device' | 'gemini-2.5-pro-cloud' | 'gemini-hybrid-fallback';
  executionTier?: ExecutionTier;
  escalationReason?: string;
  reasoningTokens?: number;
  appCheckAttestation?: AppCheckAttestation;
  nanoReadiness?: NanoReadinessStatus;
  onDeviceResult?: OnDeviceInferenceResult;
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
  appCheckEnforced?: boolean;
}
