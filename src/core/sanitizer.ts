import { createHmac, randomBytes } from 'node:crypto';
import type { EgressAuditResult, SanitizeOptions, SanitizedPayload } from '../cloud/types.js';

interface SecretDefinition {
  category: 'API_KEY' | 'PRIVATE_KEY' | 'DATABASE_URL' | 'JWT' | 'PASSWORD' | 'PII_INFRA';
  pattern: RegExp;
  hasCaptureGroup?: boolean;
}

const SECRET_DEFINITIONS: SecretDefinition[] = [
  // Private Keys
  {
    category: 'PRIVATE_KEY',
    pattern: /-----BEGIN[ A-Z0-9_-]+PRIVATE KEY-----[A-Za-z0-9+/=\r\n]+-----END[ A-Z0-9_-]+PRIVATE KEY-----/g
  },
  // Cloud, AI & SaaS API Keys (OpenAI, Anthropic, Google AI, Groq, HF, Stripe, GitHub, AWS, Slack, npm)
  {
    category: 'API_KEY',
    pattern: /\b(?:sk-ant-[a-zA-Z0-9_-]{20,120}|sk-proj-[a-zA-Z0-9_-]{20,120}|sk-[a-zA-Z0-9_-]{20,64}|AIza[0-9A-Za-z-_]{30,45}|ya29\.[0-9A-Za-z_-]{20,}|gh[pousr]_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9_]{82}|hf_[a-zA-Z0-9]{20,}|gsk_[a-zA-Z0-9]{20,}|npm_[a-zA-Z0-9]{30,}|sk_live_[0-9a-zA-Z]{24,32}|rk_live_[0-9a-zA-Z]{24,32}|whsec_[0-9a-zA-Z]{20,64}|AKIA[0-9A-Z]{16}|xox[bap]-[A-Za-z0-9-]+|wJalrXUtnFEMI\/K7MDENG\/bPxRfiCYEXAMPLEKEY)\b/g
  },
  // Bearer / Basic Authorization tokens in string literals
  {
    category: 'API_KEY',
    pattern: /\b(?:Bearer|Basic)\s+([A-Za-z0-9._+/=-]{20,160})\b/g,
    hasCaptureGroup: true
  },
  // Database connection URLs
  {
    category: 'DATABASE_URL',
    pattern: /\b(?:postgres|postgresql|mysql|mongodb(?:\+srv)?|redis|amqp|amqps):\/\/[a-zA-Z0-9_.~%-]+:[a-zA-Z0-9_.~%-]+@[a-zA-Z0-9_.-]+(?::[0-9]+)?\/[a-zA-Z0-9_.~%-]*/g
  },
  // JWT tokens
  {
    category: 'JWT',
    pattern: /\beyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\b/g
  },
  // Passwords and Secrets in quoted assignments (negative lookahead ignores already-vaulted tokens)
  {
    category: 'PASSWORD',
    pattern: /(?:[a-zA-Z0-9_]*(?:password|secret|passwd|token|pass|apikey|api_key|signing_key|private_key))\s*[:=]\s*["'](?!__SENTINEL_)([^"'\r\n]{6,128})["']/gi,
    hasCaptureGroup: true
  }
];

const INFRA_PII_DEFINITIONS: SecretDefinition[] = [
  // RFC 1918 Private IPv4 addresses
  {
    category: 'PII_INFRA',
    pattern: /\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b/g
  },
  // Internal hostnames
  {
    category: 'PII_INFRA',
    pattern: /\b[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)*\.(?:internal|corp|local|intranet)\b/g
  },
  // Email addresses
  {
    category: 'PII_INFRA',
    pattern: /\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b/g
  }
];

export class LocalSanitizer {
  // Ephemeral per-process HMAC key prevents offline dictionary/rainbow attacks on hashed placeholders
  private static readonly SESSION_HMAC_KEY: Buffer = randomBytes(32);

  /**
   * Computes Shannon entropy (bits per character) for secret randomness detection.
   */
  public static calculateShannonEntropy(input: string): number {
    if (!input || input.length === 0) return 0;
    const freq = new Map<string, number>();
    for (let i = 0; i < input.length; i++) {
      const ch = input[i];
      freq.set(ch, (freq.get(ch) || 0) + 1);
    }
    let entropy = 0;
    const len = input.length;
    for (const count of freq.values()) {
      const p = count / len;
      entropy -= p * Math.log2(p);
    }
    return Number(entropy.toFixed(3));
  }

  /**
   * Generates a keyed HMAC-SHA256 deterministic pseudonym for a secret.
   */
  private static createPseudonym(category: string, secretVal: string, sessionKey?: string | Buffer): string {
    const key = sessionKey ?? this.SESSION_HMAC_KEY;
    const hash = createHmac('sha256', key).update(`${category}:${secretVal}`).digest('hex').substring(0, 12);
    return `__SENTINEL_${category}_${hash}__`;
  }

  private static isLikelyNonSecretLiteral(literal: string): boolean {
    if (literal.startsWith('__SENTINEL_') || literal.startsWith('[VAULT_TOKEN_')) return true;
    if (/^https?:\/\//i.test(literal)) return true;
    if (/^(\.{0,2}\/|\/)[a-zA-Z0-9_./-]+$/.test(literal)) return true;
    if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(literal)) return true; // UUID
    if (/\s/.test(literal)) return true; // Natural language or SQL queries with spaces
    return false;
  }

  /**
   * Sanitizes sensitive code locally on-device.
   * Generates unique HMAC-keyed replacement tokens and stores original secrets in an isolated vault.
   */
  public static sanitize(content: string, options: SanitizeOptions = {}): SanitizedPayload {
    const vault = new Map<string, string>();
    const redactedCategories: Record<string, number> = {};
    let sanitized = content;

    const definitions = options.redactInfraAndPii
      ? [...SECRET_DEFINITIONS, ...INFRA_PII_DEFINITIONS]
      : SECRET_DEFINITIONS;

    for (const def of definitions) {
      def.pattern.lastIndex = 0;
      sanitized = sanitized.replace(def.pattern, (match: string, ...rest: unknown[]) => {
        let secretVal = match;
        const captured = def.hasCaptureGroup && typeof rest[0] === 'string' ? rest[0] : undefined;
        if (captured) {
          secretVal = captured;
        }

        if (typeof secretVal === 'string' && secretVal.startsWith('__SENTINEL_')) {
          return match;
        }

        const tokenPlaceholder = this.createPseudonym(def.category, String(secretVal), options.sessionKey);

        if (!vault.has(tokenPlaceholder)) {
          vault.set(tokenPlaceholder, secretVal);
          redactedCategories[def.category] = (redactedCategories[def.category] || 0) + 1;
        }

        if (captured) {
          return match.replace(captured, tokenPlaceholder);
        }
        return tokenPlaceholder;
      });
    }

    // Pass 2: Shannon entropy scan for unknown proprietary keys/tokens in string literals
    if (options.redactHighEntropy !== false) {
      const threshold = options.entropyThreshold ?? 4.25;
      const literalPattern = /(["'])(?!__SENTINEL_)([^"'\r\n]{20,256})\1/g;
      sanitized = sanitized.replace(literalPattern, (fullMatch: string, quote: string, inner: string) => {
        if (this.isLikelyNonSecretLiteral(inner)) {
          return fullMatch;
        }
        const entropy = this.calculateShannonEntropy(inner);
        const hasMixedClasses = /[A-Z]/.test(inner) && /[a-z]/.test(inner) && /[0-9+/=_-]/.test(inner);
        if (entropy >= threshold && hasMixedClasses) {
          const tokenPlaceholder = this.createPseudonym('ENTROPY', inner, options.sessionKey);
          if (!vault.has(tokenPlaceholder)) {
            vault.set(tokenPlaceholder, inner);
            redactedCategories['ENTROPY'] = (redactedCategories['ENTROPY'] || 0) + 1;
          }
          return `${quote}${tokenPlaceholder}${quote}`;
        }
        return fullMatch;
      });
    }

    return {
      sanitizedContent: sanitized,
      vaultTokenCount: vault.size,
      tokens: vault,
      redactedCategories
    };
  }

  /**
   * Re-hydrates a sanitized cloud remediation patch locally using the in-memory vault.
   */
  public static rehydrate(sanitizedPatch: string, vault: Map<string, string>): string {
    let rehydrated = sanitizedPatch;
    for (const [placeholder, original] of vault.entries()) {
      rehydrated = rehydrated.replaceAll(placeholder, original);
    }
    return rehydrated;
  }

  /**
   * Verifies that no known secret patterns remain in the sanitized content before cloud dispatch.
   */
  public static verifyZeroLeakage(sanitizedContent: string): boolean {
    for (const def of SECRET_DEFINITIONS) {
      const freshRegex = new RegExp(def.pattern.source, def.pattern.flags.replace('g', ''));
      if (freshRegex.test(sanitizedContent)) {
        return false;
      }
    }
    return true;
  }

  /**
   * Performs a quantitative cryptographic & entropy audit of the outbound payload.
   */
  public static auditEgress(
    sanitizedContent: string,
    tokens: Map<string, string>,
    categories: Record<string, number> = {}
  ): EgressAuditResult {
    const zeroLeakage = this.verifyZeroLeakage(sanitizedContent);
    const literalPattern = /(["'])([^"'\r\n]{20,256})\1/g;
    let residualHighEntropyLiterals = 0;
    let maxResidualEntropy = 0;

    let match: RegExpExecArray | null;
    while ((match = literalPattern.exec(sanitizedContent)) !== null) {
      const val = match[2];
      if (this.isLikelyNonSecretLiteral(val)) continue;
      const ent = this.calculateShannonEntropy(val);
      if (ent > maxResidualEntropy) maxResidualEntropy = ent;
      if (ent >= 4.25 && /[A-Z]/.test(val) && /[a-z]/.test(val) && /[0-9+/=_-]/.test(val)) {
        residualHighEntropyLiterals++;
      }
    }

    return {
      zeroLeakage: zeroLeakage && residualHighEntropyLiterals === 0,
      vaultedCount: tokens.size,
      residualHighEntropyLiterals,
      maxResidualEntropy,
      categories
    };
  }
}
