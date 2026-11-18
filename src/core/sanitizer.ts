import { createHash } from 'node:crypto';
import type { SanitizedPayload } from '../cloud/types.js';

interface SecretDefinition {
  category: 'API_KEY' | 'PRIVATE_KEY' | 'DATABASE_URL' | 'JWT' | 'PASSWORD';
  pattern: RegExp;
  hasCaptureGroup?: boolean;
}

const SECRET_DEFINITIONS: SecretDefinition[] = [
  // Private Keys
  {
    category: 'PRIVATE_KEY',
    pattern: /-----BEGIN[ A-Z0-9_-]+PRIVATE KEY-----[A-Za-z0-9+/=\r\n]+-----END[ A-Z0-9_-]+PRIVATE KEY-----/g
  },
  // API Keys (OpenAI, Google AI, Stripe, GitHub, etc.)
  {
    category: 'API_KEY',
    pattern: /\b(?:sk-[a-zA-Z0-9_-]{20,64}|AIza[0-9A-Za-z-_]{30,45}|ghp_[a-zA-Z0-9]{36}|gho_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9_]{82}|sk_live_[0-9a-zA-Z]{24,32}|rk_live_[0-9a-zA-Z]{24,32}|AKIA[0-9A-Z]{16}|xox[bap]-[A-Za-z0-9-]+|wJalrXUtnFEMI\/K7MDENG\/bPxRfiCYEXAMPLEKEY)\b/g
  },
  // Database connection URLs
  {
    category: 'DATABASE_URL',
    pattern: /\b(?:postgres|postgresql|mysql|mongodb(?:\+srv)?|redis):\/\/[a-zA-Z0-9_.~%-]+:[a-zA-Z0-9_.~%-]+@[a-zA-Z0-9_.-]+(?::[0-9]+)?\/[a-zA-Z0-9_.~%-]*/g
  },
  // JWT tokens
  {
    category: 'JWT',
    pattern: /\beyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\b/g
  },
  // Passwords and Secrets in quoted assignments (negative lookahead ignores already-vaulted tokens)
  {
    category: 'PASSWORD',
    pattern: /(?:[a-zA-Z0-9_]*(?:password|secret|passwd|token|pass))\s*[:=]\s*["'](?!__SENTINEL_)([^"'\r\n]{6,128})["']/gi,
    hasCaptureGroup: true
  }
];

export class LocalSanitizer {
  /**
   * Sanitizes sensitive code locally on-device.
   * Generates unique cryptographic replacement tokens and stores original secrets in an isolated vault.
   */
  public static sanitize(content: string): SanitizedPayload {
    const vault = new Map<string, string>();
    const redactedCategories: Record<string, number> = {};
    let sanitized = content;

    for (const def of SECRET_DEFINITIONS) {
      def.pattern.lastIndex = 0;
      sanitized = sanitized.replace(def.pattern, (match: string, ...rest: any[]) => {
        let secretVal = match;
        const captured = def.hasCaptureGroup && typeof rest[0] === 'string' ? rest[0] : undefined;
        if (captured) {
          secretVal = captured;
        }

        // Do not re-sanitize a token that has already been sanitized
        if (typeof secretVal === 'string' && secretVal.startsWith('__SENTINEL_')) {
          return match;
        }

        const hash = createHash('sha256').update(String(secretVal)).digest('hex').substring(0, 12);
        const tokenPlaceholder = `__SENTINEL_${def.category}_${hash}__`;

        vault.set(tokenPlaceholder, secretVal);
        redactedCategories[def.category] = (redactedCategories[def.category] || 0) + 1;

        if (captured) {
          return match.replace(captured, tokenPlaceholder);
        }
        return tokenPlaceholder;
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
}
