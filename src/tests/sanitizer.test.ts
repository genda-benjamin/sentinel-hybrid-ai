import { describe, it } from 'node:test';
import assert from 'node:assert';
import { LocalSanitizer } from '../core/sanitizer.js';

describe('LocalSanitizer Unit Tests', () => {
  it('should redact and vault OpenAI and Google API keys without leaking', () => {
    const code = `
      const openaiKey = "sk-live1234567890abcdef1234567890abcdef";
      const googleKey = "AIzaSyD1234567890AbcdEfGhIjKlMnOpQrStU";
      const res = await fetch("https://api.example.com", { headers: { Authorization: openaiKey } });
    `;

    const result = LocalSanitizer.sanitize(code);

    // Assert that the original keys are NOT in the sanitized output
    assert.strictEqual(result.sanitizedContent.includes('sk-live1234567890abcdef1234567890abcdef'), false);
    assert.strictEqual(result.sanitizedContent.includes('AIzaSyD1234567890AbcdEfGhIjKlMnOpQrStU'), false);

    // Assert placeholders exist
    assert.strictEqual(result.sanitizedContent.includes('__SENTINEL_API_KEY_'), true);
    assert.strictEqual(result.vaultTokenCount, 2);

    // Assert Zero Leakage verification passes
    assert.strictEqual(LocalSanitizer.verifyZeroLeakage(result.sanitizedContent), true);
  });

  it('should redact and vault database connection URLs with passwords', () => {
    const code = `
      const dbUrl = "postgres://admin_user:SuperSecretPassword123@db.prod.internal:5432/main_db";
      const client = new Client(dbUrl);
    `;

    const result = LocalSanitizer.sanitize(code);

    assert.strictEqual(result.sanitizedContent.includes('SuperSecretPassword123'), false);
    assert.strictEqual(result.sanitizedContent.includes('__SENTINEL_DATABASE_URL_'), true);
    assert.strictEqual(LocalSanitizer.verifyZeroLeakage(result.sanitizedContent), true);
  });

  it('should faithfully rehydrate original secrets into a remediation patch', () => {
    const rawSecret = 'sk-live1234567890abcdef1234567890abcdef';
    const code = `const apiKey = "${rawSecret}";`;
    
    const sanitized = LocalSanitizer.sanitize(code);
    assert.strictEqual(sanitized.sanitizedContent.includes(rawSecret), false);

    // Simulate Cloud Gemini returning a patch with the placeholder preserved
    const mockCloudPatch = `// Secure load\nconst apiKey = process.env.API_KEY || "${Array.from(sanitized.tokens.keys())[0]}";`;

    // Rehydrate locally
    const rehydrated = LocalSanitizer.rehydrate(mockCloudPatch, sanitized.tokens);
    assert.strictEqual(rehydrated.includes(rawSecret), true);
    assert.strictEqual(rehydrated.includes('__SENTINEL_API_KEY_'), false);
  });
});
