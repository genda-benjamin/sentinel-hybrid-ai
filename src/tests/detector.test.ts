import { describe, it } from 'node:test';
import assert from 'node:assert';
import { LocalDetector } from '../core/detector.js';

describe('LocalDetector Unit Tests', () => {
  it('should detect SQL Injection vulnerability (CWE-89)', () => {
    const code = `
      const query = db.query(\`SELECT * FROM users WHERE id = \${req.params.id}\`);
    `;
    const findings = LocalDetector.scanContent('api/users.ts', code);
    assert.strictEqual(findings.length, 1);
    assert.strictEqual(findings[0].cwe, 'CWE-89');
    assert.strictEqual(findings[0].severity, 'CRITICAL');
    assert.strictEqual(findings[0].requiresCloudReasoning, true);
  });

  it('should detect Command Injection vulnerability (CWE-78)', () => {
    const code = `
      const out = exec(\`ping -c 4 \${req.body.ip}\`);
    `;
    const findings = LocalDetector.scanContent('services/network.ts', code);
    assert.strictEqual(findings.length, 1);
    assert.strictEqual(findings[0].cwe, 'CWE-78');
    assert.strictEqual(findings[0].severity, 'CRITICAL');
  });

  it('should detect Path Traversal vulnerability (CWE-22)', () => {
    const code = `
      const fileData = fs.readFileSync(path.join('/uploads', req.query.file));
    `;
    const findings = LocalDetector.scanContent('routes/download.ts', code);
    assert.strictEqual(findings.length, 1);
    assert.strictEqual(findings[0].cwe, 'CWE-22');
    assert.strictEqual(findings[0].severity, 'HIGH');
  });

  it('should detect Prototype Pollution locally without requiring cloud reasoning', () => {
    const code = `
      Object.assign({}, req.body);
    `;
    const findings = LocalDetector.scanContent('utils/merge.ts', code);
    assert.strictEqual(findings.length, 1);
    assert.strictEqual(findings[0].cwe, 'CWE-1321');
    assert.strictEqual(findings[0].requiresCloudReasoning, false);
  });
});
