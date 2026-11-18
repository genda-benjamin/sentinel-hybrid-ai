/**
 * Unit & Integration Test Suite: Sentinel-AI Chrome Extension (Days 10-12)
 * Validates Manifest V3 compliance, edge vaulting, diff scanning, and SARIF output.
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);

describe('Sentinel-AI Chrome Extension (Manifest V3) Tests', () => {
  const extensionDir = path.resolve(process.cwd(), 'extension');
  let SentinelVault: any;
  let DiffScanner: any;

  it('should load extension core engines into runtime', async () => {
    // @ts-ignore
    await import('../../extension/core/extension-vault.js');
    // @ts-ignore
    await import('../../extension/core/diff-scanner.js');
    SentinelVault = (globalThis as any).SentinelVault;
    DiffScanner = (globalThis as any).DiffScanner;
    assert.ok(SentinelVault, 'SentinelVault must be defined on globalThis');
    assert.ok(DiffScanner, 'DiffScanner must be defined on globalThis');
  });

  it('should validate manifest.json schema, permissions, and Manifest V3 structure', () => {
    const manifestPath = path.join(extensionDir, 'manifest.json');
    assert.ok(fs.existsSync(manifestPath), 'manifest.json must exist');

    const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf-8'));
    assert.equal(manifest.manifest_version, 3, 'Must be Manifest V3');
    assert.equal(manifest.name, 'Sentinel-AI: On-Device PR Security Auditor');
    assert.equal(manifest.version, '1.2.0');

    // Permissions
    assert.ok(manifest.permissions.includes('storage'), 'Must include storage permission');
    assert.ok(manifest.permissions.includes('activeTab'), 'Must include activeTab permission');
    assert.ok(manifest.permissions.includes('scripting'), 'Must include scripting permission');
    assert.ok(manifest.host_permissions.includes('https://github.com/*'), 'Must include GitHub host permission');
    assert.ok(manifest.host_permissions.includes('https://gitlab.com/*'), 'Must include GitLab host permission');

    // Background service worker
    assert.ok(manifest.background.service_worker, 'Must declare background service worker');
    const swPath = path.join(extensionDir, manifest.background.service_worker);
    assert.ok(fs.existsSync(swPath), `Service worker file must exist at ${swPath}`);

    // Content scripts
    assert.ok(manifest.content_scripts.length > 0, 'Must declare content scripts');
    for (const cs of manifest.content_scripts) {
      for (const jsFile of cs.js) {
        const filePath = path.join(extensionDir, jsFile);
        assert.ok(fs.existsSync(filePath), `Content script file must exist at ${filePath}`);
      }
      for (const cssFile of cs.css) {
        const filePath = path.join(extensionDir, cssFile);
        assert.ok(fs.existsSync(filePath), `Content style file must exist at ${filePath}`);
      }
    }

    // Popup action
    assert.ok(manifest.action.default_popup, 'Must declare popup');
    const popupPath = path.join(extensionDir, manifest.action.default_popup);
    assert.ok(fs.existsSync(popupPath), `Popup file must exist at ${popupPath}`);
  });

  it('should verify all extension PNG icons exist with valid PNG magic bytes', () => {
    const sizes = [16, 48, 128];
    const pngMagic = Buffer.from([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]);

    for (const size of sizes) {
      const iconPath = path.join(extensionDir, 'icons', `icon-${size}.png`);
      assert.ok(fs.existsSync(iconPath), `Icon file icon-${size}.png must exist`);

      const bytes = fs.readFileSync(iconPath);
      assert.ok(bytes.length > 100, `Icon file must not be empty (was ${bytes.length} bytes)`);
      assert.deepEqual(bytes.subarray(0, 8), pngMagic, `Icon file must start with PNG magic bytes`);
    }
  });

  it('should perform client-side edge AST vaulting with zero plaintext leakage', () => {
    const vaultPath = path.join(extensionDir, 'core', 'extension-vault.js');
    assert.ok(fs.existsSync(vaultPath), 'extension-vault.js must exist');

    const testSnippet = `
      const dbUrl = "postgres://root:SuperSecretPassword2026@cluster0.db.internal:5432/production";
      const openAiKey = "sk-proj-1234567890abcdef1234567890abcdef";
      const awsKey = "AKIA1234567890ABCDEF";
    `;

    const result = SentinelVault.vault(testSnippet);
    assert.equal(result.vaultCount, 3, 'Must vault all 3 credentials');
    assert.ok(result.isAirgapped, 'Must certify airgap boundary');
    assert.ok(result.redactionTimeMs > 0, 'Must record dynamic execution timing');

    // Verify plaintext is completely eradicated from sanitized code
    assert.ok(!result.sanitized.includes('SuperSecretPassword2026'), 'Database password must not leak');
    assert.ok(!result.sanitized.includes('sk-proj-'), 'OpenAI key must not leak');
    assert.ok(!result.sanitized.includes('AKIA1234567890ABCDEF'), 'AWS key must not leak');

    // Verify presence of vault tokens
    assert.ok(result.sanitized.includes('[VAULT_TOKEN_001]'), 'Must replace with VAULT_TOKEN_001');
    assert.ok(result.sanitized.includes('[VAULT_TOKEN_002]'), 'Must replace with VAULT_TOKEN_002');
    assert.ok(result.sanitized.includes('[VAULT_TOKEN_003]'), 'Must replace with VAULT_TOKEN_003');
  });

  it('should accurately parse raw git diffs into structured file hunks', () => {
    const scannerPath = path.join(extensionDir, 'core', 'diff-scanner.js');
    assert.ok(fs.existsSync(scannerPath), 'diff-scanner.js must exist');

    const sampleDiff = `diff --git a/src/api.ts b/src/api.ts
index abc..def 100644
--- a/src/api.ts
+++ b/src/api.ts
@@ -10,3 +10,4 @@
  const existingLine = 1;
+ const addedVulnerability = true;
`;

    const parsed = DiffScanner.parseRawDiff(sampleDiff);
    assert.equal(parsed.length, 1, 'Must parse 1 file');
    assert.equal(parsed[0].newPath, 'src/api.ts');
    assert.equal(parsed[0].hunks.length, 1);
    assert.equal(parsed[0].hunks[0].newStart, 10);
    assert.ok(parsed[0].hunks[0].lines.includes('+ const addedVulnerability = true;'));
  });

  it('should detect SQLi, command injection, path traversal in PR diff additions', () => {
    const scannerPath = path.join(extensionDir, 'core', 'diff-scanner.js');
    assert.ok(fs.existsSync(scannerPath), 'diff-scanner.js must exist');

    const vulnerableFiles = [
      {
        newPath: 'controllers/user.ts',
        hunks: [{
          newStart: 15,
          lines: [
            "+  const data = await db.query(`SELECT * FROM users WHERE id = ${req.query.id}`);"
          ]
        }]
      },
      {
        newPath: 'services/ping.ts',
        hunks: [{
          newStart: 25,
          lines: [
            "+  exec('ping -c 3 ' + ip, (err, out) => console.log(out));"
          ]
        }]
      },
      {
        newPath: 'routes/download.ts',
        hunks: [{
          newStart: 35,
          lines: [
            "+  const file = path.join('/var/data', userFilename);"
          ]
        }]
      }
    ];

    const result = DiffScanner.scanDiffChunks(vulnerableFiles);
    assert.equal(result.status, 'CRITICAL');
    assert.equal(result.findingsCount, 3);
    assert.equal(result.cvss, 9.8);

    const cwes = result.findings.map((f: any) => f.cwe);
    assert.ok(cwes.includes('CWE-89'), 'Must detect SQL injection');
    assert.ok(cwes.includes('CWE-78'), 'Must detect Command injection');
    assert.ok(cwes.includes('CWE-22'), 'Must detect Path traversal');

    // Each finding must have synthesized patch
    for (const f of result.findings) {
      assert.ok(f.patchSnippet.length > 0, 'Must have synthesized patch snippet');
      assert.ok(f.explanation.length > 0, 'Must have explanation');
    }
  });

  it('should report SAFE status for clean PR diff additions with zero false positives', () => {
    const scannerPath = path.join(extensionDir, 'core', 'diff-scanner.js');
    assert.ok(fs.existsSync(scannerPath), 'diff-scanner.js must exist');

    const cleanFiles = [
      {
        newPath: 'utils/math.ts',
        hunks: [{
          newStart: 1,
          lines: [
            "+export function add(a: number, b: number): number {",
            "+  return a + b;",
            "+}"
          ]
        }]
      }
    ];

    const result = DiffScanner.scanDiffChunks(cleanFiles);
    assert.equal(result.status, 'SAFE');
    assert.equal(result.findingsCount, 0);
    assert.equal(result.cvss, 0.0);
  });

  it('should generate valid OASIS SARIF v2.1.0 output from extension findings', () => {
    const scannerPath = path.join(extensionDir, 'core', 'diff-scanner.js');
    assert.ok(fs.existsSync(scannerPath), 'diff-scanner.js must exist');

    const mockAudit = {
      findings: [{
        id: 'SEC-CWE89-1',
        file: 'src/api.ts',
        line: 14,
        cwe: 'CWE-89',
        title: 'SQL Injection in PR Diff Addition',
        severity: 'CRITICAL',
        explanation: 'Parameterized query replacement'
      }]
    };

    const sarif = DiffScanner.generateSarif(mockAudit);
    assert.equal(sarif.version, '2.1.0');
    assert.equal(sarif.runs[0].tool.driver.name, 'Sentinel-AI Extension');
    assert.equal(sarif.runs[0].results.length, 1);
    assert.equal(sarif.runs[0].results[0].ruleId, 'CWE-89');
    assert.equal(sarif.runs[0].results[0].level, 'error');
    assert.equal(sarif.runs[0].results[0].locations[0].physicalLocation.artifactLocation.uri, 'src/api.ts');
    assert.equal(sarif.runs[0].results[0].locations[0].physicalLocation.region.startLine, 14);
  });
});
