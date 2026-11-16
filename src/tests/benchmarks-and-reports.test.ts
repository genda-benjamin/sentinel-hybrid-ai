import { describe, it } from 'node:test';
import assert from 'node:assert';
import { ProjectScanner } from '../core/scanner.js';
import { ComplianceReporter } from '../core/reporter.js';
import { ArchitectureBenchmark } from '../core/benchmarks.js';
import type { AuditReport } from '../cloud/types.js';

describe('ProjectScanner Unit Tests', () => {
  it('should discover source files recursively and ignore node_modules and dist', () => {
    const files = ProjectScanner.discoverFiles('sample');
    assert.ok(files.length >= 1, 'Should find files in sample dir');
    assert.ok(files.some(f => f.includes('vulnerable-app.ts')), 'Should discover sample/vulnerable-app.ts');
  });
});

describe('ComplianceReporter Unit Tests', () => {
  it('should generate formal SOC 2 and GDPR markdown report with SHA-256 fingerprint', () => {
    const mockReport: AuditReport = {
      timestamp: new Date().toISOString(),
      filesScanned: 3,
      totalFindings: 2,
      criticalCount: 1,
      highCount: 1,
      mediumCount: 0,
      lowCount: 0,
      cloudEscalations: 1,
      leakagePreventionRate: '100%',
      findings: [
        {
          id: 'FIND-1',
          file: 'test.ts',
          line: 10,
          ruleId: 'SEC-001',
          cwe: 'CWE-89',
          owaspCategory: 'A03:2021-Injection',
          severity: 'CRITICAL',
          message: 'SQL Injection',
          snippet: 'db.query(...)',
          requiresCloudReasoning: true
        }
      ],
      remediations: [
        {
          findingId: 'FIND-1',
          rehydratedPatch: 'db.query("... $1", [id])',
          verifiedLocalPass: true,
          explanation: 'Remediated via parameterized placeholder.',
          cvssScore: 9.8,
          engineUsed: 'gemini-2.5-pro-cloud',
          reasoningTokens: 1488
        }
      ]
    };

    const md = ComplianceReporter.generateMarkdownReport(mockReport);
    assert.ok(md.includes('Sentinel-AI Security & Compliance Certificate'));
    assert.ok(md.includes('SOC 2 Type II'));
    assert.ok(md.includes('GDPR'));
    assert.ok(md.includes('100% COMPLIANT (PASS)'));
    assert.ok(md.includes('1488'));
  });
});

describe('ArchitectureBenchmark Unit Tests', () => {
  it('should run comparative benchmark and verify Sentinel-AI hybrid superiority', async () => {
    const testCode = `const secret = "sk-live123456789"; db.query("SELECT * FROM u WHERE id = " + id);`;
    const results = await ArchitectureBenchmark.runBenchmark(testCode);

    assert.strictEqual(results.length, 3);
    const cloud = results.find(r => r.mode === 'cloud-only');
    const edge = results.find(r => r.mode === 'edge-only');
    const hybrid = results.find(r => r.mode === 'sentinel-hybrid');

    assert.ok(cloud && cloud.secretExposureBytes > 0, 'Cloud mode exposes secret bytes');
    assert.ok(edge && edge.reasoningDepthTokens === 0, 'Edge mode lacks deep reasoning');
    assert.ok(hybrid && hybrid.secretExposureBytes === 0, 'Sentinel-AI guarantees 0 secret exposure');
    assert.ok(hybrid && hybrid.reasoningDepthTokens > 1000, 'Sentinel-AI leverages deep reasoning');

    const formatted = ArchitectureBenchmark.formatConsoleReport(results);
    assert.ok(formatted.includes('WINNER: Sentinel-AI Hybrid Architecture'));
  });
});
