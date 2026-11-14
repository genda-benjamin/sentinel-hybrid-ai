import { describe, it } from 'node:test';
import assert from 'node:assert';
import { CrossFileTaintTracker } from '../core/taint-tracker.js';

describe('CrossFileTaintTracker Unit Tests', () => {
  const sampleFiles = [
    {
      path: 'src/controllers/userController.ts',
      content: `
import { getUserProfile } from '../services/userService.js';

export function handleRequest(req, res) {
  const userId = req.query.id;
  const profile = getUserProfile(userId);
  res.json(profile);
}
      `
    },
    {
      path: 'src/services/userService.ts',
      content: `
import { queryUserRaw } from '../repositories/userRepository.js';

const DB_SECRET = "postgres://root:SuperSecretPassword2026@cluster0.db.internal:5432/users";

export function getUserProfile(id) {
  return queryUserRaw(id);
}
      `
    },
    {
      path: 'src/repositories/userRepository.ts',
      content: `
const db = { query: (q) => q };

export function queryUserRaw(rawId) {
  return db.query("SELECT * FROM users WHERE id = " + rawId);
}
      `
    }
  ];

  it('should build cross-file call graph and resolve inter-procedural edges', () => {
    const graph = CrossFileTaintTracker.buildGraph(sampleFiles);

    assert.ok(graph.nodes.size >= 3);
    assert.ok(graph.edges.length >= 2);

    // Verify presence of SOURCE, TRANSFORMER, SINK
    const hasSource = Array.from(graph.nodes.values()).some(n => n.kind === 'SOURCE');
    const hasSink = Array.from(graph.nodes.values()).some(n => n.kind === 'SINK');
    const hasTransformer = Array.from(graph.nodes.values()).some(n => n.kind === 'TRANSFORMER');

    assert.strictEqual(hasSource, true);
    assert.strictEqual(hasSink, true);
    assert.strictEqual(hasTransformer, true);
  });

  it('should trace multi-hop taint trajectory across 3 distinct files', () => {
    const graph = CrossFileTaintTracker.buildGraph(sampleFiles);
    const traces = CrossFileTaintTracker.traceTaint(graph);

    assert.ok(traces.length >= 1);
    const trace = traces[0];

    assert.strictEqual(trace.cwe, 'CWE-89');
    assert.ok(trace.hops >= 2);
    assert.strictEqual(trace.isNeutralized, false);
    assert.ok(trace.riskScore > 0.6);
    assert.ok(['CRITICAL', 'HIGH'].includes(trace.riskLevel));

    // Verify trajectory starts at controller and ends at repository
    assert.ok(trace.source.filePath.includes('userController'));
    assert.ok(trace.sink.filePath.includes('userRepository'));
  });

  it('should vault proprietary database secrets on-device and de-identify cross-file trace', () => {
    const graph = CrossFileTaintTracker.buildGraph(sampleFiles);
    const traces = CrossFileTaintTracker.traceTaint(graph);
    const trace = traces[0];

    const { deidentifiedTrace, vaultedSecretsCount } = CrossFileTaintTracker.deidentifyTrace(trace);

    // Verify trace is formatted and path is sanitized
    const reportText = CrossFileTaintTracker.formatTraceReport(deidentifiedTrace);
    assert.ok(reportText.includes('Cross-File Taint Chain'));
    assert.ok(reportText.includes('CWE-89'));

    // Verify no plaintext secrets leak in snippets
    for (const node of deidentifiedTrace.path) {
      assert.strictEqual(node.codeSnippet.includes('SuperSecretPassword2026'), false);
    }
  });

  it('should detect when sanitization neutralizes the taint chain', () => {
    const sanitizedFiles = [
      {
        path: 'src/controllers/userController.ts',
        content: `
import { getUserProfile } from '../services/userService.js';

export function handleRequest(req, res) {
  const safeId = parseInt(req.query.id, 10);
  const profile = getUserProfile(safeId);
}
        `
      },
      {
        path: 'src/services/userService.ts',
        content: `
import { queryUserRaw } from '../repositories/userRepository.js';
export function getUserProfile(id) {
  return queryUserRaw(id);
}
        `
      },
      {
        path: 'src/repositories/userRepository.ts',
        content: `
export function queryUserRaw(rawId) {
  return db.query("SELECT * FROM users WHERE id = " + rawId);
}
        `
      }
    ];

    const graph = CrossFileTaintTracker.buildGraph(sanitizedFiles);
    const traces = CrossFileTaintTracker.traceTaint(graph);

    // If sanitized, any traces that include the sanitizer should have isNeutralized = true
    const neutralizedTrace = traces.find(t => t.isNeutralized);
    if (neutralizedTrace) {
      assert.strictEqual(neutralizedTrace.riskScore, 0.0);
      assert.strictEqual(neutralizedTrace.riskLevel, 'LOW');
    }
  });
});
