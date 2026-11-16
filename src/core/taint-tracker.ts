/**
 * Sentinel-AI Cross-File Semantic Taint Graph Analyzer
 * Engineered for Google #BuildHybridAI 2026
 *
 * Maps multi-hop sources (routes/controllers), transformers (services),
 * and sinks (repositories/database/exec) across files locally, vaults secrets,
 * and passes de-identified semantic traces to Firebase AI Logic (Gemini 2.5 Pro)
 * for coordinated multi-file patch synthesis.
 */

import { LocalSanitizer } from './sanitizer.js';
import type { Severity } from '../cloud/types.js';

export type NodeKind = 'SOURCE' | 'TRANSFORMER' | 'SANITIZER' | 'SINK';
export type RiskLevel = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export interface TaintNode {
  id: string; // `${file}:${line}:${name}`
  kind: NodeKind;
  filePath: string;
  functionName: string;
  variableName?: string;
  codeSnippet: string;
  line: number;
  col: number;
  semanticTags: string[];
  isSanitized: boolean;
  confidence: number;
}

export interface CallEdge {
  id: string;
  fromId: string;
  toId: string;
  callSite: string;
  argIndex: number;
  filePath: string;
  line: number;
  taintPassed: boolean;
  transformOp?: string;
}

export interface TaintTrace {
  traceId: string;
  source: TaintNode;
  sink: TaintNode;
  path: TaintNode[]; // Ordered multi-hop chain
  edges: CallEdge[];
  sanitizersOnPath: TaintNode[];
  hops: number;
  riskScore: number;
  riskLevel: RiskLevel;
  cwe: string;
  isNeutralized: boolean;
  explanation: string;
}

export interface MultiFilePatch {
  filePath: string;
  originalSnippet: string;
  remediatedSnippet: string;
  explanation: string;
}

export interface MultiFileRemediationResult {
  traceId: string;
  cwe: string;
  cvssScore: number;
  hopsResolved: number;
  engineUsed: string;
  reasoningTokens: number;
  patches: MultiFilePatch[];
  zeroLeakageVerified: boolean;
}

export interface TaintGraph {
  nodes: Map<string, TaintNode>;
  edges: CallEdge[];
  exports: Map<string, string>; // exportName -> nodeId
  imports: Map<string, Array<{ importedName: string; fromPath: string; line: number }>>;
}

export class CrossFileTaintTracker {
  // Deterministic Catalog of Taint Sources, Sinks, and Sanitizers
  private static readonly SOURCES = [
    { pattern: /req\.(?:query|body|params|headers)(?:\.([a-zA-Z0-9_]+)|\[['"](.*?)['"]\])?/g, tag: 'express.user_input' },
    { pattern: /request\.(?:query|body|params|args)(?:\.([a-zA-Z0-9_]+))?/g, tag: 'web.user_input' },
    { pattern: /process\.argv(?:\[\d+\])?/g, tag: 'cli.user_input' },
    { pattern: /searchParams\.get\(['"](.*?)['"]\)/g, tag: 'nextjs.search_params' }
  ];

  private static readonly SINKS = [
    { pattern: /(?:db|pool|client)\.query\s*\(\s*(?:`[^`]*\$\{[^}]+\}[^`]*`|["'].*?["']\s*\+\s*[a-zA-Z0-9_.]+)/g, cwe: 'CWE-89', name: 'SQL Injection Sink', tag: 'database.query' },
    { pattern: /(?:exec|execSync|spawn|spawnSync)\s*\(\s*(?:`[^`]*\$\{[^}]+\}[^`]*`|["'].*?["']\s*\+\s*[a-zA-Z0-9_.]+)/g, cwe: 'CWE-78', name: 'OS Command Injection Sink', tag: 'os.exec' },
    { pattern: /(?:fs\.readFile|fs\.createReadStream|path\.join)\s*\([^)]*?(?:req\.|userInput|filename|pathParam)/g, cwe: 'CWE-22', name: 'Path Traversal Sink', tag: 'fs.read' }
  ];

  private static readonly SANITIZERS = [
    { pattern: /(?:escapeHtml|validator\.escape|encodeURIComponent|sanitizeInput)\s*\(/g, tag: 'sanitizer.encoding' },
    { pattern: /(?:zod\.parse|joi\.validate|schema\.validate)\s*\(/g, tag: 'sanitizer.schema' },
    { pattern: /(?:parseInt|Number|parseFloat)\s*\(/g, tag: 'sanitizer.numeric_cast' }
  ];

  /**
   * Builds an inter-procedural taint graph across multiple project files.
   */
  public static buildGraph(files: Array<{ path: string; content: string }>): TaintGraph {
    const nodes = new Map<string, TaintNode>();
    const edges: CallEdge[] = [];
    const exportsMap = new Map<string, string>(); // exportKey -> nodeId
    const importsMap = new Map<string, Array<{ importedName: string; fromPath: string; line: number }>>();

    // Phase 1: Per-File AST & Symbol Extraction
    for (const file of files) {
      const normalizedPath = file.path.replace(/\\/g, '/');
      const lines = file.content.split('\n');
      const fileImports: Array<{ importedName: string; fromPath: string; line: number }> = [];

      for (let i = 0; i < lines.length; i++) {
        const lineText = lines[i];
        const lineNum = i + 1;

        // Record imports
        const importMatch = lineText.match(/import\s+\{([^}]+)\}\s+from\s+['"]([^'"]+)['"]/);
        if (importMatch) {
          const names = importMatch[1].split(',').map(s => s.trim());
          const importRelPath = importMatch[2];
          for (const name of names) {
            fileImports.push({ importedName: name, fromPath: importRelPath, line: lineNum });
          }
        }

        // Record function declarations / exports
        const funcMatch = lineText.match(/(?:export\s+(?:default\s+)?)?(?:async\s+)?function\s+([a-zA-Z0-9_]+)\s*\(([^)]*)\)/) ||
                          lineText.match(/(?:export\s+)?const\s+([a-zA-Z0-9_]+)\s*=\s*(?:async\s*)?\(([^)]*)\)\s*=>/);
        if (funcMatch) {
          const funcName = funcMatch[1];
          const isExported = lineText.includes('export');
          const nodeId = `${normalizedPath}:${lineNum}:${funcName}`;

          const node: TaintNode = {
            id: nodeId,
            kind: 'TRANSFORMER',
            filePath: normalizedPath,
            functionName: funcName,
            codeSnippet: lineText.trim(),
            line: lineNum,
            col: 1,
            semanticTags: isExported ? ['exported_function'] : ['internal_function'],
            isSanitized: false,
            confidence: 0.8
          };
          nodes.set(nodeId, node);

          if (isExported) {
            exportsMap.set(`${normalizedPath}#${funcName}`, nodeId);
            // Also store base relative alias
            const baseName = normalizedPath.split('/').pop()?.replace(/\.(ts|js|tsx|jsx)$/, '') || '';
            exportsMap.set(`${baseName}#${funcName}`, nodeId);
          }
        }

        // Detect Sources
        for (const src of this.SOURCES) {
          src.pattern.lastIndex = 0;
          if (src.pattern.test(lineText)) {
            const sourceId = `${normalizedPath}:${lineNum}:SOURCE`;
            nodes.set(sourceId, {
              id: sourceId,
              kind: 'SOURCE',
              filePath: normalizedPath,
              functionName: 'RouteHandler',
              codeSnippet: lineText.trim(),
              line: lineNum,
              col: 1,
              semanticTags: [src.tag, 'taint_source'],
              isSanitized: false,
              confidence: 0.95
            });
          }
        }

        // Detect Sinks
        for (const sink of this.SINKS) {
          sink.pattern.lastIndex = 0;
          if (sink.pattern.test(lineText)) {
            const sinkId = `${normalizedPath}:${lineNum}:SINK`;
            nodes.set(sinkId, {
              id: sinkId,
              kind: 'SINK',
              filePath: normalizedPath,
              functionName: 'DatabaseOrExecutionSink',
              codeSnippet: lineText.trim(),
              line: lineNum,
              col: 1,
              semanticTags: [sink.tag, sink.cwe],
              isSanitized: false,
              confidence: 0.98
            });
          }
        }

        // Detect Sanitizers
        for (const san of this.SANITIZERS) {
          san.pattern.lastIndex = 0;
          if (san.pattern.test(lineText)) {
            const sanId = `${normalizedPath}:${lineNum}:SANITIZER`;
            nodes.set(sanId, {
              id: sanId,
              kind: 'SANITIZER',
              filePath: normalizedPath,
              functionName: 'InputSanitizer',
              codeSnippet: lineText.trim(),
              line: lineNum,
              col: 1,
              semanticTags: [san.tag],
              isSanitized: true,
              confidence: 0.95
            });
          }
        }
      }

      importsMap.set(normalizedPath, fileImports);
    }

    // Phase 2: Cross-File Call Edge Linking
    for (const file of files) {
      const normalizedPath = file.path.replace(/\\/g, '/');
      const lines = file.content.split('\n');
      const imports = importsMap.get(normalizedPath) || [];

      for (let i = 0; i < lines.length; i++) {
        const lineText = lines[i];
        const lineNum = i + 1;

        // Check calls to imported functions
        for (const imp of imports) {
          const callRegex = new RegExp(`\\b${imp.importedName}\\s*\\(`, 'g');
          if (callRegex.test(lineText)) {
            // Find caller node in current file
            const callerNode = Array.from(nodes.values()).find(n => 
              n.filePath === normalizedPath && n.line <= lineNum && n.kind !== 'SINK'
            );

            // Resolve target node in imported file
            const targetKey1 = `${imp.fromPath}#${imp.importedName}`;
            const targetBase = imp.fromPath.split('/').pop() || '';
            const targetKey2 = `${targetBase}#${imp.importedName}`;

            const targetNodeId = exportsMap.get(targetKey1) || exportsMap.get(targetKey2) ||
              Array.from(exportsMap.entries()).find(([k]) => k.endsWith(`#${imp.importedName}`))?.[1];

            if (callerNode && targetNodeId) {
              edges.push({
                id: `edge_${callerNode.id}->${targetNodeId}`,
                fromId: callerNode.id,
                toId: targetNodeId,
                callSite: lineText.trim(),
                argIndex: 0,
                filePath: normalizedPath,
                line: lineNum,
                taintPassed: true,
                transformOp: 'inter_procedural_call'
              });
            }
          }
        }

        // Intra-file Source -> Transformer or Transformer -> Sink edges
        const sourceHere = Array.from(nodes.values()).find(n => n.filePath === normalizedPath && n.line === lineNum && n.kind === 'SOURCE');
        const sinkHere = Array.from(nodes.values()).find(n => n.filePath === normalizedPath && n.line === lineNum && n.kind === 'SINK');
        const transformerHere = Array.from(nodes.values()).find(n => n.filePath === normalizedPath && n.line <= lineNum && n.kind === 'TRANSFORMER');

        if (sourceHere && transformerHere && sourceHere.id !== transformerHere.id) {
          edges.push({
            id: `edge_${sourceHere.id}->${transformerHere.id}`,
            fromId: sourceHere.id,
            toId: transformerHere.id,
            callSite: lineText.trim(),
            argIndex: 0,
            filePath: normalizedPath,
            line: lineNum,
            taintPassed: true,
            transformOp: 'request_param_binding'
          });
        }

        if (transformerHere && sinkHere && transformerHere.id !== sinkHere.id) {
          edges.push({
            id: `edge_${transformerHere.id}->${sinkHere.id}`,
            fromId: transformerHere.id,
            toId: sinkHere.id,
            callSite: lineText.trim(),
            argIndex: 0,
            filePath: normalizedPath,
            line: lineNum,
            taintPassed: true,
            transformOp: 'database_query_dispatch'
          });
        }
      }
    }

    return { nodes, edges, exports: exportsMap, imports: importsMap };
  }

  /**
   * Executes BFS Multi-Hop Taint Propagation with Sanitizer Neutralization.
   */
  public static traceTaint(graph: TaintGraph): TaintTrace[] {
    const traces: TaintTrace[] = [];
    const sourceNodes = Array.from(graph.nodes.values()).filter(n => n.kind === 'SOURCE');

    for (const source of sourceNodes) {
      // BFS Traversal
      const queue: Array<{ current: TaintNode; path: TaintNode[]; edgesOnPath: CallEdge[] }> = [
        { current: source, path: [source], edgesOnPath: [] }
      ];
      const visited = new Set<string>([source.id]);

      while (queue.length > 0) {
        const { current, path, edgesOnPath } = queue.shift()!;

        // Check if current is a SINK
        if (current.kind === 'SINK') {
          const cweTag = current.semanticTags.find(t => t.startsWith('CWE-')) || 'CWE-89';
          const sanitizersOnPath = path.filter(n => n.kind === 'SANITIZER');
          const isNeutralized = sanitizersOnPath.length > 0;
          const hops = path.length - 1;

          // Compute quantitative risk score (hybrid semantic decay)
          const baseSeverity = cweTag === 'CWE-89' || cweTag === 'CWE-78' ? 1.0 : 0.8;
          const decay = Math.pow(0.95, hops);
          const riskMultiplier = isNeutralized ? 0.0 : 1.0;
          const riskScore = Number((source.confidence * baseSeverity * decay * riskMultiplier).toFixed(3));

          let riskLevel: RiskLevel = 'LOW';
          if (riskScore >= 0.8) riskLevel = 'CRITICAL';
          else if (riskScore >= 0.6) riskLevel = 'HIGH';
          else if (riskScore >= 0.3) riskLevel = 'MEDIUM';

          traces.push({
            traceId: `TRACE-${cweTag}-${traces.length + 1}`,
            source,
            sink: current,
            path,
            edges: edgesOnPath,
            sanitizersOnPath,
            hops,
            riskScore,
            riskLevel,
            cwe: cweTag,
            isNeutralized,
            explanation: isNeutralized
              ? `Taint neutralized by sanitizer at ${sanitizersOnPath[0].filePath}:${sanitizersOnPath[0].line}`
              : `Unsanitized ${cweTag} flow across ${hops} hops from ${source.filePath}:${source.line} to ${current.filePath}:${current.line}`
          });
          continue;
        }

        // Traverse outgoing edges
        const outgoing = graph.edges.filter(e => e.fromId === current.id);
        for (const edge of outgoing) {
          const nextNode = graph.nodes.get(edge.toId);
          if (nextNode && !visited.has(nextNode.id)) {
            visited.add(nextNode.id);
            queue.push({
              current: nextNode,
              path: [...path, nextNode],
              edgesOnPath: [...edgesOnPath, edge]
            });
          }
        }
      }
    }

    return traces;
  }

  /**
   * Formats a human-readable and terminal-friendly cross-file taint trace diagram.
   */
  public static formatTraceReport(trace: TaintTrace): string {
    let out = `\n🔗 [Cross-File Taint Chain: ${trace.traceId}] (${trace.cwe}) - Risk: ${trace.riskLevel} (${(trace.riskScore * 100).toFixed(1)}%)\n`;
    out += `   Hops: ${trace.hops} | Neutralized: ${trace.isNeutralized ? 'YES (Safe)' : 'NO (CRITICAL VULNERABILITY)'}\n`;
    out += `   Path Trajectory:\n`;

    for (let i = 0; i < trace.path.length; i++) {
      const node = trace.path[i];
      const isLast = i === trace.path.length - 1;
      const prefix = i === 0 ? '   🟢 [SOURCE]' : (isLast ? '   🔴 [SINK]  ' : '   🟡 [HOP]   ');
      out += `${prefix} ${node.filePath}:${node.line} -> ${node.functionName} (Snippet: "${node.codeSnippet.slice(0, 60)}")\n`;
    }

    return out;
  }

  /**
   * De-identifies the cross-file taint trace prior to cloud LLM transmission.
   * Cryptographically vaults any secrets along the path in local memory.
   */
  public static deidentifyTrace(trace: TaintTrace): { deidentifiedTrace: TaintTrace; vaultedSecretsCount: number } {
    let vaultedSecretsCount = 0;
    const deidentifiedPath: TaintNode[] = [];

    for (const node of trace.path) {
      const sanitized = LocalSanitizer.sanitize(node.codeSnippet);
      vaultedSecretsCount += sanitized.vaultTokenCount;

      deidentifiedPath.push({
        ...node,
        codeSnippet: sanitized.sanitizedContent,
        filePath: node.filePath.replace(/^.*[\\/]([^\\/]+[\\/][^\\/]+)$/, '$1') // normalize to relative 2-level path
      });
    }

    const deidentifiedTrace: TaintTrace = {
      ...trace,
      path: deidentifiedPath,
      source: deidentifiedPath[0],
      sink: deidentifiedPath[deidentifiedPath.length - 1]
    };

    return { deidentifiedTrace, vaultedSecretsCount };
  }
}
