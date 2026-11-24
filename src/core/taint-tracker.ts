/**
 * Sentinel-AI Cross-File Semantic Taint Graph Analyzer (AST-Backed)
 * Engineered for Google #BuildHybridAI 2026
 *
 * Uses the TypeScript Compiler AST to map multi-hop sources (routes/controllers),
 * sanitizers (validators/encoders), transformers (services), and sinks (DB/OS/FS/SSRF/LLM)
 * across files locally, vaults secrets, and passes de-identified semantic traces to
 * Firebase AI Logic (Gemini 2.5 Pro) for coordinated multi-file patch synthesis.
 */

import ts from 'typescript';
import { LocalSanitizer } from './sanitizer.js';

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
  imports: Map<string, Array<{ importedName: string; localName: string; fromPath: string; line: number }>>;
}

interface FunctionSpan {
  nodeId: string;
  name: string;
  startLine: number;
  endLine: number;
}

export class CrossFileTaintTracker {
  private static readonly SOURCES = [
    { pattern: /\b(?:req|request)\.(?:query|body|params|headers|cookies|args)(?:\.[a-zA-Z0-9_]+|\[['"][^'"]+['"]\])?/g, tag: 'express.user_input' },
    { pattern: /\bprocess\.argv(?:\[\d+\])?/g, tag: 'cli.user_input' },
    { pattern: /\bsearchParams\.get\(['"][^'"]+['"]\)/g, tag: 'nextjs.search_params' },
    { pattern: /\b(?:userPrompt|ragContext|toolInput|mcpArgs)\b/g, tag: 'agentic.user_input' }
  ];

  private static readonly SINKS = [
    { pattern: /(?:db|pool|client)\.(?:query|execute|raw)\s*\(\s*(?:`[^`]*\$\{[^}]+\}[^`]*`|["'].*?["']\s*\+\s*[a-zA-Z0-9_.]+)/g, cwe: 'CWE-89', name: 'SQL Injection Sink', tag: 'database.query' },
    { pattern: /(?:exec|execSync|spawn|spawnSync)\s*\(\s*(?:`[^`]*\$\{[^}]+\}[^`]*`|["'].*?["']\s*\+\s*[a-zA-Z0-9_.]+)/g, cwe: 'CWE-78', name: 'OS Command Injection Sink', tag: 'os.exec' },
    { pattern: /(?:fs\.readFile|fs\.readFileSync|fs\.createReadStream|path\.join)\s*\([^)]*?(?:req\.|userInput|filename|pathParam|filePath)/g, cwe: 'CWE-22', name: 'Path Traversal Sink', tag: 'fs.read' },
    { pattern: /(?:fetch|axios\.(?:get|post|request)|http\.get)\s*\(\s*(?:targetUrl|url|req\.)/g, cwe: 'CWE-918', name: 'SSRF Sink', tag: 'network.ssrf' },
    { pattern: /(?:generateContent|prompt|createCompletion)\s*\(\s*(?:`[^`]*\$\{[^}]+\}[^`]*`|["'].*?["']\s*\+\s*[a-zA-Z0-9_.]+)/g, cwe: 'CWE-77', name: 'Prompt Injection Sink', tag: 'llm.prompt' }
  ];

  private static readonly SANITIZERS = [
    { pattern: /(?:escapeHtml|validator\.escape|encodeURIComponent|sanitizeInput|DOMPurify\.sanitize)\s*\(/g, tag: 'sanitizer.encoding' },
    { pattern: /(?:zod\.parse|schema\.safeParse|joi\.validate|schema\.validate)\s*\(/g, tag: 'sanitizer.schema' },
    { pattern: /(?:parseInt|Number|parseFloat)\s*\(/g, tag: 'sanitizer.numeric_cast' },
    { pattern: /path\.basename\s*\(/g, tag: 'sanitizer.path_basename' }
  ];

  /**
   * Builds an inter-procedural AST-backed taint graph across multiple project files.
   */
  public static buildGraph(files: Array<{ path: string; content: string }>): TaintGraph {
    const nodes = new Map<string, TaintNode>();
    const edges: CallEdge[] = [];
    const exportsMap = new Map<string, string>();
    const importsMap = new Map<string, Array<{ importedName: string; localName: string; fromPath: string; line: number }>>();
    const functionSpansByFile = new Map<string, FunctionSpan[]>();

    // Phase 1: Per-File TypeScript AST & Symbol Extraction
    for (const file of files) {
      const normalizedPath = file.path.replace(/\\/g, '/');
      const lines = file.content.split('\n');
      const fileImports: Array<{ importedName: string; localName: string; fromPath: string; line: number }> = [];
      const fileSpans: FunctionSpan[] = [];

      const sourceFile = ts.createSourceFile(normalizedPath, file.content, ts.ScriptTarget.ES2022, true);

      const hasExportModifier = (node: ts.Node): boolean => {
        const mods = ts.canHaveModifiers(node) ? ts.getModifiers(node) : undefined;
        return Boolean(mods?.some(m => m.kind === ts.SyntaxKind.ExportKeyword));
      };

      const registerFunctionNode = (funcName: string, astNode: ts.Node, isExported: boolean) => {
        const start = sourceFile.getLineAndCharacterOfPosition(astNode.getStart(sourceFile));
        const end = sourceFile.getLineAndCharacterOfPosition(astNode.getEnd());
        const startLine = start.line + 1;
        const endLine = end.line + 1;
        const nodeId = `${normalizedPath}:${startLine}:${funcName}`;

        if (!nodes.has(nodeId)) {
          nodes.set(nodeId, {
            id: nodeId,
            kind: 'TRANSFORMER',
            filePath: normalizedPath,
            functionName: funcName,
            codeSnippet: lines[startLine - 1]?.trim() || funcName,
            line: startLine,
            col: start.character + 1,
            semanticTags: isExported ? ['exported_function'] : ['internal_function'],
            isSanitized: false,
            confidence: 0.85
          });
        }

        fileSpans.push({ nodeId, name: funcName, startLine, endLine });

        if (isExported) {
          exportsMap.set(`${normalizedPath}#${funcName}`, nodeId);
          const baseName = normalizedPath.split('/').pop()?.replace(/\.(ts|js|tsx|jsx|mjs|cjs)$/, '') || '';
          exportsMap.set(`${baseName}#${funcName}`, nodeId);
        }
      };

      const visitAst = (node: ts.Node) => {
        // Import declarations (named, aliased, default)
        if (ts.isImportDeclaration(node) && ts.isStringLiteral(node.moduleSpecifier)) {
          const fromPath = node.moduleSpecifier.text;
          const line = sourceFile.getLineAndCharacterOfPosition(node.getStart(sourceFile)).line + 1;
          const clause = node.importClause;
          if (clause?.name) {
            fileImports.push({ importedName: clause.name.text, localName: clause.name.text, fromPath, line });
          }
          if (clause?.namedBindings && ts.isNamedImports(clause.namedBindings)) {
            for (const el of clause.namedBindings.elements) {
              const importedName = el.propertyName ? el.propertyName.text : el.name.text;
              const localName = el.name.text;
              fileImports.push({ importedName, localName, fromPath, line });
            }
          }
        }

        // Function declarations
        if (ts.isFunctionDeclaration(node) && node.name) {
          registerFunctionNode(node.name.text, node, hasExportModifier(node));
        }

        // Arrow / Function expressions assigned to variables
        if (ts.isVariableStatement(node)) {
          const isExported = hasExportModifier(node);
          for (const decl of node.declarationList.declarations) {
            if (
              ts.isIdentifier(decl.name) &&
              decl.initializer &&
              (ts.isArrowFunction(decl.initializer) || ts.isFunctionExpression(decl.initializer))
            ) {
              registerFunctionNode(decl.name.text, decl, isExported);
            }
          }
        }

        // Class methods
        if (ts.isMethodDeclaration(node) && ts.isIdentifier(node.name)) {
          registerFunctionNode(node.name.text, node, true);
        }

        ts.forEachChild(node, visitAst);
      };

      visitAst(sourceFile);

      // Scan non-comment AST statements / lines for Sources, Sanitizers, Sinks
      const visitStatements = (node: ts.Node) => {
        if (ts.isCallExpression(node) || ts.isVariableDeclaration(node) || ts.isBinaryExpression(node)) {
          const text = node.getText(sourceFile);
          const pos = sourceFile.getLineAndCharacterOfPosition(node.getStart(sourceFile));
          const lineNum = pos.line + 1;
          const colNum = pos.character + 1;

          for (const src of this.SOURCES) {
            src.pattern.lastIndex = 0;
            if (src.pattern.test(text)) {
              const sourceId = `${normalizedPath}:${lineNum}:SOURCE`;
              if (!nodes.has(sourceId)) {
                nodes.set(sourceId, {
                  id: sourceId,
                  kind: 'SOURCE',
                  filePath: normalizedPath,
                  functionName: 'RouteHandler',
                  codeSnippet: lines[lineNum - 1]?.trim() || text,
                  line: lineNum,
                  col: colNum,
                  semanticTags: [src.tag, 'taint_source'],
                  isSanitized: false,
                  confidence: 0.95
                });
              }
            }
          }

          for (const sink of this.SINKS) {
            sink.pattern.lastIndex = 0;
            if (sink.pattern.test(text)) {
              const sinkId = `${normalizedPath}:${lineNum}:SINK`;
              if (!nodes.has(sinkId)) {
                nodes.set(sinkId, {
                  id: sinkId,
                  kind: 'SINK',
                  filePath: normalizedPath,
                  functionName: sink.name,
                  codeSnippet: lines[lineNum - 1]?.trim() || text,
                  line: lineNum,
                  col: colNum,
                  semanticTags: [sink.tag, sink.cwe],
                  isSanitized: false,
                  confidence: 0.98
                });
              }
            }
          }

          for (const san of this.SANITIZERS) {
            san.pattern.lastIndex = 0;
            if (san.pattern.test(text)) {
              const sanId = `${normalizedPath}:${lineNum}:SANITIZER`;
              if (!nodes.has(sanId)) {
                nodes.set(sanId, {
                  id: sanId,
                  kind: 'SANITIZER',
                  filePath: normalizedPath,
                  functionName: 'InputSanitizer',
                  codeSnippet: lines[lineNum - 1]?.trim() || text,
                  line: lineNum,
                  col: colNum,
                  semanticTags: [san.tag],
                  isSanitized: true,
                  confidence: 0.95
                });
              }
            }
          }
        }
        ts.forEachChild(node, visitStatements);
      };

      visitStatements(sourceFile);
      importsMap.set(normalizedPath, fileImports);
      functionSpansByFile.set(normalizedPath, fileSpans);
    }

    const addEdge = (edge: CallEdge) => {
      if (!edges.some(e => e.id === edge.id)) {
        edges.push(edge);
      }
    };

    const findEnclosingFunction = (filePath: string, lineNum: number): TaintNode | undefined => {
      const spans = functionSpansByFile.get(filePath) || [];
      // Choose innermost enclosing span
      const matching = spans
        .filter(s => s.startLine <= lineNum && lineNum <= s.endLine)
        .sort((a, b) => (a.endLine - a.startLine) - (b.endLine - b.startLine));
      if (matching.length > 0) {
        return nodes.get(matching[0].nodeId);
      }
      return Array.from(nodes.values()).find(
        n => n.filePath === filePath && n.line <= lineNum && n.kind === 'TRANSFORMER'
      );
    };

    // Phase 2: Scope-Aware Intra-File & Cross-File Call Edge Linking
    for (const file of files) {
      const normalizedPath = file.path.replace(/\\/g, '/');
      const lines = file.content.split('\n');
      const imports = importsMap.get(normalizedPath) || [];
      const fileNodes = Array.from(nodes.values()).filter(n => n.filePath === normalizedPath);

      const fileSources = fileNodes.filter(n => n.kind === 'SOURCE');
      const fileSanitizers = fileNodes.filter(n => n.kind === 'SANITIZER');
      const fileSinks = fileNodes.filter(n => n.kind === 'SINK');

      // Link SOURCE -> SANITIZER (if present in scope) -> TRANSFORMER, and TRANSFORMER -> SINK
      for (const sourceNode of fileSources) {
        const enclosingFunc = findEnclosingFunction(normalizedPath, sourceNode.line);
        const sanitizerAfterSource = fileSanitizers.find(
          s => Math.abs(s.line - sourceNode.line) <= 2 && findEnclosingFunction(normalizedPath, s.line)?.id === enclosingFunc?.id
        );

        if (sanitizerAfterSource && enclosingFunc && sanitizerAfterSource.id !== enclosingFunc.id) {
          addEdge({
            id: `edge_${sourceNode.id}->${sanitizerAfterSource.id}`,
            fromId: sourceNode.id,
            toId: sanitizerAfterSource.id,
            callSite: sanitizerAfterSource.codeSnippet,
            argIndex: 0,
            filePath: normalizedPath,
            line: sanitizerAfterSource.line,
            taintPassed: false,
            transformOp: 'input_sanitization'
          });
          addEdge({
            id: `edge_${sanitizerAfterSource.id}->${enclosingFunc.id}`,
            fromId: sanitizerAfterSource.id,
            toId: enclosingFunc.id,
            callSite: enclosingFunc.codeSnippet,
            argIndex: 0,
            filePath: normalizedPath,
            line: enclosingFunc.line,
            taintPassed: false,
            transformOp: 'sanitized_param_binding'
          });
        } else if (enclosingFunc && sourceNode.id !== enclosingFunc.id) {
          addEdge({
            id: `edge_${sourceNode.id}->${enclosingFunc.id}`,
            fromId: sourceNode.id,
            toId: enclosingFunc.id,
            callSite: sourceNode.codeSnippet,
            argIndex: 0,
            filePath: normalizedPath,
            line: sourceNode.line,
            taintPassed: true,
            transformOp: 'request_param_binding'
          });
        }
      }

      for (const sinkNode of fileSinks) {
        const enclosingFunc = findEnclosingFunction(normalizedPath, sinkNode.line);
        if (enclosingFunc && enclosingFunc.id !== sinkNode.id) {
          addEdge({
            id: `edge_${enclosingFunc.id}->${sinkNode.id}`,
            fromId: enclosingFunc.id,
            toId: sinkNode.id,
            callSite: sinkNode.codeSnippet,
            argIndex: 0,
            filePath: normalizedPath,
            line: sinkNode.line,
            taintPassed: true,
            transformOp: 'database_query_dispatch'
          });
        }
      }

      // Cross-file imported function call edges (via AST CallExpression)
      const sourceFile = ts.createSourceFile(normalizedPath, file.content, ts.ScriptTarget.ES2022, true);
      const visitCalls = (astNode: ts.Node) => {
        if (ts.isCallExpression(astNode)) {
          const lineNum = sourceFile.getLineAndCharacterOfPosition(astNode.getStart(sourceFile)).line + 1;
          const calleeName = ts.isIdentifier(astNode.expression)
            ? astNode.expression.text
            : ts.isPropertyAccessExpression(astNode.expression)
              ? astNode.expression.name.text
              : '';

          if (calleeName) {
            const matchedImp = imports.find(imp => imp.localName === calleeName);
            if (matchedImp) {
              const callerNode = findEnclosingFunction(normalizedPath, lineNum) ||
                fileNodes.find(n => n.line <= lineNum && n.kind !== 'SINK');

              const cleanFrom = matchedImp.fromPath.replace(/\.(js|ts|mjs|cjs)$/, '');
              const targetBase = cleanFrom.split('/').pop() || '';
              const targetNodeId =
                exportsMap.get(`${matchedImp.fromPath}#${matchedImp.importedName}`) ||
                exportsMap.get(`${targetBase}#${matchedImp.importedName}`) ||
                Array.from(exportsMap.entries()).find(([k]) => k.endsWith(`#${matchedImp.importedName}`))?.[1];

              if (callerNode && targetNodeId && callerNode.id !== targetNodeId) {
                addEdge({
                  id: `edge_${callerNode.id}->${targetNodeId}`,
                  fromId: callerNode.id,
                  toId: targetNodeId,
                  callSite: lines[lineNum - 1]?.trim() || astNode.getText(sourceFile),
                  argIndex: 0,
                  filePath: normalizedPath,
                  line: lineNum,
                  taintPassed: true,
                  transformOp: 'inter_procedural_call'
                });
              }
            }
          }
        }
        ts.forEachChild(astNode, visitCalls);
      };
      visitCalls(sourceFile);
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
      const queue: Array<{ current: TaintNode; path: TaintNode[]; edgesOnPath: CallEdge[] }> = [
        { current: source, path: [source], edgesOnPath: [] }
      ];
      const visited = new Set<string>([source.id]);

      while (queue.length > 0) {
        const { current, path, edgesOnPath } = queue.shift()!;

        if (current.kind === 'SINK') {
          const cweTag = current.semanticTags.find(t => t.startsWith('CWE-')) || 'CWE-89';
          const sanitizersOnPath = path.filter(n => n.kind === 'SANITIZER');
          const isNeutralized = sanitizersOnPath.length > 0;
          const hops = path.length - 1;

          const baseSeverity = cweTag === 'CWE-89' || cweTag === 'CWE-78' ? 1.0 : 0.85;
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
      const prefix = i === 0 ? '   🟢 [SOURCE]' : (isLast ? '   🔴 [SINK]  ' : (node.kind === 'SANITIZER' ? '   🛡️  [CLEAN] ' : '   🟡 [HOP]   '));
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
        filePath: node.filePath.replace(/^.*[\\/]([^\\/]+[\\/][^\\/]+)$/, '$1')
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
