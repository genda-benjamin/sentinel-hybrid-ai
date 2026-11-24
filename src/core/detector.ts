import type { LocalFinding, Severity } from '../cloud/types.js';
import { AstSecurityEngine } from './ast-engine.js';

interface Rule {
  id: string;
  cwe: string;
  owasp: string;
  severity: Severity;
  message: string;
  regex: RegExp;
  requiresCloudReasoning: boolean;
}

const STATIC_RULES: Rule[] = [
  {
    id: 'SEC-001',
    cwe: 'CWE-89',
    owasp: 'A03:2021-Injection',
    severity: 'CRITICAL',
    message: 'Potential SQL Injection: Dynamic SQL concatenation detected in database query call.',
    regex: /(?:query|execute|raw)\s*\(\s*(?:`[^`]*\$\{.*?\}[^`]*`|["'].*?["']\s*\+\s*[a-zA-Z0-9_.]+)/g,
    requiresCloudReasoning: true
  },
  {
    id: 'SEC-002',
    cwe: 'CWE-78',
    owasp: 'A03:2021-Injection',
    severity: 'CRITICAL',
    message: 'OS Command Injection: Untrusted input directly formatted into child process shell execution.',
    regex: /(?:exec|execSync)\s*\(\s*(?:`[^`]*\$\{.*?\}[^`]*`|["'].*?["']\s*\+\s*[a-zA-Z0-9_.]+)/g,
    requiresCloudReasoning: true
  },
  {
    id: 'SEC-003',
    cwe: 'CWE-22',
    owasp: 'A01:2021-Broken Access Control',
    severity: 'HIGH',
    message: 'Path Traversal: Unvalidated path parameter passed into file system read/write operation.',
    regex: /(?:readFile|readFileSync|createReadStream)\s*\(\s*(?:path\.join\([^)]*req\.|`[^`]*\$\{req\..*?\}`)/g,
    requiresCloudReasoning: true
  },
  {
    id: 'SEC-004',
    cwe: 'CWE-1321',
    owasp: 'A06:2021-Vulnerable and Outdated Components',
    severity: 'HIGH',
    message: 'Prototype Pollution: Unchecked recursive object merge or direct __proto__ manipulation.',
    regex: /(?:__proto__|constructor\.prototype)\s*\[|\bObject\.assign\s*\(\s*\{\}\s*,\s*req\.body\b/g,
    requiresCloudReasoning: false
  },
  {
    id: 'SEC-005',
    cwe: 'CWE-798',
    owasp: 'A07:2021-Identification and Authentication Failures',
    severity: 'HIGH',
    message: 'Hardcoded Secret Detected: Unencrypted credential or private token stored directly in source code.',
    regex: /(?:apiKey|api_key|secret|password|private_key|JWT_SECRET)\s*[:=]\s*["'][A-Za-z0-9_!@#$%^&*+=/-]{16,}["']/g,
    requiresCloudReasoning: false
  },
  {
    id: 'SEC-006',
    cwe: 'CWE-95',
    owasp: 'A03:2021-Injection',
    severity: 'CRITICAL',
    message: 'Code Execution: Unsafe direct evaluation of string expressions via eval() or Function constructor.',
    regex: /\b(?:eval|Function)\s*\(\s*[^)]*req\./g,
    requiresCloudReasoning: true
  }
];

const NON_JS_EXTENSIONS = new Set(['.py', '.sql', '.yaml', '.yml', '.json']);

export class LocalDetector {
  /**
   * Scans raw file content locally using TypeScript Compiler AST dataflow analysis
   * for JS/TS files, with regex fallback for non-JS languages (Python/SQL).
   */
  public static scanContent(filePath: string, content: string): LocalFinding[] {
    const lowerPath = filePath.toLowerCase();
    const isNonJs = Array.from(NON_JS_EXTENSIONS).some(ext => lowerPath.endsWith(ext));

    const findings: LocalFinding[] = [];
    const seenKeys = new Set<string>();

    // 1. Primary TypeScript Compiler AST + Intra-procedural Taint Engine for TS/JS
    if (!isNonJs) {
      const astFindings = AstSecurityEngine.analyze(filePath, content);
      for (const f of astFindings) {
        const key = `${f.ruleId}:${f.line}`;
        if (!seenKeys.has(key)) {
          seenKeys.add(key);
          findings.push(f);
        }
      }
    }

    // 2. Hardcoded secret checks + non-JS fallback scan (ignoring JS/TS comments)
    const lines = content.split('\n');
    for (let lineIdx = 0; lineIdx < lines.length; lineIdx++) {
      const line = lines[lineIdx];
      const trimmed = line.trim();
      if (!isNonJs && (trimmed.startsWith('//') || trimmed.startsWith('/*') || trimmed.startsWith('*'))) {
        continue;
      }

      for (const rule of STATIC_RULES) {
        // For TS/JS files, only run SEC-005 (hardcoded secret literal check) as supplement;
        // AST engine handles structural rules accurately without comment false positives
        if (!isNonJs && rule.id !== 'SEC-005') continue;

        rule.regex.lastIndex = 0;
        if (rule.regex.test(line)) {
          const lineNum = lineIdx + 1;
          const key = `${rule.id}:${lineNum}`;
          if (!seenKeys.has(key)) {
            seenKeys.add(key);
            findings.push({
              id: `FIND-${rule.id}-${lineNum}`,
              file: filePath,
              line: lineNum,
              ruleId: rule.id,
              cwe: rule.cwe,
              owaspCategory: rule.owasp,
              severity: rule.severity,
              message: rule.message,
              snippet: trimmed,
              requiresCloudReasoning: rule.requiresCloudReasoning
            });
          }
        }
      }
    }

    return findings.sort((a, b) => a.line - b.line);
  }
}
