/**
 * Sentinel-AI Extension: On-Device Diff Security Scanner
 * (Google #BuildHybridAI 2026 Hackathon)
 *
 * Scans PR diffs in-browser with on-device heuristics & Chrome Built-in AI (Prompt API).
 * Never sends plaintext diffs or credentials to cloud networks.
 */

(function (global) {
  'use strict';

  const DiffScanner = {
    /**
     * Parses raw git diff text into structured file chunks
     */
    parseRawDiff(diffText) {
      const files = [];
      const lines = (diffText || '').split('\n');
      let currentFile = null;
      let currentHunk = null;

      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];

        if (line.startsWith('diff --git')) {
          const match = line.match(/diff --git a\/(.+?) b\/(.+)/);
          currentFile = {
            oldPath: match ? match[1] : 'unknown',
            newPath: match ? match[2] : 'unknown',
            hunks: []
          };
          files.push(currentFile);
        } else if (line.startsWith('@@') && currentFile) {
          const match = line.match(/@@ -(\d+)(?:,\d+)? \+(\d+)(?:,\d+)? @@/);
          currentHunk = {
            oldStart: match ? parseInt(match[1], 10) : 1,
            newStart: match ? parseInt(match[2], 10) : 1,
            lines: []
          };
          currentFile.hunks.push(currentHunk);
        } else if (currentHunk) {
          currentHunk.lines.push(line);
        }
      }

      return files;
    },

    /**
     * Scans an array of code lines/files and returns security findings
     */
    scanDiffChunks(files) {
      const vault = global.SentinelVault;
      const findings = [];
      let totalVaultCount = 0;
      let maxCvss = 0.0;
      const soc2Set = new Set(['CC6.1']);

      for (const file of files) {
        const filename = file.newPath || 'file.ts';
        let newLineNumber = 1;

        for (const hunk of (file.hunks || [])) {
          newLineNumber = hunk.newStart;

          for (const line of hunk.lines) {
            if (line.startsWith('+') && !line.startsWith('+++')) {
              const addedCode = line.substring(1);
              const { sanitized, items, vaultCount } = vault ? vault.vault(addedCode) : { sanitized: addedCode, items: [], vaultCount: 0 };
              totalVaultCount += vaultCount;

              // Check CWEs
              // 1. SQL Injection (CWE-89)
              if (/(?:query|raw|execute)\s*\(.*(?:\+|\$\{)/i.test(sanitized) || /(?:SELECT|UPDATE|INSERT|DELETE).*(?:\+|\$\{)/i.test(sanitized)) {
                findings.push({
                  id: `SEC-CWE89-${findings.length + 1}`,
                  file: filename,
                  line: newLineNumber,
                  cwe: 'CWE-89',
                  title: 'SQL Injection in PR Diff Addition',
                  severity: 'CRITICAL',
                  cvss: 9.8,
                  originalSnippet: addedCode.trim(),
                  patchSnippet: 'const result = await db.query("SELECT * FROM users WHERE id = $1", [param]);',
                  explanation: 'Replaced dynamic concatenation in PR diff with parameterized statement binding.',
                  soc2: ['CC6.1', 'CC6.6']
                });
                maxCvss = Math.max(maxCvss, 9.8);
                soc2Set.add('CC6.6');
              }

              // 2. Command Injection (CWE-78)
              else if (/(?:exec|execSync)\s*\(.*(?:\+|\$\{)/i.test(sanitized) || /(?:spawn)\s*\([^)]*shell:\s*true/i.test(sanitized)) {
                findings.push({
                  id: `SEC-CWE78-${findings.length + 1}`,
                  file: filename,
                  line: newLineNumber,
                  cwe: 'CWE-78',
                  title: 'OS Command Injection in PR Diff Addition',
                  severity: 'CRITICAL',
                  cvss: 9.8,
                  originalSnippet: addedCode.trim(),
                  patchSnippet: "execFile('tool', ['-arg', safeParam], (err, out) => {});",
                  explanation: 'Switch from subshell execution to child_process.execFile with argument array.',
                  soc2: ['CC6.1', 'CC6.8']
                });
                maxCvss = Math.max(maxCvss, 9.8);
                soc2Set.add('CC6.8');
              }

              // 3. Path Traversal (CWE-22)
              else if (/(?:readFile|readFileSync|createReadStream|sendFile)\s*\(.*(?:\+|\$\{)/i.test(sanitized) || /path\.join\s*\([^)]*,\s*[a-zA-Z0-9_.]+/i.test(sanitized) || /path\.join\s*\(.*(?:\+|\$\{)/i.test(sanitized)) {
                findings.push({
                  id: `SEC-CWE22-${findings.length + 1}`,
                  file: filename,
                  line: newLineNumber,
                  cwe: 'CWE-22',
                  title: 'Path Traversal in PR Diff Addition',
                  severity: 'HIGH',
                  cvss: 7.5,
                  originalSnippet: addedCode.trim(),
                  patchSnippet: "const safe = path.resolve(SAFE_DIR, path.basename(param));\nif (!safe.startsWith(SAFE_DIR)) throw new Error('Blocked');",
                  explanation: 'Enforce canonical base directory containment check using path.resolve.',
                  soc2: ['CC6.1', 'CC6.3']
                });
                maxCvss = Math.max(maxCvss, 7.5);
                soc2Set.add('CC6.3');
              }

              // 4. Hardcoded Secrets (CWE-798)
              else if (/(?:const|let|var)\s+[A-Z0-9_]*(?:KEY|SECRET|TOKEN|PASSWORD)\s*=\s*["'][^"']+["']/i.test(sanitized) || vaultCount > 0) {
                findings.push({
                  id: `SEC-CWE798-${findings.length + 1}`,
                  file: filename,
                  line: newLineNumber,
                  cwe: 'CWE-798',
                  title: 'Hardcoded Cryptographic Secret in PR Diff',
                  severity: 'HIGH',
                  cvss: 8.9,
                  originalSnippet: addedCode.trim(),
                  patchSnippet: 'const SECRET = process.env.SECURE_KEY || "";',
                  explanation: 'Externalize credential into environment variable at runtime; credential sealed in Edge Vault.',
                  soc2: ['CC6.1', 'CC6.2']
                });
                maxCvss = Math.max(maxCvss, 8.9);
                soc2Set.add('CC6.2');
              }

              // 5. SSRF (CWE-918)
              else if (/(?:axios\.get|fetch)\s*\(\s*(?:targetUrl|url|req\.query)/i.test(sanitized)) {
                findings.push({
                  id: `SEC-CWE918-${findings.length + 1}`,
                  file: filename,
                  line: newLineNumber,
                  cwe: 'CWE-918',
                  title: 'Server-Side Request Forgery (SSRF) in PR Diff',
                  severity: 'HIGH',
                  cvss: 8.6,
                  originalSnippet: addedCode.trim(),
                  patchSnippet: 'const parsed = new URL(targetUrl);\nif (!ALLOWED_HOSTS.has(parsed.hostname)) throw new Error("Blocked");',
                  explanation: 'Validate destination against strict domain allow-list and reject private metadata IPs.',
                  soc2: ['CC6.1', 'CC6.6']
                });
                maxCvss = Math.max(maxCvss, 8.6);
                soc2Set.add('CC6.6');
              }

              newLineNumber++;
            } else if (!line.startsWith('-')) {
              newLineNumber++;
            }
          }
        }
      }

      const status = findings.length === 0 ? 'SAFE' : maxCvss >= 9.0 ? 'CRITICAL' : 'WARNING';

      return {
        status,
        findingsCount: findings.length,
        findings,
        vaultCount: totalVaultCount,
        cvss: maxCvss,
        soc2Controls: Array.from(soc2Set),
        gdprArticle: 'Article 32(1)(a) Cryptographic Vaulting',
        executionTier: 'on-device-nano',
        timestamp: new Date().toISOString()
      };
    },

    /**
     * Generates OASIS SARIF v2.1.0 output from PR findings
     */
    generateSarif(auditResult) {
      return {
        $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
        version: '2.1.0',
        runs: [
          {
            tool: {
              driver: {
                name: 'Sentinel-AI Extension',
                semanticVersion: '1.2.0',
                informationUri: 'https://github.com/genda-benjamin/sentinel-hybrid-ai'
              }
            },
            results: auditResult.findings.map(f => ({
              ruleId: f.cwe,
              level: f.severity === 'CRITICAL' || f.severity === 'HIGH' ? 'error' : 'warning',
              message: { text: `${f.title}: ${f.explanation}` },
              locations: [
                {
                  physicalLocation: {
                    artifactLocation: { uri: f.file },
                    region: { startLine: f.line }
                  }
                }
              ]
            }))
          }
        ]
      };
    }
  };

  global.DiffScanner = DiffScanner;

  if (typeof module !== 'undefined' && module.exports) {
    module.exports = DiffScanner;
  }
})(typeof globalThis !== 'undefined' ? globalThis : this);
