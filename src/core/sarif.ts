/**
 * Sentinel-AI SARIF v2.1.0 Exporter
 * Generates OASIS-compliant Static Analysis Results Interchange Format (SARIF)
 * for native ingestion by GitHub Advanced Security, GitLab Security, and Enterprise SIEMs.
 */

import { writeFileSync } from 'node:fs';
import type { AuditReport, LocalFinding, RehydratedRemediation } from '../cloud/types.js';

export interface SarifRegion {
  startLine: number;
  startColumn?: number;
  endLine?: number;
  endColumn?: number;
  snippet?: {
    text: string;
  };
}

export interface SarifPhysicalLocation {
  artifactLocation: {
    uri: string;
    uriBaseId?: string;
  };
  region: SarifRegion;
}

export interface SarifLocation {
  physicalLocation: SarifPhysicalLocation;
}

export interface SarifReplacement {
  deletedRegion: {
    startLine: number;
    startColumn?: number;
  };
  insertedContent: {
    text: string;
  };
}

export interface SarifFix {
  description: {
    text: string;
  };
  changes: Array<{
    artifactLocation: {
      uri: string;
    };
    replacements: SarifReplacement[];
  }>;
}

export interface SarifResult {
  ruleId: string;
  ruleIndex?: number;
  level: 'error' | 'warning' | 'note' | 'none';
  message: {
    text: string;
  };
  locations: SarifLocation[];
  fixes?: SarifFix[];
  properties?: {
    cvssScore?: number;
    owaspCategory?: string;
    requiresCloudReasoning?: boolean;
    reasoningTokens?: number;
    engineUsed?: string;
    [key: string]: unknown;
  };
}

export interface SarifReportingDescriptor {
  id: string;
  name: string;
  shortDescription: {
    text: string;
  };
  fullDescription: {
    text: string;
  };
  defaultConfiguration: {
    level: 'error' | 'warning' | 'note' | 'none';
  };
  helpUri: string;
  properties: {
    tags: string[];
    'security-severity': string;
    precision: string;
    problem?: {
      severity: string;
    };
  };
}

export interface SarifRun {
  tool: {
    driver: {
      name: string;
      version: string;
      informationUri: string;
      rules: SarifReportingDescriptor[];
    };
  };
  results: SarifResult[];
  invocations?: Array<{
    executionSuccessful: boolean;
    endTimeUtc?: string;
  }>;
}

export interface SarifLog {
  $schema: string;
  version: '2.1.0';
  runs: SarifRun[];
}

export class SarifExporter {
  public static readonly SCHEMA_URI =
    'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json';

  private static readonly RULE_METADATA: Record<
    string,
    { name: string; short: string; full: string; cweUrl: string; baseScore: string }
  > = {
    'CWE-89': {
      name: 'SqlInjection',
      short: 'Improper Neutralization of Special Elements used in an SQL Command',
      full: 'The application constructs SQL queries using untrusted user input without parameterized placeholders, enabling remote arbitrary SQL execution.',
      cweUrl: 'https://cwe.mitre.org/data/definitions/89.html',
      baseScore: '9.8'
    },
    'CWE-78': {
      name: 'CommandInjection',
      short: 'Improper Neutralization of Special Elements used in an OS Command',
      full: 'The application executes operating system commands using unsanitized user inputs, enabling remote arbitrary command execution on the host server.',
      cweUrl: 'https://cwe.mitre.org/data/definitions/78.html',
      baseScore: '9.8'
    },
    'CWE-22': {
      name: 'PathTraversal',
      short: 'Improper Limitation of a Pathname to a Restricted Directory',
      full: 'The software uses external input to construct a pathname intended to identify a file or directory located under a restricted directory without proper path normalization.',
      cweUrl: 'https://cwe.mitre.org/data/definitions/22.html',
      baseScore: '7.5'
    },
    'CWE-1321': {
      name: 'PrototypePollution',
      short: 'Improperly Controlled Modification of Object Prototype Attributes',
      full: 'The application modifies attributes of an object prototype using unsanitized key access, potentially leading to denial of service or remote code execution.',
      cweUrl: 'https://cwe.mitre.org/data/definitions/1321.html',
      baseScore: '6.5'
    },
    'CWE-798': {
      name: 'HardcodedCredentials',
      short: 'Use of Hard-coded Credentials',
      full: 'The application contains hardcoded credentials, API keys, or private keys within source code.',
      cweUrl: 'https://cwe.mitre.org/data/definitions/798.html',
      baseScore: '8.9'
    }
  };

  /**
   * Transforms an AuditReport into an OASIS SARIF v2.1.0 document.
   */
  public static generateSarif(report: AuditReport): SarifLog {
    const rulesMap = new Map<string, SarifReportingDescriptor>();
    const remediationsByFinding = new Map<string, RehydratedRemediation>();

    for (const rem of report.remediations) {
      remediationsByFinding.set(rem.findingId, rem);
    }

    const results: SarifResult[] = [];

    for (const finding of report.findings) {
      const cweKey = finding.cwe || 'CWE-Other';
      if (!rulesMap.has(cweKey)) {
        const meta = SarifExporter.RULE_METADATA[cweKey] || {
          name: finding.ruleId || 'SecurityVulnerability',
          short: finding.message,
          full: finding.message,
          cweUrl: `https://cwe.mitre.org/`,
          baseScore: SarifExporter.severityToScore(finding.severity)
        };

        rulesMap.set(cweKey, {
          id: cweKey,
          name: meta.name,
          shortDescription: { text: meta.short },
          fullDescription: { text: meta.full },
          defaultConfiguration: {
            level: SarifExporter.severityToSarifLevel(finding.severity)
          },
          helpUri: meta.cweUrl,
          properties: {
            tags: ['security', 'owasp', 'hybrid-ai', 'sentinel-ai'],
            'security-severity': meta.baseScore,
            precision: 'high',
            problem: {
              severity: SarifExporter.severityToProblemSeverity(finding.severity)
            }
          }
        });
      }

      const remediation = remediationsByFinding.get(finding.id);
      const normalizedPath = finding.file.replace(/\\/g, '/');

      const resultItem: SarifResult = {
        ruleId: cweKey,
        level: SarifExporter.severityToSarifLevel(finding.severity),
        message: {
          text: `[Sentinel-AI Hybrid] ${finding.message}`
        },
        locations: [
          {
            physicalLocation: {
              artifactLocation: {
                uri: normalizedPath,
                uriBaseId: '%SRCROOT%'
              },
              region: {
                startLine: finding.line,
                startColumn: 1,
                snippet: {
                  text: finding.snippet
                }
              }
            }
          }
        ],
        properties: {
          cvssScore: remediation?.cvssScore ?? parseFloat(SarifExporter.severityToScore(finding.severity)),
          owaspCategory: finding.owaspCategory,
          requiresCloudReasoning: finding.requiresCloudReasoning,
          reasoningTokens: remediation?.reasoningTokens,
          engineUsed: remediation?.engineUsed
        }
      };

      if (remediation && remediation.rehydratedPatch) {
        resultItem.fixes = [
          {
            description: {
              text: `Apply Sentinel-AI zero-leakage verified patch (${remediation.engineUsed || 'hybrid-reasoner'})`
            },
            changes: [
              {
                artifactLocation: {
                  uri: normalizedPath
                },
                replacements: [
                  {
                    deletedRegion: {
                      startLine: finding.line,
                      startColumn: 1
                    },
                    insertedContent: {
                      text: remediation.rehydratedPatch
                    }
                  }
                ]
              }
            ]
          }
        ];
      }

      results.push(resultItem);
    }

    const rules = Array.from(rulesMap.values());

    return {
      $schema: SarifExporter.SCHEMA_URI,
      version: '2.1.0',
      runs: [
        {
          tool: {
            driver: {
              name: 'Sentinel-AI',
              version: '1.0.0',
              informationUri: 'https://github.com/genda-benjamin/sentinel-hybrid-ai',
              rules
            }
          },
          results,
          invocations: [
            {
              executionSuccessful: true,
              endTimeUtc: report.timestamp
            }
          ]
        }
      ]
    };
  }

  public static toSarifJson(report: AuditReport, indent = 2): string {
    const sarifObj = SarifExporter.generateSarif(report);
    return JSON.stringify(sarifObj, null, indent);
  }

  public static writeSarifFile(report: AuditReport, outputPath: string): void {
    const jsonStr = SarifExporter.toSarifJson(report);
    writeFileSync(outputPath, jsonStr, 'utf-8');
  }

  private static severityToSarifLevel(severity: string): 'error' | 'warning' | 'note' | 'none' {
    switch (severity.toUpperCase()) {
      case 'CRITICAL':
      case 'HIGH':
        return 'error';
      case 'MEDIUM':
        return 'warning';
      case 'LOW':
      case 'INFO':
        return 'note';
      default:
        return 'warning';
    }
  }

  private static severityToProblemSeverity(severity: string): string {
    switch (severity.toUpperCase()) {
      case 'CRITICAL':
      case 'HIGH':
        return 'error';
      case 'MEDIUM':
        return 'warning';
      default:
        return 'recommendation';
    }
  }

  private static severityToScore(severity: string): string {
    switch (severity.toUpperCase()) {
      case 'CRITICAL':
        return '9.5';
      case 'HIGH':
        return '8.0';
      case 'MEDIUM':
        return '5.5';
      case 'LOW':
        return '3.0';
      default:
        return '1.0';
    }
  }
}
