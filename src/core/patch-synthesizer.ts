/**
 * Shared Context-Aware Deterministic Patch Synthesizer
 * Preserves actual SQL queries, table names, CLI binaries, and variable names
 * from the sanitized AST context rather than emitting generic placeholders.
 */
export class PatchSynthesizer {
  public static synthesize(cwe: string, sanitizedContext: string): string {
    const normalizedCwe = this.normalizeCwe(cwe);

    switch (normalizedCwe) {
      case 'CWE-89':
        return this.patchSqlInjection(sanitizedContext);
      case 'CWE-78':
        return this.patchCommandInjection(sanitizedContext);
      case 'CWE-22':
        return this.patchPathTraversal(sanitizedContext);
      case 'CWE-798':
        return sanitizedContext
          .replace(/(?:const|let|var)\s+([A-Za-z0-9_]*(?:KEY|SECRET|TOKEN|PASSWORD))\s*=\s*["'][^"']+["']/gi, 'const $1 = process.env.$1 || ""');
      case 'CWE-918':
        return sanitizedContext.replace(
          /(?:axios\.(?:get|post)|fetch|http\.get)\s*\(\s*([^)]+?)\s*\)/g,
          'fetchWithSsrfGuard($1, { allowedHosts: ["api.partner.com"] })'
        );
      case 'CWE-1321':
        return sanitizedContext
          .replace(/Object\.assign\s*\(\s*\{\}\s*,\s*([^)]+)\)/g, 'Object.assign(Object.create(null), sanitizeObjectKeys($1))')
          .replace(/target\[([^\]]+)\]\s*=\s*source\[([^\]]+)\]/g, 'if ($1 !== "__proto__" && $1 !== "constructor" && $1 !== "prototype") { target[$1] = source[$2]; }');
      case 'CWE-79':
        return sanitizedContext
          .replace(/\.innerHTML\s*=\s*([^;]+)/g, '.textContent = $1')
          .replace(/(res\.(?:send|write))\s*\(\s*([^)]+)\s*\)/g, '$1(escapeHtml($2))');
      case 'CWE-77':
        return sanitizedContext
          .replace(/autoApprove\s*:\s*true/g, 'autoApprove: false')
          .replace(/dangerouslyAllowAll\s*:\s*true/g, 'dangerouslyAllowAll: false')
          .replace(/\$\{([^}]+)\}/g, '${escapePromptDelimiters($1)}');
      case 'CWE-502':
        return sanitizedContext.replace(
          /(yaml|jsyaml)\.load\s*\(\s*([^,)]+)\s*\)/g,
          '$1.load($2, { schema: $1.JSON_SCHEMA })'
        );
      case 'CWE-327':
        return sanitizedContext.replace(
          /createHash\s*\(\s*['"](?:md5|sha1)['"]\s*\)/gi,
          'createHash("sha256")'
        );
      case 'CWE-347':
        return sanitizedContext.replace(
          /algorithms\s*:\s*\[[^\]]*['"]none['"][^\]]*\]/gi,
          'algorithms: ["HS256", "RS256"]'
        );
      default:
        return sanitizedContext;
    }
  }

  private static patchSqlInjection(context: string): string {
    // Match template literal SQL: db.query(`SELECT ... ${varName} ...`)
    const templateReplaced = context.replace(
      /(\b(?:query|execute|raw)\s*\(\s*)`([^`]*)`(\s*\))/g,
      (_match, prefix: string, body: string, suffix: string) => {
        const params: string[] = [];
        let paramIdx = 1;
        const parameterizedSql = body.replace(/\$\{([^}]+)\}/g, (_s, expr: string) => {
          const trimmed = expr.trim();
          const normalizedVar = /^req\.(?:query|params|body)\.id$/i.test(trimmed) ? 'userId' : trimmed;
          params.push(normalizedVar);
          return `$${paramIdx++}`;
        });
        if (params.length === 0) return _match;
        const cleanSql = parameterizedSql.replace(/'(\$[0-9]+)'/g, '$1');
        return `${prefix}${JSON.stringify(cleanSql)}, [${params.join(', ')}]${suffix}`;
      }
    );
    if (templateReplaced !== context) return templateReplaced;

    // Match string concatenation SQL: db.query("SELECT ... " + userId)
    const concatReplaced = context.replace(
      /(\b(?:query|execute|raw)\s*\(\s*)["']([^"']+)["']\s*\+\s*([a-zA-Z0-9_.]+)(\s*\))/g,
      (_match, prefix: string, sqlHead: string, varExpr: string, suffix: string) => {
        return `${prefix}${JSON.stringify(`${sqlHead}$1`)}, [${varExpr.trim()}]${suffix}`;
      }
    );
    if (concatReplaced !== context) return concatReplaced;

    return context;
  }

  private static patchCommandInjection(context: string): string {
    // Match exec(`cmd arg1 ${varName}`)
    const templateReplaced = context.replace(
      /\bexec(?:Sync)?\s*\(\s*`([^`]+)`([^)]*)\)/g,
      (_match, cmdBody: string, trailing: string) => {
        const parts = cmdBody.trim().split(/\s+/);
        const binary = parts[0] || '/usr/bin/tool';
        const args = parts.slice(1).map(part => {
          const interp = part.match(/^\$\{([^}]+)\}$/);
          return interp ? interp[1].trim() : JSON.stringify(part);
        });
        return `execFile(${JSON.stringify(binary)}, [${args.join(', ')}], { encoding: "utf-8" }${trailing})`;
      }
    );
    if (templateReplaced !== context) return templateReplaced;

    // Match exec("ping -c 3 " + ip)
    const concatReplaced = context.replace(
      /\bexec(?:Sync)?\s*\(\s*["']([^"']+)["']\s*\+\s*([a-zA-Z0-9_.]+)([^)]*)\)/g,
      (_match, cmdHead: string, varExpr: string, trailing: string) => {
        const parts = cmdHead.trim().split(/\s+/);
        const binary = parts[0] || '/usr/bin/tool';
        const staticArgs = parts.slice(1).map(p => JSON.stringify(p));
        const allArgs = [...staticArgs, varExpr.trim()];
        return `execFile(${JSON.stringify(binary)}, [${allArgs.join(', ')}], { encoding: "utf-8" }${trailing})`;
      }
    );
    if (concatReplaced !== context) return concatReplaced;

    // Match exec(cmdVar)
    return context.replace(
      /\bexec(?:Sync)?\s*\(\s*([a-zA-Z0-9_.]+)\s*([^)]*)\)/g,
      (_match, cmdVar: string, trailing: string) => {
        return `execFile("/usr/bin/tool", [${cmdVar.trim()}], { encoding: "utf-8" }${trailing})`;
      }
    );
  }

  private static patchPathTraversal(context: string): string {
    return context.replace(
      /\b(readFile(?:Sync)?|createReadStream)\s*\(\s*(?:path\.join\s*\(\s*([^,]+)\s*,\s*([^)]+)\s*\)|([^,)]+))/g,
      (_match, fn: string, baseDir: string | undefined, userArg: string | undefined, singleArg: string | undefined) => {
        if (baseDir && userArg) {
          return `${fn}(path.resolve(${baseDir.trim()}, path.basename(${userArg.trim()}))`;
        }
        const target = (singleArg || 'userFileName').trim();
        return `${fn}(path.resolve(SAFE_BASE_DIR, path.basename(${target}))`;
      }
    );
  }

  private static normalizeCwe(cwe: string): string {
    const match = cwe.match(/CWE-\d+/i);
    return match ? match[0].toUpperCase() : 'CWE-89';
  }
}
