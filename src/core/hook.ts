/**
 * Sentinel-AI Git Hook Manager
 * Installs offline-first, zero-leakage pre-commit hooks to prevent
 * accidental commits of hardcoded credentials or critical vulnerabilities.
 */

import { existsSync, mkdirSync, writeFileSync, unlinkSync, chmodSync } from 'node:fs';
import { resolve, join } from 'node:path';

export class GitHookManager {
  public static readonly HOOK_FILE_NAME = 'pre-commit';

  public static getHookScript(): string {
    return `#!/bin/sh
# 🛡️ Sentinel-AI Pre-Commit Security & Airgap Gate
# https://github.com/genda-benjamin/sentinel-hybrid-ai
# Enforcing zero-secret-leakage and OWASP Top 10 compliance offline before commit

echo "🛡️  [Sentinel-AI] Executing on-device pre-commit airgap scan..."

# Find staged scannable source files
STAGED_FILES=$(git diff --cached --name-only --diff-filter=ACM | grep -E '\\.(ts|js|tsx|jsx|json|py|env)$')

if [ -z "$STAGED_FILES" ]; then
  echo "✅ [Sentinel-AI] No scannable source files in commit."
  exit 0
fi

# Locate Sentinel CLI
if [ -f "dist/cli/index.js" ]; then
  SENTINEL_CMD="node dist/cli/index.js"
elif command -v sentinel > /dev/null 2>&1; then
  SENTINEL_CMD="sentinel"
else
  SENTINEL_CMD="npx --no-install sentinel-hybrid-ai"
fi

FAILURES=0

for FILE in $STAGED_FILES; do
  if [ -f "$FILE" ]; then
    $SENTINEL_CMD scan "$FILE"
    SCAN_EXIT=$?
    if [ $SCAN_EXIT -ne 0 ]; then
      FAILURES=$((FAILURES + 1))
    fi
  fi
done

if [ $FAILURES -gt 0 ]; then
  echo ""
  echo "❌ [Sentinel-AI] COMMIT BLOCKED: $FAILURES file(s) contain unvaulted secrets or critical vulnerabilities."
  echo "💡 Run 'sentinel audit <file>' to view deep AI remediation plans with zero secret egress."
  echo "⚠️  To bypass in emergency (not recommended): git commit --no-verify"
  echo ""
  exit 1
fi

echo "✅ [Sentinel-AI] 100% Zero-Leakage Airgap Verified. Commit accepted."
exit 0
`;
  }

  /**
   * Installs the pre-commit hook into the target repository's .git/hooks directory.
   */
  public static installPreCommitHook(targetDir = '.'): { success: boolean; path: string; message: string } {
    const gitDir = resolve(targetDir, '.git');
    if (!existsSync(gitDir)) {
      return {
        success: false,
        path: '',
        message: `Directory "${targetDir}" is not a git repository (missing .git directory).`
      };
    }

    const hooksDir = join(gitDir, 'hooks');
    if (!existsSync(hooksDir)) {
      mkdirSync(hooksDir, { recursive: true });
    }

    const hookPath = join(hooksDir, GitHookManager.HOOK_FILE_NAME);
    const content = GitHookManager.getHookScript();
    writeFileSync(hookPath, content, { encoding: 'utf-8', mode: 0o755 });

    try {
      chmodSync(hookPath, 0o755);
    } catch {
      // Best-effort on Windows
    }

    return {
      success: true,
      path: hookPath,
      message: `Sentinel-AI pre-commit hook successfully installed at "${hookPath}".`
    };
  }

  /**
   * Uninstalls the Sentinel-AI pre-commit hook.
   */
  public static uninstallPreCommitHook(targetDir = '.'): { success: boolean; message: string } {
    const hookPath = resolve(targetDir, '.git', 'hooks', GitHookManager.HOOK_FILE_NAME);
    if (!existsSync(hookPath)) {
      return {
        success: true,
        message: `No pre-commit hook found at "${hookPath}".`
      };
    }

    unlinkSync(hookPath);
    return {
      success: true,
      message: `Sentinel-AI pre-commit hook removed from "${hookPath}".`
    };
  }
}
