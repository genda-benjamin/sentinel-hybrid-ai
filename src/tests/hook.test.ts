import { describe, it } from 'node:test';
import assert from 'node:assert';
import { mkdtempSync, mkdirSync, existsSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { GitHookManager } from '../core/hook.js';

describe('GitHookManager Unit Tests', () => {
  it('should generate valid shell hook script', () => {
    const script = GitHookManager.getHookScript();
    assert.ok(script.includes('#!/bin/sh'));
    assert.ok(script.includes('Sentinel-AI'));
    assert.ok(script.includes('git diff --cached --name-only'));
    assert.ok(script.includes('COMMIT BLOCKED'));
  });

  it('should fail gracefully when target directory is not a git repo', () => {
    const tempDir = mkdtempSync(join(tmpdir(), 'sentinel-non-git-'));
    try {
      const res = GitHookManager.installPreCommitHook(tempDir);
      assert.strictEqual(res.success, false);
      assert.ok(res.message.includes('not a git repository'));
    } finally {
      rmSync(tempDir, { recursive: true, force: true });
    }
  });

  it('should install and uninstall pre-commit hook in a git repository', () => {
    const tempDir = mkdtempSync(join(tmpdir(), 'sentinel-git-'));
    const gitDir = join(tempDir, '.git');
    mkdirSync(gitDir, { recursive: true });

    try {
      // Install hook
      const installRes = GitHookManager.installPreCommitHook(tempDir);
      assert.strictEqual(installRes.success, true);
      assert.ok(existsSync(installRes.path));

      // Uninstall hook
      const uninstallRes = GitHookManager.uninstallPreCommitHook(tempDir);
      assert.strictEqual(uninstallRes.success, true);
      assert.strictEqual(existsSync(installRes.path), false);
    } finally {
      rmSync(tempDir, { recursive: true, force: true });
    }
  });
});
