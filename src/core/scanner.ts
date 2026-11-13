import { readdirSync, statSync } from 'node:fs';
import { join, extname } from 'node:path';

export class ProjectScanner {
  private static DEFAULT_EXTENSIONS = new Set([
    '.ts', '.js', '.mjs', '.cjs', '.tsx', '.jsx', '.py', '.sql'
  ]);

  private static IGNORE_DIRS = new Set([
    'node_modules', '.git', 'dist', 'build', '.venv', 'coverage', '.pytest_cache', '__pycache__'
  ]);

  /**
   * Recursively finds all scannable source files in a target directory or file.
   */
  public static discoverFiles(targetPath: string, allowedExtensions: Set<string> = this.DEFAULT_EXTENSIONS): string[] {
    const stats = statSync(targetPath);
    if (stats.isFile()) {
      return [targetPath];
    }

    const discovered: string[] = [];
    const entries = readdirSync(targetPath, { withFileTypes: true });

    for (const entry of entries) {
      if (entry.isDirectory()) {
        if (!this.IGNORE_DIRS.has(entry.name)) {
          discovered.push(...this.discoverFiles(join(targetPath, entry.name), allowedExtensions));
        }
      } else if (entry.isFile()) {
        const ext = extname(entry.name).toLowerCase();
        if (allowedExtensions.has(ext)) {
          discovered.push(join(targetPath, entry.name));
        }
      }
    }

    return discovered;
  }
}
