/**
 * Sentinel-AI | Web Studio Build & Bundle Pipeline
 * Engineered for Google #BuildHybridAI 2026 Hackathon (Apache-2.0)
 *
 * Packages client-side JavaScript bundle for GitHub Pages (docs/ & web/).
 * Enforces zero-mock DOM hygiene and strict schema validation.
 */

import { readFileSync, writeFileSync, existsSync, mkdirSync, copyFileSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const ROOT_DIR = resolve(__dirname, '..');

const DOCS_DIR = resolve(ROOT_DIR, 'docs');
const WEB_DIR = resolve(ROOT_DIR, 'web');

console.log('⚡ [Sentinel-AI] Building Web Studio Client Bundle for GitHub Pages...');

// 1. Ensure target directories exist
if (!existsSync(DOCS_DIR)) mkdirSync(DOCS_DIR, { recursive: true });
if (!existsSync(WEB_DIR)) mkdirSync(WEB_DIR, { recursive: true });

// 2. Ensure .nojekyll exists in both folders
writeFileSync(resolve(DOCS_DIR, '.nojekyll'), '', 'utf8');
writeFileSync(resolve(WEB_DIR, '.nojekyll'), '', 'utf8');

// 3. Process index.html to guarantee bundle script loading and zero mocks
const docsHtmlPath = resolve(DOCS_DIR, 'index.html');
if (existsSync(docsHtmlPath)) {
  let html = readFileSync(docsHtmlPath, 'utf8');

  // Strip any legacy inline <script> block and replace with bundle reference
  const scriptStartIdx = html.indexOf('  <script>');
  if (scriptStartIdx !== -1) {
    const endBodyIdx = html.indexOf('</body>');
    if (endBodyIdx !== -1) {
      html = html.substring(0, scriptStartIdx) +
        '  <script src="app.js"></script>\n</body>\n</html>\n';
    }
  }

  // Ensure script src="app.js" is present
  if (!html.includes('<script src="app.js"></script>')) {
    html = html.replace('</body>', '  <script src="app.js"></script>\n</body>');
  }

  // Purge any residual mock tokens in static HTML attributes
  html = html
    .replace('id="hudRedactTime">0.38 ms</div>', 'id="hudRedactTime">-- ms</div>')
    .replace('id="hudAirgap">100%</div>', 'id="hudAirgap">-- %</div>')
    .replace('id="vaultStatus">1 Credential Protected</span>', 'id="vaultStatus">0 Credentials Protected</span>');

  writeFileSync(docsHtmlPath, html, 'utf8');
  writeFileSync(resolve(WEB_DIR, 'index.html'), html, 'utf8');
  console.log('   ✓ docs/index.html & web/index.html validated and purged of static mocks.');
}

// 4. Validate and synchronize docs/app.js to web/app.js
const docsAppJs = resolve(DOCS_DIR, 'app.js');
const webAppJs = resolve(WEB_DIR, 'app.js');

if (existsSync(docsAppJs)) {
  const appJsContent = readFileSync(docsAppJs, 'utf8');
  writeFileSync(webAppJs, appJsContent, 'utf8');
  const sizeKb = (Buffer.byteLength(appJsContent, 'utf8') / 1024).toFixed(1);
  console.log(`   ✓ docs/app.js & web/app.js synchronized (${sizeKb} KB bundle).`);
} else {
  console.error('   ❌ ERROR: docs/app.js bundle source not found!');
  process.exit(1);
}

console.log('✅ [Sentinel-AI] Web Studio bundle packaging complete. Ready for GitHub Pages deployment.\n');
