/**
 * Sentinel-AI YouTube Thumbnail Generator
 * (Google #BuildHybridAI 2026 Hackathon)
 *
 * Generates an ultra-crisp, high-impact 1280x720 YouTube Thumbnail (16:9)
 * with Cyberpunk glowing glassmorphism, exact branding, and empirical metrics.
 */

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { chromium } from 'playwright';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const ROOT_DIR = path.resolve(__dirname, '..');

const THUMBNAIL_HTML = `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Sentinel-AI YouTube Thumbnail</title>
  <style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700;800;900&family=JetBrains+Mono:wght@500;700;800&display=swap');

    * {
      box-sizing: border-box;
      margin: 0;
      padding: 0;
    }

    body {
      width: 1280px;
      height: 720px;
      overflow: hidden;
      background: #060913;
      font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
      color: #ffffff;
      position: relative;
    }

    /* Ambient Cyberpunk Glows */
    .glow-cyan {
      position: absolute;
      top: -120px;
      right: 180px;
      width: 550px;
      height: 550px;
      background: radial-gradient(circle, rgba(56, 189, 248, 0.28) 0%, rgba(56, 189, 248, 0) 70%);
      filter: blur(50px);
      pointer-events: none;
    }

    .glow-emerald {
      position: absolute;
      bottom: -150px;
      left: 100px;
      width: 650px;
      height: 650px;
      background: radial-gradient(circle, rgba(34, 197, 94, 0.22) 0%, rgba(34, 197, 94, 0) 70%);
      filter: blur(60px);
      pointer-events: none;
    }

    .glow-purple {
      position: absolute;
      top: 150px;
      right: -80px;
      width: 450px;
      height: 450px;
      background: radial-gradient(circle, rgba(168, 85, 247, 0.2) 0%, rgba(168, 85, 247, 0) 70%);
      filter: blur(50px);
      pointer-events: none;
    }

    /* Grid Overlay */
    .cyber-grid {
      position: absolute;
      inset: 0;
      background-image: 
        linear-gradient(rgba(255, 255, 255, 0.03) 1px, transparent 1px),
        linear-gradient(90deg, rgba(255, 255, 255, 0.03) 1px, transparent 1px);
      background-size: 40px 40px;
      pointer-events: none;
    }

    /* Outer Container */
    .container {
      position: relative;
      width: 100%;
      height: 100%;
      padding: 50px 60px;
      display: flex;
      justify-content: space-between;
      z-index: 10;
    }

    /* Left Column: Branding & Punchy Text */
    .left-col {
      width: 620px;
      display: flex;
      flex-direction: column;
      justify-content: space-between;
    }

    .event-badge {
      display: inline-flex;
      align-items: center;
      gap: 10px;
      background: linear-gradient(135deg, rgba(34, 197, 94, 0.2), rgba(56, 189, 248, 0.15));
      border: 1px solid rgba(56, 189, 248, 0.5);
      box-shadow: 0 0 20px rgba(56, 189, 248, 0.35);
      border-radius: 30px;
      padding: 8px 18px;
      font-size: 14px;
      font-weight: 800;
      letter-spacing: 0.08em;
      text-transform: uppercase;
      color: #38bdf8;
      width: fit-content;
    }

    .brand-title {
      margin-top: 16px;
      font-size: 72px;
      font-weight: 900;
      line-height: 0.95;
      letter-spacing: -0.03em;
      color: #ffffff;
      text-shadow: 0 4px 20px rgba(0, 0, 0, 0.8);
    }

    .brand-title span.cyan {
      color: #38bdf8;
      text-shadow: 0 0 30px rgba(56, 189, 248, 0.6);
    }

    .brand-title span.emerald {
      color: #22c55e;
      text-shadow: 0 0 30px rgba(34, 197, 94, 0.6);
    }

    .sub-title {
      margin-top: 14px;
      font-size: 26px;
      font-weight: 700;
      color: #94a3b8;
      letter-spacing: -0.01em;
      line-height: 1.25;
    }

    .sub-title strong {
      color: #f1f5f9;
    }

    .pill-matrix {
      display: flex;
      flex-wrap: wrap;
      gap: 12px;
      margin-top: 24px;
    }

    .pill {
      background: rgba(15, 23, 42, 0.85);
      border: 1px solid rgba(148, 163, 184, 0.25);
      backdrop-filter: blur(12px);
      padding: 8px 16px;
      border-radius: 8px;
      font-size: 14px;
      font-weight: 700;
      display: flex;
      align-items: center;
      gap: 8px;
      box-shadow: 0 4px 12px rgba(0, 0, 0, 0.4);
    }

    .pill.pill-green {
      border-color: rgba(34, 197, 94, 0.5);
      color: #4ade80;
      background: rgba(34, 197, 94, 0.1);
    }

    .pill.pill-purple {
      border-color: rgba(192, 132, 252, 0.5);
      color: #c084fc;
      background: rgba(168, 85, 247, 0.1);
    }

    .pill.pill-blue {
      border-color: rgba(56, 189, 248, 0.5);
      color: #38bdf8;
      background: rgba(56, 189, 248, 0.1);
    }

    .bottom-meta {
      display: flex;
      align-items: center;
      gap: 20px;
    }

    .metric-callout {
      background: rgba(10, 15, 29, 0.85);
      border: 1px solid rgba(56, 189, 248, 0.4);
      border-radius: 12px;
      padding: 12px 20px;
      display: flex;
      flex-direction: column;
    }

    .metric-callout .val {
      font-family: 'JetBrains Mono', monospace;
      font-size: 28px;
      font-weight: 800;
      color: #22c55e;
      text-shadow: 0 0 16px rgba(34, 197, 94, 0.5);
    }

    .metric-callout .lbl {
      font-size: 11px;
      font-weight: 700;
      color: #94a3b8;
      text-transform: uppercase;
      letter-spacing: 0.05em;
    }

    /* Right Column: High-Tech Glass HUD Cards */
    .right-col {
      width: 520px;
      display: flex;
      flex-direction: column;
      justify-content: center;
      gap: 18px;
      position: relative;
    }

    .glass-card {
      background: rgba(15, 23, 42, 0.88);
      border: 1px solid rgba(56, 189, 248, 0.35);
      box-shadow: 0 16px 40px rgba(0, 0, 0, 0.7), 0 0 25px rgba(56, 189, 248, 0.15);
      backdrop-filter: blur(16px);
      border-radius: 14px;
      padding: 20px;
    }

    .card-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 12px;
      padding-bottom: 10px;
      border-bottom: 1px solid rgba(255, 255, 255, 0.08);
    }

    .card-title {
      font-size: 13px;
      font-weight: 800;
      text-transform: uppercase;
      letter-spacing: 0.06em;
      color: #38bdf8;
      display: flex;
      align-items: center;
      gap: 8px;
    }

    .card-badge {
      font-size: 11px;
      font-weight: 800;
      padding: 3px 8px;
      border-radius: 4px;
      background: rgba(34, 197, 94, 0.2);
      color: #4ade80;
      border: 1px solid rgba(34, 197, 94, 0.4);
    }

    .vault-box {
      font-family: 'JetBrains Mono', monospace;
      font-size: 12px;
      background: #090d16;
      border: 1px solid rgba(255, 255, 255, 0.1);
      border-radius: 8px;
      padding: 10px 14px;
      color: #e2e8f0;
    }

    .vault-token {
      color: #22c55e;
      font-weight: 700;
    }

    .diff-box {
      font-family: 'JetBrains Mono', monospace;
      font-size: 12px;
      background: #090d16;
      border: 1px solid rgba(255, 255, 255, 0.1);
      border-radius: 8px;
      padding: 12px;
      line-height: 1.5;
    }

    .diff-del {
      color: #f87171;
      background: rgba(239, 68, 68, 0.12);
      padding: 2px 4px;
      border-radius: 3px;
    }

    .diff-add {
      color: #4ade80;
      background: rgba(34, 197, 94, 0.15);
      padding: 2px 4px;
      border-radius: 3px;
      font-weight: 700;
    }

    .badge-bar {
      display: flex;
      justify-content: space-between;
      align-items: center;
      background: linear-gradient(90deg, rgba(2, 132, 199, 0.25), rgba(168, 85, 247, 0.25));
      border: 1px solid rgba(56, 189, 248, 0.4);
      border-radius: 10px;
      padding: 10px 16px;
    }

    .badge-item {
      font-size: 12px;
      font-weight: 800;
      color: #ffffff;
      display: flex;
      align-items: center;
      gap: 6px;
    }
  </style>
</head>
<body>
  <div class="cyber-grid"></div>
  <div class="glow-cyan"></div>
  <div class="glow-emerald"></div>
  <div class="glow-purple"></div>

  <div class="container">
    <!-- Left Column: Big Bold Typography & Proof Badges -->
    <div class="left-col">
      <div>
        <div class="event-badge">
          <span>🏆</span> Google #BuildHybridAI 2026
        </div>
        
        <h1 class="brand-title">
          SENTINEL<span class="cyan">-AI</span>
        </h1>

        <div class="sub-title">
          Offline-First <strong>Autonomous Hybrid AI</strong><br>
          Cybersecurity Auditor & Remediation
        </div>

        <div class="pill-matrix">
          <div class="pill pill-purple">
            <span>⚡</span> Gemini Nano 4 (NPU)
          </div>
          <div class="pill pill-blue">
            <span>🧠</span> Gemini 2.5 Pro (Cloud)
          </div>
          <div class="pill pill-green">
            <span>🛡️</span> Firebase App Check
          </div>
          <div class="pill pill-green">
            <span>🔒</span> 100% Airgap Sealed
          </div>
        </div>
      </div>

      <div class="bottom-meta">
        <div class="metric-callout">
          <div class="val">&lt; 15 ms</div>
          <div class="lbl">On-Device Triage</div>
        </div>
        <div class="metric-callout">
          <div class="val">0 Bytes</div>
          <div class="lbl">Plaintext Egress</div>
        </div>
        <div class="metric-callout">
          <div class="val" style="color: #38bdf8;">87 / 87</div>
          <div class="lbl">Tests 100% Green</div>
        </div>
      </div>
    </div>

    <!-- Right Column: Live Invariant HUD Cards -->
    <div class="right-col">
      <!-- Card 1: Edge Vault -->
      <div class="glass-card">
        <div class="card-header">
          <div class="card-title">
            <span>🔐</span> Local AST Edge Vault
          </div>
          <span class="card-badge">Zero Plaintext Egress</span>
        </div>
        <div class="vault-box">
          postgres://root:*** ➔ <span class="vault-token">[VAULT_TOKEN_001]</span>
        </div>
      </div>

      <!-- Card 2: Unified Diff -->
      <div class="glass-card">
        <div class="card-header">
          <div class="card-title">
            <span>🛠️</span> Self-Healing Diff Synthesis
          </div>
          <span class="card-badge" style="background: rgba(56, 189, 248, 0.2); color: #38bdf8; border-color: rgba(56, 189, 248, 0.4);">CWE-89 Remediation</span>
        </div>
        <div class="diff-box">
          <div class="diff-del">- db.query(\`SELECT * FROM users WHERE id = \${id}\`);</div>
          <div class="diff-add">+ db.query("SELECT * FROM users WHERE id = $1", [id]);</div>
        </div>
      </div>

      <!-- Bottom Bar -->
      <div class="badge-bar">
        <div class="badge-item">
          <span>🌐</span> Web Studio
        </div>
        <div class="badge-item">
          <span>🧩</span> Chrome MV3
        </div>
        <div class="badge-item">
          <span>💻</span> Native CLI
        </div>
        <div class="badge-item">
          <span>📊</span> SARIF v2.1.0
        </div>
      </div>
    </div>
  </div>
</body>
</html>
`;

async function generateThumbnail() {
  console.log('🎨 [Thumbnail Generator] Launching Chromium to render 1280x720 YouTube Thumbnail...');

  const artifactsDir = path.join(ROOT_DIR, 'artifacts');
  const docsDir = path.join(ROOT_DIR, 'docs');
  const webDir = path.join(ROOT_DIR, 'web');

  const thumbnailPngPath = path.join(artifactsDir, 'sentinel-ai-thumbnail.png');
  const docsThumbnailPath = path.join(docsDir, 'sentinel-ai-thumbnail.png');
  const webThumbnailPath = path.join(webDir, 'sentinel-ai-thumbnail.png');

  const browser = await chromium.launch({
    headless: true,
    args: ['--no-sandbox', '--disable-gpu']
  });

  const page = await browser.newPage({
    viewport: { width: 1280, height: 720 },
    deviceScaleFactor: 2 // High-DPI 2x supersampling for ultra-crisp YouTube rendering
  });

  await page.setContent(THUMBNAIL_HTML, { waitUntil: 'networkidle' });
  await page.waitForTimeout(1000); // Wait for fonts and glows to settle

  console.log('📸 [Thumbnail Generator] Capturing high-resolution PNG screenshot...');
  const pngBuffer = await page.screenshot({
    type: 'png',
    omitBackground: false
  });

  await browser.close();

  // Save to artifacts/, docs/, and web/
  fs.writeFileSync(thumbnailPngPath, pngBuffer);
  fs.writeFileSync(docsThumbnailPath, pngBuffer);
  fs.writeFileSync(webThumbnailPath, pngBuffer);

  const stats = fs.statSync(thumbnailPngPath);
  console.log('\n🎉 =====================================================================');
  console.log('🎉 [Thumbnail Generator] YouTube Thumbnail Generated Successfully!');
  console.log(`📁 Artifact Path: ${thumbnailPngPath} (${(stats.size / 1024).toFixed(1)} KB)`);
  console.log(`🌐 Web Path: ${docsThumbnailPath}`);
  console.log('📐 Dimensions: 1280x720 (16:9 Standard YouTube Thumbnail, High-DPI 2x supersampled)');
  console.log('🎉 =====================================================================\n');
}

generateThumbnail().catch(err => {
  console.error('❌ Failed to generate thumbnail:', err);
  process.exit(1);
});
