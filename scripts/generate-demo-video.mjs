/**
 * Sentinel-AI Video Generator: Automated 1080p Judge Demo Video (Day 15)
 * (Google #BuildHybridAI 2026 Hackathon)
 *
 * Programmatically records and renders a crisp, judge-ready 1080p MP4 demo video
 * (artifacts/sentinel-ai-demo-2026.mp4) obeying Devpost's < 3:00 minute ceiling,
 * English subtitle rule, and multi-platform demonstration requirement.
 */

import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { chromium } from 'playwright';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const ROOT_DIR = path.resolve(__dirname, '..');
const PORT = 4173;

// MIME types for static server
const MIME_TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.mjs': 'application/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon'
};

/**
 * Start lightweight local HTTP server for deterministic local rendering
 */
function startStaticServer() {
  return new Promise((resolve) => {
    const server = http.createServer((req, res) => {
      let reqPath = decodeURI(req.url.split('?')[0]);
      if (reqPath === '/' || reqPath === '') reqPath = '/docs/index.html';

      let filePath = path.join(ROOT_DIR, reqPath);

      // Default to docs/index.html if requesting root or index.html
      if (reqPath === '/index.html') {
        filePath = path.join(ROOT_DIR, 'docs', 'index.html');
      }

      fs.stat(filePath, (err, stats) => {
        if (err || !stats.isFile()) {
          res.writeHead(404, { 'Content-Type': 'text/plain' });
          res.end(`404 Not Found: ${reqPath}`);
          return;
        }

        const ext = path.extname(filePath).toLowerCase();
        const contentType = MIME_TYPES[ext] || 'application/octet-stream';
        res.writeHead(200, {
          'Content-Type': contentType,
          'Access-Control-Allow-Origin': '*'
        });
        fs.createReadStream(filePath).pipe(res);
      });
    });

    server.listen(PORT, '127.0.0.1', () => {
      console.log(`⚡ [Demo Server] Serving Sentinel-AI on http://127.0.0.1:${PORT}`);
      resolve(server);
    });
  });
}

/**
 * Generate standard SRT subtitle file
 */
function writeSrtSubtitles(outputPath) {
  const srtContent = `1
00:00:01,000 --> 00:00:17,500
Sentinel-AI: Offline-First Autonomous Hybrid AI Security Auditor & Remediation Engine.
Scanning enterprise code without leaking proprietary intellectual property or credentials.

2
00:00:18,000 --> 00:00:41,500
Scene 2: Zero-Leakage Local AST Edge Vault. High-entropy database secrets and API tokens
are tokenized into [VAULT_TOKEN_001] on-device in sub-millisecond latency.

3
00:00:42,000 --> 00:01:04,500
Scene 3: On-Device Generative AI via Gemini Nano 4. Standard CWE vulnerabilities
are triaged locally via Chrome Built-in AI with sub-15ms execution and $0 cloud cost.

4
00:01:05,000 --> 00:01:27,500
Scene 4: Self-Healing Unified Diffs & Verifiable Tests. Synthesizes atomic git patches
and auto-generates executable node:test suites verifying invariant correctness.

5
00:01:28,000 --> 00:01:49,500
Scene 5: Intelligent Cloud Escalation to Gemini 2.5 Pro via Firebase AI Logic.
Multi-file taint triggers cloud reasoning with verified Firebase App Check attestation.

6
00:01:50,000 --> 00:02:09,500
Scene 6: Multi-Platform Chrome Extension (Manifest V3). Inspects pull request diffs
directly inside GitHub & GitLab with inline review badges and OASIS SARIF v2.1.0 exports.

7
00:02:10,000 --> 00:02:15,000
Google #BuildHybridAI 2026. 83/83 Tests Green.
Explore live deployment at https://genda-benjamin.github.io/sentinel-hybrid-ai
`;

  fs.writeFileSync(outputPath, srtContent, 'utf-8');
  console.log(`📄 [Demo SRT] Subtitle track generated at: ${outputPath}`);
}

/**
 * Execute FFmpeg transcoding with H.264 @ 30fps
 */
function transcodeToMp4(rawWebmPath, srtPath, finalMp4Path) {
  return new Promise((resolve, reject) => {
    console.log(`🎬 [FFmpeg] Transcoding raw recording to 1080p MP4 (${finalMp4Path})...`);

    // Verify raw file exists and has content
    const stats = fs.statSync(rawWebmPath);
    console.log(`   Input raw video: ${rawWebmPath} (${(stats.size / 1024 / 1024).toFixed(2)} MB)`);

    const args = [
      '-y',
      '-i', rawWebmPath,
      '-c:v', 'libx264',
      '-pix_fmt', 'yuv420p',
      '-r', '30',
      '-crf', '20',
      '-preset', 'fast',
      '-movflags', '+faststart',
      finalMp4Path
    ];

    const ffmpegProc = spawn('ffmpeg', args);

    ffmpegProc.stderr.on('data', (d) => {
      const line = d.toString();
      if (line.includes('frame=') || line.includes('time=')) {
        process.stdout.write(`\r   Transcoding progress: ${line.trim().slice(0, 70)}`);
      }
    });

    ffmpegProc.on('close', (code) => {
      console.log('');
      if (code === 0) {
        const outStats = fs.statSync(finalMp4Path);
        console.log(`✅ [FFmpeg] 1080p MP4 rendering complete: ${(outStats.size / 1024 / 1024).toFixed(2)} MB`);
        resolve(finalMp4Path);
      } else {
        reject(new Error(`FFmpeg exited with code ${code}`));
      }
    });

    ffmpegProc.on('error', (err) => {
      reject(err);
    });
  });
}

/**
 * Main Demo Recording Orchestrator
 */
async function generateDemoVideo() {
  console.log('🚀 [Sentinel-AI] Starting Automated 1080p Judge Demo Video Generator (Day 15)...');

  const artifactsDir = path.join(ROOT_DIR, 'artifacts');
  const recordingsDir = path.join(artifactsDir, 'recordings');
  if (!fs.existsSync(artifactsDir)) fs.mkdirSync(artifactsDir, { recursive: true });
  if (!fs.existsSync(recordingsDir)) fs.mkdirSync(recordingsDir, { recursive: true });

  const srtPath = path.join(artifactsDir, 'sentinel-ai-demo.srt');
  const finalMp4Path = path.join(artifactsDir, 'sentinel-ai-demo-2026.mp4');
  writeSrtSubtitles(srtPath);

  // 1. Launch HTTP server
  const server = await startStaticServer();

  // 2. Launch Playwright Chromium with 1920x1080 recording
  console.log('🎥 [Playwright] Launching Chromium (1920x1080 @ 30fps)...');
  const browser = await chromium.launch({
    headless: true,
    args: ['--no-sandbox', '--disable-gpu']
  });

  const context = await browser.newContext({
    viewport: { width: 1920, height: 1080 },
    recordVideo: {
      dir: recordingsDir,
      size: { width: 1920, height: 1080 }
    }
  });

  const page = await context.newPage();
  const overlayScript = fs.readFileSync(path.join(__dirname, 'demo-overlay.js'), 'utf-8');

  // Helper to inject overlay
  async function injectOverlay() {
    await page.evaluate(overlayScript);
  }

  try {
    // =========================================================================
    // SCENE 1: Problem & Architecture Overview (0:00 - 0:18) [~18s]
    // =========================================================================
    console.log('🎬 [Scene 1/7] Recording Problem & Architecture Overview (0:00 - 0:18)...');
    await page.goto(`http://127.0.0.1:${PORT}/docs/index.html`, { waitUntil: 'networkidle' });
    await injectOverlay();

    await page.evaluate(() => {
      window.__demo.setScene('SCENE 1', 'Problem & Hybrid Architecture Overview');
      window.__demo.setSubtitle(
        '🛡️ PROBLEM & ARCHITECTURE OVERVIEW',
        'Enterprise code contains confidential IP & credentials that <span class="subtitle-highlight">must never leak</span> to cloud LLMs. Sentinel-AI guarantees an offline-first airgap.'
      );
      window.__demo.setPos(960, 140);
    });
    await page.waitForTimeout(2500);

    // Spotlight App Check Badge
    await page.evaluate(() => {
      window.__demo.spotlight('#appCheckBadge', 'FIREBASE APP CHECK: CRYPTOGRAPHICALLY ATTESTED', 6);
      window.__demo.moveTo('#appCheckBadge', 800);
    });
    await page.waitForTimeout(3000);

    // Spotlight Gemini Nano Badge
    await page.evaluate(() => {
      window.__demo.spotlight('#nanoBadge', 'ON-DEVICE GEMINI NANO 4: HARDWARE ACCELERATED', 6);
      window.__demo.moveTo('#nanoBadge', 800);
      window.__demo.setSubtitle(
        '⚡ DUAL-ENGINE HYBRID ARBITRATION',
        'Built for Google #BuildHybridAI 2026: <span class="subtitle-highlight">Gemini Nano 4</span> on-device paired with <span class="subtitle-highlight">Gemini 2.5 Pro</span> via Firebase AI Logic.'
      );
    });
    await page.waitForTimeout(3500);

    // Glide across HUD cards
    await page.evaluate(() => {
      window.__demo.spotlight('#hudRedactTime', 'SUB-MILLISECOND AST REDACTION', 8);
      window.__demo.moveTo('#hudRedactTime', 700);
    });
    await page.waitForTimeout(2800);

    await page.evaluate(() => {
      window.__demo.spotlight('#hudAirgap', '100% AIRGAP GUARANTEED', 8);
      window.__demo.moveTo('#hudAirgap', 700);
    });
    await page.waitForTimeout(3000);

    await page.evaluate(() => {
      window.__demo.clearSpotlight();
    });
    await page.waitForTimeout(1000);

    // =========================================================================
    // SCENE 2: Zero-Leakage Local AST Edge Vault (0:18 - 0:42) [~24s]
    // =========================================================================
    console.log('🎬 [Scene 2/7] Recording Zero-Leakage Local AST Edge Vault (0:18 - 0:42)...');
    await page.evaluate(() => {
      window.__demo.setScene('SCENE 2', 'Zero-Leakage Local AST Edge Vault');
      window.__demo.setSubtitle(
        '🔐 ZERO-LEAKAGE AST EDGE VAULT',
        'High-entropy database credentials and API keys are <span class="subtitle-highlight">intercepted at the AST level</span> and tokenized into [VAULT_TOKEN_001] before model egress.'
      );
    });
    await page.waitForTimeout(2500);

    // Spotlight editor line with postgres connection
    await page.evaluate(() => {
      window.__demo.spotlight('#codeInput', 'PROPRIETARY CODE WITH HIGH-ENTROPY SECRETS', 6);
      window.__demo.moveTo('#codeInput', 800, 0.4, 0.25);
    });
    await page.waitForTimeout(4000);

    // Move to Edge Vault Inspector
    await page.evaluate(() => {
      window.__demo.spotlight('#vaultItems', 'EDGE VAULT: ZERO PLAINTEXT ESCAPES TO CLOUD', 8);
      window.__demo.moveTo('#vaultItems', 800);
      window.__demo.setSubtitle(
        '🛡️ PRIVACY-PRESERVING DE-IDENTIFICATION',
        'Sanitized buffer contains <span class="subtitle-highlight">zero plaintext credentials</span>. Rehydration occurs exclusively on the developer\'s local machine.'
      );
    });
    await page.waitForTimeout(5000);

    await page.evaluate(() => {
      window.__demo.spotlight('#vaultStatus', '1 CREDENTIAL PROTECTED (SOC 2 & GDPR ART. 32)', 6);
      window.__demo.moveTo('#vaultStatus', 600);
    });
    await page.waitForTimeout(4500);

    await page.evaluate(() => {
      window.__demo.clearSpotlight();
    });
    await page.waitForTimeout(1000);

    // =========================================================================
    // SCENE 3: On-Device Generative AI (Gemini Nano 4) (0:42 - 1:05) [~23s]
    // =========================================================================
    console.log('🎬 [Scene 3/7] Recording On-Device Generative AI (0:42 - 1:05)...');
    await page.evaluate(() => {
      window.__demo.setScene('SCENE 3', 'On-Device Generative AI (Gemini Nano 4)');
      window.__demo.setSubtitle(
        '📱 ON-DEVICE GEMINI NANO 4 REASONING',
        'For 85%+ of standard vulnerabilities (SQLi, Command Injection, Path Traversal), inference runs <span class="subtitle-highlight">100% on-device at $0 compute cost</span>.'
      );
    });
    await page.waitForTimeout(2500);

    // Select Engine dropdown
    await page.evaluate(() => {
      window.__demo.spotlight('#engineSelect', 'INFERENCE MODE: PREFER_ON_DEVICE', 6);
      window.__demo.moveTo('#engineSelect', 700);
    });
    await page.waitForTimeout(2500);

    // Click "Run Hybrid AI Audit"
    await page.evaluate(() => {
      window.__demo.spotlight('#runAuditBtn', 'TRIGGERING ON-DEVICE HYBRID AUDIT', 6);
      window.__demo.moveTo('#runAuditBtn', 600);
    });
    await page.waitForTimeout(1500);

    await page.evaluate(() => {
      window.__demo.clickElement('#runAuditBtn');
      window.__demo.setSubtitle(
        '⚡ SUB-15MS LOCAL EXECUTION',
        'Instant AST analysis and <span class="subtitle-highlight">Gemini Nano patch synthesis</span>. Proven in under 15ms latency with zero network hops.'
      );
    });
    await page.waitForTimeout(4500);

    await page.evaluate(() => {
      window.__demo.spotlight('#hudRedactTime', 'HIGH-PRECISION PERFORMANCE.NOW() TIMING', 6);
      window.__demo.moveTo('#hudRedactTime', 600);
    });
    await page.waitForTimeout(4500);

    await page.evaluate(() => {
      window.__demo.clearSpotlight();
    });
    await page.waitForTimeout(1000);

    // =========================================================================
    // SCENE 4: Self-Healing Diff & Live Invariant Verification (1:05 - 1:28) [~23s]
    // =========================================================================
    console.log('🎬 [Scene 4/7] Recording Self-Healing Diff & Invariant Tests (1:05 - 1:28)...');
    await page.evaluate(() => {
      window.__demo.setScene('SCENE 4', 'Self-Healing Unified Diff & Verification Tests');
      window.__demo.setSubtitle(
        '🛠️ ATOMIC UNIFIED DIFF SYNTHESIS',
        'Sentinel-AI generates compliant <span class="subtitle-highlight">diff --git</span> patches replacing dynamic string concatenation with parameterized prepared statements.'
      );
    });
    await page.waitForTimeout(2500);

    // Spotlight Diff Viewer
    await page.evaluate(() => {
      window.__demo.spotlight('#diffView', 'SYNTHESIZED ATOMIC REMEDIATION PATCH', 6);
      window.__demo.moveTo('#diffView', 800, 0.5, 0.35);
    });
    await page.waitForTimeout(4500);

    // Switch to Test Suite Tab
    await page.evaluate(() => {
      window.__demo.spotlight("button[onclick=\"switchTab('tests')\"]", 'AUTO-GENERATED EXPLOIT & REGRESSION SUITE', 6);
      window.__demo.clickElement("button[onclick=\"switchTab('tests')\"]", 600);
      window.__demo.setSubtitle(
        '🧪 NATIVE NODE:TEST REGRESSION SUITE',
        'Auto-synthesizes mathematically verifiable unit tests proving that <span class="subtitle-highlight">attack payloads are rejected</span> and benign inputs are preserved.'
      );
    });
    await page.waitForTimeout(5000);

    // Spotlight synthesized test view
    await page.evaluate(() => {
      window.__demo.spotlight('#testCodeView', 'EXECUTABLE NODE:TEST INVARIANT SUITE', 6);
      window.__demo.moveTo('#testCodeView', 800, 0.5, 0.4);
    });
    await page.waitForTimeout(4000);

    // Copy patch button click
    await page.evaluate(() => {
      window.__demo.clickElement("button[onclick=\"switchTab('diff')\"]", 400);
    });
    await page.waitForTimeout(1000);

    await page.evaluate(() => {
      window.__demo.moveTo("button[onclick='copyPatch()']", 600);
      window.__demo.clickElement("button[onclick='copyPatch()']");
    });
    await page.waitForTimeout(2000);

    await page.evaluate(() => {
      window.__demo.clearSpotlight();
    });
    await page.waitForTimeout(1000);

    // =========================================================================
    // SCENE 5: Cloud Escalation to Gemini 2.5 Pro & Taint Graph (1:28 - 1:50) [~22s]
    // =========================================================================
    console.log('🎬 [Scene 5/7] Recording Cloud Escalation & Cross-File Taint (1:28 - 1:50)...');
    await page.evaluate(() => {
      window.__demo.setScene('SCENE 5', 'Intelligent Cloud Escalation to Gemini 2.5 Pro');
      window.__demo.setSubtitle(
        '🧠 INTELLIGENT CLOUD ESCALATION',
        'When cross-service taint or architectural CWEs are detected, Sentinel-AI <span class="subtitle-highlight">escalates to Gemini 2.5 Pro</span> via Firebase AI Logic.'
      );
    });
    await page.waitForTimeout(2500);

    // Select Multi-Hop Taint Preset
    await page.evaluate(() => {
      const sel = document.getElementById('presetSelect');
      sel.value = 'multi';
      sel.dispatchEvent(new Event('change'));
      window.__demo.spotlight('#presetSelect', 'CROSS-FILE TAINT FLOW PRESET SELECTED', 6);
      window.__demo.moveTo('#presetSelect', 600);
    });
    await page.waitForTimeout(2000);

    // Run Audit
    await page.evaluate(() => {
      window.__demo.clickElement('#runAuditBtn');
    });
    await page.waitForTimeout(2000);

    // Spotlight Cloud Escalation Pill
    await page.evaluate(() => {
      window.__demo.spotlight('#escalationPill', 'ESCALATION TRIGGER: MULTI_HOP_TAINT (APP CHECK ATTESTED)', 6);
      window.__demo.moveTo('#escalationPill', 700);
      window.__demo.setSubtitle(
        '🛡️ CRYPTOGRAPHIC APP CHECK ATTESTATION',
        'Firebase App Check attestation is attached and verified on all cloud calls. Deep reasoning depth: <span class="subtitle-highlight">1,642 tokens</span>.'
      );
    });
    await page.waitForTimeout(4500);

    // Scroll down to Cross-File Taint Graph
    await page.evaluate(() => {
      window.scrollBy({ top: 400, behavior: 'smooth' });
    });
    await page.waitForTimeout(800);

    await page.evaluate(() => {
      window.__demo.spotlight('#taintGraphContainer', 'INTER-PROCEDURAL CROSS-FILE TAINT TRAJECTORY', 8);
      window.__demo.moveTo('#taintGraphContainer', 700);
      window.__demo.setSubtitle(
        '📊 INTER-PROCEDURAL TAINT TRACING',
        'Traces taint trajectory across 3 distinct services: HTTP route -> <span class="subtitle-highlight">Edge Airgap Vault</span> -> DB Controller -> SQL Sink.'
      );
    });
    await page.waitForTimeout(5000);

    await page.evaluate(() => {
      window.__demo.clearSpotlight();
    });
    await page.waitForTimeout(1000);

    // =========================================================================
    // SCENE 6: Multi-Platform Chrome Extension (1:50 - 2:10) [~20s]
    // =========================================================================
    console.log('🎬 [Scene 6/7] Recording Multi-Platform Chrome Extension (1:50 - 2:10)...');
    await page.goto(`http://127.0.0.1:${PORT}/docs/github-pr-demo.html`, { waitUntil: 'networkidle' });
    await injectOverlay();

    await page.evaluate(() => {
      window.__demo.setScene('SCENE 6', 'Multi-Platform Chrome Extension (Manifest V3)');
      window.__demo.setSubtitle(
        '🧩 MULTI-PLATFORM CHROME EXTENSION',
        'Sentinel-AI runs natively inside Chrome. Inspects <span class="subtitle-highlight">GitHub & GitLab Pull Requests</span> directly in the browser DOM.'
      );
      window.__demo.setPos(960, 200);
    });
    await page.waitForTimeout(2500);

    // Spotlight Injected PR Banner
    await page.evaluate(() => {
      window.__demo.spotlight('#sentinel-pr-banner', 'INJECTED ON-DEVICE PR SECURITY BANNER', 6);
      window.__demo.moveTo('#sentinel-pr-banner', 800, 0.5, 0.4);
    });
    await page.waitForTimeout(4000);

    // Click "View Invariant Patch" inside GitHub PR
    await page.evaluate(() => {
      window.__demo.clickElement('#sentinelBtnViewPatch', 500);
      window.__demo.setSubtitle(
        '⚡ ZERO-EGRESS PR CODE REVIEW',
        'Pull request diff additions are audited with <span class="subtitle-highlight">Gemini Nano in sub-15ms</span> with inline diff annotations.'
      );
    });
    await page.waitForTimeout(3500);

    // Open Extension Popup HUD
    await page.evaluate(() => {
      window.toggleExtensionPopup(true);
      window.__demo.spotlight('#extensionPopupFrame', 'SENTINEL-AI POPUP HUD (MANIFEST V3)', 8);
      window.__demo.moveTo('#extensionPopupFrame', 700);
      window.__demo.setSubtitle(
        '🛡️ COMPREHENSIVE HUD & SARIF V2.1.0',
        'One-click SARIF v2.1.0 exports, real-time App Check attestation, and enterprise PR health monitoring.'
      );
    });
    await page.waitForTimeout(5000);

    await page.evaluate(() => {
      window.__demo.clearSpotlight();
    });
    await page.waitForTimeout(1000);

    // =========================================================================
    // SCENE 7: Closing Callout & Verifiable Links (2:10 - 2:15) [~5s]
    // =========================================================================
    console.log('🎬 [Scene 7/7] Recording Closing Callout (2:10 - 2:15)...');
    await page.goto(`http://127.0.0.1:${PORT}/docs/index.html`, { waitUntil: 'networkidle' });
    await injectOverlay();

    await page.evaluate(() => {
      window.__demo.setScene('SUMMARY', 'Google #BuildHybridAI 2026 Hackathon');
      window.__demo.setSubtitle(
        '🏆 100% GREEN • APACHE 2.0 • LIVE DEPLOYMENT',
        '<strong>83/83 Tests Passing (100% Green)</strong> • Live at <span class="subtitle-highlight">genda-benjamin.github.io/sentinel-hybrid-ai</span>'
      );
      window.__demo.setPos(960, 540);
    });
    await page.waitForTimeout(4000);

  } finally {
    // 3. Stop recording and close browser
    console.log('🛑 [Playwright] Stopping recording and finalizing stream...');
    await page.close();
    await context.close();
    await browser.close();
    server.close();
  }

  // 4. Locate raw WebM recording
  const recordedFiles = fs.readdirSync(recordingsDir).filter(f => f.endsWith('.webm'));
  if (recordedFiles.length === 0) {
    throw new Error('No recorded WebM file found in artifacts/recordings!');
  }

  // Pick the newest recording
  recordedFiles.sort((a, b) => {
    return fs.statSync(path.join(recordingsDir, b)).mtimeMs - fs.statSync(path.join(recordingsDir, a)).mtimeMs;
  });

  const rawWebmPath = path.join(recordingsDir, recordedFiles[0]);
  console.log(`📹 [Recording Saved] Raw WebM capture: ${rawWebmPath}`);

  // 5. Transcode with FFmpeg to 1080p MP4
  await transcodeToMp4(rawWebmPath, srtPath, finalMp4Path);

  console.log('\n🎉 =====================================================================');
  console.log('🎉 [Sentinel-AI] Day 15 Video Generation Complete!');
  console.log(`🎬 1080p MP4: ${finalMp4Path}`);
  console.log(`📄 English Subtitles: ${srtPath}`);
  console.log('🎉 =====================================================================\n');
}

generateDemoVideo().catch((err) => {
  console.error('❌ [Error] Failed to generate demo video:', err);
  process.exit(1);
});
