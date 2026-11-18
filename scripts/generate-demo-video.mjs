/**
 * Sentinel-AI Video Generator: Ultra-Crisp 1080p Master Video with Humanized Voice
 * (Google #BuildHybridAI 2026 Hackathon)
 *
 * 1. Synchronized to exact scene speech durations (Zero Voice Overlap)
 * 2. High-Bitrate Visually Lossless Encoding (CRF 12 @ 12Mbps, Zero Blurriness)
 * 3. Humanized Narration via Google Speech Engine
 * 4. Strictly under Devpost's 3:00 minute ceiling (~2m 50s)
 */

import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { spawn, execSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { chromium } from 'playwright';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const ROOT_DIR = path.resolve(__dirname, '..');
const PORT = 4173;

const MIME_TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.mjs': 'application/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon',
  '.mp3': 'audio/mpeg',
  '.mp4': 'video/mp4'
};

function startStaticServer() {
  return new Promise((resolve) => {
    const server = http.createServer((req, res) => {
      let reqPath = decodeURI(req.url.split('?')[0]);
      if (reqPath === '/' || reqPath === '') reqPath = '/docs/index.html';

      let filePath = path.join(ROOT_DIR, reqPath);
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
      console.log(`⚡ [Demo Server] Serving on http://127.0.0.1:${PORT}`);
      resolve(server);
    });
  });
}

function ensureVoiceTimings() {
  const timingsPath = path.join(ROOT_DIR, 'artifacts', 'scene_timings.json');
  const masterAudioPath = path.join(ROOT_DIR, 'artifacts', 'sentinel-ai-master-voice.mp3');

  if (!fs.existsSync(timingsPath) || !fs.existsSync(masterAudioPath)) {
    console.log('🎙️ [Voice Generator] Building human voice tracks and scene timings...');
    execSync('python scripts/build-human-voice.py', { cwd: ROOT_DIR, stdio: 'inherit' });
  }

  return JSON.parse(fs.readFileSync(timingsPath, 'utf-8'));
}

function writeSrtSubtitles(outputPath, timingsData) {
  const sceneHeaders = {
    1: 'Scene 1: Hybrid AI Architecture & Airgap (Google #BuildHybridAI 2026)',
    2: 'Scene 2: Zero-Leakage Local AST Edge Vault',
    3: 'Scene 3: On-Device Generative AI via Gemini Nano 4',
    4: 'Scene 4: Self-Healing Unified Diffs & Verifiable Tests',
    5: 'Scene 5: Intelligent Cloud Escalation to Gemini 2.5 Pro',
    6: 'Scene 6: Multi-Platform Chrome Extension (Manifest V3)',
    7: 'Scene 7: Summary Callout & Live Links (Google #BuildHybridAI 2026)'
  };

  let srtContent = '';
  timingsData.scenes.forEach((scene, idx) => {
    const startSec = scene.start_sec;
    const endSec = scene.end_sec;

    function formatTime(sec) {
      const h = Math.floor(sec / 3600).toString().padStart(2, '0');
      const m = Math.floor((sec % 3600) / 60).toString().padStart(2, '0');
      const s = Math.floor(sec % 60).toString().padStart(2, '0');
      const ms = Math.floor((sec % 1) * 1000).toString().padStart(3, '0');
      return `${h}:${m}:${s},${ms}`;
    }

    const header = sceneHeaders[scene.id] ? `[${sceneHeaders[scene.id]}]\n` : '';
    srtContent += `${idx + 1}\n${formatTime(startSec)} --> ${formatTime(endSec)}\n${header}${scene.text}\n\n`;
  });

  fs.writeFileSync(outputPath, srtContent, 'utf-8');
  console.log(`📄 [Demo SRT] Subtitle track generated at: ${outputPath}`);
}

function transcodeWithAudio(rawWebmPath, masterAudioPath, finalMp4Path) {
  return new Promise((resolve, reject) => {
    console.log(`🎬 [FFmpeg] Transcoding to Ultra-Crisp 1080p MP4 with Master Voice Dubbing...`);
    console.log(`   Video: Lossless CRF 12 @ 12 Mbps target bitrate (Pristine YouTube Clarity)`);
    console.log(`   Audio: Single-stream Human Voice (Zero Overlap Guaranteed)`);

    const args = [
      '-y',
      '-i', rawWebmPath,
      '-i', masterAudioPath,
      '-map', '0:v:0',
      '-map', '1:a:0',
      '-c:v', 'libx264',
      '-pix_fmt', 'yuv420p',
      '-r', '30',
      '-crf', '12',
      '-b:v', '12M',
      '-maxrate', '16M',
      '-bufsize', '24M',
      '-preset', 'medium',
      '-c:a', 'aac',
      '-b:a', '192k',
      '-shortest',
      '-movflags', '+faststart',
      finalMp4Path
    ];

    const proc = spawn('ffmpeg', args);

    proc.stderr.on('data', (d) => {
      const line = d.toString();
      if (line.includes('frame=') || line.includes('time=')) {
        process.stdout.write(`\r   Rendering: ${line.trim().slice(0, 75)}`);
      }
    });

    proc.on('close', (code) => {
      console.log('');
      if (code === 0) {
        const stats = fs.statSync(finalMp4Path);
        console.log(`✅ [FFmpeg] 1080p MP4 Complete: ${(stats.size / 1024 / 1024).toFixed(2)} MB`);
        resolve(finalMp4Path);
      } else {
        reject(new Error(`FFmpeg exited with code ${code}`));
      }
    });

    proc.on('error', (err) => reject(err));
  });
}

async function generateDemoVideo() {
  console.log('🚀 [Sentinel-AI] Launching Ultra-Crisp Video Recording Pipeline (Day 15)...');

  const artifactsDir = path.join(ROOT_DIR, 'artifacts');
  const recordingsDir = path.join(artifactsDir, 'recordings');
  if (!fs.existsSync(recordingsDir)) {
    fs.mkdirSync(recordingsDir, { recursive: true });
  } else {
    for (const f of fs.readdirSync(recordingsDir)) {
      try { fs.unlinkSync(path.join(recordingsDir, f)); } catch (_) {}
    }
  }

  const timingsData = ensureVoiceTimings();
  const scenes = timingsData.scenes;

  const srtPath = path.join(artifactsDir, 'sentinel-ai-demo.srt');
  const masterAudioPath = path.join(artifactsDir, 'sentinel-ai-master-voice.mp3');
  const finalMp4Path = path.join(artifactsDir, 'sentinel-ai-demo-2026.mp4');

  writeSrtSubtitles(srtPath, timingsData);

  const server = await startStaticServer();

  console.log('🎥 [Playwright] Launching Chromium 1920x1080 with 1.5x device supersampling...');
  const browser = await chromium.launch({
    headless: true,
    args: ['--no-sandbox', '--disable-gpu']
  });

  const context = await browser.newContext({
    viewport: { width: 1920, height: 1080 },
    deviceScaleFactor: 1.5,
    recordVideo: {
      dir: recordingsDir,
      size: { width: 1920, height: 1080 }
    }
  });

  const page = await context.newPage();
  const overlayScript = fs.readFileSync(path.join(__dirname, 'demo-overlay.js'), 'utf-8');

  async function injectOverlay() {
    await page.evaluate(overlayScript);
  }

  try {
    // =========================================================================
    // SCENE 1: Problem & Hybrid Architecture (Duration: ~26s)
    // =========================================================================
    const s1 = scenes[0];
    console.log(`🎬 [1/7] ${s1.name} (Duration: ${s1.duration_sec}s)...`);
    await page.goto(`http://127.0.0.1:${PORT}/docs/index.html`, { waitUntil: 'networkidle' });
    await injectOverlay();

    await page.evaluate((s) => {
      window.__demo.setScene(s.badge, s.name);
      window.__demo.setSubtitle(s.topic, s.subtitle);
      window.__demo.setPos(960, 160);
    }, s1);
    await page.waitForTimeout(3000);

    // Spotlight App Check Badge
    await page.evaluate(() => {
      window.__demo.spotlight('#appCheckBadge', 'FIREBASE APP CHECK: CRYPTOGRAPHICALLY ATTESTED', 6);
      window.__demo.moveTo('#appCheckBadge', 800);
    });
    await page.waitForTimeout(4000);

    // Spotlight Gemini Nano Badge
    await page.evaluate(() => {
      window.__demo.spotlight('#nanoBadge', 'ON-DEVICE GEMINI NANO 4: HARDWARE ACCELERATED', 6);
      window.__demo.moveTo('#nanoBadge', 800);
    });
    await page.waitForTimeout(4000);

    // Spotlight Telemetry Cards
    await page.evaluate(() => {
      window.__demo.spotlight('#hudRedactTime', 'SUB-MILLISECOND AST REDACTION', 8);
      window.__demo.moveTo('#hudRedactTime', 700);
    });
    await page.waitForTimeout(3500);

    await page.evaluate(() => {
      window.__demo.spotlight('#hudAirgap', '100% AIRGAP GUARANTEED', 8);
      window.__demo.moveTo('#hudAirgap', 700);
    });
    await page.waitForTimeout(3500);

    await page.evaluate(() => window.__demo.clearSpotlight());
    await page.waitForTimeout(Math.max(1000, (s1.total_scene_sec - 19) * 1000));

    // =========================================================================
    // SCENE 2: Zero-Leakage Local AST Edge Vault (Duration: ~25s)
    // =========================================================================
    const s2 = scenes[1];
    console.log(`🎬 [2/7] ${s2.name} (Duration: ${s2.duration_sec}s)...`);
    await page.evaluate((s) => {
      window.__demo.setScene(s.badge, s.name);
      window.__demo.setSubtitle(s.topic, s.subtitle);
    }, s2);
    await page.waitForTimeout(2500);

    // Spotlight code editor
    await page.evaluate(() => {
      window.__demo.spotlight('#codeInput', 'PROPRIETARY CODE WITH HIGH-ENTROPY SECRETS', 6);
      window.__demo.moveTo('#codeInput', 800, 0.4, 0.25);
    });
    await page.waitForTimeout(5000);

    // Move to Edge Vault Inspector
    await page.evaluate(() => {
      window.__demo.spotlight('#vaultItems', 'EDGE VAULT: ZERO PLAINTEXT ESCAPES TO CLOUD', 8);
      window.__demo.moveTo('#vaultItems', 800);
    });
    await page.waitForTimeout(6000);

    await page.evaluate(() => {
      window.__demo.spotlight('#vaultStatus', '1 CREDENTIAL PROTECTED (SOC 2 & GDPR ART. 32)', 6);
      window.__demo.moveTo('#vaultStatus', 600);
    });
    await page.waitForTimeout(5000);

    await page.evaluate(() => window.__demo.clearSpotlight());
    await page.waitForTimeout(Math.max(1000, (s2.total_scene_sec - 18.5) * 1000));

    // =========================================================================
    // SCENE 3: On-Device Generative AI (Gemini Nano 4) (Duration: ~24s)
    // =========================================================================
    const s3 = scenes[2];
    console.log(`🎬 [3/7] ${s3.name} (Duration: ${s3.duration_sec}s)...`);
    await page.evaluate((s) => {
      window.__demo.setScene(s.badge, s.name);
      window.__demo.setSubtitle(s.topic, s.subtitle);
    }, s3);
    await page.waitForTimeout(2500);

    // Select Engine dropdown
    await page.evaluate(() => {
      window.__demo.spotlight('#engineSelect', 'INFERENCE MODE: PREFER_ON_DEVICE', 6);
      window.__demo.moveTo('#engineSelect', 700);
    });
    await page.waitForTimeout(3000);

    // Click "Run Hybrid AI Audit"
    await page.evaluate(() => {
      window.__demo.spotlight('#runAuditBtn', 'TRIGGERING ON-DEVICE HYBRID AUDIT', 6);
      window.__demo.clickElement('#runAuditBtn');
    });
    await page.waitForTimeout(5000);

    await page.evaluate(() => {
      window.__demo.spotlight('#hudRedactTime', 'HIGH-PRECISION PERFORMANCE.NOW() TIMING', 6);
      window.__demo.moveTo('#hudRedactTime', 600);
    });
    await page.waitForTimeout(6000);

    await page.evaluate(() => window.__demo.clearSpotlight());
    await page.waitForTimeout(Math.max(1000, (s3.total_scene_sec - 16.5) * 1000));

    // =========================================================================
    // SCENE 4: Self-Healing Diff & Invariant Tests (Duration: ~21s)
    // =========================================================================
    const s4 = scenes[3];
    console.log(`🎬 [4/7] ${s4.name} (Duration: ${s4.duration_sec}s)...`);
    await page.evaluate((s) => {
      window.__demo.setScene(s.badge, s.name);
      window.__demo.setSubtitle(s.topic, s.subtitle);
    }, s4);
    await page.waitForTimeout(2500);

    // Spotlight Diff Viewer
    await page.evaluate(() => {
      window.__demo.spotlight('#diffView', 'SYNTHESIZED ATOMIC REMEDIATION PATCH', 6);
      window.__demo.moveTo('#diffView', 800, 0.5, 0.35);
    });
    await page.waitForTimeout(5000);

    // Switch to Test Suite Tab
    await page.evaluate(() => {
      window.__demo.spotlight("button[onclick=\"switchTab('tests')\"]", 'AUTO-GENERATED EXPLOIT & REGRESSION SUITE', 6);
      window.__demo.clickElement("button[onclick=\"switchTab('tests')\"]", 600);
    });
    await page.waitForTimeout(5000);

    // Spotlight test code view
    await page.evaluate(() => {
      window.__demo.spotlight('#testCodeView', 'EXECUTABLE NODE:TEST INVARIANT SUITE', 6);
      window.__demo.moveTo('#testCodeView', 800, 0.5, 0.4);
    });
    await page.waitForTimeout(5000);

    // Switch back to diff
    await page.evaluate(() => {
      window.__demo.clickElement("button[onclick=\"switchTab('diff')\"]", 400);
      window.__demo.clearSpotlight();
    });
    await page.waitForTimeout(Math.max(1000, (s4.total_scene_sec - 17.5) * 1000));

    // =========================================================================
    // SCENE 5: Cloud Escalation to Gemini 2.5 Pro & Taint Graph (Duration: ~21s)
    // =========================================================================
    const s5 = scenes[4];
    console.log(`🎬 [5/7] ${s5.name} (Duration: ${s5.duration_sec}s)...`);
    await page.evaluate((s) => {
      window.__demo.setScene(s.badge, s.name);
      window.__demo.setSubtitle(s.topic, s.subtitle);
    }, s5);
    await page.waitForTimeout(2000);

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
    await page.waitForTimeout(3000);

    // Spotlight Cloud Escalation Pill
    await page.evaluate(() => {
      window.__demo.spotlight('#escalationPill', 'ESCALATION TRIGGER: MULTI_HOP_TAINT (APP CHECK ATTESTED)', 6);
      window.__demo.moveTo('#escalationPill', 700);
    });
    await page.waitForTimeout(4500);

    // Scroll to Cross-File Taint Graph
    await page.evaluate(() => {
      window.scrollBy({ top: 400, behavior: 'smooth' });
    });
    await page.waitForTimeout(1000);

    await page.evaluate(() => {
      window.__demo.spotlight('#taintGraphContainer', 'INTER-PROCEDURAL CROSS-FILE TAINT TRAJECTORY', 8);
      window.__demo.moveTo('#taintGraphContainer', 700);
    });
    await page.waitForTimeout(5000);

    await page.evaluate(() => window.__demo.clearSpotlight());
    await page.waitForTimeout(Math.max(1000, (s5.total_scene_sec - 17.5) * 1000));

    // =========================================================================
    // SCENE 6: Multi-Platform Chrome Extension (Duration: ~23s)
    // =========================================================================
    const s6 = scenes[5];
    console.log(`🎬 [6/7] ${s6.name} (Duration: ${s6.duration_sec}s)...`);
    await page.goto(`http://127.0.0.1:${PORT}/docs/github-pr-demo.html`, { waitUntil: 'networkidle' });
    await injectOverlay();

    await page.evaluate((s) => {
      window.__demo.setScene(s.badge, s.name);
      window.__demo.setSubtitle(s.topic, s.subtitle);
      window.__demo.setPos(960, 200);
    }, s6);
    await page.waitForTimeout(3000);

    // Spotlight PR Banner
    await page.evaluate(() => {
      window.__demo.spotlight('#sentinel-pr-banner', 'INJECTED ON-DEVICE PR SECURITY BANNER', 6);
      window.__demo.moveTo('#sentinel-pr-banner', 800, 0.5, 0.4);
    });
    await page.waitForTimeout(4500);

    // Click "View Invariant Patch" inside GitHub PR
    await page.evaluate(() => {
      window.__demo.clickElement('#sentinelBtnViewPatch', 500);
    });
    await page.waitForTimeout(4000);

    // Open Extension Popup HUD
    await page.evaluate(() => {
      window.toggleExtensionPopup(true);
      window.__demo.spotlight('#extensionPopupFrame', 'SENTINEL-AI POPUP HUD (MANIFEST V3)', 8);
      window.__demo.moveTo('#extensionPopupFrame', 700);
    });
    await page.waitForTimeout(6000);

    await page.evaluate(() => window.__demo.clearSpotlight());
    await page.waitForTimeout(Math.max(1000, (s6.total_scene_sec - 17.5) * 1000));

    // =========================================================================
    // SCENE 7: Summary Callout & Live Links (Duration: ~18s)
    // =========================================================================
    const s7 = scenes[6];
    console.log(`🎬 [7/7] ${s7.name} (Duration: ${s7.duration_sec}s)...`);
    await page.goto(`http://127.0.0.1:${PORT}/docs/index.html`, { waitUntil: 'networkidle' });
    await injectOverlay();

    await page.evaluate((s) => {
      window.__demo.setScene(s.badge, s.name);
      window.__demo.setSubtitle(s.topic, s.subtitle);
      window.__demo.setPos(960, 540);
    }, s7);
    await page.waitForTimeout(s7.total_scene_sec * 1000);

  } finally {
    console.log('🛑 [Playwright] Stopping recording and finalizing stream...');
    await page.close();
    await context.close();
    await browser.close();
    server.close();
  }

  // Locate the newest raw recording
  const recordedFiles = fs.readdirSync(recordingsDir).filter(f => f.endsWith('.webm'));
  recordedFiles.sort((a, b) => {
    return fs.statSync(path.join(recordingsDir, b)).mtimeMs - fs.statSync(path.join(recordingsDir, a)).mtimeMs;
  });
  const rawWebmPath = path.join(recordingsDir, recordedFiles[0]);

  // Transcode to high-bitrate 1080p MP4 with master audio dubbing
  await transcodeWithAudio(rawWebmPath, masterAudioPath, finalMp4Path);

  // Synchronize to docs/ and web/
  fs.copyFileSync(finalMp4Path, path.join(ROOT_DIR, 'docs', 'sentinel-ai-demo-2026.mp4'));
  fs.copyFileSync(finalMp4Path, path.join(ROOT_DIR, 'web', 'sentinel-ai-demo-2026.mp4'));

  console.log('\n🎉 =====================================================================');
  console.log('🎉 [Sentinel-AI] Master 1080p Video Re-generation Complete!');
  console.log(`🎬 Crisp 1080p Voiced MP4: ${finalMp4Path}`);
  console.log(`📄 English Subtitles: ${srtPath}`);
  console.log('🎉 =====================================================================\n');
}

generateDemoVideo().catch((err) => {
  console.error('❌ Failed to generate master demo video:', err);
  process.exit(1);
});
