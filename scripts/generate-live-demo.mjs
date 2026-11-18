/**
 * Sentinel-AI Master Live Demo Video Generator
 * (Google #BuildHybridAI 2026 Hackathon)
 *
 * Records directly from the real public production site:
 * https://genda-benjamin.github.io/sentinel-hybrid-ai/
 *
 * 1. Synchronized to exact scene speech durations (Zero Voice Overlap)
 * 2. High-Bitrate Visually Lossless Encoding (CRF 12 @ 12Mbps, 1080p, Zero Blurriness)
 * 3. Warm, Natural Humanized Voice Narration (Google TTS UK English)
 * 4. Subtitles elevated at bottom: 64px (Above YouTube player scrubber)
 * 5. Strictly under Devpost's 3:00 minute ceiling (~2m 49s)
 */

import fs from 'node:fs';
import path from 'node:path';
import { spawn, execSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { chromium } from 'playwright';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const ROOT_DIR = path.resolve(__dirname, '..');
const LIVE_URL = 'https://genda-benjamin.github.io/sentinel-hybrid-ai/';

function ensureLiveVoiceTimings() {
  const timingsPath = path.join(ROOT_DIR, 'artifacts', 'scene_timings.json');
  const masterAudioPath = path.join(ROOT_DIR, 'artifacts', 'sentinel-ai-master-voice.mp3');

  if (!fs.existsSync(timingsPath) || !fs.existsSync(masterAudioPath)) {
    console.log('🎙️ [Voice Generator] Building live human voice tracks and scene timings...');
    execSync('python scripts/build-live-voice.py', { cwd: ROOT_DIR, stdio: 'inherit' });
  }

  return JSON.parse(fs.readFileSync(timingsPath, 'utf-8'));
}

function writeSrtSubtitles(outputPath, timingsData) {
  const sceneHeaders = {
    1: 'Scene 1: Live Studio Overview & Hybrid Architecture (Google #BuildHybridAI 2026)',
    2: 'Scene 2: Custom Code Input & Zero-Leakage AST Edge Vault',
    3: 'Scene 3: On-Device Gemini Nano 4 Reasoning & Sub-15ms Latency',
    4: 'Scene 4: Self-Healing Unified Diff & Verifiable Invariant Tests',
    5: 'Scene 5: Multi-Hop Cross-File Taint Flow & Cloud Escalation',
    6: 'Scene 6: OASIS SARIF v2.1.0 Export & Hackathon Conclusion'
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

async function generateLiveDemoVideo() {
  console.log('🚀 [Sentinel-AI] Launching Live Site 1080p Demo Video Generator...');
  console.log(`🌐 Target: ${LIVE_URL}`);

  const artifactsDir = path.join(ROOT_DIR, 'artifacts');
  const recordingsDir = path.join(artifactsDir, 'recordings');
  if (!fs.existsSync(recordingsDir)) {
    fs.mkdirSync(recordingsDir, { recursive: true });
  } else {
    for (const f of fs.readdirSync(recordingsDir)) {
      try { fs.unlinkSync(path.join(recordingsDir, f)); } catch (_) {}
    }
  }

  const timingsData = ensureLiveVoiceTimings();
  const scenes = timingsData.scenes;

  const srtPath = path.join(artifactsDir, 'sentinel-ai-demo.srt');
  const masterAudioPath = path.join(artifactsDir, 'sentinel-ai-master-voice.mp3');
  const finalMp4Path = path.join(artifactsDir, 'sentinel-ai-demo-2026.mp4');

  writeSrtSubtitles(srtPath, timingsData);

  console.log('🎥 [Playwright] Launching Chromium 1920x1080 to record live site...');
  const browser = await chromium.launch({
    headless: true,
    args: [
      '--no-sandbox',
      '--disable-setuid-sandbox',
      '--disable-web-security',
      '--force-device-scale-factor=1',
      '--high-dpi-support=1'
    ]
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

  async function injectOverlay() {
    await page.evaluate(overlayScript);
  }

  try {
    // =========================================================================
    // SCENE 1: Live Studio Overview & Hybrid Architecture (Duration: ~33.3s)
    // =========================================================================
    const s1 = scenes[0];
    console.log(`🎬 [1/6] ${s1.name} (Duration: ${s1.duration_sec}s)...`);
    await page.goto(LIVE_URL, { waitUntil: 'networkidle' });
    await injectOverlay();

    await page.evaluate((s) => {
      window.__demo.setScene(s.badge, s.name);
      window.__demo.setSubtitle(s.topic, s.subtitle);
      window.__demo.setPos(960, 200);
    }, s1);
    await page.waitForTimeout(3000);

    // Spotlight Live URL Banner
    await page.evaluate(() => {
      window.__demo.spotlight('#demo-url-banner', 'LIVE GITHUB PAGES PRODUCTION SITE', 6);
      window.__demo.moveTo('#demo-url-banner', 800);
    });
    await page.waitForTimeout(4000);

    // Spotlight Airgap Badge
    await page.evaluate(() => {
      window.__demo.spotlight('#airgapBadge', '100% OFFLINE-FIRST ZERO-LEAKAGE AIRGAP', 6);
      window.__demo.moveTo('#airgapBadge', 700);
    });
    await page.waitForTimeout(4000);

    // Spotlight Gemini Nano Badge
    await page.evaluate(() => {
      window.__demo.spotlight('#nanoBadge', 'ON-DEVICE GEMINI NANO 4 (EDGE NPU ACCELERATED)', 6);
      window.__demo.moveTo('#nanoBadge', 700);
    });
    await page.waitForTimeout(4000);

    // Spotlight App Check Badge
    await page.evaluate(() => {
      window.__demo.spotlight('#appCheckBadge', 'FIREBASE APP CHECK: CRYPTOGRAPHICALLY ATTESTED', 6);
      window.__demo.moveTo('#appCheckBadge', 700);
    });
    await page.waitForTimeout(4000);

    // Spotlight Step Cards
    await page.evaluate(() => {
      const stepRow = document.querySelector('.pipeline-steps') || document.querySelector('.architecture-grid') || document.querySelector('#codeInput');
      window.__demo.spotlight(stepRow, '4-STAGE HYBRID DEFENSE PIPELINE', 8);
      window.__demo.moveTo(stepRow, 800, 0.5, 0.3);
    });
    await page.waitForTimeout(4500);

    await page.evaluate(() => window.__demo.clearSpotlight());
    await page.waitForTimeout(Math.max(1000, (s1.total_scene_sec - 24.5) * 1000));

    // =========================================================================
    // SCENE 2: Custom Code Input & Zero-Leakage AST Edge Vault (Duration: ~30.9s)
    // =========================================================================
    const s2 = scenes[1];
    console.log(`🎬 [2/6] ${s2.name} (Duration: ${s2.duration_sec}s)...`);
    await page.evaluate((s) => {
      window.__demo.setScene(s.badge, s.name);
      window.__demo.setSubtitle(s.topic, s.subtitle);
    }, s2);
    await page.waitForTimeout(2000);

    // Move to Preset dropdown and select Custom User Code
    await page.evaluate(() => {
      const sel = document.getElementById('presetSelect');
      sel.value = 'custom';
      sel.dispatchEvent(new Event('change'));
      window.__demo.spotlight('#presetSelect', 'CUSTOM USER CODE (LIVE DYNAMIC EXECUTION)', 6);
      window.__demo.moveTo('#presetSelect', 700);
    });
    await page.waitForTimeout(3000);

    // Move to code editor
    await page.evaluate(() => {
      window.__demo.spotlight('#codeInput', 'ARBITRARY CODE INPUT WITH LIVE DATABASE PASSWORD', 6);
      window.__demo.moveTo('#codeInput', 700, 0.3, 0.2);
    });
    await page.waitForTimeout(2500);

    // Type realistic vulnerable code containing database password
    const vulnerableSample = `// Production API Handler with database secret\nconst dbSecret = "postgres://admin:SuperSecret2026!@finance.internal:5432/accounts";\n\napp.get("/users/search", async (req, res) => {\n  const query = "SELECT * FROM users WHERE id = " + req.query.id;\n  return await db.query(query);\n});`;

    await page.evaluate((sample) => {
      const input = document.getElementById('codeInput');
      input.value = sample;
      input.dispatchEvent(new Event('input', { bubbles: true }));
      window.__demo.click();
    }, vulnerableSample);
    await page.waitForTimeout(3500);

    // Spotlight Edge Vault Inspector
    await page.evaluate(() => {
      window.__demo.spotlight('#vaultStatus', '1 CREDENTIAL PROTECTED (SOC 2 & GDPR ART. 32)', 6);
      window.__demo.moveTo('#vaultStatus', 700);
    });
    await page.waitForTimeout(4500);

    await page.evaluate(() => {
      window.__demo.spotlight('#vaultItems', 'EDGE VAULT: ZERO PLAINTEXT BYTES SENT TO CLOUD', 8);
      window.__demo.moveTo('#vaultItems', 700);
    });
    await page.waitForTimeout(5500);

    await page.evaluate(() => window.__demo.clearSpotlight());
    await page.waitForTimeout(Math.max(1000, (s2.total_scene_sec - 21.0) * 1000));

    // =========================================================================
    // SCENE 3: On-Device Gemini Nano 4 Reasoning & Sub-15ms Latency (Duration: ~26.9s)
    // =========================================================================
    const s3 = scenes[2];
    console.log(`🎬 [3/6] ${s3.name} (Duration: ${s3.duration_sec}s)...`);
    await page.evaluate((s) => {
      window.__demo.setScene(s.badge, s.name);
      window.__demo.setSubtitle(s.topic, s.subtitle);
    }, s3);
    await page.waitForTimeout(2000);

    // Spotlight Engine dropdown
    await page.evaluate(() => {
      window.__demo.spotlight('#engineSelect', 'INFERENCE MODE: PREFER_ON_DEVICE (GEMINI NANO 4)', 6);
      window.__demo.moveTo('#engineSelect', 700);
    });
    await page.waitForTimeout(3500);

    // Click "Run Hybrid AI Audit"
    await page.evaluate(() => {
      window.__demo.spotlight('#runAuditBtn', 'TRIGGERING ON-DEVICE HYBRID AI AUDIT', 6);
      window.__demo.clickElement('#runAuditBtn');
    });
    await page.waitForTimeout(4000);

    // Spotlight Latency HUD
    await page.evaluate(() => {
      window.__demo.spotlight('#hudRedactTime', 'HIGH-PRECISION PERFORMANCE.NOW() TIMING (< 15MS)', 8);
      window.__demo.moveTo('#hudRedactTime', 700);
    });
    await page.waitForTimeout(5500);

    // Spotlight Zero-Leakage Airgap HUD
    await page.evaluate(() => {
      window.__demo.spotlight('#hudAirgap', '100% AIRGAP AT $0 COMPUTE COST', 8);
      window.__demo.moveTo('#hudAirgap', 700);
    });
    await page.waitForTimeout(4500);

    await page.evaluate(() => window.__demo.clearSpotlight());
    await page.waitForTimeout(Math.max(1000, (s3.total_scene_sec - 19.5) * 1000));

    // =========================================================================
    // SCENE 4: Self-Healing Unified Diff & Verifiable Invariant Tests (Duration: ~22.9s)
    // =========================================================================
    const s4 = scenes[3];
    console.log(`🎬 [4/6] ${s4.name} (Duration: ${s4.duration_sec}s)...`);
    await page.evaluate((s) => {
      window.__demo.setScene(s.badge, s.name);
      window.__demo.setSubtitle(s.topic, s.subtitle);
    }, s4);
    await page.waitForTimeout(2000);

    // Spotlight Diff Viewer
    await page.evaluate(() => {
      window.__demo.spotlight('#diffView', 'SYNTHESIZED ATOMIC PARAMETERIZED PATCH', 6);
      window.__demo.moveTo('#diffView', 800, 0.5, 0.35);
    });
    await page.waitForTimeout(5500);

    // Switch to Test Suite Tab
    await page.evaluate(() => {
      window.__demo.spotlight("button[onclick=\"switchTab('tests')\"]", 'AUTO-GENERATED EXPLOIT & REGRESSION SUITE', 6);
      window.__demo.clickElement("button[onclick=\"switchTab('tests')\"]", 600);
    });
    await page.waitForTimeout(5000);

    // Spotlight Test Code View
    await page.evaluate(() => {
      window.__demo.spotlight('#testCodeView', 'EXECUTABLE NODE:TEST INVARIANT SUITE', 6);
      window.__demo.moveTo('#testCodeView', 800, 0.5, 0.4);
    });
    await page.waitForTimeout(5000);

    // Switch back to diff tab
    await page.evaluate(() => {
      window.__demo.clickElement("button[onclick=\"switchTab('diff')\"]", 400);
      window.__demo.clearSpotlight();
    });
    await page.waitForTimeout(Math.max(1000, (s4.total_scene_sec - 18.0) * 1000));

    // =========================================================================
    // SCENE 5: Multi-Hop Cross-File Taint Flow & Cloud Escalation (Duration: ~23.7s)
    // =========================================================================
    const s5 = scenes[4];
    console.log(`🎬 [5/6] ${s5.name} (Duration: ${s5.duration_sec}s)...`);
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
    await page.waitForTimeout(2500);

    // Click Run Audit
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
      window.scrollBy({ top: 450, behavior: 'smooth' });
    });
    await page.waitForTimeout(1000);

    await page.evaluate(() => {
      window.__demo.spotlight('#taintGraphContainer', 'INTER-PROCEDURAL CROSS-FILE TAINT TRAJECTORY', 8);
      window.__demo.moveTo('#taintGraphContainer', 700);
    });
    await page.waitForTimeout(5000);

    await page.evaluate(() => window.__demo.clearSpotlight());
    await page.waitForTimeout(Math.max(1000, (s5.total_scene_sec - 18.0) * 1000));

    // =========================================================================
    // SCENE 6: OASIS SARIF v2.1.0 Export & Hackathon Conclusion (Duration: ~33.1s)
    // =========================================================================
    const s6 = scenes[5];
    console.log(`🎬 [6/6] ${s6.name} (Duration: ${s6.duration_sec}s)...`);

    // Scroll back to top
    await page.evaluate(() => {
      window.scrollTo({ top: 0, behavior: 'smooth' });
    });
    await page.waitForTimeout(1000);

    await page.evaluate((s) => {
      window.__demo.setScene(s.badge, s.name);
      window.__demo.setSubtitle(s.topic, s.subtitle);
      window.__demo.setPos(960, 400);
    }, s6);
    await page.waitForTimeout(3000);

    // Spotlight SARIF Export Button
    await page.evaluate(() => {
      const btn = document.querySelector('button[onclick="exportSarifReport()"]');
      if (btn) {
        window.__demo.spotlight(btn, 'OASIS SARIF v2.1.0 EXPORT (GITHUB CODE SCANNING)', 6);
        window.__demo.moveTo(btn, 700);
      }
    });
    await page.waitForTimeout(4500);

    // Spotlight SOC 2 / GDPR PDF Export Button
    await page.evaluate(() => {
      const btn = document.querySelector('button[onclick="exportComplianceReport()"]');
      if (btn) {
        window.__demo.spotlight(btn, 'FORMAL SOC 2 CC6.1 & GDPR ART. 32 AUDIT REPORT', 6);
        window.__demo.moveTo(btn, 700);
      }
    });
    await page.waitForTimeout(4500);

    // Spotlight SARIF HUD badge
    await page.evaluate(() => {
      window.__demo.spotlight('#hudSarif', 'SARIF v2.1.0 ATTESTATION', 8);
      window.__demo.moveTo('#hudSarif', 700);
    });
    await page.waitForTimeout(4500);

    // Center cursor and show full live studio
    await page.evaluate(() => {
      window.__demo.clearSpotlight();
      window.__demo.moveTo('#demo-url-banner', 800);
    });
    await page.waitForTimeout(Math.max(1000, (s6.total_scene_sec - 18.0) * 1000));

  } finally {
    console.log('🛑 [Playwright] Stopping recording and finalizing live site stream...');
    await page.close();
    await context.close();
    await browser.close();
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
  fs.copyFileSync(srtPath, path.join(ROOT_DIR, 'docs', 'sentinel-ai-demo.srt'));
  fs.copyFileSync(srtPath, path.join(ROOT_DIR, 'web', 'sentinel-ai-demo.srt'));

  console.log('\n🎉 =====================================================================');
  console.log('🎉 [Sentinel-AI] Master Live Site 1080p Video Generation Complete!');
  console.log(`🌐 Recorded Directly From: ${LIVE_URL}`);
  console.log(`🎬 Crisp 1080p Voiced MP4: ${finalMp4Path}`);
  console.log(`📄 English Subtitles: ${srtPath}`);
  console.log('🎉 =====================================================================\n');
}

generateLiveDemoVideo().catch((err) => {
  console.error('❌ Failed to generate master live demo video:', err);
  process.exit(1);
});
