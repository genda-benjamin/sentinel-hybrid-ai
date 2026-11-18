/**
 * Sentinel-AI Master Live Demo Video Generator (High-Precision Audio Sync)
 * (Google #BuildHybridAI 2026 Hackathon)
 *
 * Records directly from the real public production site:
 * https://genda-benjamin.github.io/sentinel-hybrid-ai/
 *
 * Synchronized second-by-second to uploaded_media_1795013250367.mp3 (169.28s)
 * Uses wall-clock absolute timecode scheduling (waitUntilSec) to prevent any cumulative drift.
 */

import fs from 'node:fs';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { chromium } from 'playwright';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const ROOT_DIR = path.resolve(__dirname, '..');
const LIVE_URL = 'https://genda-benjamin.github.io/sentinel-hybrid-ai/';

function transcodeWithAudio(rawWebmPath, masterAudioPath, finalMp4Path) {
  return new Promise((resolve, reject) => {
    console.log(`🎬 [FFmpeg] Transcoding to Ultra-Crisp 1080p MP4 with Master Voice Dubbing...`);
    console.log(`   Video: Lossless CRF 12 @ 12 Mbps target bitrate (Pristine YouTube Clarity)`);
    console.log(`   Audio: Synced Single-stream Voiceover (Zero Drift)`);

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
  console.log('🚀 [Sentinel-AI] Launching High-Precision Live Site Demo Video Generator...');
  console.log(`🌐 Live Target: ${LIVE_URL}`);

  const artifactsDir = path.join(ROOT_DIR, 'artifacts');
  const recordingsDir = path.join(artifactsDir, 'recordings');
  if (!fs.existsSync(recordingsDir)) {
    fs.mkdirSync(recordingsDir, { recursive: true });
  } else {
    for (const f of fs.readdirSync(recordingsDir)) {
      try { fs.unlinkSync(path.join(recordingsDir, f)); } catch (_) {}
    }
  }

  const srtPath = path.join(artifactsDir, 'sentinel-ai-demo.srt');
  const masterAudioPath = path.join(artifactsDir, 'sentinel-ai-master-voice.mp3');
  const finalMp4Path = path.join(artifactsDir, 'sentinel-ai-demo-2026.mp4');

  if (!fs.existsSync(masterAudioPath)) {
    throw new Error(`Master audio not found at ${masterAudioPath}`);
  }

  console.log('🎥 [Playwright] Launching Chromium 1920x1080...');
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

  // Pre-load the live site and inject overlay before starting timeline timer
  console.log('🌐 Loading live site...');
  await page.goto(LIVE_URL, { waitUntil: 'networkidle' });
  await injectOverlay();

  // Reset preset to default clean state
  await page.evaluate(() => {
    const sel = document.getElementById('presetSelect');
    if (sel) {
      sel.value = 'sqli';
      sel.dispatchEvent(new Event('change'));
    }
  });
  await page.waitForTimeout(500);

  // START MASTER SYNCHRONIZED TIMELINE
  console.log('⏱️  Starting synchronized audio-visual recording timeline (00:00 -> 02:49.28)...');
  const t0 = Date.now();

  async function atTime(min, sec) {
    const targetSec = min * 60 + sec;
    const targetMs = targetSec * 1000;
    const elapsed = Date.now() - t0;
    const remaining = targetMs - elapsed;
    if (remaining > 0) {
      await page.waitForTimeout(remaining);
    }
  }

  try {
    // =========================================================================
    // 00:00 - 00:33 | SCENE 1: Live Studio Overview & Hybrid Architecture
    // =========================================================================
    console.log('🎬 [00:00] SCENE 1: Live Studio Overview');
    await page.evaluate(() => {
      window.__demo.setScene('SCENE 1', 'Live Studio Overview & Hybrid Architecture');
      window.__demo.setSubtitle(
        '🛡️ LIVE PRODUCTION STUDIO • GOOGLE #BUILDHYBRIDAI 2026',
        'Welcome to Sentinel-AI, live on GitHub Pages at <span class="subtitle-highlight">genda-benjamin.github.io/sentinel-hybrid-ai</span>. Offline-first on-device AI pairing Gemini Nano 4 with Gemini 2.5 Pro.'
      );
      window.__demo.setPos(960, 200);
      window.__demo.spotlight('#demo-url-banner', 'LIVE GITHUB PAGES PRODUCTION SITE', 6);
    });

    // 00:10: "On our live production deployment, we show real time on device AST analysis..."
    await atTime(0, 10);
    await page.evaluate(() => {
      window.__demo.setSubtitle(
        '🛡️ OFFLINE-FIRST ARCHITECTURE',
        'On our live production deployment, we demonstrate real-time on-device AST analysis and self-healing patch generation.'
      );
      const stepRow = document.querySelector('.pipeline-steps') || document.querySelector('.architecture-grid') || document.querySelector('#codeInput');
      window.__demo.spotlight(stepRow, '4-STAGE HYBRID DEFENSE PIPELINE', 8);
      window.__demo.moveTo(stepRow, 700, 0.5, 0.3);
    });

    // 00:19: "Notice our live telemetry badges..."
    await atTime(0, 19);
    await page.evaluate(() => {
      window.__demo.setSubtitle(
        '🛡️ LIVE TELEMETRY BADGES',
        'Notice our live telemetry badges: active zero-leakage airgap, Gemini Nano readiness, and cryptographically verified Firebase App Check attestation.'
      );
      window.__demo.moveTo('#airgapBadge', 600);
    });

    // 00:22: "active zero leakage air gap..."
    await atTime(0, 22);
    await page.evaluate(() => {
      window.__demo.spotlight('#airgapBadge', '100% OFFLINE-FIRST ZERO-LEAKAGE AIRGAP', 6);
      window.__demo.moveTo('#airgapBadge', 400);
    });

    // 00:25: "Gemini Nano readiness..."
    await atTime(0, 25);
    await page.evaluate(() => {
      window.__demo.spotlight('#nanoBadge', 'ON-DEVICE GEMINI NANO 4 (EDGE NPU ACCELERATED)', 6);
      window.__demo.moveTo('#nanoBadge', 400);
    });

    // 00:27: "and cryptographically verified Firebase App Check attestation."
    await atTime(0, 27);
    await page.evaluate(() => {
      window.__demo.spotlight('#appCheckBadge', 'FIREBASE APP CHECK: CRYPTOGRAPHICALLY ATTESTED', 6);
      window.__demo.moveTo('#appCheckBadge', 400);
    });

    // 00:32: End of Scene 1 speech
    await atTime(0, 32);
    await page.evaluate(() => {
      window.__demo.clearSpotlight();
      window.__demo.setPos(960, 450);
    });

    // =========================================================================
    // 00:34 - 01:03 | SCENE 2: Custom Code Input & Zero-Leakage AST Edge Vault
    // =========================================================================
    await atTime(0, 34);
    console.log('🎬 [00:34] SCENE 2: Custom Code Input & Zero-Leakage AST Edge Vault');
    await page.evaluate(() => {
      window.__demo.setScene('SCENE 2', 'Custom Code Input & Zero-Leakage AST Edge Vault');
      window.__demo.setSubtitle(
        '🔐 DYNAMIC AST EDGE VAULTING (ZERO PLAINTEXT ESCAPE)',
        'To prove the live studio is truly dynamic, we select Custom User Code and type production code with a database secret.'
      );
      window.__demo.spotlight('#presetSelect', 'SELECTING CUSTOM USER CODE PRESET', 6);
      window.__demo.moveTo('#presetSelect', 600);
    });

    // 00:38: "we select custom user code and type production code with a database secret."
    await atTime(0, 38);
    await page.evaluate(() => {
      const sel = document.getElementById('presetSelect');
      sel.value = 'custom';
      sel.dispatchEvent(new Event('change'));
      window.__demo.click();
      window.__demo.spotlight('#codeInput', 'CUSTOM USER CODE (LIVE DYNAMIC EXECUTION)', 6);
      window.__demo.moveTo('#codeInput', 600, 0.4, 0.25);
    });

    // 00:41: Typing arbitrary code with database secret into live editor
    await atTime(0, 41);
    const vulnerableSample = `// Production API Handler with database secret\nconst dbSecret = "postgres://admin:SuperSecret2026!@finance.internal:5432/accounts";\n\napp.get("/users/search", async (req, res) => {\n  const query = "SELECT * FROM users WHERE id = " + req.query.id;\n  return await db.query(query);\n});`;

    await page.evaluate((sample) => {
      const input = document.getElementById('codeInput');
      input.value = sample;
      input.dispatchEvent(new Event('input', { bubbles: true }));
      window.__demo.click();
    }, vulnerableSample);

    // 00:43: "Instantly, our on device AST engine tokenizes the password into vault token 001..."
    await atTime(0, 43);
    await page.evaluate(() => {
      window.__demo.setSubtitle(
        '🔐 INSTANT ON-DEVICE AST TOKENIZATION',
        'Instantly, our on-device AST engine tokenizes the password into vault token zero-zero-one in sub-millisecond latency.'
      );
      window.__demo.spotlight('#vaultStatus', '1 CREDENTIAL PROTECTED (SOC 2 & GDPR ART. 32)', 6);
      window.__demo.moveTo('#vaultStatus', 600);
    });

    // 00:48: Hover over vaulted token items
    await atTime(0, 48);
    await page.evaluate(() => {
      window.__demo.spotlight('#vaultItems', 'EDGE VAULT: ZERO PLAINTEXT BYTES ESCAPE TO CLOUD', 8);
      window.__demo.moveTo('#vaultItems', 600);
    });

    // 00:54: "Zero plain text bytes escape to the cloud, satisfying SOC 2 and GDPR Article 32."
    await atTime(0, 54);
    await page.evaluate(() => {
      window.__demo.setSubtitle(
        '🔐 COMPLIANCE ATTESTATION',
        'Zero plaintext bytes escape to the cloud, satisfying SOC 2 and GDPR Article 32.'
      );
      window.__demo.spotlight('#vaultStatus', 'ZERO-LEAKAGE AIRGAP VERIFIED', 6);
      window.__demo.moveTo('#vaultStatus', 500);
    });

    // 01:02: End of Scene 2 speech
    await atTime(1, 2);
    await page.evaluate(() => {
      window.__demo.clearSpotlight();
    });

    // =========================================================================
    // 01:05 - 01:31 | SCENE 3: On-Device Gemini Nano 4 Reasoning & Sub-15ms Latency
    // =========================================================================
    await atTime(1, 5);
    console.log('🎬 [01:05] SCENE 3: On-Device Gemini Nano 4 Reasoning');
    await page.evaluate(() => {
      window.__demo.setScene('SCENE 3', 'On-Device Gemini Nano 4 Reasoning & Sub-15ms Latency');
      window.__demo.setSubtitle(
        '⚡ ON-DEVICE GEMINI NANO 4 LOCAL REASONING',
        'Next, we click Run Hybrid AI Audit. As a standard SQL injection vulnerability, Sentinel-AI routes execution on-device to Gemini Nano 4.'
      );
      window.__demo.spotlight('#runAuditBtn', 'TRIGGERING ON-DEVICE HYBRID AI AUDIT', 6);
      window.__demo.moveTo('#runAuditBtn', 500);
    });

    // 01:07: Click "Run Hybrid AI Audit"
    await atTime(1, 7);
    await page.evaluate(() => {
      window.__demo.click();
      document.getElementById('runAuditBtn').click();
    });

    // 01:09: "As a standard SQL injection vulnerability, Sentinel AI routes execution on device to Gemini Nano 4."
    await atTime(1, 9);
    await page.evaluate(() => {
      window.__demo.spotlight('#engineSelect', 'INFERENCE MODE: PREFER_ON_DEVICE (GEMINI NANO 4)', 6);
      window.__demo.moveTo('#engineSelect', 600);
    });

    // 01:18: "With local NPU acceleration, triage completes in under 15 milliseconds..."
    await atTime(1, 18);
    await page.evaluate(() => {
      window.__demo.setSubtitle(
        '⚡ SUB-15MS LOCAL EXECUTION',
        'With local NPU acceleration, triage completes in under fifteen milliseconds at zero compute cost with a complete airgap guarantee.'
      );
      window.__demo.spotlight('#hudRedactTime', 'HIGH-PRECISION PERFORMANCE.NOW() LATENCY (< 15MS)', 8);
      window.__demo.moveTo('#hudRedactTime', 600);
    });

    // 01:25: "at zero compute cost with a complete air gap guarantee."
    await atTime(1, 25);
    await page.evaluate(() => {
      window.__demo.spotlight('#hudAirgap', '100% AIRGAP AT $0 COMPUTE COST', 8);
      window.__demo.moveTo('#hudAirgap', 600);
    });

    // 01:30: End of Scene 3 speech
    await atTime(1, 30);
    await page.evaluate(() => {
      window.__demo.clearSpotlight();
    });

    // =========================================================================
    // 01:32 - 01:53 | SCENE 4: Self-Healing Unified Diff & Verifiable Invariant Tests
    // =========================================================================
    await atTime(1, 32);
    console.log('🎬 [01:32] SCENE 4: Self-Healing Unified Diff & Verification Tests');
    await page.evaluate(() => {
      window.__demo.setScene('SCENE 4', 'Self-Healing Unified Diff & Verifiable Invariant Tests');
      window.__demo.setSubtitle(
        '🛠️ ATOMIC REMEDIATION PATCH & NODE:TEST SUITE',
        'The engine dynamically synthesizes a Git unified diff replacing string concatenation with safe parameterized queries.'
      );
      window.__demo.spotlight('#diffView', 'SYNTHESIZED ATOMIC PARAMETERIZED PATCH (diff --git)', 6);
      window.__demo.moveTo('#diffView', 700, 0.5, 0.35);
    });

    // 01:41: "Clicking the regression test tab..."
    await atTime(1, 41);
    await page.evaluate(() => {
      window.__demo.setSubtitle(
        '🧪 AUTOMATED REGRESSION SUITE',
        'Clicking the Regression Test tab reveals an auto-generated executable node:test suite proving the exploit payload is rejected while benign inputs pass.'
      );
      const testBtn = document.querySelector('button[onclick="switchTab(\'tests\')"]');
      window.__demo.spotlight(testBtn, 'SWITCHING TO NODE:TEST TAB', 6);
      window.__demo.moveTo(testBtn, 500);
    });

    // 01:43: Click Regression Test Tab
    await atTime(1, 43);
    await page.evaluate(() => {
      window.__demo.click();
      const testBtn = document.querySelector('button[onclick="switchTab(\'tests\')"]');
      if (testBtn) testBtn.click();
      window.__demo.spotlight('#testCodeView', 'EXECUTABLE NODE:TEST INVARIANT SUITE', 6);
      window.__demo.moveTo('#testCodeView', 600, 0.5, 0.4);
    });

    // 01:50: Switch back to diff tab
    await atTime(1, 50);
    await page.evaluate(() => {
      const diffBtn = document.querySelector('button[onclick="switchTab(\'diff\')"]');
      if (diffBtn) diffBtn.click();
      window.__demo.clearSpotlight();
    });

    // =========================================================================
    // 01:54 - 02:17 | SCENE 5: Multi-Hop Cross-File Taint Flow & Cloud Escalation
    // =========================================================================
    await atTime(1, 54);
    console.log('🎬 [01:54] SCENE 5: Multi-Hop Cross-File Taint Flow & Cloud Escalation');
    await page.evaluate(() => {
      window.__demo.setScene('SCENE 5', 'Multi-Hop Cross-File Taint Flow & Cloud Escalation');
      window.__demo.setSubtitle(
        '🧠 CLOUD ESCALATION TO GEMINI 2.5 PRO & TAINT GRAPH',
        'Selecting the Multi-File Taint Graph preset, Sentinel-AI detects cross-service dependencies and escalates to Gemini 2.5 Pro via Firebase AI Logic with App Check attestation.'
      );
      window.__demo.spotlight('#presetSelect', 'CROSS-FILE TAINT FLOW PRESET SELECTED', 6);
      window.__demo.moveTo('#presetSelect', 600);
    });

    // 01:56: Select multi-file preset and click run
    await atTime(1, 56);
    await page.evaluate(() => {
      const sel = document.getElementById('presetSelect');
      sel.value = 'multi';
      sel.dispatchEvent(new Event('change'));
      document.getElementById('runAuditBtn').click();
      window.__demo.click();
    });

    // 01:59: "Sentinel AI detects cross service dependencies and escalates to Gemini 2.5 Pro..."
    await atTime(1, 59);
    await page.evaluate(() => {
      window.__demo.spotlight('#escalationPill', 'ESCALATION TRIGGER: MULTI_HOP_TAINT (APP CHECK ATTESTED)', 6);
      window.__demo.moveTo('#escalationPill', 600);
    });

    // 02:08: "Scrolling down reveals the interactive four stage taint graph tracing the flow from source to sink."
    await atTime(2, 8);
    await page.evaluate(() => {
      window.__demo.setSubtitle(
        '🔗 4-STAGE INTERACTIVE TAINT GRAPH',
        'Scrolling down reveals the interactive four-stage taint graph tracing the flow from source to sink.'
      );
      window.scrollBy({ top: 450, behavior: 'smooth' });
    });

    // 02:10: Spotlight Taint Graph
    await atTime(2, 10);
    await page.evaluate(() => {
      window.__demo.spotlight('#taintGraphContainer', 'INTER-PROCEDURAL CROSS-FILE TAINT TRAJECTORY: Source ➔ Vault ➔ Transformer ➔ Neutralized Sink', 8);
      window.__demo.moveTo('#taintGraphContainer', 600);
    });

    // 02:16: End of Scene 5 speech
    await atTime(2, 16);
    await page.evaluate(() => {
      window.__demo.clearSpotlight();
    });

    // =========================================================================
    // 02:18 - 02:49.28 | SCENE 6: OASIS SARIF v2.1.0 Export & Hackathon Conclusion
    // =========================================================================
    await atTime(2, 18);
    console.log('🎬 [02:18] SCENE 6: OASIS SARIF v2.1.0 Export & Hackathon Conclusion');
    await page.evaluate(() => {
      window.scrollTo({ top: 0, behavior: 'smooth' });
      window.__demo.setScene('SUMMARY', 'OASIS SARIF v2.1.0 Export & Hackathon Conclusion');
      window.__demo.setSubtitle(
        '🏆 OASIS SARIF v2.1.0 • 100% GREEN • APACHE 2.0',
        'Sentinel-AI exports compliant OASIS SARIF v2.1.0 reports and formal SOC 2 compliance summaries.'
      );
    });

    // 02:21: Spotlight SARIF export button
    await atTime(2, 21);
    await page.evaluate(() => {
      const btn = document.querySelector('button[onclick="exportSarifReport()"]');
      if (btn) {
        window.__demo.spotlight(btn, 'OASIS SARIF v2.1.0 EXPORT (GITHUB CODE SCANNING)', 6);
        window.__demo.moveTo(btn, 500);
        window.__demo.click();
      }
    });

    // 02:25: "and formal SOC 2 compliance summaries."
    await atTime(2, 25);
    await page.evaluate(() => {
      const btn = document.querySelector('button[onclick="exportComplianceReport()"]');
      if (btn) {
        window.__demo.spotlight(btn, 'FORMAL SOC 2 CC6.1 & GDPR ART. 32 AUDIT REPORT', 6);
        window.__demo.moveTo(btn, 500);
        window.__demo.click();
      }
    });

    // 02:29: "With 88 passing tests, 100% green coverage, and Apache 2.0 open source licensing..."
    await atTime(2, 29);
    await page.evaluate(() => {
      window.__demo.setSubtitle(
        '🏆 ENTERPRISE AUDIT READY',
        'With eighty-eight passing tests, one hundred percent green coverage, and Apache 2.0 open-source licensing, Sentinel-AI is enterprise ready.'
      );
      window.__demo.spotlight('#hudSarif', 'SARIF v2.1.0 ATTESTATION', 8);
      window.__demo.moveTo('#hudSarif', 600);
    });

    // 02:40: "Try the live deployment at gender-benjamin.github.io/sentinel-hybrid-ai."
    await atTime(2, 40);
    await page.evaluate(() => {
      window.__demo.setSubtitle(
        '🚀 LIVE PRODUCTION STUDIO',
        'Try the live deployment at <span class="subtitle-highlight">genda-benjamin.github.io/sentinel-hybrid-ai</span>.'
      );
      window.__demo.spotlight('#demo-url-banner', 'EXPLORE THE LIVE STUDIO AT: genda-benjamin.github.io/sentinel-hybrid-ai', 8);
      window.__demo.moveTo('#demo-url-banner', 600);
    });

    // 02:49.28: Conclude master timeline
    await atTime(2, 49.28);
    console.log('⏱️  Master timeline complete (169.28s)!');

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
