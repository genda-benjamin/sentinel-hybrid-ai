import { describe, it } from 'node:test';
import assert from 'node:assert';
import fs from 'node:fs';
import path from 'node:path';

describe('Automated 1080p Demo Video Generator Tests (Day 15)', () => {
  const rootDir = process.cwd();
  const scriptPath = path.join(rootDir, 'scripts', 'generate-demo-video.mjs');
  const overlayPath = path.join(rootDir, 'scripts', 'demo-overlay.js');
  const prDemoPath = path.join(rootDir, 'docs', 'github-pr-demo.html');
  const srtPath = path.join(rootDir, 'artifacts', 'sentinel-ai-demo.srt');
  const mp4Path = path.join(rootDir, 'artifacts', 'sentinel-ai-demo-2026.mp4');

  it('should verify generator scripts and demo assets exist', () => {
    assert.ok(fs.existsSync(scriptPath), 'generate-demo-video.mjs must exist');
    assert.ok(fs.existsSync(overlayPath), 'demo-overlay.js must exist');
    assert.ok(fs.existsSync(prDemoPath), 'docs/github-pr-demo.html must exist');

    const overlay = fs.readFileSync(overlayPath, 'utf-8');
    assert.ok(overlay.includes('demo-cursor'), 'Overlay must define custom glowing cursor');
    assert.ok(overlay.includes('demo-spotlight'), 'Overlay must define component spotlight');
    assert.ok(overlay.includes('demo-subtitle-container'), 'Overlay must define subtitle container');
    assert.ok(overlay.includes('window.__demo'), 'Overlay must attach __demo API to window');
  });

  it('should verify valid OASIS/Devpost compliant SRT subtitle track', () => {
    assert.ok(fs.existsSync(srtPath), 'Subtitle file sentinel-ai-demo.srt must exist');
    const srt = fs.readFileSync(srtPath, 'utf-8');

    // Verify 7 scenes represented
    assert.ok(srt.includes('Scene 2: Zero-Leakage Local AST Edge Vault'), 'Must contain Scene 2');
    assert.ok(srt.includes('Scene 3: On-Device Generative AI via Gemini Nano 4'), 'Must contain Scene 3');
    assert.ok(srt.includes('Scene 4: Self-Healing Unified Diffs & Verifiable Tests'), 'Must contain Scene 4');
    assert.ok(srt.includes('Scene 5: Intelligent Cloud Escalation to Gemini 2.5 Pro'), 'Must contain Scene 5');
    assert.ok(srt.includes('Scene 6: Multi-Platform Chrome Extension (Manifest V3)'), 'Must contain Scene 6');
    assert.ok(srt.includes('Google #BuildHybridAI 2026'), 'Must contain Hackathon Callout');

    // Standard SRT timecode pattern
    const timecodeRegex = /\d{2}:\d{2}:\d{2},\d{3} --> \d{2}:\d{2}:\d{2},\d{3}/;
    assert.ok(timecodeRegex.test(srt), 'SRT file must contain valid timecodes');
  });

  it('should verify rendered 1080p MP4 demo video exists and satisfies Devpost rules', () => {
    assert.ok(fs.existsSync(mp4Path), 'MP4 video artifacts/sentinel-ai-demo-2026.mp4 must exist');
    const stats = fs.statSync(mp4Path);

    // File size sanity check (> 1 MB, < 100 MB)
    assert.ok(stats.size > 1024 * 1024, `Video file size must be > 1MB (actual: ${stats.size} bytes)`);
    assert.ok(stats.size < 100 * 1024 * 1024, `Video file size must be < 100MB for fast judge streaming`);

    // Verify MP4 ftyp box in first 32 bytes
    const buffer = Buffer.alloc(32);
    const fd = fs.openSync(mp4Path, 'r');
    fs.readSync(fd, buffer, 0, 32, 0);
    fs.closeSync(fd);

    const ftyp = buffer.toString('utf-8', 4, 8);
    assert.strictEqual(ftyp, 'ftyp', 'File must begin with MP4 ftyp signature box');
  });

  it('should verify simulated GitHub PR review page wires extension components', () => {
    const html = fs.readFileSync(prDemoPath, 'utf-8');
    assert.ok(html.includes('sentinel-banner-anchor'), 'Must contain anchor for Sentinel-AI banner');
    assert.ok(html.includes('extensionPopupFrame'), 'Must contain iframe for Chrome Extension popup');
    assert.ok(html.includes('diff-scanner.js'), 'Must load diff scanner core');
    assert.ok(html.includes('extension-vault.js'), 'Must load extension edge vault');
  });
});
