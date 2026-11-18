#!/usr/bin/env python3
"""
Sentinel-AI Live Voice Generator (Optimized for < 3:00 Devpost Ceiling)
Synthesizes warm, natural human speech clips for the Live Site Demo walkthrough
using Google Text-to-Speech (gTTS) with UK English (tld='co.uk').
Measures exact duration with ffprobe and builds a non-overlapping master audio file.
"""

import json
import os
import subprocess
from gtts import gTTS

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ARTIFACTS_DIR = os.path.join(ROOT_DIR, "artifacts")
VOICE_DIR = os.path.join(ARTIFACTS_DIR, "live_voice_clips")
os.makedirs(VOICE_DIR, exist_ok=True)

SCENES = [
    {
        "id": 1,
        "name": "Live Studio Overview & Hybrid Architecture",
        "badge": "SCENE 1",
        "topic": "🛡️ LIVE PRODUCTION STUDIO • GOOGLE #BUILDHYBRIDAI 2026",
        "subtitle": "Welcome to Sentinel-AI, live on GitHub Pages at <span class=\"subtitle-highlight\">genda-benjamin.github.io/sentinel-hybrid-ai</span>. Offline-first on-device AI pairing Gemini Nano 4 with Gemini 2.5 Pro.",
        "text": (
            "Welcome to Sentinel-AI, the offline-first hybrid AI security auditor for Google BuildHybridAI 2026. "
            "On our live production deployment, we show real-time on-device AST analysis and self-healing patch generation. "
            "Notice our live telemetry badges: active zero-leakage airgap, Gemini Nano readiness, and cryptographically verified Firebase App Check attestation."
        )
    },
    {
        "id": 2,
        "name": "Custom Code Input & Zero-Leakage AST Edge Vault",
        "badge": "SCENE 2",
        "topic": "🔐 DYNAMIC AST EDGE VAULTING (ZERO PLAINTEXT ESCAPE)",
        "subtitle": "Typing arbitrary code with secrets triggers <span class=\"subtitle-highlight\">sub-millisecond AST redaction</span> into [VAULT_TOKEN_001] before any egress.",
        "text": (
            "To prove the live studio is truly dynamic, we select Custom User Code and type production code with a database secret. "
            "Instantly, our on-device AST engine tokenizes the password into vault token zero-zero-one in sub-millisecond latency. "
            "Zero plaintext bytes escape to the cloud, satisfying SOC 2 and GDPR Article 32."
        )
    },
    {
        "id": 3,
        "name": "On-Device Gemini Nano 4 Reasoning & Sub-15ms Latency",
        "badge": "SCENE 3",
        "topic": "⚡ ON-DEVICE GEMINI NANO 4 LOCAL REASONING",
        "subtitle": "Standard vulnerabilities execute <span class=\"subtitle-highlight\">100% on-device in under 15ms</span> at zero cloud compute cost.",
        "text": (
            "Next, we click Run Hybrid AI Audit. "
            "As a standard SQL injection vulnerability, Sentinel-AI routes execution on-device to Gemini Nano 4. "
            "With local NPU acceleration, triage completes in under fifteen milliseconds at zero compute cost with a complete airgap guarantee."
        )
    },
    {
        "id": 4,
        "name": "Self-Healing Unified Diff & Verifiable Invariant Tests",
        "badge": "SCENE 4",
        "topic": "🛠️ ATOMIC REMEDIATION PATCH & NODE:TEST SUITE",
        "subtitle": "Synthesizes standard <span class=\"subtitle-highlight\">diff --git</span> parameterized patches and executable node:test mathematical proofs.",
        "text": (
            "The engine dynamically synthesizes a Git unified diff replacing string concatenation with safe parameterized queries. "
            "Clicking the Regression Test tab reveals an auto-generated executable node:test suite proving the exploit payload is rejected while benign inputs pass."
        )
    },
    {
        "id": 5,
        "name": "Multi-Hop Cross-File Taint Flow & Cloud Escalation",
        "badge": "SCENE 5",
        "topic": "🧠 CLOUD ESCALATION TO GEMINI 2.5 PRO & TAINT GRAPH",
        "subtitle": "Cross-service call graphs <span class=\"subtitle-highlight\">escalate to Gemini 2.5 Pro</span> with verified App Check attestation.",
        "text": (
            "Selecting the Multi-File Taint Graph preset, Sentinel-AI detects cross-service dependencies and escalates to Gemini 2.5 Pro via Firebase AI Logic with App Check attestation. "
            "Scrolling down reveals the interactive four-stage taint graph tracing the flow from source to sink."
        )
    },
    {
        "id": 6,
        "name": "OASIS SARIF v2.1.0 Export & Hackathon Conclusion",
        "badge": "SUMMARY",
        "topic": "🏆 OASIS SARIF v2.1.0 • 100% GREEN • APACHE 2.0",
        "subtitle": "<strong>88/88 Passing Tests (100% Green)</strong> • Live at <span class=\"subtitle-highlight\">genda-benjamin.github.io/sentinel-hybrid-ai</span>",
        "text": (
            "Sentinel-AI exports compliant OASIS SARIF v2.1.0 reports and formal SOC 2 compliance summaries. "
            "With eighty-eight passing tests, one hundred percent green coverage, and Apache 2.0 open-source licensing, Sentinel-AI is enterprise ready. "
            "Try the live deployment at genda-benjamin.github.io/sentinel-hybrid-ai."
        )
    }
]

def get_audio_duration_seconds(file_path):
    cmd = [
        "ffprobe", "-v", "error",
        "-show_entries", "format=duration",
        "-of", "default=noprint_wrappers=1:nokey=1",
        file_path
    ]
    res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)
    return float(res.stdout.strip())

def main():
    print("🎙️ [Live Voice Generator] Synthesizing 6 scenes with Google Humanized Voice...")
    
    current_time = 0.5  # Start 0.5s after video begins
    scene_data = []
    clip_files = []

    for s in SCENES:
        clip_path = os.path.join(VOICE_DIR, f"live_scene_{s['id']}.mp3")
        print(f"   Generating {s['badge']}: {s['name']}...")
        
        tts = gTTS(text=s["text"], lang="en", tld="co.uk", slow=False)
        tts.save(clip_path)

        duration = get_audio_duration_seconds(clip_path)
        start_sec = round(current_time, 2)
        end_sec = round(start_sec + duration, 2)
        total_scene_sec = round(duration + 2.0, 2)

        s_entry = {
            "id": s["id"],
            "name": s["name"],
            "badge": s["badge"],
            "topic": s["topic"],
            "subtitle": s["subtitle"],
            "text": s["text"],
            "clip_path": clip_path,
            "start_sec": start_sec,
            "duration_sec": round(duration, 2),
            "end_sec": end_sec,
            "total_scene_sec": total_scene_sec
        }
        scene_data.append(s_entry)
        clip_files.append((clip_path, duration))
        print(f"      Duration: {duration:.2f}s | Timeline: {start_sec}s -> {end_sec}s (Total scene: {total_scene_sec}s)")

        current_time += duration + 2.0  # 2.0s breathing silence between scenes (Zero Overlap Guaranteed)

    # Generate master concatenated audio with FFmpeg
    master_audio_path = os.path.join(ARTIFACTS_DIR, "sentinel-ai-master-voice.mp3")
    print("\n🎛️ [Audio Mastering] Concatenating scenes with 2.0s non-overlapping silence...")

    filter_inputs = []
    filter_complex = []
    for i, (clip_p, dur) in enumerate(clip_files):
        filter_inputs.extend(["-i", clip_p])
        delay_ms = int(scene_data[i]["start_sec"] * 1000)
        filter_complex.append(f"[{i}:a]adelay={delay_ms}|{delay_ms}[a{i}];")

    mix_inputs = "".join(f"[a{i}]" for i in range(len(clip_files)))
    filter_complex.append(f"{mix_inputs}amix=inputs={len(clip_files)}:normalize=0:dropout_transition=0[outa]")

    cmd = [
        "ffmpeg", "-y",
        *filter_inputs,
        "-filter_complex", "".join(filter_complex),
        "-map", "[outa]",
        "-c:a", "libmp3lame",
        "-b:a", "192k",
        master_audio_path
    ]
    subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)

    master_duration = get_audio_duration_seconds(master_audio_path)
    print(f"✅ [Master Voice Complete] File: {master_audio_path}")
    print(f"   Total Duration: {master_duration:.2f}s ({int(master_duration//60)}m {int(master_duration%60)}s)")
    assert master_duration < 180.0, f"Duration {master_duration}s exceeds 3:00 minute Devpost limit!"

    timings_json_path = os.path.join(ARTIFACTS_DIR, "scene_timings.json")
    with open(timings_json_path, "w", encoding="utf-8") as f:
        json.dump({"total_duration": master_duration, "scenes": scene_data}, f, indent=2)

    print(f"✅ [Scene Timings Saved] {timings_json_path}")

if __name__ == "__main__":
    main()
