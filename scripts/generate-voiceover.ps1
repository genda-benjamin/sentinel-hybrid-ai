# Sentinel-AI: Local Offline Voiceover Generator & Audio Compositor
# Uses Windows System.Speech.Synthesis (100% Offline, Zero Cloud Dependency)

$ErrorActionPreference = "Stop"

$RootDir = Split-Path -Parent $PSScriptRoot
$ArtifactsDir = Join-Path $RootDir "artifacts"
$TempAudioDir = Join-Path $ArtifactsDir "temp_voiceover"

if (-not (Test-Path $TempAudioDir)) {
    New-Item -ItemType Directory -Path $TempAudioDir | Out-Null
}

Add-Type -AssemblyName System.Speech

Write-Host "🎙️ [Voiceover] Initializing Windows Speech Synthesizer..."
$synth = New-Object System.Speech.Synthesis.SpeechSynthesizer
$synth.SelectVoice("Microsoft David Desktop")
$synth.Rate = 0  # Normal natural speaking rate

$scenes = @(
    @{
        Id = 1
        Name = "Scene 1 - Problem & Architecture"
        OffsetSec = 1.0
        Text = "Enterprise source code contains proprietary secrets and database connection strings that must never leak to third-party cloud LLMs. Sentinel-AI solves this through an offline-first hybrid AI architecture built for Google BuildHybridAI 2026, pairing on-device Gemini Nano 4 with Gemini 2.5 Pro via Firebase AI Logic."
    },
    @{
        Id = 2
        Name = "Scene 2 - Zero-Leakage Edge Vault"
        OffsetSec = 18.0
        Text = "In Scene 2, we inspect proprietary code containing a high-entropy database password. Sentinel-AI's on-device AST engine intercepts and tokenizes credentials into reversible vault tokens in sub-millisecond time. Zero plaintext bytes escape to the cloud, satisfying SOC 2 and GDPR Article 32."
    },
    @{
        Id = 3
        Name = "Scene 3 - On-Device Gemini Nano 4"
        OffsetSec = 42.0
        Text = "For standard vulnerabilities like SQL Injection and Command Injection, Sentinel-AI routes inference entirely on-device to Gemini Nano 4. With Chrome Built-in AI, local triage completes in sub-15 milliseconds at exactly zero compute cost with a 100% airgap guarantee."
    },
    @{
        Id = 4
        Name = "Scene 4 - Self-Healing Diffs & Tests"
        OffsetSec = 65.0
        Text = "Sentinel-AI automatically synthesizes atomic unified diffs, replacing dynamic string concatenation with parameterized prepared statements. Simultaneously, it auto-generates executable node:test invariant suites verifying that attack payloads are rejected."
    },
    @{
        Id = 5
        Name = "Scene 5 - Intelligent Cloud Escalation"
        OffsetSec = 88.0
        Text = "When complex multi-file taint trajectories are detected, Sentinel-AI intelligently escalates to Gemini 2.5 Pro via Firebase AI Logic. Every cloud call is guarded by verified Firebase App Check attestation, tracing data flow across multiple services."
    },
    @{
        Id = 6
        Name = "Scene 6 - Multi-Platform Chrome Extension"
        OffsetSec = 110.0
        Text = "Multi-platform by design: The Sentinel-AI Chrome Extension inspects pull request diffs directly inside GitHub and GitLab. It injects on-device security audit banners, provides inline annotations, and exports compliant OASIS SARIF v2.1.0 reports."
    },
    @{
        Id = 7
        Name = "Scene 7 - Summary Callout"
        OffsetSec = 130.0
        Text = "Sentinel-AI: 88 passing tests, 100% green, open source under Apache 2.0. Explore the live deployment at genda-benjamin.github.io/sentinel-hybrid-ai."
    }
)

$clipList = @()

foreach ($scene in $scenes) {
    $wavPath = Join-Path $TempAudioDir ("scene_" + $scene.Id + ".wav")
    Write-Host "   Generating: $($scene.Name) -> $wavPath"
    $synth.SetOutputToWaveFile($wavPath)
    $synth.Speak($scene.Text)
    $clipList += @{
        OffsetSec = $scene.OffsetSec
        Path = $wavPath
    }
}

$synth.Dispose()
Write-Host "✅ [Voiceover] All 7 narration clips generated."

# Composite Audio Track with FFmpeg
$masterAudioPath = Join-Path $ArtifactsDir "sentinel-ai-narration.wav"
Write-Host "🎛️ [FFmpeg] Compositing audio timeline with accurate scene delays..."

$ffmpegInputs = @()
$ffmpegFilters = @()
for ($i = 0; $i -lt $clipList.Count; $i++) {
    $clip = $clipList[$i]
    $ffmpegInputs += "-i"
    $ffmpegInputs += $clip.Path
    $delayMs = [int]($clip.OffsetSec * 1000)
    $ffmpegFilters += "[$i`:a]adelay=$delayMs|$delayMs[a$i]"
}

$mixInputs = ""
for ($i = 0; $i -lt $clipList.Count; $i++) {
    $mixInputs += "[a$i]"
}
$filterComplex = ($ffmpegFilters -join ";") + ";$mixInputs" + "amix=inputs=" + $clipList.Count + ":normalize=0[aout]"

& ffmpeg -y $ffmpegInputs -filter_complex $filterComplex -map "[aout]" -c:a pcm_s16le $masterAudioPath
Write-Host "✅ [FFmpeg] Master narration audio composited: $masterAudioPath"

# Merge Audio with Video
$masterVideo = Join-Path $ArtifactsDir "sentinel-ai-demo-2026.mp4"
$tempOutputVideo = Join-Path $ArtifactsDir "sentinel-ai-demo-voiced.mp4"

Write-Host "🎬 [FFmpeg] Dubbing narration audio into video: $masterVideo..."
& ffmpeg -y -i $masterVideo -i $masterAudioPath -c:v copy -c:a aac -b:a 192k -shortest $tempOutputVideo

# Replace master video
Move-Item -Path $tempOutputVideo -Destination $masterVideo -Force

# Copy to docs/ and web/
$docsVideo = Join-Path $RootDir "docs\sentinel-ai-demo-2026.mp4"
$webVideo = Join-Path $RootDir "web\sentinel-ai-demo-2026.mp4"
Copy-Item -Path $masterVideo -Destination $docsVideo -Force
Copy-Item -Path $masterVideo -Destination $webVideo -Force

Write-Host "`n🎉 ====================================================================="
Write-Host "🎉 [Sentinel-AI] Video Narration & Audio Dubbing Complete!"
Write-Host "🎬 Voiced 1080p Video: $masterVideo"
Write-Host "🎉 =====================================================================`n"
