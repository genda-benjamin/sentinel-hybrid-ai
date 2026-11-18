# 🛡️ Sentinel-AI: Chrome Extension (Manifest V3)
> **Multi-Platform On-Device PR Security Auditor & Invariant Verifier**  
> **Target Event:** Google #BuildHybridAI 2026 Hackathon ($30,000 Track)  
> **Compliance:** Chrome Manifest V3, CSP Sandboxing, 100% On-Device Privacy Guarantee

---

## 🎯 Purpose & Multi-Platform Criterion

To satisfy Google #BuildHybridAI's judging criterion — *"Multi-platform solutions are preferred"* — Sentinel-AI extends beyond the Web Studio and CLI into an enterprise-grade **Chrome Extension (Manifest V3)**.

The extension autonomously monitors GitHub (`https://github.com/*/*/pull/*`) and GitLab (`https://gitlab.com/*/*/-/merge_requests/*`) Pull Requests:
1. **On-Device AST Secret Vaulting (`core/extension-vault.js`):** In-browser credential tokenization. Intercepts database credentials, AWS access keys, OpenAI keys, Slack tokens, and JWT secrets directly inside DOM memory and vaults them into `[VAULT_TOKEN_001]` tokens before any reasoning occurs. Zero plaintext leakage to external networks.
2. **On-Device Gemini Nano Audit (`core/diff-scanner.js`):** Leverages Chrome Built-in AI (`window.ai.languageModel` / Prompt API) and edge heuristic playbooks to detect SQL injection (CWE-89), OS command injection (CWE-78), path traversal (CWE-22), hardcoded secrets (CWE-798), and SSRF (CWE-918) in sub-15ms local latency.
3. **Inline PR Security Banner & Diff Annotations (`content/content.js`):** Injects a cybersecurity banner above the PR conversation header and renders inline remediation diff annotations with synthesized parameterized statements directly next to vulnerable code additions.
4. **Interactive Action Popup (`popup/popup.html`):** Dark-mode HUD displaying real-time PR audit telemetry, App Check attestation status, CVSS scores, and 1-click exports for OASIS SARIF v2.1.0 findings and SOC 2 / GDPR attestation reports.

---

## 📦 Extension Architecture

```
extension/
├── manifest.json              # Chrome Manifest V3 configuration & permission boundaries
├── icons/                     # Generated 16x16, 48x48, 128x128 PNG icons
│   ├── icon-16.png
│   ├── icon-48.png
│   └── icon-128.png
├── background/
│   └── service-worker.js      # Ephemeral background worker managing action badges & state
├── core/
│   ├── extension-vault.js     # Edge AST secret tokenization & zero-leakage airgap engine
│   └── diff-scanner.js        # Multi-CWE git diff parser & SARIF v2.1.0 generator
├── content/
│   ├── content.js             # GitHub / GitLab PR DOM parser & inline badge injector
│   └── content.css            # Cyber-glassmorphism stylesheet for PR review UI
└── popup/
    ├── popup.html             # Extension action popup interface
    ├── popup.js               # Reactive telemetry & SARIF exporter controller
    └── popup.css              # Dark-mode enterprise HUD styling
```

---

## 🚀 How to Load Unpacked in Chrome / Chromium

1. Open **Google Chrome** (or Chromium / Brave / Edge).
2. Navigate to `chrome://extensions/`.
3. Toggle on **Developer mode** in the top-right corner.
4. Click **Load unpacked** in the top-left toolbar.
5. Select the `extension/` directory inside this repository:
   ```
   sentinel-hybrid-ai/extension
   ```
6. The extension **Sentinel-AI: On-Device PR Security Auditor** is loaded and ready.
7. Click the extension puzzle piece in the browser toolbar to pin Sentinel-AI.
8. Navigate to any GitHub or GitLab Pull Request page (or open the action popup) to observe real-time on-device auditing in action!

---

## 🧪 Automated Test Suite

The extension is continuously validated by Sentinel-AI's test suite:
- `manifest.json` schema validation & permission verification
- PNG icon magic bytes verification (`89 50 4E 47 0D 0A 1A 0A`)
- Edge AST vaulting unit tests
- In-browser diff scanner tests across all supported CWE categories
- OASIS SARIF v2.1.0 generation test
