# 🛡️ Sentinel-AI

> **Offline-First Hybrid AI Security Auditor & Remediation Engine**  
> *Built for Google **#BuildHybridAI 2026** ($30,000 Cash Prize Track)*

[![Tests](https://img.shields.io/badge/tests-9%20passed-brightgreen.svg)](#test-suite)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Architecture](https://img.shields.io/badge/architecture-Hybrid%20AI%20(Local%20%2B%20Cloud)-orange.svg)](#architecture)
[![Google Tech](https://img.shields.io/badge/powered%20by-Firebase%20AI%20Logic%20%26%20Gemini-4285F4.svg)](#firebase--gemini-cloud-tier)

---

## 📌 Executive Summary

Enterprise teams and developers face a critical dilemma: **they want AI-powered code auditing, vulnerability remediation, and compliance verification**, but corporate privacy standards (SOC 2 CC6.1, GDPR Article 32, HIPAA) **strictly forbid sending proprietary code, database connection strings, JWTs, or private API keys to third-party cloud LLMs**.

**Sentinel-AI solves this through a breakthrough Hybrid AI Architecture**:
1. **Local Edge Tier (100% On-Device)**: Instantly scans code, detects static vulnerabilities, and uses a deterministic cryptographic **Vaulting & Tokenization Engine** to strip every secret, credential, and PII token into irreversible cryptographic hashes *before* network egress.
2. **Cloud Tier (Google Firebase & Gemini AI Logic)**: Receives *only sanitized, de-identified structural code ASTs*. Leverages Gemini 2.5's deep reasoning for multi-step vulnerability analysis (taint tracking, auth bypass, CVSS 3.1 scoring, and surgical patch generation).
3. **Local Re-hydration & Verification Tier**: The client receives the sanitized remediation diff and seamlessly re-hydrates the original secrets in memory locally. Zero credentials ever touch Google servers.

---

## 🏗️ Hybrid Architecture

```mermaid
flowchart TD
    subgraph Client ["🖥️ Local / Edge Tier (100% On-Device)"]
        Source["📄 Raw Source Code<br/>(API Keys, Passwords, SQLi)"]
        Sanitizer["🔒 LocalSanitizer<br/>Regex & AST Engine"]
        Vault["🗄️ In-Memory Token Vault<br/>(Never leaves host)"]
        Detector["🔎 LocalDetector<br/>OWASP Static Rules"]
        Classifier["⚖️ HybridClassifier<br/>Cost & Privacy Boundary"]
        Rehydrator["✨ Local Re-hydrator<br/>Original Secret Reconstitution"]
        Verified["✅ Verified Remediated Code<br/>(Passes 100% Local Tests)"]
    end

    subgraph Cloud ["☁️ Cloud Tier (Firebase & Gemini 2.5)"]
        Payload["📦 De-identified Payload<br/>(__SENTINEL_API_KEY_...__)"]
        FirebaseAI["⚡ Firebase AI Logic<br/>Gemini 2.5 Flash / Pro"]
        Remediation["🛠️ Structured Remediation<br/>(CVSS 3.1, SOC2, Diff)"]
    end

    Source --> Sanitizer
    Sanitizer -->|Extract Secrets| Vault
    Sanitizer -->|Sanitized Code| Detector
    Detector --> Classifier
    Classifier -->|Escalate Complex Flaws| Payload
    Payload --> FirebaseAI
    FirebaseAI --> Remediation
    Remediation --> Rehydrator
    Vault -.->|Local Reconstitution| Rehydrator
    Rehydrator --> Verified
```

---

## 🌟 Key Capabilities

### 1. 🛡️ Guaranteed Zero-Leakage Redaction
* Automatically tokenizes:
  * Private Keys (`-----BEGIN RSA/EC PRIVATE KEY-----`)
  * API Keys (`sk-live...`, `AIzaSy...`, `ghp_...`, `stripe_sk...`)
  * Database URLs (`postgres://user:pass@host/db`)
  * JWTs (`eyJhbGci...`)
  * High-entropy secrets and passwords
* Verified by automated assertions: mathematical certainty that 0% of secret material egresses to cloud APIs.

### 2. ⚡ Intelligent Hybrid Triage
* **Local Deterministic Rules**: Low-complexity issues (e.g. Prototype Pollution, direct parameter assignments) are remediated locally in under 5ms at **$0.00 cloud cost**.
* **Cloud Gemini Escalation**: High-severity semantic vulnerabilities (SQL Injection, OS Command Injection, Path Traversal, SSRF) are dispatched to Gemini for contextual semantic reasoning and code synthesis.

### 3. 📋 Compliance & CVSS 3.1 Mapping
Every cloud remediation plan automatically computes:
* Precise **CVSS 3.1 Base Score**
* Applicable **CWE Category** (e.g., CWE-89, CWE-78, CWE-22)
* Formal **Compliance Controls** (SOC 2 CC6.1 Logical Access, GDPR Article 32 Security of Processing, OWASP Top 10)

---

## 🚀 Quickstart

### Prerequisites
* Node.js `>= 20.0.0`
* npm `>= 10.0.0`

### 1. Clone & Build
```bash
git clone https://github.com/genda-benjamin/sentinel-hybrid-ai.git
cd sentinel-hybrid-ai
npm install
npm run build
```

### 2. Run Offline Local Scan
```bash
node dist/cli/index.js scan sample/vulnerable-app.ts
```

### 3. Run End-to-End Hybrid AI Audit
```bash
node dist/cli/index.js audit sample/vulnerable-app.ts
```

---

## 🧪 Test Suite

Sentinel-AI includes a comprehensive native test suite with 100% green passing status:

```bash
npm test
```

### Test Coverage Breakdown:
* `LocalSanitizer Unit Tests`: Verifies redaction, cryptographic hashing, and local rehydration fidelity.
* `LocalDetector Unit Tests`: Covers OWASP Top 10 injection, access control, and prototype pollution rules.
* `HybridClassifier Unit Tests`: Validates the edge vs. cloud routing boundary and privacy preservation metrics.
* `End-to-End Hybrid AI Workflow`: Tests the complete round-trip loop from vulnerable code with secrets to verified, rehydrated patch.

---

## 🏆 Google #BuildHybridAI 2026 Submission

* **Project Title**: Sentinel-AI
* **Track**: Hybrid AI (Edge + Cloud with Firebase / Gemini)
* **Author**: Benjamin Genda (`genda-benjamin`)
* **Repository**: [https://github.com/genda-benjamin/sentinel-hybrid-ai](https://github.com/genda-benjamin/sentinel-hybrid-ai)
* **License**: Apache 2.0
