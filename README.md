<div align="center">

```
  ██████╗ ██╗  ██╗██╗███████╗██╗  ██╗ ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗
  ██╔══██╗██║  ██║██║██╔════╝██║  ██║██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗
  ██████╔╝███████║██║███████╗███████║██║  ███╗██║   ██║███████║██████╔╝██║  ██║
  ██╔═══╝ ██╔══██║██║╚════██║██╔══██║██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║
  ██║     ██║  ██║██║███████║██║  ██║╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝
  ╚═╝     ╚═╝  ╚═╝╚═╝╚══════╝╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝
```

# PhishGuard AI — CLI Phishing Detection Tool

**AI-powered phishing detection from your terminal — URLs, Emails, APKs, Code, Files & Messages**

[![Python](https://img.shields.io/badge/Python-3.7%2B-blue?style=flat-square&logo=python&logoColor=white)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow?style=flat-square)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Termux-green?style=flat-square&logo=linux&logoColor=white)](https://github.com)
[![AI Model](https://img.shields.io/badge/AI-Gemini%201.5%20Flash-blue?style=flat-square&logo=google&logoColor=white)](https://aistudio.google.com)
[![Tor](https://img.shields.io/badge/Tor-Supported-purple?style=flat-square)](https://www.torproject.org)
[![Free API](https://img.shields.io/badge/API-Free%201500%2Fday-brightgreen?style=flat-square)](https://aistudio.google.com/app/apikey)
[![Version](https://img.shields.io/badge/Version-2.1.0-orange?style=flat-square)](https://github.com)

</div>

---

## Table of Contents

- [Overview](#-overview)
- [Features](#-features)
- [Demo](#-demo)
- [Requirements](#-requirements)
- [Installation](#-installation)
- [Usage](#-usage)
- [Scan Types](#-scan-types)
- [Configuration](#-configuration)
- [APK Scanning Guide](#-apk-scanning-guide)
- [Tor Integration](#-tor-integration)
- [Threat Scoring](#-threat-scoring)
- [File Structure](#-file-structure)
- [Contributing](#-contributing)
- [License](#-license)

---

## Overview

**PhishGuard AI** is a professional command-line phishing detection tool powered by **Google Gemini 1.5 Flash** (free tier). It analyzes URLs, emails, source code, Android APKs, files, and messages for phishing, malware, social engineering, and credential harvesting — all from your terminal.

Fully compatible with **Linux** (Debian/Ubuntu/Kali/Arch) and **Termux** (Android), with optional **Tor** routing for anonymity.

> **API Cost:** Completely free — Gemini free tier gives **1,500 scans/day**, no credit card required.

---

## Features

| Feature | Description |
|---------|-------------|
|  **6 Random Banners** | Different ASCII art on every run (slant, doom, banner3, epic, digital, shadow) |
|  **Tor Integration** | Auto-starts Tor daemon, routes scans through onion network |
|  **Tor IP Rotation** | Rotate exit node identity from inside the tool |
|  **Secure Key Storage** | API key hidden during input, stored with `chmod 600` |
|  **Auto Dependencies** | Missing Python packages auto-installed on first run |
|  **URL Scanner** | Typosquatting, homograph attacks, suspicious TLDs, fake domains |
|  **Email Scanner** | Phishing emails, spoofed senders, urgency tactics, impersonation |
|  **Code Scanner** | Malicious JS/PHP/Python, eval() obfuscation, data exfiltration |
|  **APK Scanner** | Dangerous permissions, SMS stealers, overlay attacks, dropper malware |
|  **File Scanner** | Malicious scripts, embedded URLs, encoded payloads, macros |
|  **Message Scanner** | WhatsApp/SMS scams, fake banks, OTP theft, prize fraud |
|  **Scan History** | Persistent JSON history, export, stats across sessions |
|  **Settings Menu** | API key change, Tor toggle, history export, full reset |
|  **Threat Indicators** | 7 specific threat vectors checked per scan |
|  **Detailed Findings** | Severity-graded findings with descriptions |
|  **Recommendations** | Actionable security advice per scan |
|  **Linux + Termux** | Single codebase, works on both platforms |

---

## 🎬 Demo

```
╭──────────────────────────────────────────────────────────────╮
│                                                              │
│    ____  _     _     _      ____                     _       │
│   |  _ \| |__ (_)___| |__  / ___|_   _  __ _ _ __ __| |      │
│   | |_) | '_ \| / __| '_ \| |  _| | | |/ _` | '__/ _` |      │
│   |  __/| | | | \__ \ | | | |_| | |_| | (_| | | | (_| |      │
│   |_|   |_| |_|_|___/_| |_|\____|\__,_|\__,_|_|  \__,_|      │
│                                                              │
│              [ AI-Powered Phishing Detection ]               │
│                                                              │
╰──────────────────────────────────────────────────────────────╯

  SCAN TOOLS
  [1]  URL / Website Scanner
  [2]  Email Scanner
  [3]  Code / Script Scanner
  [4]  APK / App Scanner
  [5]  File Scanner
  [6]  Message / SMS Scanner

  TOOLS
  [7]  Scan History
  [8]  Rotate Tor Identity
  [9]  Settings
  [0]  Exit

  → Enter choice:
```

**Scan Result Example:**
```
━━━━━━━━━━━━ SCAN RESULTS  #20261109104823 ━━━━━━━━━━━━

╭────────────────── 💀 CRITICAL RISK ─────────────────────
│                                                                 
│  Threat Score  :  ████████████████████████░░░░  96/100          
│  Confidence    :  ███████████████████████████░  94/100         
│                                                                 
│  Risk Level    :  💀 CRITICAL                                   
│  Phishing      :  ⚠️  YES — PHISHING DETECTED                  
│  Scan Type     :  URL                                           
│  Timestamp     :  2026-11-09 10:48:23                          
╰─────────────────────────────────────────────────────────

╭──────────────── 🎯 Threat Indicators ─────────────────╮
│  🔗 URL Manipulation       ⚠️  FOUND                  │
│  ⏰ Urgency Tactics        ✅  CLEAN                  │
│  🎭 Impersonation          ⚠️  FOUND                  │
│  🔑 Credential Harvesting  ⚠️  FOUND                  │
│  💀 Malicious Code         ✅  CLEAN                  │
╰───────────────────────────────────────────────────────╯
```

---

## Requirements

| Requirement | Details |
|-------------|---------|
| **OS** | Linux (Debian/Ubuntu/Kali/Arch) or Android (Termux) |
| **Python** | 3.7 or higher |
| **Gemini API** | Free key from [aistudio.google.com](https://aistudio.google.com/app/apikey) |
| **Tor** | Optional — installed automatically by installer |
| **Internet** | Required for Gemini API calls |

**Python packages** (auto-installed):
```
rich >= 13.0
pyfiglet >= 0.8
requests >= 2.28
requests[socks]  # for Tor routing (optional)
```

---

##  Installation

### Linux (Debian / Ubuntu / Kali)

```bash
# 1. Clone the repository
git clone https://github.com/Zeeshan-78/phishguard.git
cd phishguard-ai

# 2. Run the installer
bash install.sh

# 3. Done! Launch with:
ai-detect
```

### Termux (Android)

```bash
# 1. Update packages
pkg update && pkg upgrade -y

# 2. Install git
pkg install git -y

# 3. Clone
git clone https://github.com/Zeeshan-78/phishguard.git
cd phishguard-ai

# 4. Install
bash install.sh

# 5. Launch
ai-detect
```

### Manual Installation (without installer)

```bash
# Install Python packages
pip install rich pyfiglet requests "requests[socks]"

# Run directly
python3 ai_detect.py

# Or make it global
chmod +x ai_detect.py
sudo cp ai_detect.py /usr/local/bin/ai-detect
```

---

## Usage

```bash
# Interactive mode (recommended)
ai-detect

# Skip Tor, connect directly
ai-detect --no-tor

# Show version
ai-detect --version

# Show help
ai-detect --help
```

**First Launch:**
On first run, the tool will ask for your Gemini API key (input is hidden). Get a free key at [aistudio.google.com/app/apikey](https://aistudio.google.com/app/apikey).

---

##  Scan Types

### URL / Website Scanner
Detects: Typosquatting (`paypa1.com`), suspicious TLDs (`.tk .xyz .ml`), IP-based URLs, homograph attacks, URL shorteners hiding malicious destinations, mismatched brand/domain tricks.

### Email Scanner
Detects: Spoofed sender addresses, mismatched display name vs email, generic greetings ("Dear Customer"), urgency/fear language, credential/OTP requests, impersonation of banks, PayPal, Google, Microsoft.

### Code Scanner
Detects: `eval()` with base64/encoded strings, hidden iframes, form action to external domain, `fetch()`/XHR exfiltrating data, keyloggers (`addEventListener keydown`), `String.fromCharCode` obfuscation, cookie stealing.

### APK / App Scanner
Detects: `READ_SMS + SEND_SMS` (OTP stealer), `REQUEST_INSTALL_PACKAGES` (dropper), `SYSTEM_ALERT_WINDOW + BIND_ACCESSIBILITY_SERVICE` (overlay attack), `DEVICE_ADMIN` (ransomware), unofficial distribution (WhatsApp/Telegram link).

### File Scanner
Detects: Embedded phishing URLs, credential harvesting forms, encoded payloads, `Auto_Open`/`Document_Open` macros, PowerShell encoded commands (`-EncodedCommand`), C2 server addresses.

### Message / SMS Scanner
Detects: Prize/lottery scams, bank/government impersonation, OTP/PIN requests, URL shorteners, urgency threats ("account blocked", "FIR"), advance fee fraud, fake app installation links.

---

## Configuration

Config is stored in `~/.ai-detect/config.json`:

```json
{
  "gemini_api_key": "AIzaSy...",
  "first_run_done": true,
  "setup_date": "2026-11-09T10:48:00",
  "skip_tor": false
}
```

Scan history in `~/.ai-detect/history.json` (up to 500 entries).

**Change API key:**
```bash
ai-detect  # → [9] Settings → [1] Change API Key
```

**Environment variable (alternative):**
```bash
export GEMINI_API_KEY="AIzaSy..."
ai-detect
```

---

## APK Scanning Guide

Since APK files can be very large (100MB+), extract content first:

```bash
# Install apktool
sudo apt install apktool    # Linux
pkg install apktool          # Termux

# Extract APK
apktool d suspicious-app.apk -o extracted/

# Key files to paste into scanner:
# 1. extracted/AndroidManifest.xml  ← most important
# 2. extracted/res/values/strings.xml
# 3. extracted/smali/com/app/MainActivity.smali
```

Then paste the content into the **APK Scanner** in PhishGuard AI.

---

## Tor Integration

PhishGuard AI automatically starts the Tor daemon and routes all Gemini API calls through the Tor network.

```
Your Terminal → Tor Network → AI API
```

**Tor setup:**
```bash
# Tor is installed by install.sh automatically

# For IP rotation from inside the tool:
# → [8] Rotate Tor Identity

# For control port (enable rotation):
# Add to /etc/tor/torrc:
ControlPort 9051
CookieAuthentication 0
```

**Disable Tor:**
```bash
ai-detect --no-tor        # one-time
# or inside tool → [9] Settings → [2] Toggle Tor
```

---

## 📊 Threat Scoring

| Score | Level | Meaning |
|-------|-------|---------|
| 0–14  | ✅ **SAFE**     | No significant threat detected 
| 15–34 | 🔵 **LOW**      | Minor concerns, likely safe 
| 35–59 | ⚠️ **MEDIUM**   | Suspicious — proceed with caution 
| 60–79 | 🔴 **HIGH**     | Likely phishing — do not interact 
| 80–100| 💀 **CRITICAL** | Confirmed phishing/malware 

---

## 📁 File Structure

```
phishguard-ai/
├── ai_detect.py      ← Main tool (all logic in one file)
├── install.sh        ← Installer (Linux + Termux)
├── README.md         ← This file
└── LICENSE           ← MIT License
```

Data stored at runtime:
```
~/.ai-detect/
├── config.json       ← API key & settings (chmod 600)
└── history.json      ← Scan history (up to 500 entries)
```

---

## 🆓 Gemini Free Tier

| Metric | Limit |
|--------|-------|
| Requests per day | **1,500** |
| Requests per minute | 15 |
| Tokens per minute | 1,000,000 |
| Cost | **$0.00** |

Get your free key: [aistudio.google.com/app/apikey](https://aistudio.google.com/app/apikey)

---

## Contributing

Contributions are welcome!

```bash
# 1. Fork the repo
# 2. Create a branch
git checkout -b feature/new-scanner

# 3. Make changes
# 4. Test
python3 -m py_compile ai_detect.py
bash -n install.sh

# 5. Commit
git commit -m "feat: add new scanner type"

# 6. Push & PR
git push origin feature/new-scanner
```

**Ideas for contribution:**
- New scanner types (PDF, Office docs, QR codes)
- Additional AI models support
- Output formats (JSON, CSV export)
- More banner styles
- Windows compatibility

---

## Security & Privacy

- API key is **never logged** or transmitted except to Google Gemini
- API key input is **hidden** (uses `getpass`)
- Config file has **restricted permissions** (`chmod 600`)
- **Tor routing** hides your IP from Google's servers
- Scan content is sent to Google Gemini — do not scan **highly confidential** data

---

## Troubleshooting

**`ai-detect: command not found`**
```bash
source ~/.bashrc    # Termux
# or
export PATH="$PATH:/usr/local/bin"
```

**`Invalid API key (HTTP 400)`**
```bash
# Get a fresh key from:
# https://aistudio.google.com/app/apikey
# Then: ai-detect → [9] Settings → [1] Change API Key
```

**`Tor failed to start`**
```bash
# Check Tor is installed
which tor

# Start manually
sudo systemctl start tor    # Linux
tor &                        # Termux

# Or disable Tor
ai-detect --no-tor
```

**`Rate limit (HTTP 429)`**
```bash
# Wait 60 seconds between scans
# Gemini free tier: 15 requests/minute
```

---

## License

```
MIT License — Copyright (c) 2026 PhishGuard AI by Zeeshan Ali
```

See [LICENSE](LICENSE) for full text.

---

<div align="center">

**Made with ❤️ | Powered by Ai | Built for Security**

[⭐ Star this repo](https://github.com/YOUR-USERNAME/phishguard-ai) · [🐛 Report Bug](https://github.com/YOUR-USERNAME/phishguard-ai/issues) · [💡 Request Feature](https://github.com/YOUR-USERNAME/phishguard-ai/issues)

</div>
