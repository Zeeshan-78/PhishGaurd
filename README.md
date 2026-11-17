<div align="center">

# 🔰 PhishGuard AI — `ai-detect`

**Phishing, malware and website-vulnerability scanner for the terminal.**
Paste an API key — the provider and model are detected automatically.

![Python](https://img.shields.io/badge/python-3.7%2B-blue)
![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20Kali%20%7C%20Termux-green)
![License](https://img.shields.io/badge/license-MIT-yellow)
![Version](https://img.shields.io/badge/version-3.1.0-orange)

</div>

---

## Why it's different

- **One input: your API key.** Gemini, OpenAI, Claude, Groq, OpenRouter, xAI, DeepSeek, Mistral, Together, Cerebras, Ollama or any OpenAI-compatible endpoint. The tool identifies the provider, lists the models your key can use, **verifies each candidate with a real call**, and picks the best working one. Models get retired (e.g. `gemini-1.5-flash`) — if the saved model ever returns 404, it re-detects and heals itself.
- **Works without AI too.** Every scan first runs offline checks (listed below). The AI adds judgement on top; if the AI is unreachable you still get a full local report.
- **Real website scanning**, not just a URL string check: one passive `GET`, TLS certificate check, security headers, cookie flags, forms, hidden iframes, obfuscated scripts, redirects.
- **Fast.** Menu opens in ~0.2 s. Tor is optional and starts in the background — it never blocks the UI.
- **Safe by design.** Your key is sent in a header (never in a URL), redacted from every error message, stored with `chmod 600`. Scanned content is treated as untrusted data (prompt-injection hardened).

## Install

```bash
git clone https://github.com/Zeeshan-78/PhishGaurd.git
cd PhishGaurd
bash install.sh            # add --with-tor for optional Tor
ai-detect
```

Works on Debian/Ubuntu/Kali/Arch/Fedora and Termux. Missing Python packages (`rich`, `pyfiglet`, `requests`) are installed automatically, including on PEP 668 systems (Kali/Debian 12+).
Uninstall: `bash install.sh --uninstall`

## First run

Run `ai-detect`, paste your key (input is hidden). Example:

```
✅ Detected!
  Provider : Google Gemini
  Model    : gemini-2.5-flash
```

| Key looks like | Detected as |
|---|---|
| `AQ.…` or `AIza…` | Google Gemini (**`AQ.` is Google's newer, valid key format**) |
| `sk-ant-…` | Anthropic Claude |
| `sk-proj-…` | OpenAI |
| `sk-…` (other) | OpenAI or DeepSeek (resolved automatically) |
| `gsk_…` | Groq |
| `sk-or-…` / `xai-…` / `csk-…` | OpenRouter / xAI / Cerebras |
| `o` | Ollama (local, no key) |
| `c` | Custom OpenAI-compatible endpoint |
| `l` | Local checks only (no AI) |

Free keys: [Gemini](https://aistudio.google.com/app/apikey) · [Groq](https://console.groq.com/keys)

## Usage

```bash
ai-detect                                  # interactive menu
ai-detect url example.com                  # website scan
ai-detect message "You won! Send your OTP"
ai-detect email suspicious.eml
ai-detect code payload.js
ai-detect apk AndroidManifest.xml
ai-detect file macro.ps1
cat mail.txt | ai-detect email -           # from stdin
ai-detect url example.com --json           # machine-readable
ai-detect url example.com --no-ai          # local checks only
ai-detect url example.com --tor            # route through Tor
ai-detect setup | models | history | reset
```

Exit code: `0` low risk · `1` medium · `2` high/critical — handy in scripts and CI.

In the interactive menu you can paste text **or type a file path** as the first line. Finish a paste with two empty lines.

## What it checks (offline, no AI needed)

| Scanner | Checks |
|---|---|
| **URL / website** | typosquatting & look-alike characters (`paypa1`), brand-in-subdomain, punycode, `@` tricks, suspicious TLDs, shorteners, raw-IP hosts · TLS validity/expiry/protocol · HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, CORS · cookie `Secure`/`HttpOnly`/`SameSite` · server/`X-Powered-By` disclosure · login forms posting to another domain or over HTTP · hidden iframes, meta-refresh, `eval(atob())`, mixed content · redirect chains · brand-in-title with a password form |
| **Email / message** | display-name spoofing, Reply-To mismatch, OTP/PIN/CVV requests, urgency and prize lures, investment-fraud wording, APK-install requests, verify-account lures, embedded-URL analysis |
| **Code / file** | obfuscated `eval`, PowerShell `-enc`, pipe-to-shell, reverse shells, macro auto-exec, keyloggers, cookie access, miners, hardcoded secrets, large base64 blobs |
| **APK** | SMS read+send (OTP stealers), accessibility + overlay attacks, device-admin, install-packages, boot persistence, spyware combos, `debuggable`, cleartext traffic, hardcoded IPs |

Findings carry a severity; the score is the maximum of the AI score and the local score, and any phishing/malware-type HIGH/CRITICAL finding guarantees at least a HIGH level.

> **Large APKs:** extract first (`apktool d app.apk`) and scan `AndroidManifest.xml` — the manifest contains what matters (permissions, components).

## Tor (optional)

`ai-detect --tor` or menu → Tor. It starts in the background (`systemctl`/`service`, or a user-mode `tor` if you have no root); scans use it automatically once it is ready, and fall back to a direct connection if it fails. With Tor on, DNS/TLS probes are skipped so nothing leaks around it. Identity rotation needs `ControlPort 9051` in `torrc`.

## Files

```
ai_detect.py   the tool (single file)        install.sh   installer / uninstaller
~/.ai-detect/config.json   provider, model, key (chmod 600)
~/.ai-detect/history.json  last 500 scans
```

Advanced: `AI_DETECT_BASE_URLS='{"openai":"https://my-proxy/v1"}'` overrides a provider's base URL (gateways/proxies).

## Troubleshooting

| Problem | Fix |
|---|---|
| `Key reject hui` | Re-copy the full key; create a new one. |
| Gemini `AQ.` key rejected with `ACCESS_TOKEN_TYPE_UNSUPPORTED` | Some accounts can't use `AQ.` keys on the REST API yet — regenerate the key in AI Studio or create an `AIza…` key in Google Cloud Console. |
| `429` / quota | Free-tier limit; wait a minute or switch provider (`ai-detect setup`). |
| Model 404 | Handled automatically (re-detect). Manual: Settings → *Model re-detect*. |
| Termux `command not found` | `export PATH="$PREFIX/bin:$PATH"` |

## Responsible use & privacy

- Scan only sites you own or are authorised to test. The scanner sends one ordinary `GET` request and nothing intrusive.
- Content you scan is sent to the AI provider you configured (not to us). Don't scan secrets you can't share; use `--no-ai` or Ollama for fully local analysis.
- Results are heuristics + AI judgement: treat them as strong signals, not proof.

## Development & testing

The test-suite (not shipped) drives the real binary against local mock servers that emulate the Gemini, OpenAI, DeepSeek, Anthropic and Groq APIs (including retired models, parameter rejection, rate limits and bad keys) and a deliberately vulnerable website, plus a pseudo-terminal run of every menu option. Live provider endpoints depend on your own key and network.

## License

MIT — see [LICENSE](LICENSE).
