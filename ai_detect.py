#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# ================================================================
#   PhishGuard AI — CLI Phishing Detection Tool
#   Author  : Zeeshan Ali
#   Version : 1.0
#   Command : ai-detect
#   Compat  : Linux (Debian/Ubuntu/Kali/Arch) | Termux (Android)
#   Python  : 3.7+
#   License : MIT
# ================================================================

import sys
import os
import subprocess

# ── Python version guard ─────────────────────────────────────────
if sys.version_info < (3, 7):
    sys.exit('[!] Python 3.7+ required. Current: ' + sys.version)

# ════════════════════════════════════════════════════════════════
#  SECTION 1 — BOOTSTRAP
#  Critical packages missing hone pe automatically install karo
# ════════════════════════════════════════════════════════════════

_REQUIRED = {'rich': 'rich', 'pyfiglet': 'pyfiglet', 'requests': 'requests'}
_SOCKS    = 'requests[socks]'

def _pip(pkg: str) -> bool:
    """Silently install a pip package. Returns True on success."""
    try:
        subprocess.check_call(
            [sys.executable, '-m', 'pip', 'install', pkg, '-q'],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        return True
    except Exception:
        return False

def _bootstrap():
    missing = [pkg for imp, pkg in _REQUIRED.items()
               if not __import__('importlib').util.find_spec(imp)]

    if missing:
        print('\n\033[93m[*] Installing required packages...\033[0m')
        for pkg in missing:
            print(f'    \033[36m→ {pkg}...\033[0m', end='', flush=True)
            ok = _pip(pkg)
            print(' \033[92m✓\033[0m' if ok else ' \033[91m✗ FAILED\033[0m')
            if not ok:
                print(f'\033[91m[!] Cannot install {pkg}. Run: pip install {pkg}\033[0m')
                sys.exit(1)

    # Socks support for Tor (optional)
    if not __import__('importlib').util.find_spec('socks'):
        _pip(_SOCKS)   # failure OK — Tor is optional

_bootstrap()

# ════════════════════════════════════════════════════════════════
#  SECTION 2 — IMPORTS
# ════════════════════════════════════════════════════════════════

import re
import json
import time
import random
import socket
import signal
import argparse
import getpass
from pathlib import Path
from datetime import datetime

import requests
import pyfiglet
from rich.console import Console
from rich.panel   import Panel
from rich.table   import Table
from rich.text    import Text
from rich.prompt  import Prompt, Confirm
from rich.align   import Align
from rich.rule    import Rule
from rich         import box

# ════════════════════════════════════════════════════════════════
#  SECTION 3 — CONSTANTS
# ════════════════════════════════════════════════════════════════

VERSION      = '2.1.0'
TOOL_NAME    = 'PhishGuard AI'
CONFIG_DIR   = Path.home() / '.ai-detect'
CONFIG_FILE  = CONFIG_DIR / 'config.json'
HISTORY_FILE = CONFIG_DIR / 'history.json'

GEMINI_URL = (
    'https://generativelanguage.googleapis.com/v1beta/'
    'models/gemini-1.5-flash:generateContent'
)
TOR_PROXY = {
    'http':  'socks5h://127.0.0.1:9050',
    'https': 'socks5h://127.0.0.1:9050',
}

console = Console()

# ════════════════════════════════════════════════════════════════
#  SECTION 4 — SIGNAL HANDLER
#  FIX: Ctrl+C inside any input() now exits cleanly
# ════════════════════════════════════════════════════════════════

def _sigint_handler(sig, frame):
    console.print('\n\n  [dim]Interrupted. Goodbye! 🛡️[/dim]\n')
    sys.exit(0)

signal.signal(signal.SIGINT, _sigint_handler)

# ════════════════════════════════════════════════════════════════
#  SECTION 5 — BANNER SYSTEM (6 Random Banners)
# ════════════════════════════════════════════════════════════════

# Hardcoded ASCII fallback if pyfiglet completely fails
_FALLBACK_ART = r"""
  ██████╗ ██╗  ██╗██╗███████╗██╗  ██╗ ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗
  ██╔══██╗██║  ██║██║██╔════╝██║  ██║██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗
  ██████╔╝███████║██║███████╗███████║██║  ███╗██║   ██║███████║██████╔╝██║  ██║
  ██╔═══╝ ██╔══██║██║╚════██║██╔══██║██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║
  ██║     ██║  ██║██║███████║██║  ██║╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝
  ╚═╝     ╚═╝  ╚═╝╚═╝╚══════╝╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝
"""

BANNERS = [
    {'font': 'slant',   'text': 'PhishGuard', 'color': 'bold cyan',
     'sub': '[ AI-Powered Phishing Detection ]',       'sub_color': 'cyan'},
    {'font': 'doom',    'text': 'AI-DETECT',  'color': 'bold magenta',
     'sub': '◈  Scan Everything. Trust Nothing.  ◈',   'sub_color': 'magenta'},
    {'font': 'banner3', 'text': 'PHISHGUARD', 'color': 'bold green',
     'sub': '━━━  Cyber Threat Intelligence  ━━━',      'sub_color': 'green'},
    {'font': 'epic',    'text': 'AI DETECT',  'color': 'bold yellow',
     'sub': '⚡  Powered by Google Gemini  ⚡',          'sub_color': 'yellow'},
    {'font': 'digital', 'text': 'PHISHGUARD', 'color': 'bold red',
     'sub': '◀  Professional Phishing Scanner  ▶',      'sub_color': 'red'},
    {'font': 'shadow',  'text': 'AI-DETECT',  'color': 'bold blue',
     'sub': '▸  Linux  |  Termux  |  Tor Ready  ◂',    'sub_color': 'blue'},
]

def _make_art(b: dict) -> str:
    """FIX: Triple-layer fallback so banner NEVER crashes."""
    for font in (b['font'], 'standard', 'banner'):
        try:
            art = pyfiglet.figlet_format(b['text'], font=font, width=82)
            if art.strip():
                return art
        except Exception:
            continue
    return _FALLBACK_ART  # ultimate hardcoded fallback

def show_banner(tor_active: bool = False, scan_count: int = 0):
    os.system('clear' if os.name != 'nt' else 'cls')
    b = random.choice(BANNERS)

    console.print(Align.center(Text(_make_art(b), style=b['color'])))
    console.print(Align.center(Text(b['sub'], style=b['sub_color'])))
    console.print()

    tor_str   = '[bold green]● TOR ON[/bold green]' if tor_active \
                else '[bold red]○ TOR OFF[/bold red]'
    scan_str  = f'[dim]Scans: {scan_count}[/dim]' if scan_count else ''
    sep       = '  │  ' if scan_count else ''

    info = (f'[bold white]v{VERSION}[/bold white]  │  '
            f'[cyan]🤖 Gemini 1.5 Flash[/cyan]  │  '
            f'{tor_str}  │  '
            f'[dim]{datetime.now().strftime("%Y-%m-%d %H:%M")}[/dim]'
            f'{sep}{scan_str}')
    console.print(Align.center(info))
    console.print(Rule(style='dim'))

# ════════════════════════════════════════════════════════════════
#  SECTION 6 — CONFIG MANAGER
# ════════════════════════════════════════════════════════════════

def ensure_config_dir():
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    try:
        CONFIG_DIR.chmod(0o700)
    except OSError:
        pass   # Termux may not support chmod

def load_config() -> dict:
    ensure_config_dir()
    if CONFIG_FILE.exists():
        try:
            return json.loads(CONFIG_FILE.read_text(encoding='utf-8'))
        except Exception:
            pass
    return {}

def save_config(cfg: dict):
    ensure_config_dir()
    CONFIG_FILE.write_text(json.dumps(cfg, indent=2, ensure_ascii=False),
                           encoding='utf-8')
    try:
        CONFIG_FILE.chmod(0o600)
    except OSError:
        pass

def get_api_key(cfg: dict) -> str:
    return cfg.get('gemini_api_key', '') or os.environ.get('GEMINI_API_KEY', '')

# ════════════════════════════════════════════════════════════════
#  SECTION 7 — TOR MANAGER
# ════════════════════════════════════════════════════════════════

def _is_termux() -> bool:
    return (
        'com.termux' in os.environ.get('PREFIX', '')
        or os.path.isdir('/data/data/com.termux')
        or 'TERMUX_VERSION' in os.environ
    )

def _run_cmd(cmd: list, timeout: int = 10) -> bool:
    try:
        return subprocess.run(
            cmd, capture_output=True, timeout=timeout
        ).returncode == 0
    except Exception:
        return False

def check_tor() -> bool:
    """Check if Tor SOCKS5 port is open."""
    try:
        s = socket.create_connection(('127.0.0.1', 9050), timeout=3)
        s.close()
        return True
    except Exception:
        return False

def get_ip(use_tor: bool = False) -> str:
    try:
        proxies = TOR_PROXY if use_tor else None
        r = requests.get('https://api.ipify.org?format=json',
                         proxies=proxies, timeout=10)
        return r.json().get('ip', '?')
    except Exception:
        return 'Unknown'

def start_tor(cfg: dict) -> bool:
    """Start Tor daemon and wait for it to be ready."""
    if check_tor():
        return True
    if cfg.get('skip_tor'):
        return False

    with console.status('[bold yellow]🧅 Starting Tor daemon...', spinner='dots'):
        if _is_termux():
            os.system('tor > /dev/null 2>&1 &')
        else:
            if not _run_cmd(['which', 'tor']):
                return False
            # FIX: Try systemctl first (modern Linux), then service (legacy)
            started = False
            if os.geteuid() == 0:
                started = (_run_cmd(['systemctl', 'start', 'tor'])
                           or _run_cmd(['service', 'tor', 'start']))
            else:
                started = (_run_cmd(['sudo', '-n', 'systemctl', 'start', 'tor'])
                           or _run_cmd(['sudo', '-n', 'service', 'tor', 'start']))
            if not started:
                return False

        for _ in range(20):
            time.sleep(1)
            if check_tor():
                return True

    return False

def rotate_tor_identity() -> bool:
    """
    FIX: Proper Tor control protocol.
    Commands must be sent one-by-one with response reads.
    """
    try:
        # FIX: Added timeout so socket never hangs
        s = socket.create_connection(('127.0.0.1', 9051), timeout=5)
        s.settimeout(5)

        def _send(cmd: str) -> str:
            s.sendall((cmd + '\r\n').encode())
            return s.recv(1024).decode(errors='ignore')

        auth_resp = _send('AUTHENTICATE ""')
        if '250' not in auth_resp:
            s.close()
            return False

        newnym_resp = _send('SIGNAL NEWNYM')
        s.sendall(b'QUIT\r\n')
        s.close()

        return '250' in newnym_resp

    except Exception:
        return False

# ════════════════════════════════════════════════════════════════
#  SECTION 8 — GEMINI SCANNER
# ════════════════════════════════════════════════════════════════

SCAN_TYPES = {
    '1': ('url',     '🌐', 'URL / Website'),
    '2': ('email',   '📧', 'Email'),
    '3': ('code',    '💻', 'Code / Script'),
    '4': ('apk',     '📱', 'APK / App'),
    '5': ('file',    '📂', 'File Content'),
    '6': ('message', '💬', 'Message / SMS'),
}

_BASE_JSON = '''{
  "threatScore": <0-100>,
  "riskLevel": "<SAFE|LOW|MEDIUM|HIGH|CRITICAL>",
  "summary": "<2-3 sentence summary>",
  "isPhishing": <true|false>,
  "confidence": <0-100>,
  "findings": [
    {"severity":"<CRITICAL|HIGH|MEDIUM|LOW|INFO>","title":"<title>","description":"<detail>"}
  ],
  "indicators": {
    "urlManipulation":"<FOUND|NOT_FOUND|N/A>",
    "urgencyTactics":"<FOUND|NOT_FOUND|N/A>",
    "impersonation":"<FOUND|NOT_FOUND|N/A>",
    "credentialHarvesting":"<FOUND|NOT_FOUND|N/A>",
    "maliciousCode":"<FOUND|NOT_FOUND|N/A>",
    "dataExfiltration":"<FOUND|NOT_FOUND|N/A>",
    "suspiciousPermissions":"<FOUND|NOT_FOUND|N/A>"
  },
  "recommendations": ["<action 1>","<action 2>","<action 3>"]
}'''

_TYPE_PROMPTS = {
    'url': (
        'Analyze this URL/Website for: typosquatting (paypa1, g00gle), '
        'suspicious TLDs (.tk .xyz .ml .ga .cf), IP address instead of domain, '
        'homograph attacks, URL shorteners, HTTP login pages, '
        'brand-in-subdomain tricks, excessive subdomains.'
    ),
    'email': (
        'Analyze this Email for: spoofed/mismatched sender address, '
        'generic greetings (Dear Customer), urgency/fear language (suspended/24h), '
        'credential/OTP/PIN requests, grammar mistakes, fake invoices, '
        'impersonation of banks, PayPal, Google, Microsoft, government.'
    ),
    'code': (
        'Analyze this Code for: eval() with encoded/base64 strings, '
        'hidden iframes (display:none), form action to external domain, '
        'fetch/XHR exfiltrating credentials, keylogger patterns, '
        'String.fromCharCode obfuscation, atob()+eval(), cookie stealing, '
        'script injection from suspicious CDN.'
    ),
    'apk': (
        'Analyze this APK/App for: READ_SMS+SEND_SMS combination (OTP stealer), '
        'REQUEST_INSTALL_PACKAGES (dropper), SYSTEM_ALERT_WINDOW+BIND_ACCESSIBILITY_SERVICE '
        '(overlay attack), DEVICE_ADMIN (ransomware), RECEIVE_BOOT_COMPLETED (persistence), '
        'hardcoded C2 URLs, unofficial distribution source (WhatsApp/Telegram link).'
    ),
    'file': (
        'Analyze this File for: embedded phishing URLs, credential harvesting forms, '
        'eval() or base64 payloads, macro indicators (Auto_Open, Document_Open), '
        'PowerShell encoded commands (-EncodedCommand), C2 server addresses/IPs, '
        'social engineering text, obfuscated shell commands.'
    ),
    'message': (
        'Analyze this Message for: prize/lottery/lucky draw claims, '
        'bank/government impersonation (SBP, HBL, Meezan, FBR, NADRA), '
        'OTP/PIN/password requests, URL shorteners (bit.ly, wa.me), '
        'urgency/threat language (blocked/arrest/FIR/expire), '
        'investment fraud (guaranteed returns), install-app-via-link requests, '
        'advance fee fraud patterns.'
    ),
}

def build_prompt(scan_type: str, content: str) -> str:
    instruction = _TYPE_PROMPTS.get(scan_type, _TYPE_PROMPTS['url'])
    return (
        f'You are PhishGuard AI, expert cybersecurity phishing detector.\n'
        f'{instruction}\n\n'
        f'CONTENT TO ANALYZE:\n{content[:12000]}\n\n'
        f'Reply ONLY as valid JSON — zero extra text, no markdown fences:\n'
        f'{_BASE_JSON}'
    )

def call_gemini(api_key: str, prompt: str, use_tor: bool = False) -> dict:
    payload = {
        'contents': [{'parts': [{'text': prompt}]}],
        'generationConfig': {
            'temperature': 0.1,
            'maxOutputTokens': 1200,
            'responseMimeType': 'application/json',
        },
        'safetySettings': [
            {'category': c, 'threshold': 'BLOCK_NONE'}
            for c in [
                'HARM_CATEGORY_HARASSMENT',
                'HARM_CATEGORY_HATE_SPEECH',
                'HARM_CATEGORY_SEXUALLY_EXPLICIT',
                'HARM_CATEGORY_DANGEROUS_CONTENT',
            ]
        ],
    }

    r = requests.post(
        f'{GEMINI_URL}?key={api_key}',
        json=payload,
        proxies=(TOR_PROXY if use_tor else None),
        timeout=35,
    )
    r.raise_for_status()
    data = r.json()

    if data.get('promptFeedback', {}).get('blockReason'):
        return {'error': 'Gemini safety block: ' + data['promptFeedback']['blockReason']}

    candidate = (data.get('candidates') or [{}])[0]
    if candidate.get('finishReason') == 'SAFETY':
        return {'error': 'Gemini safety filter triggered. Try reducing content size.'}

    raw = (candidate.get('content', {})
                    .get('parts', [{}])[0]
                    .get('text', ''))
    if not raw:
        return {'error': 'Empty response from Gemini. Please retry.'}

    # FIX: import re at top level — parse JSON cleanly
    cleaned = raw.replace('```json', '').replace('```', '').strip()
    try:
        return json.loads(cleaned)
    except json.JSONDecodeError:
        m = re.search(r'\{[\s\S]*\}', cleaned)
        if m:
            try:
                return json.loads(m.group())
            except json.JSONDecodeError:
                pass
    return {'error': 'Could not parse Gemini JSON response.', '_raw': raw[:500]}

# ════════════════════════════════════════════════════════════════
#  SECTION 9 — RESULTS DISPLAY
# ════════════════════════════════════════════════════════════════

_LEVEL_CFG = {
    'SAFE':     ('green',    '✅', '0–14  → No threat'),
    'LOW':      ('cyan',     '🔵', '15–34 → Minor concerns'),
    'MEDIUM':   ('yellow',   '⚠️ ', '35–59 → Suspicious'),
    'HIGH':     ('red',      '🔴', '60–79 → Likely phishing'),
    'CRITICAL': ('bold red', '💀', '80–100→ Confirmed threat'),
}
_SEV_STYLE = {
    'CRITICAL': 'bold red',
    'HIGH':     'red',
    'MEDIUM':   'yellow',
    'LOW':      'green',
    'INFO':     'cyan',
}
_IND_LABELS = {
    'urlManipulation':       '🔗 URL Manipulation',
    'urgencyTactics':        '   Urgency Tactics',
    'impersonation':         '🎭 Impersonation',
    'credentialHarvesting':  '🔑 Credential Harvesting',
    'maliciousCode':         '💀 Malicious Code',
    'dataExfiltration':      '   Data Exfiltration',
    'suspiciousPermissions': '📋 Suspicious Permissions',
}

def _bar(value: int, color: str, width: int = 28) -> str:
    filled = max(0, min(width, int(value / 100 * width)))
    return (f'[{color}]' + '█' * filled + '[/{color}]'
            + '[dim]' + '░' * (width - filled) + '[/dim]'
            + f' [bold]{value}/100[/bold]')

def display_result(result: dict, scan_type: str):
    if 'error' in result:
        console.print(Panel(
            f'[bold red]❌ Error:[/bold red]  {result["error"]}',
            title='[red]Scan Failed[/red]',
            border_style='red',
        ))
        return

    score      = max(0, min(100, int(result.get('threatScore', 0))))
    level      = result.get('riskLevel', 'MEDIUM')
    if level not in _LEVEL_CFG:
        level = 'MEDIUM'
    color, icon, _ = _LEVEL_CFG[level]
    phishing   = bool(result.get('isPhishing', False))
    confidence = max(0, min(100, int(result.get('confidence', 0))))
    summary    = result.get('summary', '').strip()
    scan_id    = datetime.now().strftime('%Y%m%d%H%M%S')

    console.print()
    console.print(Rule(f'[bold white]SCAN RESULTS  [dim]#{scan_id}[/dim][/bold white]',
                       style='dim'))

    # ── Score card ──
    card = (
        f'\n'
        f'  Threat Score  :  {_bar(score, color)}\n'
        f'  Confidence    :  {_bar(confidence, "cyan")}\n\n'
        f'  Risk Level    :  [{color}]{icon} {level}[/{color}]\n'
        f'  Phishing      :  '
        + ('[bold red]⚠️  YES — PHISHING DETECTED[/bold red]'
           if phishing else '[bold green]✅  NO[/bold green]')
        + f'\n'
        f'  Scan Type     :  [cyan]{scan_type.upper()}[/cyan]\n'
        f'  Timestamp     :  [dim]{datetime.now().strftime("%Y-%m-%d %H:%M:%S")}[/dim]\n'
    )
    console.print(Panel(card, title=f'[{color}]● {level} RISK[/{color}]',
                        border_style=color, padding=(0, 1)))

    # ── Summary ──
    if summary:
        console.print(Panel(summary,
                            title='[bold cyan]📋 Summary[/bold cyan]',
                            border_style='cyan'))

    # ── Indicators ──
    indicators = result.get('indicators', {})
    if indicators:
        tbl = Table(show_header=True, header_style='bold white',
                    box=box.SIMPLE_HEAVY, border_style='dim', pad_edge=False)
        tbl.add_column('Indicator', style='dim white', width=28)
        tbl.add_column('Status',    width=22)

        for key, label in _IND_LABELS.items():
            val = indicators.get(key, 'N/A')
            status = ('[bold red]⚠️  FOUND[/bold red]'  if val == 'FOUND'
                      else '[bold green]✅  CLEAN[/bold green]' if val == 'NOT_FOUND'
                      else '[dim]─  N/A[/dim]')
            tbl.add_row(label, status)

        console.print(Panel(tbl,
                            title='[bold yellow]🎯 Threat Indicators[/bold yellow]',
                            border_style='yellow'))

    # ── Findings ──
    findings = result.get('findings', [])
    if findings:
        tbl2 = Table(show_header=True, header_style='bold white',
                     box=box.SIMPLE_HEAVY, border_style='dim', pad_edge=False)
        tbl2.add_column('SEV',         width=10)
        tbl2.add_column('Title',       width=28)
        tbl2.add_column('Description', width=50)

        for f in findings:
            sev   = str(f.get('severity', 'INFO')).upper()
            style = _SEV_STYLE.get(sev, 'white')
            tbl2.add_row(
                f'[{style}]{sev}[/{style}]',
                f'[bold]{f.get("title", "")}[/bold]',
                f.get('description', ''),
            )
        console.print(Panel(tbl2,
                            title='[bold red]🔍 Detailed Findings[/bold red]',
                            border_style='red'))

    # ── Recommendations ──
    recs = result.get('recommendations', [])
    if recs:
        rec_txt = '\n'.join(f'  [{i+1}] {r}' for i, r in enumerate(recs))
        console.print(Panel(rec_txt,
                            title='[bold green]💡 Recommended Actions[/bold green]',
                            border_style='green'))

# ════════════════════════════════════════════════════════════════
#  SECTION 10 — HISTORY
# ════════════════════════════════════════════════════════════════

def _load_history() -> list:
    ensure_config_dir()
    if HISTORY_FILE.exists():
        try:
            return json.loads(
                HISTORY_FILE.read_text(encoding='utf-8')
            ).get('scans', [])
        except Exception:
            pass
    return []

def save_to_history(result: dict, scan_type: str, preview: str):
    if 'error' in result:
        return
    history = _load_history()
    # FIX: Use timestamp-based ID to avoid collisions after clear
    entry = {
        'id':        datetime.now().strftime('%Y%m%d%H%M%S%f'),
        'timestamp': datetime.now().isoformat(),
        'type':      scan_type,
        'preview':   (preview[:60] + '…') if len(preview) > 60 else preview,
        'score':     max(0, min(100, int(result.get('threatScore', 0)))),
        'level':     result.get('riskLevel', 'UNKNOWN'),
        'phishing':  bool(result.get('isPhishing', False)),
        'summary':   result.get('summary', '')[:150],
    }
    history.insert(0, entry)
    if len(history) > 500:
        history = history[:500]
    ensure_config_dir()
    HISTORY_FILE.write_text(
        json.dumps({'scans': history}, indent=2, ensure_ascii=False),
        encoding='utf-8',
    )

def show_history():
    history = _load_history()
    total   = len(history)

    if not history:
        console.print(Panel(
            '[yellow]No scans recorded yet. Run your first scan![/yellow]',
            title='📊 Scan History', border_style='yellow',
        ))
        return

    _CLRS = {'SAFE':'green','LOW':'cyan','MEDIUM':'yellow',
              'HIGH':'red','CRITICAL':'bold red'}

    tbl = Table(show_header=True, header_style='bold white',
                box=box.ROUNDED, border_style='dim')
    tbl.add_column('#',        width=5,  style='dim')
    tbl.add_column('Time',     width=17)
    tbl.add_column('Type',     width=10)
    tbl.add_column('Preview',  width=38)
    tbl.add_column('Score',    width=7)
    tbl.add_column('Level',    width=11)
    tbl.add_column('Phishing', width=9)

    threats = sum(1 for h in history if h.get('phishing'))

    for i, h in enumerate(history[:40], 1):
        c = _CLRS.get(h.get('level', ''), 'white')
        tbl.add_row(
            str(i),
            h.get('timestamp', '')[:16].replace('T', ' '),
            h.get('type', '').upper(),
            h.get('preview', ''),
            f'[{c}]{h.get("score", 0)}[/{c}]',
            f'[{c}]{h.get("level", "")}[/{c}]',
            '[red]⚠ YES[/red]' if h.get('phishing') else '[green]✅ NO[/green]',
        )

    console.print(Panel(tbl,
                        title='[bold cyan]📊 Scan History[/bold cyan]',
                        border_style='cyan'))
    console.print(
        f'  [dim]Total: {total} scans  |  '
        f'Threats: [bold red]{threats}[/bold red]  |  '
        f'Safe: [bold green]{total - threats}[/bold green][/dim]'
    )

def _get_history_stats() -> dict:
    history = _load_history()
    return {
        'total':    len(history),
        'threats':  sum(1 for h in history if h.get('phishing')),
        'safe':     sum(1 for h in history if not h.get('phishing')),
    }

def export_history():
    history = _load_history()
    if not history:
        console.print('  [yellow]No history to export.[/yellow]')
        return
    path = CONFIG_DIR / f'history_export_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json'
    path.write_text(json.dumps({'exported': datetime.now().isoformat(),
                                'scans': history}, indent=2, ensure_ascii=False),
                    encoding='utf-8')
    console.print(f'  [green]✓ Exported {len(history)} records to:[/green]')
    console.print(f'  [cyan]{path}[/cyan]')

def clear_history():
    if Confirm.ask('[yellow]  Clear ALL scan history?[/yellow]'):
        HISTORY_FILE.write_text(json.dumps({'scans': []}), encoding='utf-8')
        console.print('  [green]✓ History cleared.[/green]')

# ════════════════════════════════════════════════════════════════
#  SECTION 11 — INPUT COLLECTORS
# ════════════════════════════════════════════════════════════════

def _multiline(prompt_txt: str, hint: str = '') -> str:
    """Multi-line input until user types END on a new line."""
    console.print(f'\n  [cyan]{prompt_txt}[/cyan]')
    if hint:
        console.print(f'  [dim]{hint}[/dim]')
    console.print('  [dim](Type END on a new line to finish)[/dim]\n')
    lines = []
    try:
        while True:
            line = input('  > ')
            if line.strip().upper() == 'END':
                break
            lines.append(line)
    except (EOFError, KeyboardInterrupt):
        pass
    return '\n'.join(lines)

def collect_url() -> tuple:
    console.print(Panel(
        '[bold]URL / Website to scan[/bold]\n'
        '[dim]e.g. https://paypa1-login.xyz  or  secure.yourbank.update.evil.com[/dim]',
        border_style='cyan', padding=(0, 2),
    ))
    url  = Prompt.ask('\n  [cyan]→ URL[/cyan]').strip()
    html = _multiline('HTML Source (optional — better accuracy):',
                      'Paste page source or press END to skip')
    content = f'URL: {url}'
    if html.strip():
        content += f'\n\nHTML Source:\n{html}'
    return content, url or 'URL'

def collect_email() -> tuple:
    console.print(Panel('[bold]Email to scan[/bold]', border_style='cyan'))
    sender  = Prompt.ask('\n  [cyan]→ From[/cyan]', default='').strip()
    subject = Prompt.ask('  [cyan]→ Subject[/cyan]', default='').strip()
    body    = _multiline('Email Body:', 'Paste the full email text')
    parts = []
    if sender:  parts.append(f'From: {sender}')
    if subject: parts.append(f'Subject: {subject}')
    if body:    parts.append(body)
    return '\n\n'.join(parts), subject or sender or 'Email'

def collect_code() -> tuple:
    console.print(Panel('[bold]Code / Script to scan[/bold]', border_style='cyan'))
    lang    = Prompt.ask('\n  [cyan]→ Language[/cyan]', default='Unknown').strip()
    code    = _multiline(f'{lang} code:')
    content = f'Language: {lang}\n\n{code}'
    return content, f'{lang} script'

def collect_apk() -> tuple:
    console.print(Panel(
        '[bold]APK / App Scanner[/bold]\n'
        '[dim]Paste AndroidManifest.xml, permission list, or extracted smali code[/dim]',
        border_style='cyan',
    ))
    name  = Prompt.ask('\n  [cyan]→ App Name / Source[/cyan]',
                       default='Unknown APK').strip()
    perms = _multiline('Permissions (one per line):',
                       'e.g.  READ_SMS   SEND_SMS   DEVICE_ADMIN')
    mani  = _multiline('AndroidManifest.xml or code content:')
    parts = [f'App: {name}']
    if perms.strip(): parts.append(f'Permissions:\n{perms}')
    if mani.strip():  parts.append(f'Manifest/Code:\n{mani}')
    return '\n\n'.join(parts), name

def collect_file() -> tuple:
    console.print(Panel(
        '[bold]File Scanner[/bold]\n'
        '[dim]Provide a file path OR paste content directly[/dim]',
        border_style='cyan',
    ))
    choice = Prompt.ask('\n  [cyan]→ [1] File path  [2] Paste content[/cyan]',
                        choices=['1', '2'])

    if choice == '1':
        raw_path = Prompt.ask('  [cyan]→ Path[/cyan]').strip()
        try:
            fp = Path(raw_path).expanduser().resolve()
            # FIX: separate error types
            if not fp.exists():
                raise FileNotFoundError(f'File not found: {fp}')
            if not fp.is_file():
                raise IsADirectoryError(f'Path is a directory: {fp}')
            size = fp.stat().st_size
            if size > 500_000:
                console.print(f'  [yellow]⚠ File is {size//1024}KB — using first 500KB[/yellow]')
            content = fp.read_text(errors='ignore', encoding='utf-8')[:500_000]
            return content, fp.name
        except FileNotFoundError as e:
            console.print(f'  [red]✗ {e}[/red]')
        except PermissionError:
            console.print('  [red]✗ Permission denied — cannot read file[/red]')
        except IsADirectoryError as e:
            console.print(f'  [red]✗ {e}[/red]')
        except Exception as e:
            console.print(f'  [red]✗ Error reading file: {e}[/red]')
        return '', ''

    content = _multiline('Paste file content:')
    return content, 'Pasted content'

def collect_message() -> tuple:
    console.print(Panel('[bold]Message / SMS / Chat to scan[/bold]',
                        border_style='cyan'))
    platform = Prompt.ask('\n  [cyan]→ Platform[/cyan]',
                          default='Unknown').strip()
    text     = _multiline('Message text:')
    content  = f'Platform: {platform}\n\nMessage:\n{text}'
    return content, f'{platform} message'

_COLLECTORS = {
    'url':     collect_url,
    'email':   collect_email,
    'code':    collect_code,
    'apk':     collect_apk,
    'file':    collect_file,
    'message': collect_message,
}

# ════════════════════════════════════════════════════════════════
#  SECTION 12 — FIRST RUN SETUP
# ════════════════════════════════════════════════════════════════

def _test_key(api_key: str) -> bool:
    try:
        result = call_gemini(api_key,
                             'Reply ONLY valid JSON: {"status":"ok"}',
                             use_tor=False)
        return 'error' not in result
    except Exception:
        return False

def first_run_setup(cfg: dict) -> dict:
    os.system('clear' if os.name != 'nt' else 'cls')

    art = _make_art({'font': 'slant', 'text': 'PhishGuard',
                     'color': 'bold cyan', 'sub': '', 'sub_color': 'cyan'})
    console.print(Align.center(Text(art, style='bold cyan')))
    console.print(Align.center('[bold cyan][ First Time Setup ][/bold cyan]'))
    console.print(Rule(style='dim'))
    console.print()

    console.print(Panel(
        '[bold white]Welcome to PhishGuard AI! 🛡️[/bold white]\n\n'
        'Is tool ko Google Gemini API key chahiye (bilkul FREE).\n\n'
        '  [bold]Step 1:[/bold] Open → [cyan]https://aistudio.google.com/app/apikey[/cyan]\n'
        '  [bold]Step 2:[/bold] "Create API Key" click karo\n'
        '  [bold]Step 3:[/bold] Key copy karo (starts with AIzaSy...)\n'
        '  [bold]Step 4:[/bold] Neeche paste karo\n\n'
        '[dim]Key sirf ek baar maangi jayegi. ~/.ai-detect/config.json mein safely saved.[/dim]',
        title='[bold yellow]🔑 Gemini API Key Setup[/bold yellow]',
        border_style='yellow', padding=(1, 2),
    ))

    while True:
        # FIX: Use getpass to hide key while typing
        try:
            api_key = getpass.getpass('\n  → Gemini API Key (hidden): ').strip()
        except Exception:
            api_key = Prompt.ask('\n  [yellow]→ Gemini API Key[/yellow]').strip()

        if not api_key:
            console.print('  [red]✗ Empty. Try again.[/red]')
            continue
        if not api_key.startswith('AIza'):
            console.print('  [yellow]⚠ Key should start with "AIza..." — verify?[/yellow]')
            if not Confirm.ask('  Continue anyway?'):
                continue

        with console.status('[yellow]  🔑 Verifying with Gemini...', spinner='dots'):
            valid = _test_key(api_key)

        if valid:
            console.print('  [bold green]✓ API Key verified![/bold green]')
        else:
            console.print('  [yellow]⚠ Could not verify — saving anyway (check your key)[/yellow]')

        cfg.update({
            'gemini_api_key': api_key,
            'first_run_done': True,
            'setup_date':     datetime.now().isoformat(),
            'skip_tor':       False,
        })
        save_config(cfg)

        masked = api_key[:8] + '*' * 20
        console.print(Panel(
            f'[bold green]✅ Setup Complete![/bold green]\n\n'
            f'  API Key  :  [cyan]{masked}[/cyan]\n'
            f'  Config   :  [dim]{CONFIG_FILE}[/dim]\n\n'
            '[dim]Press Enter to continue to main menu...[/dim]',
            border_style='green', padding=(1, 2),
        ))
        try:
            input()
        except (EOFError, KeyboardInterrupt):
            pass
        return cfg

# ════════════════════════════════════════════════════════════════
#  SECTION 13 — SETTINGS
# ════════════════════════════════════════════════════════════════

def show_settings(cfg: dict, tor_active: bool) -> tuple:
    """
    FIX: Returns (cfg, tor_active) tuple so caller can update tor status.
    """
    while True:
        key   = get_api_key(cfg)
        masked = (key[:8] + '*' * 20) if key else '[red]NOT SET[/red]'
        skip_tor = cfg.get('skip_tor', False)

        console.print()
        console.print(Panel(
            f'  [cyan]API Key     :[/cyan]  {masked}\n'
            f'  [cyan]Tor Status  :[/cyan]  {"[green]ACTIVE[/green]" if tor_active else "[red]INACTIVE[/red]"}\n'
            f'  [cyan]Skip Tor    :[/cyan]  {"[yellow]YES[/yellow]" if skip_tor else "[green]NO[/green]"}\n'
            f'  [cyan]Config      :[/cyan]  [dim]{CONFIG_FILE}[/dim]\n'
            f'  [cyan]History     :[/cyan]  [dim]{HISTORY_FILE}[/dim]\n'
            f'  [cyan]Version     :[/cyan]  [dim]{VERSION}[/dim]\n',
            title='[bold]⚙️  Settings[/bold]', border_style='dim',
        ))
        console.print(
            '  [cyan][1][/cyan]  🔑 Change API Key\n'
            '  [cyan][2][/cyan]  🧅 Toggle Tor routing\n'
            '  [cyan][3][/cyan]  🔄 Restart Tor\n'
            '  [cyan][4][/cyan]  📤 Export Scan History\n'
            '  [cyan][5][/cyan]  🗑️  Clear History\n'
            '  [cyan][6][/cyan]  💥 Reset ALL Settings\n'
            '  [cyan][0][/cyan]  ← Back\n'
        )

        choice = Prompt.ask('  [cyan]→ Choice[/cyan]',
                            choices=['0','1','2','3','4','5','6'])

        if choice == '0':
            break
        elif choice == '1':
            try:
                new_key = getpass.getpass('  → New API Key (hidden): ').strip()
            except Exception:
                new_key = Prompt.ask('  [yellow]→ New API Key[/yellow]').strip()
            if new_key:
                cfg['gemini_api_key'] = new_key
                save_config(cfg)
                console.print('  [green]✓ Key updated.[/green]')
        elif choice == '2':
            # FIX: Toggle and update tor_active so caller sees the change
            cfg['skip_tor'] = not skip_tor
            save_config(cfg)
            if cfg['skip_tor']:
                tor_active = False
                console.print('  [yellow]✓ Tor: DISABLED (direct connections)[/yellow]')
            else:
                console.print('  [cyan]✓ Tor: ENABLED — will start on next run[/cyan]')
        elif choice == '3':
            with console.status('[yellow]  Restarting Tor...', spinner='dots'):
                tor_active = start_tor(cfg)
            status = '[green]ACTIVE[/green]' if tor_active else '[red]FAILED[/red]'
            console.print(f'  Tor: {status}')
        elif choice == '4':
            export_history()
        elif choice == '5':
            clear_history()
        elif choice == '6':
            if Confirm.ask('[red]  Reset ALL settings? API key will be deleted![/red]'):
                save_config({})
                console.print('  [green]✓ Reset done. Restart to re-configure.[/green]')
                sys.exit(0)

    return cfg, tor_active

# ════════════════════════════════════════════════════════════════
#  SECTION 14 — MAIN MENU
# ════════════════════════════════════════════════════════════════

def show_menu(tor_active: bool, stats: dict):
    h_total   = stats.get('total', 0)
    h_threats = stats.get('threats', 0)
    footer = (f'  [dim]Session scans: {h_total}  │  '
              f'Threats: [red]{h_threats}[/red]  │  '
              f'Safe: [green]{h_total - h_threats}[/green][/dim]') if h_total else ''

    menu = (
        '  [bold white]SCAN TOOLS[/bold white]\n'
        '  [cyan][1][/cyan]  🌐  URL / Website Scanner\n'
        '  [cyan][2][/cyan]  📧  Email Scanner\n'
        '  [cyan][3][/cyan]  💻  Code / Script Scanner\n'
        '  [cyan][4][/cyan]  📱  APK / App Scanner\n'
        '  [cyan][5][/cyan]  📂  File Scanner\n'
        '  [cyan][6][/cyan]  💬  Message / SMS Scanner\n\n'
        '  [bold white]TOOLS[/bold white]\n'
        '  [cyan][7][/cyan]  📊  Scan History\n'
        '  [cyan][8][/cyan]  🧅  Rotate Tor Identity\n'
        '  [cyan][9][/cyan]  ⚙️   Settings\n'
        '  [cyan][0][/cyan]  🚪  Exit\n'
        + ('\n' + footer if footer else '')
    )
    console.print(Panel(
        menu,
        title='[bold cyan]🛡️  PhishGuard AI — Main Menu[/bold cyan]',
        border_style='cyan', padding=(0, 2),
    ))

# ════════════════════════════════════════════════════════════════
#  SECTION 15 — SCAN RUNNER
# ════════════════════════════════════════════════════════════════

def run_scan(scan_key: str, api_key: str,
             tor_active: bool, session_stats: dict) -> bool:
    """
    Returns updated tor_active (may change if Tor fallback needed).
    FIX: tor_active state now propagates back to main loop.
    """
    stype, icon, label = SCAN_TYPES[scan_key]

    console.print()
    console.print(Rule(f'[bold]{icon} {label} Scanner[/bold]', style='cyan'))

    collector = _COLLECTORS[stype]
    content, preview = collector()

    if not content or not content.strip():
        console.print('\n  [yellow]⚠ No content provided. Cancelled.[/yellow]')
        return tor_active

    via = 'Tor' if tor_active else 'Direct'
    console.print()

    with console.status(
        f'[bold cyan]  🤖 Gemini analyzing via {via}...[/bold cyan]',
        spinner='dots2',
    ):
        prompt = build_prompt(stype, content)
        try:
            result = call_gemini(api_key, prompt, use_tor=tor_active)

        except requests.ConnectionError:
            if tor_active:
                console.print(
                    '  [yellow]⚠ Tor connection failed — retrying directly...[/yellow]'
                )
                try:
                    result = call_gemini(api_key, prompt, use_tor=False)
                    tor_active = False   # FIX: update local state
                except Exception as e:
                    result = {'error': f'Direct fallback failed: {e}'}
            else:
                result = {'error': 'Connection error. Check internet connection.'}

        except requests.Timeout:
            result = {'error': 'Timeout (35s). Gemini is slow — retry in a moment.'}

        except requests.HTTPError as e:
            if e.response is not None and e.response.status_code == 400:
                result = {'error': 'Invalid API key or malformed request (HTTP 400).'}
            elif e.response is not None and e.response.status_code == 429:
                result = {'error': 'Rate limit reached (HTTP 429). Wait 60s and retry.'}
            else:
                result = {'error': f'HTTP error: {e}'}

        except Exception as e:
            result = {'error': f'Unexpected: {e}'}

    display_result(result, stype)
    save_to_history(result, stype, preview)

    if 'error' not in result:
        session_stats['total'] += 1
        if result.get('isPhishing'):
            session_stats['threats'] += 1
        else:
            session_stats['safe'] += 1

    console.print()
    try:
        input('  [Press Enter to return to menu] ')
    except (EOFError, KeyboardInterrupt):
        pass

    return tor_active  # FIX: return (possibly updated) state

# ════════════════════════════════════════════════════════════════
#  SECTION 16 — ENTRY POINT
# ════════════════════════════════════════════════════════════════

def main():
    # ── CLI arguments ────────────────────────────────────────────
    parser = argparse.ArgumentParser(
        prog='ai-detect',
        description='PhishGuard AI — CLI Phishing Detection Tool',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            'Examples:\n'
            '  ai-detect              # Interactive mode\n'
            '  ai-detect --no-tor     # Skip Tor\n'
            '  ai-detect --version    # Show version\n'
        ),
    )
    parser.add_argument('--version',  action='version',
                        version=f'%(prog)s {VERSION}')
    parser.add_argument('--no-tor',   action='store_true',
                        help='Skip Tor and connect directly')
    args = parser.parse_args()

    # ── Load config ──────────────────────────────────────────────
    cfg = load_config()

    if args.no_tor:
        cfg['skip_tor'] = True

    # ── First run ────────────────────────────────────────────────
    if not cfg.get('first_run_done') or not get_api_key(cfg):
        cfg = first_run_setup(cfg)

    api_key = get_api_key(cfg)

    # ── Start Tor ────────────────────────────────────────────────
    tor_active = False
    if not cfg.get('skip_tor'):
        tor_active = start_tor(cfg)

    # ── Session stats ────────────────────────────────────────────
    session_stats = {'total': 0, 'threats': 0, 'safe': 0}

    # ── Main loop ────────────────────────────────────────────────
    while True:
        try:
            show_banner(tor_active, session_stats['total'])
            show_menu(tor_active, session_stats)

            choice = Prompt.ask(
                '\n  [bold cyan]→ Enter choice[/bold cyan]',
                choices=['0','1','2','3','4','5','6','7','8','9'],
            )

            if choice == '0':
                console.print('\n  [dim]Goodbye! Stay safe online. 🛡️[/dim]\n')
                sys.exit(0)

            elif choice in SCAN_TYPES:
                # FIX: capture returned tor_active so fallback propagates
                tor_active = run_scan(
                    choice, api_key, tor_active, session_stats
                )

            elif choice == '7':
                show_banner(tor_active, session_stats['total'])
                show_history()
                try:
                    input('\n  [Press Enter to return] ')
                except (EOFError, KeyboardInterrupt):
                    pass

            elif choice == '8':
                console.print()
                ok = rotate_tor_identity()
                if ok:
                    time.sleep(2)
                    new_ip = get_ip(use_tor=check_tor())
                    console.print(f'  [green]✓ Tor identity rotated[/green]')
                    console.print(f'  [cyan]  New IP: {new_ip}[/cyan]')
                else:
                    console.print(
                        '  [yellow]⚠ Could not rotate Tor identity.[/yellow]\n'
                        '  [dim]  Tip: add "ControlPort 9051" to /etc/tor/torrc[/dim]'
                    )
                try:
                    input('\n  [Press Enter] ')
                except (EOFError, KeyboardInterrupt):
                    pass

            elif choice == '9':
                show_banner(tor_active, session_stats['total'])
                # FIX: unpack (cfg, tor_active) tuple
                cfg, tor_active = show_settings(cfg, tor_active)
                api_key = get_api_key(cfg)

        except KeyboardInterrupt:
            console.print('\n\n  [dim]Ctrl+C — Exiting...[/dim]\n')
            sys.exit(0)
        except Exception as e:
            console.print(f'\n  [bold red]Unexpected error:[/bold red] {e}')
            try:
                input('  [Press Enter to continue] ')
            except (EOFError, KeyboardInterrupt):
                sys.exit(1)


if __name__ == '__main__':
    main()
