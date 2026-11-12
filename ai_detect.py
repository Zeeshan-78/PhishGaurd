#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# ================================================================
#   PhishGuard AI — CLI Phishing & Vulnerability Detection Tool
#   Version : 1.1
#   Author  : Zeeshan Ali
#   Command : ai-detect
#   Compat  : Linux | Termux | Kali | Python 3.7+
#   Models  : Gemini | OpenAI | Claude | Groq | Ollama | Custom
# ================================================================

import sys, os, subprocess

if sys.version_info < (3, 7):
    sys.exit('[!] Python 3.7+ required. Got: ' + sys.version)


#  SECTION 1 — BOOTSTRAP
#  ye bootstrap hai bhai jan main thing hai ye dehan sy check krna 

_REQUIRED = {'rich': 'rich', 'pyfiglet': 'pyfiglet', 'requests': 'requests'}

def _can_import(name):
    try:
        __import__(name)
        return True
    except ImportError:
        return False

def _pip(pkg):
    for flags in ([], ['--break-system-packages'], ['--user']):
        try:
            subprocess.check_call(
                [sys.executable, '-m', 'pip', 'install', pkg, '-q'] + flags,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return True
        except Exception:
            continue
    return False

def _bootstrap():
    missing = [p for k, p in _REQUIRED.items() if not _can_import(k)]
    if missing:
        print('\n\033[93m[*] Installing packages...\033[0m')
        for pkg in missing:
            print(f'    \033[36m→ {pkg}...\033[0m', end='', flush=True)
            print(' \033[92m✓\033[0m' if _pip(pkg) else ' \033[91m✗ FAILED\033[0m')
    if not _can_import('socks'):
        _pip('requests[socks]')

_bootstrap()


#  SECTION 2 — IMPORTS 
#  sari libarary file import hai bachoo 

import re, json, time, random, socket, signal, argparse, getpass, ssl
from pathlib import Path
from datetime import datetime
from urllib.parse import urlparse

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

requests.packages.urllib3.disable_warnings()  # SSL warning suppress


#  SECTION 3 — CONSTANTS & PROVIDER CONFIGS

VERSION      = '1.1'
CONFIG_DIR   = Path.home() / '.ai-detect'
CONFIG_FILE  = CONFIG_DIR / 'config.json'
HISTORY_FILE = CONFIG_DIR / 'history.json'
TOR_PROXY    = {'http': 'socks5h://127.0.0.1:9050', 'https': 'socks5h://127.0.0.1:9050'}

PROVIDERS = {
    '1': {
        'id': 'gemini', 'name': 'Google Gemini',
        'free': True,   'key_url': 'https://aistudio.google.com/app/apikey',
        'models': [
            ('gemini-1.5-flash',    'Fast + FREE (1500/day)'),
            ('gemini-1.5-pro',      'More capable'),
            ('gemini-2.0-flash-exp','Latest experimental'),
        ],
        'needs_key': True,
    },
    '2': {
        'id': 'openai', 'name': 'OpenAI GPT',
        'free': False,  'key_url': 'https://platform.openai.com/api-keys',
        'models': [
            ('gpt-4o-mini',    'Fast & cheap'),
            ('gpt-4o',         'Most capable'),
            ('gpt-3.5-turbo',  'Legacy fast'),
        ],
        'needs_key': True,
        'base_url': 'https://api.openai.com/v1',
    },
    '3': {
        'id': 'anthropic', 'name': 'Anthropic Claude',
        'free': False,     'key_url': 'https://console.anthropic.com/',
        'models': [
            ('claude-3-haiku-20240307',       'Fast & cheap'),
            ('claude-3-5-sonnet-20241022',    'Most capable'),
            ('claude-3-opus-20240229',        'Most powerful'),
        ],
        'needs_key': True,
    },
    '4': {
        'id': 'groq',  'name': 'Groq',
        'free': True,  'key_url': 'https://console.groq.com/keys',
        'models': [
            ('llama-3.1-8b-instant',      'Ultra fast + FREE'),
            ('llama-3.1-70b-versatile',   'Powerful + FREE'),
            ('mixtral-8x7b-32768',        'Long context + FREE'),
        ],
        'needs_key': True,
        'base_url': 'https://api.groq.com/openai/v1',
    },
    '5': {
        'id': 'ollama', 'name': 'Ollama (Local)',
        'free': True,   'key_url': None,
        'models': [
            ('llama3.2',   'Recommended'),
            ('mistral',    'Fast'),
            ('phi3',       'Small & light'),
            ('codellama',  'Code analysis'),
        ],
        'needs_key': False,
        'base_url': 'http://localhost:11434/v1',
    },
    '6': {
        'id': 'custom', 'name': 'Custom OpenAI-Compatible',
        'free': True,   'key_url': None,
        'models': [],
        'needs_key': False,
    },
}

SCAN_TYPES = {
    '1': ('url',     '🌐', 'URL / Website Vulnerability'),
    '2': ('email',   '📧', 'Email'),
    '3': ('code',    '💻', 'Code / Script'),
    '4': ('apk',     '📱', 'APK / App'),
    '5': ('file',    '📂', 'File Content'),
    '6': ('message', '💬', 'Message / SMS'),
}

console = Console()


#  SECTION 4 — SIGNAL HANDLER

def _sigint(sig, frame):
    console.print('\n\n  [dim]Interrupted. Bye! 🛡️[/dim]\n')
    sys.exit(0)
signal.signal(signal.SIGINT, _sigint)


#  SECTION 5 — BANNER SYSTEM
# ye sirf banner hai aur kuch 
# just a asci code jo kisi bhi ai sy bna skty hai

_FALLBACK = r"""
  ██████╗ ██╗  ██╗██╗███████╗██╗  ██╗ ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗
  ██╔══██╗██║  ██║██║██╔════╝██║  ██║██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗
  ██████╔╝███████║██║███████╗███████║██║  ███╗██║   ██║███████║██████╔╝██║  ██║
  ██╔═══╝ ██╔══██║██║╚════██║██╔══██║██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║
  ██║     ██║  ██║██║███████║██║  ██║╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝
  ╚═╝     ╚═╝  ╚═╝╚═╝╚══════╝╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝
"""
BANNERS = [
    {'font': 'slant',   'text': 'PhishGuard', 'color': 'bold cyan',    'sub': '[ AI Phishing & Vulnerability Detector ]', 'sc': 'cyan'},
    {'font': 'doom',    'text': 'AI-DETECT',  'color': 'bold magenta', 'sub': '◈  Scan Everything. Trust Nothing.  ◈',    'sc': 'magenta'},
    {'font': 'banner3', 'text': 'PHISHGUARD', 'color': 'bold green',   'sub': '━━━  Cyber Threat Intelligence  ━━━',       'sc': 'green'},
    {'font': 'epic',    'text': 'AI DETECT',  'color': 'bold yellow',  'sub': '⚡  Multi-LLM Security Scanner  ⚡',         'sc': 'yellow'},
    {'font': 'digital', 'text': 'PHISHGUARD', 'color': 'bold red',     'sub': '◀  Professional Security Scanner  ▶',       'sc': 'red'},
    {'font': 'shadow',  'text': 'AI-DETECT',  'color': 'bold blue',    'sub': '▸  Gemini | OpenAI | Claude | Groq  ◂',    'sc': 'blue'},
]

def _art(b):
    for f in (b['font'], 'standard', 'banner'):
        try:
            a = pyfiglet.figlet_format(b['text'], font=f, width=82)
            if a.strip(): return a
        except Exception: continue
    return _FALLBACK

def show_banner(tor_ok=False, provider='', model='', scans=0):
    os.system('clear' if os.name != 'nt' else 'cls')
    b = random.choice(BANNERS)
    console.print(Align.center(Text(_art(b), style=b['color'])))
    console.print(Align.center(Text(b['sub'], style=b['sc'])))
    console.print()
    tor_s  = '[bold green]● TOR ON[/bold green]' if tor_ok else '[bold red]○ TOR OFF[/bold red]'
    mdl_s  = f'[cyan]{provider}[/cyan] [dim]{model}[/dim]' if provider else '[dim]No model[/dim]'
    scn_s  = f'[dim]Scans: {scans}[/dim]' if scans else ''
    info   = (f'[bold white]v{VERSION}[/bold white]  │  🤖 {mdl_s}  │  '
              f'{tor_s}  │  [dim]{datetime.now().strftime("%H:%M")}[/dim]'
              + (f'  │  {scn_s}' if scn_s else ''))
    console.print(Align.center(info))
    console.print(Rule(style='dim'))


#  SECTION 6 — CONFIG MANAGER

def ensure_dir():
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    try: CONFIG_DIR.chmod(0o700)
    except: pass

def load_cfg():
    ensure_dir()
    if CONFIG_FILE.exists():
        try: return json.loads(CONFIG_FILE.read_text(encoding='utf-8'))
        except: pass
    return {}

def save_cfg(cfg):
    ensure_dir()
    CONFIG_FILE.write_text(json.dumps(cfg, indent=2, ensure_ascii=False), encoding='utf-8')
    try: CONFIG_FILE.chmod(0o600)
    except: pass

def get_provider_info(cfg):
    pid  = cfg.get('provider', 'gemini')
    name = next((v['name'] for v in PROVIDERS.values() if v['id'] == pid), pid)
    return pid, name, cfg.get('model', ''), cfg.get('api_key', ''), cfg.get('base_url', '')


#  SECTION 7 — TOR MANAGER

def _is_termux():
    return ('com.termux' in os.environ.get('PREFIX','') or
            os.path.isdir('/data/data/com.termux') or
            'TERMUX_VERSION' in os.environ)

def _run(cmd, t=10):
    try: return subprocess.run(cmd, capture_output=True, timeout=t).returncode == 0
    except: return False

def check_tor():
    try:
        s = socket.create_connection(('127.0.0.1', 9050), timeout=3)
        s.close(); return True
    except: return False

def start_tor(cfg):
    if check_tor(): return True
    if cfg.get('skip_tor'): return False
    with console.status('[yellow]🧅 Starting Tor...', spinner='dots'):
        if _is_termux():
            os.system('tor > /dev/null 2>&1 &')
        else:
            if not _run(['which', 'tor']): return False
            uid = os.geteuid() if hasattr(os, 'geteuid') else 1
            if uid == 0:
                _run(['systemctl','start','tor']) or _run(['service','tor','start'])
            else:
                _run(['sudo','-n','systemctl','start','tor']) or _run(['sudo','-n','service','tor','start'])
        for _ in range(20):
            time.sleep(1)
            if check_tor(): return True
    return False

def get_ip(use_tor=False):
    try:
        r = requests.get('https://api.ipify.org?format=json',
                         proxies=TOR_PROXY if use_tor else None, timeout=8)
        return r.json().get('ip', '?')
    except: return 'Unknown'

def rotate_tor():
    try:
        s = socket.create_connection(('127.0.0.1', 9051), timeout=5)
        s.settimeout(5)
        def send(cmd):
            s.sendall((cmd+'\r\n').encode())
            return s.recv(1024).decode(errors='ignore')
        ok = '250' in send('AUTHENTICATE ""')
        if ok: ok = '250' in send('SIGNAL NEWNYM')
        s.sendall(b'QUIT\r\n'); s.close()
        return ok
    except: return False

# ye hoi na bat issue reslove 
#  SECTION 8 — MULTI-LLM CALLER
#  ye code sary bry bry ai detect kr skta hai 
_DEFAULT_URLS = {
    'openai':    'https://api.openai.com/v1',
    'groq':      'https://api.groq.com/openai/v1',
    'ollama':    'http://localhost:11434/v1',
}

def _parse_json(raw):
    cleaned = raw.replace('```json','').replace('```','').strip()
    try: return json.loads(cleaned)
    except:
        m = re.search(r'\{[\s\S]*\}', cleaned)
        if m:
            try: return json.loads(m.group())
            except: pass
    return None

def _call_gemini(api_key, model, prompt, proxies):
    url = (f'https://generativelanguage.googleapis.com/v1beta/models/'
           f'{model}:generateContent?key={api_key}')
    payload = {
        'contents': [{'parts': [{'text': prompt}]}],
        'generationConfig': {'temperature': 0.1, 'maxOutputTokens': 1500,
                             'responseMimeType': 'application/json'},
        'safetySettings': [{'category': c, 'threshold': 'BLOCK_NONE'} for c in
                            ['HARM_CATEGORY_HARASSMENT','HARM_CATEGORY_HATE_SPEECH',
                             'HARM_CATEGORY_SEXUALLY_EXPLICIT','HARM_CATEGORY_DANGEROUS_CONTENT']],
    }
    r = requests.post(url, json=payload, proxies=proxies, timeout=35)
    r.raise_for_status()
    data = r.json()
    if data.get('promptFeedback', {}).get('blockReason'):
        return {'error': 'Gemini safety block: ' + data['promptFeedback']['blockReason']}
    cand = (data.get('candidates') or [{}])[0]
    if cand.get('finishReason') == 'SAFETY':
        return {'error': 'Gemini safety filter. Try shorter content.'}
    raw = cand.get('content', {}).get('parts', [{}])[0].get('text', '')
    if not raw: return {'error': 'Empty response from Gemini.'}
    return _parse_json(raw) or {'error': 'Could not parse JSON.', '_raw': raw[:300]}

def _call_openai_compat(api_key, model, base_url, prompt, proxies):
    headers = {'Content-Type': 'application/json'}
    if api_key: headers['Authorization'] = f'Bearer {api_key}'
    payload = {
        'model': model,
        'messages': [
            {'role': 'system', 'content': 'You are PhishGuard AI, expert cybersecurity analyst. Reply ONLY with valid JSON.'},
            {'role': 'user',   'content': prompt},
        ],
        'temperature': 0.1,
        'max_tokens': 1500,
    }
    url = base_url.rstrip('/') + '/chat/completions'
    r = requests.post(url, json=payload, headers=headers, proxies=proxies, timeout=35)
    r.raise_for_status()
    data = r.json()
    raw = data.get('choices', [{}])[0].get('message', {}).get('content', '')
    if not raw: return {'error': 'Empty response from model.'}
    return _parse_json(raw) or {'error': 'Could not parse JSON.', '_raw': raw[:300]}

def _call_anthropic(api_key, model, prompt, proxies):
    headers = {
        'x-api-key':         api_key,
        'anthropic-version': '2023-06-01',
        'Content-Type':      'application/json',
    }
    payload = {
        'model': model,
        'max_tokens': 1500,
        'system': 'You are PhishGuard AI, expert cybersecurity analyst. Reply ONLY with valid JSON.',
        'messages': [{'role': 'user', 'content': prompt}],
    }
    r = requests.post('https://api.anthropic.com/v1/messages',
                      json=payload, headers=headers, proxies=proxies, timeout=35)
    r.raise_for_status()
    data = r.json()
    raw = data.get('content', [{}])[0].get('text', '')
    if not raw: return {'error': 'Empty response from Claude.'}
    return _parse_json(raw) or {'error': 'Could not parse JSON.', '_raw': raw[:300]}

def call_llm(cfg, prompt, use_tor=False):
    """Universal LLM caller — routes to correct provider automatically."""
    pid     = cfg.get('provider', 'gemini')
    api_key = cfg.get('api_key', '')
    model   = cfg.get('model', '')
    base_url= cfg.get('base_url', _DEFAULT_URLS.get(pid, ''))
    proxies = TOR_PROXY if use_tor else None

    try:
        if   pid == 'gemini':    return _call_gemini(api_key, model, prompt, proxies)
        elif pid == 'anthropic': return _call_anthropic(api_key, model, prompt, proxies)
        else:                    return _call_openai_compat(api_key, model, base_url, prompt, proxies)
    except requests.ConnectionError as e:
        if use_tor:
            # Retry direct
            proxies = None
            try:
                if pid == 'gemini':    return _call_gemini(api_key, model, prompt, proxies)
                elif pid == 'anthropic':return _call_anthropic(api_key, model, prompt, proxies)
                else:                  return _call_openai_compat(api_key, model, base_url, prompt, proxies)
            except Exception as e2:
                return {'error': f'Connection failed (Tor+Direct): {e2}'}
        return {'error': f'Connection error: {e}'}
    except requests.Timeout:
        return {'error': 'Timeout (35s). Model is slow — retry.'}
    except requests.HTTPError as e:
        code = e.response.status_code if e.response else '?'
        msgs = {400: 'Bad request (check model name)',
                401: 'Invalid API key (401)',
                403: 'Forbidden — check API key permissions',
                429: 'Rate limit reached — wait 60s',
                500: 'Provider server error — retry later'}
        return {'error': msgs.get(code, f'HTTP {code}: {e}')}
    except Exception as e:
        return {'error': f'Unexpected error: {e}'}

# ════════════════════════════════════════════════════════════════
#  SECTION 9 — PROMPT BUILDER
# ════════════════════════════════════════════════════════════════
_JSON_SCHEMA = '''{
  "threatScore": <0-100>,
  "riskLevel": "<SAFE|LOW|MEDIUM|HIGH|CRITICAL>",
  "summary": "<2-3 sentence summary>",
  "isPhishing": <true|false>,
  "hasVulnerabilities": <true|false>,
  "confidence": <0-100>,
  "findings": [
    {"severity":"<CRITICAL|HIGH|MEDIUM|LOW|INFO>","title":"<title>","description":"<what found and why dangerous>"}
  ],
  "indicators": {
    "urlManipulation":        "<FOUND|NOT_FOUND|N/A>",
    "urgencyTactics":         "<FOUND|NOT_FOUND|N/A>",
    "impersonation":          "<FOUND|NOT_FOUND|N/A>",
    "credentialHarvesting":   "<FOUND|NOT_FOUND|N/A>",
    "maliciousCode":          "<FOUND|NOT_FOUND|N/A>",
    "dataExfiltration":       "<FOUND|NOT_FOUND|N/A>",
    "suspiciousPermissions":  "<FOUND|NOT_FOUND|N/A>",
    "missingSecurityHeaders": "<FOUND|NOT_FOUND|N/A>",
    "sslIssues":              "<FOUND|NOT_FOUND|N/A>",
    "infoDisclosure":         "<FOUND|NOT_FOUND|N/A>"
  },
  "vulnerabilities": [
    {"type":"<vuln type>","severity":"<CRITICAL|HIGH|MEDIUM|LOW>","detail":"<description>"}
  ],
  "recommendations": ["<action 1>","<action 2>","<action 3>"]
}'''

_PROMPTS = {
    'url': (
        'You are PhishGuard AI, expert web security and phishing analyst.\n'
        'Analyze this URL/Website scan data for ALL threats and vulnerabilities:\n\n'
        'CHECK FOR:\n'
        '1. PHISHING: Typosquatting (paypa1, g00gle), suspicious TLDs (.tk .xyz .ml), '
        'IP instead of domain, homograph attacks, URL shorteners, brand-in-subdomain tricks\n'
        '2. SECURITY HEADERS: Missing CSP, HSTS, X-Frame-Options, X-XSS-Protection, '
        'X-Content-Type-Options, Referrer-Policy, Permissions-Policy\n'
        '3. SSL/TLS ISSUES: Self-signed, expired, weak cipher, HTTP instead of HTTPS\n'
        '4. INFO DISCLOSURE: Server header leaking version, tech stack exposed\n'
        '5. COOKIE SECURITY: Missing Secure, HttpOnly, SameSite flags\n'
        '6. MALICIOUS CONTENT: Hidden iframes, eval() code, suspicious scripts, '
        'fake login forms, credential harvesting\n'
        '7. CORS/REDIRECT ISSUES: Open redirects, suspicious redirect chains\n'
    ),
    'email': (
        'You are PhishGuard AI, expert email phishing analyst.\n'
        'Analyze this email for ALL phishing and social engineering indicators:\n\n'
        'CHECK FOR: Spoofed sender, mismatched display name vs email, generic greetings '
        '(Dear Customer), urgency/fear language (suspended/24h/immediately), '
        'credential/OTP/PIN requests, grammar mistakes, fake invoices, '
        'impersonation of banks/PayPal/Google/Microsoft/government, suspicious links, '
        'requests to click to verify/confirm account.\n'
    ),
    'code': (
        'You are PhishGuard AI, expert malicious code analyst.\n'
        'Analyze this code for ALL malicious patterns:\n\n'
        'CHECK FOR: eval() with base64/encoded strings, hidden iframes (display:none), '
        'form action to external domain, fetch/XHR exfiltrating credentials, '
        'keylogger (addEventListener keydown/keypress), String.fromCharCode obfuscation, '
        'atob()+eval() shellcode, cookie stealing, script injection from suspicious CDN, '
        'WebSocket C2, clipboard hijacking, crypto mining.\n'
    ),
    'apk': (
        'You are PhishGuard AI, expert Android malware analyst.\n'
        'Analyze this APK/App data for ALL malicious indicators:\n\n'
        'CHECK FOR: READ_SMS+SEND_SMS (OTP stealer), REQUEST_INSTALL_PACKAGES (dropper), '
        'SYSTEM_ALERT_WINDOW+BIND_ACCESSIBILITY_SERVICE (overlay attack), '
        'DEVICE_ADMIN (ransomware), RECEIVE_BOOT_COMPLETED (persistence), '
        'hardcoded C2 URLs, unofficial distribution (WhatsApp/Telegram link), '
        'package name mimicking real apps (com.paypa1.android).\n'
    ),
    'file': (
        'You are PhishGuard AI, expert file security analyst.\n'
        'Analyze this file content for ALL malicious indicators:\n\n'
        'CHECK FOR: Embedded phishing URLs, credential harvesting forms, '
        'eval()/base64 payloads, macro indicators (Auto_Open, Document_Open), '
        'PowerShell encoded commands (-EncodedCommand), C2 server addresses, '
        'social engineering text, obfuscated shell commands.\n'
    ),
    'message': (
        'You are PhishGuard AI, expert social engineering analyst.\n'
        'Analyze this message for ALL scam/phishing indicators:\n\n'
        'CHECK FOR: Prize/lottery claims, bank/government impersonation '
        '(SBP, HBL, Meezan, FBR, NADRA), OTP/PIN/password requests, '
        'URL shorteners (bit.ly, wa.me), urgency/threat language '
        '(blocked/arrest/FIR/expire), investment fraud (guaranteed returns), '
        'install-app-via-link, advance fee fraud.\n'
    ),
}

def build_prompt(scan_type, content):
    instruction = _PROMPTS.get(scan_type, _PROMPTS['url'])
    return (f'{instruction}\n'
            f'CONTENT TO ANALYZE:\n{content[:12000]}\n\n'
            f'Reply ONLY as valid JSON — zero extra text, no markdown:\n'
            f'{_JSON_SCHEMA}')

# ════════════════════════════════════════════════════════════════
#  SECTION 10 — WEBSITE FETCHER (Real URL Scanner)
# ════════════════════════════════════════════════════════════════
_SEC_HEADERS = [
    'Content-Security-Policy',
    'Strict-Transport-Security',
    'X-Frame-Options',
    'X-Content-Type-Options',
    'X-XSS-Protection',
    'Referrer-Policy',
    'Permissions-Policy',
    'Cross-Origin-Opener-Policy',
    'Cross-Origin-Resource-Policy',
]

def fetch_url_data(url: str, use_tor: bool = False) -> str:
    """
    Actually fetch the URL and collect security data.
    Returns a rich content string for AI analysis.
    """
    console.print(f'\n  [cyan]🌐 Fetching: {url}[/cyan]')

    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url

    headers_req = {
        'User-Agent': ('Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
                       'AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36'),
        'Accept': 'text/html,application/xhtml+xml,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
    }
    proxies  = TOR_PROXY if use_tor else None
    sections = [f'=== URL SCAN REPORT ===', f'Target URL: {url}']

    # ── 1. HTTP Fetch ──────────────────────────────────────────
    try:
        resp = requests.get(url, headers=headers_req, proxies=proxies,
                            timeout=15, verify=False, allow_redirects=True)

        sections.append(f'\n--- HTTP Response ---')
        sections.append(f'Status Code   : {resp.status_code}')
        sections.append(f'Final URL     : {resp.url}')
        sections.append(f'Redirect Chain: {len(resp.history)} redirect(s)')
        if resp.history:
            for h in resp.history:
                sections.append(f'  → {h.status_code} {h.url}')

        sections.append(f'\n--- Server Information ---')
        sections.append(f'Server       : {resp.headers.get("Server", "HIDDEN")}')
        sections.append(f'X-Powered-By : {resp.headers.get("X-Powered-By", "HIDDEN")}')
        sections.append(f'Content-Type : {resp.headers.get("Content-Type", "?")}')
        sections.append(f'Content-Length: {resp.headers.get("Content-Length", "?")}')

        # ── 2. Security Headers Check ──────────────────────────
        sections.append(f'\n--- Security Headers ---')
        missing_headers = []
        for h in _SEC_HEADERS:
            val = resp.headers.get(h)
            if val:
                sections.append(f'✓ {h}: {val[:100]}')
            else:
                sections.append(f'✗ {h}: MISSING')
                missing_headers.append(h)

        if missing_headers:
            sections.append(f'\nMISSING SECURITY HEADERS ({len(missing_headers)}): '
                            + ', '.join(missing_headers))

        # ── 3. All Response Headers ────────────────────────────
        sections.append(f'\n--- All Response Headers ---')
        for k, v in resp.headers.items():
            sections.append(f'{k}: {v}')

        # ── 4. Cookies ────────────────────────────────────────
        sections.append(f'\n--- Cookies ({len(resp.cookies)}) ---')
        for c in resp.cookies:
            secure   = '✓ Secure'   if c.secure                             else '✗ NOT Secure'
            httponly = '✓ HttpOnly' if c.has_nonstandard_attr('HttpOnly')    else '✗ NOT HttpOnly'
            samesite = c._rest.get('SameSite', 'NOT SET')
            sections.append(f'Cookie: {c.name} | {secure} | {httponly} | SameSite={samesite}')

        # ── 5. HTML Content ────────────────────────────────────
        html = resp.text
        sections.append(f'\n--- HTML Content (first 5000 chars) ---')
        sections.append(html[:5000])

        console.print(f'  [green]✓ Fetched successfully ({resp.status_code}, '
                      f'{len(html)} chars)[/green]')

    except requests.exceptions.SSLError as e:
        sections.append(f'\n--- SSL/TLS ERROR ---')
        sections.append(f'SSL Error: {e}')
        sections.append('NOTE: SSL certificate issue detected — possible MITM or self-signed cert')
        console.print('  [yellow]⚠ SSL error — scanning URL structure only[/yellow]')

    except requests.exceptions.ConnectionError:
        sections.append(f'\n--- CONNECTION FAILED ---')
        sections.append('Could not connect to host. Analyzing URL structure only.')
        console.print('  [yellow]⚠ Connection failed — analyzing URL only[/yellow]')

    except requests.exceptions.Timeout:
        sections.append(f'\n--- TIMEOUT ---')
        sections.append('Request timed out (15s). Site may be slow or blocking scanners.')
        console.print('  [yellow]⚠ Timeout — partial analysis[/yellow]')

    except Exception as e:
        sections.append(f'\n--- ERROR ---')
        sections.append(f'Fetch error: {e}')
        console.print(f'  [yellow]⚠ {e}[/yellow]')

    # ── 6. URL Structure Analysis (always) ────────────────────
    try:
        parsed = urlparse(url)
        sections.append(f'\n--- URL Structure Analysis ---')
        sections.append(f'Scheme     : {parsed.scheme}')
        sections.append(f'Domain     : {parsed.netloc}')
        sections.append(f'Path       : {parsed.path}')
        sections.append(f'Query      : {parsed.query}')
        sections.append(f'Subdomains : {parsed.netloc.count(".")} dots')
        sections.append(f'Is HTTPS   : {"YES" if parsed.scheme == "https" else "NO — HTTP only"}')
        sections.append(f'Has Port   : {"YES: " + str(parsed.port) if parsed.port else "No"}')
        domain = parsed.netloc.lower()
        suspicious_tlds = ['.tk','.ml','.ga','.cf','.gq','.xyz','.top','.click','.pw','.cc','.su']
        for tld in suspicious_tlds:
            if domain.endswith(tld):
                sections.append(f'⚠ SUSPICIOUS TLD: {tld}')
    except Exception:
        pass

    return '\n'.join(sections)

# ════════════════════════════════════════════════════════════════
#  SECTION 11 — RESULTS DISPLAY
# ════════════════════════════════════════════════════════════════
_LEVEL_CFG = {
    'SAFE':     ('green',    '✅'),
    'LOW':      ('cyan',     '🔵'),
    'MEDIUM':   ('yellow',   '⚠️ '),
    'HIGH':     ('red',      '🔴'),
    'CRITICAL': ('bold red', '💀'),
}
_SEV_STYLE = {'CRITICAL':'bold red','HIGH':'red','MEDIUM':'yellow','LOW':'green','INFO':'cyan'}
_IND_LABELS = {
    'urlManipulation':        '🔗 URL Manipulation',
    'urgencyTactics':         '⏰ Urgency Tactics',
    'impersonation':          '🎭 Impersonation',
    'credentialHarvesting':   '🔑 Credential Harvesting',
    'maliciousCode':          '💀 Malicious Code',
    'dataExfiltration':       '📤 Data Exfiltration',
    'suspiciousPermissions':  '📋 Suspicious Permissions',
    'missingSecurityHeaders': '🔓 Missing Sec Headers',
    'sslIssues':              '🔒 SSL/TLS Issues',
    'infoDisclosure':         '🕵 Info Disclosure',
}

def _bar(v, color, w=26):
    filled = max(0, min(w, int(v / 100 * w)))
    return (f'[{color}]' + '█'*filled + f'[/{color}]'
            + '[dim]' + '░'*(w-filled) + '[/dim]'
            + f' [bold]{v}/100[/bold]')

def display_result(result, scan_type, provider_name, model_name):
    if 'error' in result:
        console.print(Panel(
            f'[bold red]❌ Error:[/bold red] {result["error"]}',
            title='[red]Scan Failed[/red]', border_style='red'))
        return

    score     = max(0, min(100, int(result.get('threatScore', 0))))
    level     = result.get('riskLevel', 'MEDIUM')
    if level not in _LEVEL_CFG: level = 'MEDIUM'
    color, icon = _LEVEL_CFG[level]
    phishing  = bool(result.get('isPhishing', False))
    vulns_found = bool(result.get('hasVulnerabilities', False))
    confidence  = max(0, min(100, int(result.get('confidence', 0))))
    summary   = result.get('summary', '').strip()

    console.print()
    console.print(Rule(f'[bold white]SCAN RESULT[/bold white]  [dim]{datetime.now().strftime("%H:%M:%S")}[/dim]', style='dim'))

    # Score card
    card = (
        f'\n'
        f'  Threat Score  :  {_bar(score, color)}\n'
        f'  Confidence    :  {_bar(confidence, "cyan")}\n\n'
        f'  Risk Level    :  [{color}]{icon} {level}[/{color}]\n'
        f'  Phishing      :  ' +
        ('[bold red]⚠️  YES — PHISHING DETECTED[/bold red]' if phishing else '[bold green]✅  NO[/bold green]') + '\n'
        f'  Vulnerabilities: ' +
        ('[bold red]⚠️  YES — VULNERABILITIES FOUND[/bold red]' if vulns_found else '[bold green]✅  NONE[/bold green]') + '\n'
        f'  Scan Type     :  [cyan]{scan_type.upper()}[/cyan]\n'
        f'  AI Model      :  [dim]{provider_name}[/dim] [cyan]{model_name}[/cyan]\n'
    )
    console.print(Panel(card, title=f'[{color}]● {level} RISK[/{color}]',
                        border_style=color, padding=(0,1)))

    if summary:
        console.print(Panel(summary, title='[bold cyan]📋 Summary[/bold cyan]',
                            border_style='cyan'))

    # Indicators
    indicators = result.get('indicators', {})
    if indicators:
        tbl = Table(show_header=True, header_style='bold white',
                    box=box.SIMPLE_HEAVY, border_style='dim', pad_edge=False)
        tbl.add_column('Indicator', style='dim white', width=28)
        tbl.add_column('Status', width=24)
        for key, label in _IND_LABELS.items():
            val = indicators.get(key, 'N/A')
            status = ('[bold red]⚠️  FOUND[/bold red]'    if val == 'FOUND'
                      else '[bold green]✅  CLEAN[/bold green]' if val == 'NOT_FOUND'
                      else '[dim]─  N/A[/dim]')
            tbl.add_row(label, status)
        console.print(Panel(tbl, title='[bold yellow]🎯 Threat Indicators[/bold yellow]',
                            border_style='yellow'))

    # Findings
    findings = result.get('findings', [])
    if findings:
        tbl2 = Table(show_header=True, header_style='bold white',
                     box=box.SIMPLE_HEAVY, border_style='dim', pad_edge=False)
        tbl2.add_column('SEV',    width=10)
        tbl2.add_column('Title',  width=26)
        tbl2.add_column('Detail', width=48)
        for f in findings:
            sev   = str(f.get('severity','INFO')).upper()
            style = _SEV_STYLE.get(sev, 'white')
            tbl2.add_row(f'[{style}]{sev}[/{style}]',
                         f'[bold]{f.get("title","")}[/bold]',
                         f.get('description',''))
        console.print(Panel(tbl2, title='[bold red]🔍 Detailed Findings[/bold red]',
                            border_style='red'))

    # Vulnerabilities
    vulns = result.get('vulnerabilities', [])
    if vulns:
        tbl3 = Table(show_header=True, header_style='bold white',
                     box=box.SIMPLE_HEAVY, border_style='dim', pad_edge=False)
        tbl3.add_column('Type',   width=26)
        tbl3.add_column('SEV',    width=10)
        tbl3.add_column('Detail', width=48)
        for v in vulns:
            sev   = str(v.get('severity','MEDIUM')).upper()
            style = _SEV_STYLE.get(sev, 'white')
            tbl3.add_row(v.get('type',''),
                         f'[{style}]{sev}[/{style}]',
                         v.get('detail',''))
        console.print(Panel(tbl3, title='[bold orange1]🛡️ Vulnerabilities[/bold orange1]',
                            border_style='orange1'))

    # Recommendations
    recs = result.get('recommendations', [])
    if recs:
        rec_txt = '\n'.join(f'  [{i+1}] {r}' for i, r in enumerate(recs))
        console.print(Panel(rec_txt, title='[bold green]💡 Recommended Actions[/bold green]',
                            border_style='green'))

# ════════════════════════════════════════════════════════════════
#  SECTION 12 — HISTORY
# ════════════════════════════════════════════════════════════════
def _load_hist():
    ensure_dir()
    if HISTORY_FILE.exists():
        try: return json.loads(HISTORY_FILE.read_text(encoding='utf-8')).get('scans', [])
        except: pass
    return []

def save_hist(result, scan_type, preview):
    if 'error' in result: return
    hist = _load_hist()
    hist.insert(0, {
        'id':        datetime.now().strftime('%Y%m%d%H%M%S%f'),
        'timestamp': datetime.now().isoformat(),
        'type':      scan_type,
        'preview':   (preview[:55]+'…') if len(preview) > 55 else preview,
        'score':     max(0, min(100, int(result.get('threatScore', 0)))),
        'level':     result.get('riskLevel', '?'),
        'phishing':  bool(result.get('isPhishing', False)),
        'vulns':     bool(result.get('hasVulnerabilities', False)),
        'summary':   result.get('summary','')[:100],
    })
    HISTORY_FILE.write_text(
        json.dumps({'scans': hist[:500]}, indent=2, ensure_ascii=False),
        encoding='utf-8')

def show_history():
    hist = _load_hist()
    if not hist:
        console.print(Panel('[yellow]No scans yet.[/yellow]',
                            title='📊 History', border_style='yellow'))
        return
    _C = {'SAFE':'green','LOW':'cyan','MEDIUM':'yellow','HIGH':'red','CRITICAL':'bold red'}
    tbl = Table(show_header=True, header_style='bold white',
                box=box.ROUNDED, border_style='dim')
    tbl.add_column('#',       width=4,  style='dim')
    tbl.add_column('Time',    width=16)
    tbl.add_column('Type',    width=9)
    tbl.add_column('Preview', width=36)
    tbl.add_column('Score',   width=7)
    tbl.add_column('Level',   width=11)
    tbl.add_column('Phish',   width=7)
    tbl.add_column('Vuln',    width=6)
    for i, h in enumerate(hist[:40], 1):
        c = _C.get(h.get('level',''), 'white')
        tbl.add_row(str(i),
                    h.get('timestamp','')[:16].replace('T',' '),
                    h.get('type','').upper(),
                    h.get('preview',''),
                    f'[{c}]{h.get("score",0)}[/{c}]',
                    f'[{c}]{h.get("level","")}[/{c}]',
                    '[red]⚠ Y[/red]' if h.get('phishing') else '[green]✅ N[/green]',
                    '[red]⚠ Y[/red]' if h.get('vulns')    else '[dim]  N[/dim]')
    console.print(Panel(tbl, title=f'[bold cyan]📊 Scan History ({len(hist)} total)[/bold cyan]',
                        border_style='cyan'))
    threats = sum(1 for h in hist if h.get('phishing') or h.get('vulns'))
    console.print(f'  [dim]Threats/Vulns: [red]{threats}[/red]  |  '
                  f'Clean: [green]{len(hist)-threats}[/green][/dim]')

def export_hist():
    hist = _load_hist()
    if not hist:
        console.print('  [yellow]No history to export.[/yellow]'); return
    path = CONFIG_DIR / f'export_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json'
    path.write_text(json.dumps({'exported': datetime.now().isoformat(), 'scans': hist},
                               indent=2, ensure_ascii=False), encoding='utf-8')
    console.print(f'  [green]✓ Exported {len(hist)} records → {path}[/green]')

def clear_hist():
    if Confirm.ask('[yellow]  Clear ALL history?[/yellow]'):
        HISTORY_FILE.write_text(json.dumps({'scans': []}), encoding='utf-8')
        console.print('  [green]✓ Cleared.[/green]')

# ════════════════════════════════════════════════════════════════
#  SECTION 13 — INPUT COLLECTORS (Fixed)
# ════════════════════════════════════════════════════════════════
def _ask(label, placeholder='', required=True):
    """Simple single-line input with optional placeholder hint."""
    while True:
        try:
            val = Prompt.ask(f'  [cyan]{label}[/cyan]',
                             default='' if placeholder else ...).strip()
        except (EOFError, KeyboardInterrupt):
            return ''
        if val or not required:
            return val
        console.print('  [red]✗ This field cannot be empty.[/red]')

def _multiline(label, hint=''):
    """Multi-line input. Empty line = done (more natural than typing END)."""
    console.print(f'\n  [cyan]{label}[/cyan]')
    if hint: console.print(f'  [dim]{hint}[/dim]')
    console.print('  [dim](Paste content — press Enter twice on empty line to finish)[/dim]\n')
    lines = []
    empty_count = 0
    try:
        while True:
            line = input('  > ')
            if line == '':
                empty_count += 1
                if empty_count >= 2:
                    break
                lines.append(line)
            else:
                empty_count = 0
                lines.append(line)
    except (EOFError, KeyboardInterrupt):
        pass
    # Remove trailing empty lines
    while lines and lines[-1] == '':
        lines.pop()
    return '\n'.join(lines)

def collect_url(use_tor=False):
    console.print(Panel(
        '[bold]URL / Website Scanner[/bold]\n'
        '[dim]Actual website fetch ho gi — security headers, SSL, cookies sab check honge[/dim]',
        border_style='cyan', padding=(0,2)))
    url = _ask('→ URL ya Domain', placeholder='https://example.com')
    if not url:
        return '', ''
    content = fetch_url_data(url, use_tor=use_tor)
    return content, url

def collect_email():
    console.print(Panel('[bold]Email Scanner[/bold]', border_style='cyan'))
    sender  = _ask('→ From (Sender Email)', required=False)
    subject = _ask('→ Subject Line',        required=False)
    body    = _multiline('Email Body:', 'Poori email paste karo')
    parts = []
    if sender:  parts.append(f'From: {sender}')
    if subject: parts.append(f'Subject: {subject}')
    if body:    parts.append(body)
    return '\n\n'.join(parts), subject or sender or 'Email'

def collect_code():
    console.print(Panel(
        '[bold]Code / Script Scanner[/bold]\n'
        '[dim]Paste karo ya file path do[/dim]', border_style='cyan'))
    lang   = _ask('→ Language (e.g. JavaScript, Python, PHP)', required=False)
    choice = Prompt.ask('  [cyan]→ [1] Paste code  [2] File path[/cyan]', choices=['1','2'])
    if choice == '2':
        path = _ask('→ File path')
        try:
            fp = Path(path).expanduser().resolve()
            if not fp.exists():    raise FileNotFoundError(f'File not found: {fp}')
            if not fp.is_file():   raise IsADirectoryError(f'Not a file: {fp}')
            code = fp.read_text(errors='ignore', encoding='utf-8')[:20000]
            lang = lang or fp.suffix.lstrip('.')
            console.print(f'  [green]✓ Loaded: {fp.name} ({len(code)} chars)[/green]')
        except FileNotFoundError as e:
            console.print(f'  [red]✗ {e}[/red]'); return '', ''
        except PermissionError:
            console.print('  [red]✗ Permission denied[/red]'); return '', ''
        except Exception as e:
            console.print(f'  [red]✗ {e}[/red]'); return '', ''
    else:
        code = _multiline(f'{lang or "Code"}:', 'Code paste karo')
    if not code.strip():
        console.print('  [yellow]⚠ No code provided.[/yellow]'); return '', ''
    content = f'Language: {lang or "Unknown"}\n\n{code}'
    return content, f'{lang or "code"} script'

def collect_apk():
    console.print(Panel(
        '[bold]APK / App Scanner[/bold]\n'
        '[dim]AndroidManifest.xml ya permissions list paste karo[/dim]', border_style='cyan'))
    name  = _ask('→ App Name / Source', required=False)
    perms = _multiline('Permissions list (ek per line):', 'e.g.  READ_SMS   DEVICE_ADMIN   CAMERA')
    mani  = _multiline('AndroidManifest.xml / Code:', 'Content paste karo')
    parts = [f'App: {name}' if name else '']
    if perms.strip(): parts.append(f'Permissions:\n{perms}')
    if mani.strip():  parts.append(f'Manifest/Code:\n{mani}')
    content = '\n\n'.join(p for p in parts if p)
    if not content.strip():
        console.print('  [yellow]⚠ No content provided.[/yellow]'); return '', ''
    return content, name or 'APK'

def collect_file():
    console.print(Panel(
        '[bold]File Scanner[/bold]\n'
        '[dim]File path do ya content paste karo[/dim]', border_style='cyan'))
    choice = Prompt.ask('  [cyan]→ [1] File path  [2] Paste content[/cyan]', choices=['1','2'])
    if choice == '1':
        path = _ask('→ File path')
        try:
            fp = Path(path).expanduser().resolve()
            if not fp.exists():  raise FileNotFoundError(f'Not found: {fp}')
            if not fp.is_file(): raise IsADirectoryError(f'Not a file: {fp}')
            if fp.stat().st_size > 500_000:
                console.print(f'  [yellow]⚠ Large file — using first 500KB[/yellow]')
            content = fp.read_text(errors='ignore', encoding='utf-8')[:500_000]
            console.print(f'  [green]✓ Loaded: {fp.name}[/green]')
            return content, fp.name
        except FileNotFoundError as e:
            console.print(f'  [red]✗ {e}[/red]')
        except PermissionError:
            console.print('  [red]✗ Permission denied[/red]')
        except Exception as e:
            console.print(f'  [red]✗ {e}[/red]')
        return '', ''
    content = _multiline('File content:')
    return content, 'Pasted file'

def collect_message():
    console.print(Panel('[bold]Message / SMS / Chat Scanner[/bold]', border_style='cyan'))
    platform = _ask('→ Platform (WhatsApp/SMS/Slack/etc.)', required=False)
    text     = _multiline('Message text:', 'Poora message paste karo')
    if not text.strip():
        console.print('  [yellow]⚠ No message provided.[/yellow]'); return '', ''
    content = f'Platform: {platform or "Unknown"}\n\nMessage:\n{text}'
    return content, f'{platform or "Message"}'

_COLLECTORS = {
    'url': None,      # special — needs use_tor param
    'email':   collect_email,
    'code':    collect_code,
    'apk':     collect_apk,
    'file':    collect_file,
    'message': collect_message,
}

# ════════════════════════════════════════════════════════════════
#  SECTION 14 — FIRST RUN SETUP (Multi-LLM)
# ════════════════════════════════════════════════════════════════
def _test_llm(cfg):
    try:
        result = call_llm(cfg, 'Reply ONLY: {"status":"ok"}', use_tor=False)
        return 'error' not in result
    except Exception:
        return False

def first_run_setup(cfg):
    os.system('clear' if os.name != 'nt' else 'cls')
    art = _art({'font':'slant','text':'PhishGuard','color':'bold cyan','sub':'','sc':'cyan'})
    console.print(Align.center(Text(art, style='bold cyan')))
    console.print(Align.center('[bold cyan][ First Time Setup ][/bold cyan]'))
    console.print(Rule(style='dim'))
    console.print()

    # ── Step 1: Choose Provider ──────────────────────────────
    console.print(Panel(
        '  [bold white]Choose your AI Provider:[/bold white]\n\n'
        '  [cyan][1][/cyan]  🟢 Google Gemini     [bold green]FREE[/bold green] — 1500 scans/day\n'
        '  [cyan][2][/cyan]  ⚫ OpenAI GPT         Paid — GPT-4o, GPT-3.5\n'
        '  [cyan][3][/cyan]  🟠 Anthropic Claude   Paid — Claude 3.5 Sonnet\n'
        '  [cyan][4][/cyan]  🟣 Groq               [bold green]FREE tier[/bold green] — Llama, Mixtral (fast!)\n'
        '  [cyan][5][/cyan]  🔵 Ollama (Local)     [bold green]FREE[/bold green] — Run models on your PC\n'
        '  [cyan][6][/cyan]  ⚙️  Custom OpenAI API  Your own endpoint\n',
        title='[bold yellow]🤖 Select AI Provider[/bold yellow]',
        border_style='yellow', padding=(0,2)))

    p_choice = Prompt.ask('\n  [yellow]→ Choice[/yellow]',
                          choices=['1','2','3','4','5','6'])
    provider = PROVIDERS[p_choice]

    # ── Step 2: Choose Model ─────────────────────────────────
    if provider['models']:
        console.print(f'\n  [bold]Models for {provider["name"]}:[/bold]\n')
        for i, (m, desc) in enumerate(provider['models'], 1):
            console.print(f'  [cyan][{i}][/cyan]  {m}  [dim]{desc}[/dim]')
        console.print(f'  [cyan][{len(provider["models"])+1}][/cyan]  Enter custom model name\n')

        m_choices = [str(i) for i in range(1, len(provider['models'])+2)]
        m_choice = Prompt.ask('  [yellow]→ Model choice[/yellow]', choices=m_choices)
        idx = int(m_choice) - 1
        if idx < len(provider['models']):
            model = provider['models'][idx][0]
        else:
            model = _ask('→ Custom model name')
    else:
        model = _ask('→ Model name (e.g. llama3.2, mistral)')

    # ── Step 3: Base URL (for custom/ollama) ─────────────────
    base_url = provider.get('base_url', '')
    if provider['id'] in ('custom', 'ollama'):
        default_url = base_url or 'http://localhost:11434/v1'
        console.print(f'\n  [dim]Default base URL: {default_url}[/dim]')
        entered = _ask(f'→ Base URL (Enter to use default)', required=False)
        base_url = entered or default_url

    # ── Step 4: API Key ──────────────────────────────────────
    api_key = ''
    if provider['needs_key']:
        if provider.get('key_url'):
            console.print(f'\n  [dim]Get free key: {provider["key_url"]}[/dim]')
        console.print()
        while True:
            try:
                api_key = getpass.getpass('  → API Key (hidden input): ').strip()
            except Exception:
                api_key = _ask('→ API Key')
            if api_key: break
            console.print('  [red]✗ API key cannot be empty.[/red]')

    # ── Step 5: Test ─────────────────────────────────────────
    test_cfg = {
        'provider': provider['id'],
        'model':    model,
        'api_key':  api_key,
        'base_url': base_url,
    }
    console.print()
    with console.status(f'[yellow]  🔍 Testing {provider["name"]} / {model}...', spinner='dots'):
        ok = _test_llm(test_cfg)

    if ok:
        console.print(f'  [bold green]✓ Connection verified![/bold green]')
    else:
        console.print(f'  [yellow]⚠ Could not verify — saving anyway (check key/model)[/yellow]')

    cfg.update({**test_cfg, 'first_run_done': True, 'skip_tor': False,
                'setup_date': datetime.now().isoformat()})
    save_cfg(cfg)

    masked = (api_key[:6]+'*'*16) if api_key else 'None (local)'
    console.print(Panel(
        f'[bold green]✅ Setup Complete![/bold green]\n\n'
        f'  Provider  :  [cyan]{provider["name"]}[/cyan]\n'
        f'  Model     :  [cyan]{model}[/cyan]\n'
        f'  API Key   :  [dim]{masked}[/dim]\n'
        f'  Config    :  [dim]{CONFIG_FILE}[/dim]\n\n'
        '[dim]Press Enter to continue...[/dim]',
        border_style='green', padding=(1,2)))
    try: input()
    except: pass
    return cfg

# ════════════════════════════════════════════════════════════════
#  SECTION 15 — SETTINGS
# ════════════════════════════════════════════════════════════════
def show_settings(cfg, tor_ok):
    pid, pname, model, api_key, base_url = get_provider_info(cfg)
    while True:
        masked = (api_key[:6]+'*'*16) if api_key else '[red]NOT SET[/red]'
        console.print()
        console.print(Panel(
            f'  [cyan]Provider  :[/cyan]  {pname}  ([dim]{pid}[/dim])\n'
            f'  [cyan]Model     :[/cyan]  {model}\n'
            f'  [cyan]API Key   :[/cyan]  {masked}\n'
            f'  [cyan]Base URL  :[/cyan]  [dim]{base_url or "default"}[/dim]\n'
            f'  [cyan]Tor       :[/cyan]  {"[green]ACTIVE[/green]" if tor_ok else "[red]INACTIVE[/red]"}\n'
            f'  [cyan]Skip Tor  :[/cyan]  {"[yellow]YES[/yellow]" if cfg.get("skip_tor") else "[green]NO[/green]"}\n'
            f'  [cyan]Config    :[/cyan]  [dim]{CONFIG_FILE}[/dim]\n',
            title='[bold]⚙️  Settings[/bold]', border_style='dim'))
        console.print(
            '  [cyan][1][/cyan]  🤖 Change AI Provider / Model\n'
            '  [cyan][2][/cyan]  🔑 Change API Key only\n'
            '  [cyan][3][/cyan]  🧅 Toggle Tor routing\n'
            '  [cyan][4][/cyan]  🔄 Restart Tor\n'
            '  [cyan][5][/cyan]  📤 Export Scan History\n'
            '  [cyan][6][/cyan]  🗑️  Clear History\n'
            '  [cyan][7][/cyan]  💥 Reset ALL Settings\n'
            '  [cyan][0][/cyan]  ← Back\n')
        c = Prompt.ask('  [cyan]→[/cyan]', choices=['0','1','2','3','4','5','6','7'])
        if c == '0':
            break
        elif c == '1':
            cfg = first_run_setup(cfg)
            pid, pname, model, api_key, base_url = get_provider_info(cfg)
        elif c == '2':
            try:    new_key = getpass.getpass('  → New API Key (hidden): ').strip()
            except: new_key = _ask('→ New API Key')
            if new_key:
                cfg['api_key'] = new_key; api_key = new_key
                save_cfg(cfg); console.print('  [green]✓ Key updated.[/green]')
        elif c == '3':
            cfg['skip_tor'] = not cfg.get('skip_tor', False)
            if cfg['skip_tor']: tor_ok = False
            save_cfg(cfg)
            console.print(f'  [green]✓ Tor: {"DISABLED" if cfg["skip_tor"] else "ENABLED"}[/green]')
        elif c == '4':
            with console.status('[yellow]  Restarting Tor...', spinner='dots'):
                tor_ok = start_tor(cfg)
            console.print(f'  Tor: {"[green]ACTIVE[/green]" if tor_ok else "[red]FAILED[/red]"}')
        elif c == '5':
            export_hist()
        elif c == '6':
            clear_hist()
        elif c == '7':
            if Confirm.ask('[red]  Reset ALL settings?[/red]'):
                save_cfg({}); console.print('  [green]✓ Reset. Restart to reconfigure.[/green]')
                sys.exit(0)
    return cfg, tor_ok

# ════════════════════════════════════════════════════════════════
#  SECTION 16 — SCAN RUNNER
# ════════════════════════════════════════════════════════════════
def run_scan(scan_key, cfg, tor_ok, session_stats):
    stype, icon, label = SCAN_TYPES[scan_key]
    pid, pname, model, _, _ = get_provider_info(cfg)

    console.print()
    console.print(Rule(f'[bold]{icon} {label}[/bold]', style='cyan'))

    # Collect input
    if stype == 'url':
        content, preview = collect_url(use_tor=tor_ok)
    else:
        collector = _COLLECTORS[stype]
        content, preview = collector()

    if not content or not content.strip():
        console.print('\n  [yellow]⚠ No content. Scan cancelled.[/yellow]')
        return tor_ok

    # Call LLM
    console.print()
    with console.status(
        f'[bold cyan]  🤖 {pname} / {model} analyzing '
        f'via {"Tor" if tor_ok else "Direct"}...[/bold cyan]', spinner='dots2'):
        prompt = build_prompt(stype, content)
        result = call_llm(cfg, prompt, use_tor=tor_ok)

        # If Tor failed, try direct
        if 'error' in result and 'connect' in result.get('error','').lower() and tor_ok:
            console.print('  [yellow]⚠ Tor failed — retrying direct...[/yellow]')
            result  = call_llm(cfg, prompt, use_tor=False)
            tor_ok  = False

    # Display
    display_result(result, stype, pname, model)
    save_hist(result, stype, preview)

    if 'error' not in result:
        session_stats['total'] += 1
        if result.get('isPhishing') or result.get('hasVulnerabilities'):
            session_stats['threats'] += 1

    console.print()
    try: input('  [Press Enter to return to menu] ')
    except (EOFError, KeyboardInterrupt): pass
    return tor_ok

# ════════════════════════════════════════════════════════════════
#  SECTION 17 — MAIN MENU + ENTRY POINT
# ════════════════════════════════════════════════════════════════
def show_menu(tor_ok, stats):
    t = stats.get('total', 0)
    footer = (f'\n  [dim]Session: {t} scans  |  '
              f'Threats: [red]{stats.get("threats",0)}[/red]  |  '
              f'Clean: [green]{t-stats.get("threats",0)}[/green][/dim]') if t else ''
    console.print(Panel(
        '  [bold white]SCAN TOOLS[/bold white]\n'
        '  [cyan][1][/cyan]  🌐  URL / Website Vulnerability Scanner\n'
        '  [cyan][2][/cyan]  📧  Email Phishing Scanner\n'
        '  [cyan][3][/cyan]  💻  Code / Script Scanner\n'
        '  [cyan][4][/cyan]  📱  APK / App Scanner\n'
        '  [cyan][5][/cyan]  📂  File Content Scanner\n'
        '  [cyan][6][/cyan]  💬  Message / SMS Scanner\n\n'
        '  [bold white]TOOLS[/bold white]\n'
        '  [cyan][7][/cyan]  📊  Scan History\n'
        '  [cyan][8][/cyan]  🧅  Rotate Tor Identity\n'
        '  [cyan][9][/cyan]  ⚙️   Settings\n'
        '  [cyan][0][/cyan]  🚪  Exit'
        + footer,
        title='[bold cyan]🛡️  PhishGuard AI — Main Menu[/bold cyan]',
        border_style='cyan', padding=(0,2)))

def main():
    parser = argparse.ArgumentParser(prog='ai-detect',
                                     description='PhishGuard AI — CLI Security Scanner')
    parser.add_argument('--version', action='version', version=f'%(prog)s {VERSION}')
    parser.add_argument('--no-tor',  action='store_true', help='Skip Tor')
    parser.add_argument('--reset',   action='store_true', help='Reset config')
    args = parser.parse_args()

    if args.reset:
        save_cfg({})
        print('Config reset.'); sys.exit(0)

    cfg = load_cfg()
    if args.no_tor:
        cfg['skip_tor'] = True

    # First run
    if not cfg.get('first_run_done') or not cfg.get('provider'):
        cfg = first_run_setup(cfg)

    pid, pname, model, _, _ = get_provider_info(cfg)

    # Tor
    tor_ok = False
    if not cfg.get('skip_tor'):
        tor_ok = start_tor(cfg)

    session_stats = {'total': 0, 'threats': 0}

    # Main loop
    while True:
        try:
            show_banner(tor_ok, pname, model, session_stats['total'])
            show_menu(tor_ok, session_stats)
            choice = Prompt.ask('\n  [bold cyan]→ Choice[/bold cyan]',
                                choices=['0','1','2','3','4','5','6','7','8','9'])

            if choice == '0':
                console.print('\n  [dim]Goodbye! Stay safe. 🛡️[/dim]\n')
                sys.exit(0)

            elif choice in SCAN_TYPES:
                tor_ok = run_scan(choice, cfg, tor_ok, session_stats)

            elif choice == '7':
                show_banner(tor_ok, pname, model, session_stats['total'])
                show_history()
                try: input('\n  [Press Enter] ')
                except: pass

            elif choice == '8':
                console.print()
                ok = rotate_tor()
                if ok:
                    time.sleep(2)
                    new_ip = get_ip(use_tor=check_tor())
                    console.print(f'  [green]✓ Tor identity rotated — IP: {new_ip}[/green]')
                else:
                    console.print('  [yellow]⚠ Could not rotate. Add "ControlPort 9051" to /etc/tor/torrc[/yellow]')
                try: input('\n  [Press Enter] ')
                except: pass

            elif choice == '9':
                show_banner(tor_ok, pname, model, session_stats['total'])
                cfg, tor_ok = show_settings(cfg, tor_ok)
                pid, pname, model, _, _ = get_provider_info(cfg)

        except KeyboardInterrupt:
            console.print('\n\n  [dim]Ctrl+C — Exiting...[/dim]\n')
            sys.exit(0)
        except Exception as e:
            console.print(f'\n  [bold red]Error:[/bold red] {e}')
            try: input('  [Press Enter] ')
            except: sys.exit(1)

if __name__ == '__main__':
    main()
