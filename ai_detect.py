#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# ================================================================
#   PhishGuard AI — CLI Phishing Detection Tool
#   Version : 2.1.0
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

def _can_import(name: str) -> bool:
    """
    FIX: Python 3.14 mein importlib.util directly import karna padta hai.
    __import__('importlib').util kaam nahi karta tha — simple try/except use karo.
    """
    try:
        __import__(name)
        return True
    except ImportError:
        return False

def _pip(pkg: str) -> bool:
