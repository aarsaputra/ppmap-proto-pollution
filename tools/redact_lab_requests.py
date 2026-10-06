"""Redaksi capture request lab PortSwigger (idempotent).

Dipakai dua kali:
  1. langsung pada working tree      -> python redact_lab.py <repo-root>
  2. di dalam git filter-branch
     --tree-filter                   -> python redact_lab.py .
"""
import pathlib
import re
import sys

ROOT = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else ".")
D = ROOT / "tests" / "portswigger_labs"

RX_HOST = re.compile(r"\b0a[0-9a-f]{4,}\.web-security-academy\.net\b")
RX_SESSION_KV = re.compile(r"session=[A-Za-z0-9_\-%./+=]{8,}")
RX_SID = re.compile(r'("sessionId"\s*:\s*")[A-Za-z0-9_\-]{8,}(")')
RX_COOKIE_LINE = re.compile(r"(?m)^Cookie:.*$")

changed = []
if D.is_dir():
    for p in sorted(D.glob("*.txt")):
        t = orig = p.read_text(errors="replace")
        t = RX_HOST.sub("YOUR-LAB-ID.web-security-academy.net", t)
        t = RX_SID.sub(r"\1YOUR_LAB_SESSION_ID\2", t)
        t = RX_SESSION_KV.sub("session=YOUR_SESSION_HERE", t)
        if "Cookie:" in t and "YOUR_SESSION_HERE" not in t:
            t = RX_COOKIE_LINE.sub("Cookie: session=YOUR_SESSION_HERE", t)
        if t != orig:
            p.write_text(t)
            changed.append(p.name)
if "--verbose" in sys.argv:
    print("diubah:", ", ".join(changed) or "(tidak ada)")
