import urllib.request
import urllib.error
import json
import socket
from packaging import version

class Colors:
    WARNING = '\033[93m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'

_REPO_API = "https://api.github.com/repos/aarsaputra/ppmap-proto-pollution"


def _fetch_json(url: str, timeout: float = 3.0):
    # B310: URL berasal dari konstanta https-only di modul ini (bukan input
    # pengguna); verify scheme https secara eksplisit lalu nosec.
    if not url.startswith("https://"):
        raise ValueError(f"non-https URL rejected: {url}")
    req = urllib.request.Request(url, headers={'User-Agent': 'PPMAP-Update-Checker'})
    with urllib.request.urlopen(req, timeout=timeout) as response:  # nosec B310
        if response.status == 200:
            return json.loads(response.read().decode())
    return None


def _latest_tag() -> str:
    """Tag terbaru (semver tertinggi) dari releases/latest; fallback: /tags.
    /tags urut kronologis -> pilih max semver, bukan elemen pertama."""
    try:
        data = _fetch_json(f"{_REPO_API}/releases/latest")
        tag = (data or {}).get("tag_name", "")
        if tag:
            return tag
    except Exception:
        pass
    try:
        tags = _fetch_json(f"{_REPO_API}/tags?per_page=30") or []
        candidates = [t.get("name", "") for t in tags if t.get("name")]
        vers = [t for t in candidates if t.lstrip("v")[:1].isdigit()]
        if vers:
            return max(vers, key=lambda t: version.parse(t.lstrip("v")))
    except Exception:
        pass
    return ""


def check_for_updates(current_version: str) -> None:
    """Check GitHub for newer tags/releases of PPMAP (non-blocking, fail-silent)."""
    try:
        latest_tag = _latest_tag()
        if not latest_tag:
            return
        latest_ver_str = latest_tag.lstrip('v') if latest_tag.startswith('v') else latest_tag
        current_ver_str = (current_version.lstrip('v')
                           if current_version.startswith('v') else current_version)

        if latest_ver_str and version.parse(latest_ver_str) > version.parse(current_ver_str):
            update_msg = f"""
{Colors.WARNING}========================================================================
[!] UPDATE AVAILABLE: PPMAP v{latest_ver_str} is now available!
    You are currently running v{current_ver_str}

    To update (git clone install):
    git pull origin master && pip install -e .

    Release notes:
    https://github.com/aarsaputra/ppmap-proto-pollution/releases
    (bila belum ada Release object, lihat tab Tags)
========================================================================{Colors.ENDC}
"""
            print(update_msg)
    except (urllib.error.URLError, socket.timeout, ValueError, json.JSONDecodeError):
        pass
    except Exception:
        import logging
        logging.getLogger(__name__).debug("Auto-update check failed", exc_info=True)
