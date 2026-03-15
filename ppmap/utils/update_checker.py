import urllib.request
import urllib.error
import json
import socket
from packaging import version

class Colors:
    WARNING = '\033[93m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'

def check_for_updates(current_version: str) -> None:
    """Check the GitHub API for newer releases of PPMAP."""
    repo_url = "https://api.github.com/repos/aarsaputra/ppmap-proto-pollution/releases/latest"
    
    try:
        # 3 second timeout for DNS and connect so it's unobtrusive
        req = urllib.request.Request(repo_url, headers={'User-Agent': 'PPMAP-Update-Checker'})
        with urllib.request.urlopen(req, timeout=3.0) as response:  # nosec B310
            if response.status == 200:
                data = json.loads(response.read().decode())
                latest_tag = data.get("tag_name", "")
                
                # Strip the 'v' prefix if it exists to compare version numbers properly
                latest_ver_str = latest_tag.lstrip('v') if latest_tag.startswith('v') else latest_tag
                current_ver_str = current_version.lstrip('v') if current_version.startswith('v') else current_version
                
                if latest_ver_str and version.parse(latest_ver_str) > version.parse(current_ver_str):
                    update_msg = f"""
{Colors.WARNING}========================================================================
[!] UPDATE AVAILABLE: PPMAP v{latest_ver_str} is now available!
    You are currently running v{current_ver_str}
    
    To update, run:
    git pull origin master && pip install -r requirements.txt
    
    Or view the release notes: 
    https://github.com/aarsaputra/ppmap-proto-pollution/releases/latest
========================================================================{Colors.ENDC}
"""
                    print(update_msg)
    except (urllib.error.URLError, socket.timeout, ValueError, json.JSONDecodeError):
        # Fail silently to not annoy the user if offline or rate limited
        pass
    except Exception:
        # Broad catch-all for any other unanticipated errors
        import logging
        logging.getLogger(__name__).debug("Auto-update check failed", exc_info=True)
