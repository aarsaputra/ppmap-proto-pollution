"""Report generator utilities (CSV/Markdown minimal implementations)"""
from pathlib import Path
import csv
from datetime import datetime
import logging
from urllib.parse import urlparse
import re
logger = logging.getLogger(__name__)


class EnhancedReportGenerator:
    def __init__(self, output_dir: str = './reports'):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
    
    def _sanitize_domain(self, target_url: str) -> str:
        """Extract and sanitize domain from target URL for directory naming."""
        try:
            parsed = urlparse(target_url)
            domain = parsed.netloc or parsed.path.split('/')[0]
            # Remove www., port, and invalid chars
            domain = domain.replace('www.', '').split(':')[0]
            domain = re.sub(r'[^a-zA-Z0-9.-]', '_', domain)
            domain = domain.replace('.', '_')
            return domain or 'unknown_target'
        except Exception:
            return 'unknown_target'

    def generate_csv_report(self, findings: list, filename: str = None) -> str:
        if not findings:
            return ''
        if not filename:
            filename = f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        fp = self.output_dir / filename
        try:
            # collect keys
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

    def generate_markdown_report(self, findings: list, target: str = '', filename: str = None) -> str:
        if not filename:
            filename = f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
        fp = self.output_dir / filename
        try:
            content = f"# Report for {target}\n\nTotal findings: {len(findings)}\n\n"
            for i, f in enumerate(findings, 1):
                 content += "## Finding {}\n\n```\n{}\n```\n\n".format(i, str(f)[:1000])
            with open(fp, 'w') as fh:
                fh.write(content)
            return str(fp)
        except Exception as e:
            logger.error(f"Markdown generation failed: {e}")
            return ''

    def generate_html_report(self, findings: list, target: str = '', filename: str = None) -> str:
        if not filename:
            filename = f"report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        fp = self.output_dir / filename
        
        try:
            # Minimal HTML Template
            html = f"""
            <!DOCTYPE html>
            <html>
            <head>
                <title>PPMAP Report - {target}</title>
                <style>
                    body {{ font-family: -apple-system, system-ui, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif; margin: 2rem; background: #f8f9fa; }}
                    .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 2rem; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
                    h1 {{ border-bottom: 2px solid #eee; padding-bottom: 1rem; color: #2c3e50; }}
                    .summary {{ display: flex; gap: 2rem; margin-bottom: 2rem; padding: 1rem; background: #f1f3f5; border-radius: 4px; }}
                    .vuln {{ border: 1px solid #e9ecef; margin-bottom: 1rem; border-radius: 4px; overflow: hidden; }}
                    .header {{ background: #f8f9fa; padding: 1rem; border-bottom: 1px solid #e9ecef; font-weight: bold; display: flex; justify-content: space-between; align-items: center; }}
                    .high {{ border-left: 5px solid #dc3545; }}
                    .critical {{ border-left: 5px solid #721c24; }}
                    .medium {{ border-left: 5px solid #ffc107; }}
                    .content {{ padding: 1rem; font-family: monospace; white-space: pre-wrap; background: #fff; }}
                </style>
            </head>
            <body>
                <div class="container">
                    <h1>PPMAP Scan Report</h1>
                    <div class="summary">
                        <div><strong>Target:</strong> {target}</div>
                        <div><strong>Date:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</div>
                        <div><strong>Findings:</strong> {len(findings)}</div>
                    </div>
                    <h2>Vulnerabilities</h2>
            """
            
            for f in findings:
                severity = f.get('severity', 'MEDIUM').lower()
                name = f.get('name', f.get('type', 'Unknown Vulnerability'))
                cve = f.get('cve', '')
                title = f"{name} {f'({cve})' if cve else ''}"
                
                html += f"""
                    <div class="vuln {severity}">
                        <div class="header">
                            <span>{title}</span>
                            <span class="badge">{severity.upper()}</span>
                        </div>
                        <div class="content">{str(f)}</div>
                    </div>
                """
                
            html += """
                </div>
            </body>
            </html>
            """
            
            with open(fp, 'w') as fh:
                fh.write(html)
            return str(fp)
        except Exception as e:
            logger.error(f"HTML generation failed: {e}")
            return ''

    def generate_all_formats(self, findings: list, target: str = '', formats: list = None) -> dict:
        """Generate multiple report formats and return dict of created file paths.
        Creates target-specific subdirectory: reports/DOMAIN_TIMESTAMP/
        """
        if formats is None:
            # Default to JSON and HTML as per enterprise standard
            formats = ['json', 'html']
            
        generated = {}
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        # Create target-specific subdirectory
        domain = self._sanitize_domain(target)
        date_str = datetime.now().strftime('%Y%m%d')
        target_dir = self.output_dir / f"{domain}_{date_str}"
        target_dir.mkdir(parents=True, exist_ok=True)
        
        # Update output_dir for this generation cycle
        original_output_dir = self.output_dir
        self.output_dir = target_dir

        if 'json' in formats:
            try:
                fp = self.output_dir / f"report_{timestamp}.json"
                import json
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
        
        # Restore original output_dir
        self.output_dir = original_output_dir
        
        return generated
