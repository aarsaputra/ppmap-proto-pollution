"""Report generator utilities (CSV/Markdown minimal implementations)"""
from pathlib import Path
import csv
from datetime import datetime
import logging
logger = logging.getLogger(__name__)


class EnhancedReportGenerator:
    def __init__(self, output_dir: str = './reports'):
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

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

    def generate_all_formats(self, findings: list, target: str = '', formats: list = None) -> dict:
        """Generate multiple report formats and return dict of created file paths."""
        if formats is None:
            formats = ['json', 'md', 'csv']
        generated = {}
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')

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

        return generated
