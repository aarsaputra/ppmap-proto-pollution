import json
import glob
import os
import argparse
from pathlib import Path
from datetime import datetime
from collections import defaultdict


def generate_markdown_report(report_dir: str, title: str, output_file: str):
    base_path = Path(report_dir).resolve()
    if not base_path.exists() or not base_path.is_dir():
        print(f"Error: Directory '{report_dir}' not found.")
        return

    search_pattern = str(base_path / "*/report.json")
    report_files = glob.glob(search_pattern)
    vulnerable_targets = []
    vuln_counts = defaultdict(int)

    # Data structure to hold findings by target
    findings_by_target = {}

    for report_path in report_files:
        try:
            with open(report_path, "r", encoding="utf-8") as f:
                data = json.load(f)

            target = data.get("target", "Unknown")
            findings = data.get("findings", [])

            real_vulns = []
            for finding in findings:
                f_type = finding.get("type")
                if f_type is None:
                    f_type = "unknown"
                if f_type not in ["discovered_endpoint", "info"]:
                    real_vulns.append(finding)
                    vuln_counts[f_type] += 1

            if real_vulns:
                vulnerable_targets.append(target)
                findings_by_target[target] = real_vulns

        except FileNotFoundError:
            print(f"Warning: File not found {report_path}")
        except json.JSONDecodeError as e:
            print(f"Warning: Invalid JSON in {report_path}: {e}")
        except PermissionError:
            print(f"Warning: Permission denied reading {report_path}")
        except IOError as e:
            print(f"Warning: IO Error reading {report_path}: {e}")
    unique_targets_count = len(set(vulnerable_targets))

    # Generate Markdown Content
    md_content = f"""# Full Vulnerability Scan Report - {title}

**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
**Scan Tool:** PPMAP v4.0.0 (Enterprise)

## Executive Summary

A comprehensive automated scan was conducted on `{title}` targets to detect Prototype Pollution and associated vulnerabilities (XSS, RCE, WAF Bypass).

*   **Total Reports Analyzed:** {len(report_files)}
*   **Vulnerable Targets Found:** {unique_targets_count} (unique domains)
*   **Total Vulnerabilities Detected:** {sum(vuln_counts.values())}

### Vulnerability Statistics
"""

    for v_type, count in sorted(vuln_counts.items(), key=lambda x: x[1], reverse=True):
        md_content += f"- **{v_type.replace('_', ' ').title()}:** {count}\n"

    md_content += "\n## Critical Findings Overview\n\n"
    md_content += "The following targets exhibited high-severity vulnerabilities commonly associated with RCE or full system compromise:\n\n"

    # Helper to check criticality
    def is_critical(findings):
        for f in findings:
            if f.get("severity") == "CRITICAL":
                return True
            if "blitz" in f.get("type", "").lower():
                return True
            if "constructor" in f.get("type", "").lower():
                return True
        return False

    # List Critical Targets first
    for target, findings in findings_by_target.items():
        if is_critical(findings):
            md_content += f"- **{target}** (CRITICAL)\n"

    md_content += "\n## Detailed Findings by Target\n"

    # Sort targets alphabetically
    for target in sorted(findings_by_target.keys()):
        findings = findings_by_target[target]
        md_content += f"\n### Target: {target}\n"

        # Group by severity
        findings.sort(key=lambda x: x.get("severity", "LOW"), reverse=True)

        for i, finding in enumerate(findings, 1):
            severity = finding.get("severity", "UNKNOWN")
            vuln_type = finding.get("type", "Unknown Type").replace("_", " ").title()
            description = finding.get("description", "No description provided.")
            payload = finding.get("payload", "N/A")

            # Severity Icon
            icon = (
                "🔴" if severity == "CRITICAL" else "🟠" if severity == "HIGH" else "🟡"
            )

            md_content += f"\n#### {i}. {icon} {vuln_type} ({severity})\n"
            md_content += f"- **Description:** {description}\n"
            if payload != "N/A":
                md_content += f"- **Payload:** `{payload}`\n"
            if "component" in finding:
                md_content += f"- **Component:** {finding['component']}\n"
            if "method" in finding:
                md_content += f"- **Method:** {finding['method']}\n"

    md_content += "\n---\n*Report generated automatically by PPMAP Analyzer Agent.*\n"

    try:
        with open(output_file, "w", encoding="utf-8") as f:
            f.write(md_content)
    except IOError as e:
        print(f"Error writing report to {output_file}: {e}")
        return

    print("""
    ____  ____  __  __    _    ____  
   |  _ \|  _ \|  \/  |  / \  |  _ \ 
   | |_) | |_) | |\/| | / _ \ | |_) |
   |  __/|  __/| |  | |/ ___ \|  __/ 
   |_|   |_|   |_|  |_/_/   \_\_|    
                                     
   Prototype Pollution Multi-Purpose Assessment Platform
   v4.0.0 Enterprise (Scanner | Browser | 0-Day | OOB)
""")
    print(f"Report successfully generated at: {os.path.abspath(output_file)}")


def main():
    parser = argparse.ArgumentParser(description="PPMAP Markdown Report Generator")
    parser.add_argument(
        "--dir",
        default="report",
        help="Directory containing report.json files (default: 'report')",
    )
    parser.add_argument(
        "--title",
        default="Target Project",
        help="Title for the report (e.g., 'Company XYZ')",
    )
    parser.add_argument(
        "--out", default="full_scan_report.md", help="Output Markdown file name"
    )
    args = parser.parse_args()

    generate_markdown_report(args.dir, args.title, args.out)


if __name__ == "__main__":
    main()
