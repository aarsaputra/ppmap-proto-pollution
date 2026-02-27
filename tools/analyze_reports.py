import json
import glob
import argparse
import logging
import csv
from pathlib import Path
from collections import defaultdict

# ============================================================================
# LOGGING SETUP
# ============================================================================
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


def analyze_reports(report_dir: str):
    # Validate the report directory
    base_path = Path(report_dir).resolve()
    if not base_path.exists() or not base_path.is_dir():
        logger.error(
            f"Report directory '{report_dir}' does not exist or is not a directory"
        )
        return

    # Find all report.json files
    search_pattern = str(base_path / "*/report.json")
    report_files = glob.glob(search_pattern)

    if not report_files:
        logger.warning(f"No report files found in {report_dir}")
        return

    logger.info(f"Found {len(report_files)} report files")

    summary = []

    for file_path in report_files:
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                data = json.load(f)

            target = data.get("target", "Unknown")
            findings = data.get("findings", [])

            if not findings:
                logger.debug(f"No findings in {target}")
                continue

            # Group findings by type
            vuln_counts = defaultdict(int)
            vuln_severities = {}

            for finding in findings:
                ftype = finding.get("type", "Unknown")
                severity = finding.get("severity", "Info")
                vuln_counts[ftype] += 1
                vuln_severities[ftype] = severity

            summary.append(
                {
                    "target": target,
                    "counts": dict(vuln_counts),
                    "severities": vuln_severities,
                    "file": file_path,
                }
            )
            logger.info(f"Processed {target}: {sum(vuln_counts.values())} findings")
        except FileNotFoundError:
            logger.warning(f"File not found {file_path}")
        except json.JSONDecodeError as e:
            logger.warning(f"Invalid JSON in {file_path}: {e}")
        except PermissionError:
            logger.warning(f"Permission denied reading {file_path}")
        except IOError as e:
            logger.warning(f"IO Error reading {file_path}: {e}")

    return summary


def export_summary(summary: list, output_format: str, output_file: str):
    """Export summary in various formats."""
    # Print the banner and table if using table format
    if output_format == "table":
        total_reports = len(summary)
        print(f"Total Vulnerable Reports Found: {total_reports}")
        print("-" * 80)
        print(r"""
    ____  ____  __  __    _    ____  
   |  _ \|  _ \|  \/  |  / \  |  _ \ 
   | |_) | |_) | |\/| | / _ \ | |_) |
   |  __/|  __/| |  | |/ ___ \|  __/ 
   |_|   |_|   |_|  |_/_/   \_\_|    
                                     
   Prototype Pollution Multi-Purpose Assessment Platform
   v4.1.0 Enterprise (Scanner | Browser | 0-Day | OOB)
""")
        print(f"{'Target':<40} | {'Type':<30} | {'Severity':<10}")
        print("-" * 125)

        for item in summary:
            first = True
            for vtype, count in item["counts"].items():
                severity = item["severities"][vtype]
                target_str = item["target"] if first else ""
                print(f"{target_str:<60} | {vtype:<40} | {count:<5} | {severity:<10}")
                first = False
            print("-" * 125)

    elif output_format == "json":
        data = json.dumps(summary, indent=2)
        if output_file:
            with open(output_file, "w", encoding="utf-8") as f:
                f.write(data)
            logger.info(f"JSON summary exported to {output_file}")
        else:
            print(data)

    elif output_format == "csv":
        if output_file:
            with open(output_file, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["Target", "Vulnerability Type", "Count", "Severity"])
                for item in summary:
                    for vtype, count in item["counts"].items():
                        writer.writerow(
                            [
                                item["target"],
                                vtype,
                                count,
                                item["severities"].get(vtype, "UNKNOWN"),
                            ]
                        )
            logger.info(f"CSV summary exported to {output_file}")
        else:
            logger.error("CSV format requires an --out output file specified.")


def main():
    parser = argparse.ArgumentParser(description="PPMAP Report Analyzer")
    parser.add_argument(
        "--dir",
        default="report",
        help="Base directory containing scan reports (default: 'report')",
    )
    parser.add_argument(
        "--format",
        choices=["table", "csv", "json"],
        default="table",
        help="Output format (default: 'table')",
    )
    parser.add_argument(
        "--out",
        help="Output file path (required for csv, optional for json)",
    )
    args = parser.parse_args()

    logger.info(f"Analyzing reports in {args.dir}")
    summary = analyze_reports(args.dir)
    if summary is not None:
        export_summary(summary, args.format, args.out)


if __name__ == "__main__":
    main()
