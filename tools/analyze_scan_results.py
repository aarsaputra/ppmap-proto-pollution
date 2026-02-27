import json
import glob
import argparse
import hashlib
import logging
from pathlib import Path
from collections import defaultdict

# ============================================================================
# LOGGING SETUP
# ============================================================================
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

# ============================================================================
# SECURITY FUNCTIONS
# ============================================================================


def validate_file_path(filepath: str, allowed_dir: Path) -> Path:
    """Validate file path against directory traversal."""
    try:
        path = Path(filepath).resolve()
        # Ensure the resolved path starts with the resolved allowed_dir
        # This prevents ../../etc/passwd type attacks
        if not path.is_relative_to(allowed_dir):
            logger.error(f"🔴 SECURITY: Path traversal attack detected!")
            logger.error(f"   Attempted to access: {path}")
            logger.error(f"   Allowed directory: {allowed_dir}")
            logger.error(f"   Access DENIED")
            return None

        if not path.exists():
            logger.error(f"File not found: {filepath}")
            return None

        if not path.is_file():
            logger.error(f"Not a valid file: {filepath}")
            return None

        logger.info(f"✅ Validated file: {path}")
        return path
    except Exception as e:
        logger.error(f"Error validating path '{filepath}': {e}")
        return None


def summarize_vulnerabilities(report_dir: str):
    base_path = Path(report_dir).resolve()
    if not base_path.exists() or not base_path.is_dir():
        logger.error(f"Directory '{report_dir}' not found.")
        return

    search_pattern = str(base_path / "*/report.json")
    report_files = glob.glob(search_pattern)
    vulnerable_targets = []

    total_scanned = len(report_files)

    logger.info(f"Total Reports Found: {total_scanned}")
    logger.info("-" * 80)
    logger.info(r"""
    ____  ____  __  __    _    ____  
   |  _ \|  _ \|  \/  |  / \  |  _ \ 
   | |_) | |_) | |\/| | / _ \ | |_) |
   |  __/|  __/| |  | |/ ___ \|  __/ 
   |_|   |_|   |_|  |_/_/   \_\_|    
                                     
   Prototype Pollution Multi-Purpose Assessment Platform
   v4.0.0 Enterprise (Scanner | Browser | 0-Day | OOB)
""")
    logger.info(f"{'Target':<40} | {'Type':<30} | {'Severity':<10}")
    logger.info("-" * 80)

    vuln_counts = defaultdict(int)

    for report_path in report_files:
        try:
            with open(report_path, "r", encoding="utf-8") as f:
                data = json.load(f)

            target = data.get("target", "Unknown")
            findings = data.get("findings", [])

            real_vulns = []
            for finding in findings:
                f_type = finding.get("type")
                # Filter out informational findings
                if f_type not in ["discovered_endpoint", "info"]:
                    real_vulns.append(finding)

            if real_vulns:
                vulnerable_targets.append(target)
                for vuln in real_vulns:
                    v_type = vuln.get("type", "unknown")
                    severity = vuln.get("severity", "UNKNOWN")
                    logger.info(f"{target:<40} | {v_type:<30} | {severity:<10}")
                    vuln_counts[v_type] += 1

        except FileNotFoundError:
            logger.warning(f"File not found {report_path}")
        except json.JSONDecodeError as e:
            logger.warning(f"Invalid JSON in {report_path}: {e}")
        except PermissionError:
            logger.warning(f"Permission denied reading {report_path}")
        except IOError as e:
            logger.warning(f"IO Error reading {report_path}: {e}")
    logger.info("-" * 80)
    logger.info(f"Total Vulnerable Targets: {len(set(vulnerable_targets))}")
    logger.info("\nVulnerability Summary:")
    for v_type, count in vuln_counts.items():
        logger.info(f"  - {v_type}: {count}")


def diff_scan_results(file1_path: str, file2_path: str, report_dir: str):
    """Compare two JSON scan result files and report differences."""

    allowed_dir = Path(report_dir).resolve()
    path1 = validate_file_path(file1_path, allowed_dir)
    path2 = validate_file_path(file2_path, allowed_dir)

    if not path1 or not path2:
        logger.error("Cannot compare: One or both files failed validation")
        return

    logger.info(f"Comparing {path1.name} vs {path2.name}")
    logger.info("-" * 80)

    try:
        with open(path1, "r", encoding="utf-8") as f1, open(
            path2, "r", encoding="utf-8"
        ) as f2:
            data1 = json.load(f1)
            data2 = json.load(f2)

        # Helper to extract unique finding identifiers
        def get_findings_set(data):
            findings = set()
            target = data.get("target", "Unknown")
            for f in data.get("findings", []):
                # Create a unique tuple for each finding using a secure hash
                ftype = f.get("type", "unknown")
                param = f.get("parameter", "global")
                payload_str = json.dumps(f.get("payload", ""))
                payload_hash = hashlib.sha256(payload_str.encode()).hexdigest()[:12]
                findings.add((target, ftype, param, payload_hash))
            return findings

        set1 = get_findings_set(data1)
        set2 = get_findings_set(data2)

        new_findings = set2 - set1
        fixed_findings = set1 - set2

        logger.info(f"Base Findings (File 1): {len(set1)}")
        logger.info(f"New Findings (File 2):  {len(set2)}")
        logger.info("-" * 80)

        if new_findings:
            logger.info("\n[+] NEW VULNERABILITIES FOUND:")
            for item in new_findings:
                logger.info(f"  Target: {item[0]}")
                logger.info(f"  Type:   {item[1]}")
                logger.info(f"  Param:  {item[2]}")
                logger.info(f"  Ref:    {item[3]}...")
                logger.info("")
        else:
            logger.info("\n[+] No new vulnerabilities found.")

        if fixed_findings:
            logger.info("\n[-] VULNERABILITIES FIXED/GONE:")
            for item in fixed_findings:
                logger.info(f"  Target: {item[0]}")
                logger.info(f"  Type:   {item[1]}")
                logger.info(f"  Param:  {item[2]}")
                logger.info("")
        else:
            logger.info("\n[-] No regressions or fixes detected.")

    except json.JSONDecodeError as e:
        logger.error(f"Invalid JSON in files: {e}")
    except Exception as e:
        logger.error(f"Unexpected error comparing files: {e}", exc_info=True)


def main():
    parser = argparse.ArgumentParser(description="PPMAP Scan Results Analyzer & Differ")
    parser.add_argument(
        "--dir", default="report", help="Directory containing reports to summarize"
    )
    parser.add_argument(
        "--diff",
        nargs=2,
        metavar=("FILE1", "FILE2"),
        help="Compare two exact report files",
    )
    # The --allowed-dir argument is now implicitly handled by --dir for diff mode
    # as diff_scan_results uses report_dir for validation.
    # Removed --allowed-dir as it's redundant with --dir for diff validation.
    args = parser.parse_args()

    if args.diff:
        logger.info(
            f"Diff mode: comparing {args.diff[0]} vs {args.diff[1]} within directory '{args.dir}'"
        )
        diff_scan_results(args.diff[0], args.diff[1], args.dir)
    else:
        logger.info(f"Summary mode: analyzing reports in {args.dir}")
        summarize_vulnerabilities(args.dir)


if __name__ == "__main__":
    main()
