import json
import glob
import argparse
import logging
from pathlib import Path

# ============================================================================
# LOGGING SETUP
# ============================================================================
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


def check_reports(report_dir: str, domain_pattern: str = "*"):
    """
    Check for library-related vulnerabilities in reports.
    
    Args:
        report_dir: Directory containing reports
        domain_pattern: Domain pattern to search for (default: * for all)
    """
    base_path = Path(report_dir).resolve()
    if not base_path.exists() or not base_path.is_dir():
        logger.error(f"Directory '{report_dir}' not found")
        return {}

    # Search for all report.json files recursively up to a reasonable depth
    patterns = [
        str(base_path / f"*{domain_pattern}*/report.json"),
        str(base_path / f"*/*{domain_pattern}*/report.json"),
    ]

    files = []
    for p in patterns:
        files.extend(glob.glob(p))

    # Remove duplicates
    files = list(set(files))
    
    if not files:
        logger.warning(f"No report files found matching pattern '{domain_pattern}' in '{report_dir}'")
        return {}

    logger.info(f"Found {len(files)} report files")

    targets = {}

    for fpath in files:
        try:
            with open(fpath, encoding="utf-8") as f:
                data = json.load(f)

            target = data.get("target", "unknown")
            findings = data.get("findings", [])

            lib_findings = []
            for find in findings:
                ftype = find.get("type", "").lower()
                desc = find.get("description", "").lower()

                # Check for jQuery or Vue or Older Libraries
                # Also checks for 'vulnerable' keyword in description just in case
                if (
                    (
                        ("jquery" in ftype or "jquery" in desc)
                        and "vulnerable" in desc.lower()
                    )
                    or ("vue" in ftype or "vue" in desc)
                    or ("library" in ftype and "vulnerable" in desc.lower())
                ):
                    lib_findings.append(find)

            if lib_findings:
                targets[target] = lib_findings
                logger.info(f"{target}: Found {len(lib_findings)} library-related vulnerabilities")

        except FileNotFoundError:
            logger.warning(f"File not found {fpath}")
        except json.JSONDecodeError as e:
            logger.warning(f"Invalid JSON in {fpath}: {e}")
        except PermissionError:
            logger.warning(f"Permission denied reading {fpath}")
        except IOError as e:
            logger.warning(f"IO Error reading {fpath}: {e}")

    return targets


def main():
    parser = argparse.ArgumentParser(
        description="Find library-related vulnerabilities in scan reports"
    )
    parser.add_argument(
        "--report-dir",
        default="report",
        help="Report directory (default: report)"
    )
    parser.add_argument(
        "--domain",
        default="*",
        help="Domain pattern to search for (default: * for all)"
    )
    args = parser.parse_args()

    print(r"""
    ____  ____  __  __    _    ____  
   |  _ \|  _ \|  \/  |  / \  |  _ \ 
   | |_) | |_) | |\/| | / _ \ | |_) |
   |  __/|  __/| |  | |/ ___ \|  __/ 
   |_|   |_|   |_|  |_/_/   \_\_|    
                                     
   Prototype Pollution Multi-Purpose Assessment Platform
   v4.1.0 Enterprise (Scanner | Browser | 0-Day | OOB)
""")

    logger.info(f"Searching for library issues with domain pattern: {args.domain}")
    targets = check_reports(args.report_dir, args.domain)

    if not targets:
        print("No library-related vulnerabilities found.\n")
        return

    # Print results
    for target, items in targets.items():
        print(f"\nTarget: {target}")
        for item in items:
            print(f"  - Type: {item.get('type')}")
            print(f"    Severity: {item.get('severity')}")
            print(f"    Desc: {item.get('description')}")
            print(f"    CVE: {item.get('cve', 'N/A')}")


if __name__ == "__main__":
    main()


def main():
    parser = argparse.ArgumentParser(description="PPMAP Library Vulnerability Finder")
    parser.add_argument(
        "--dir",
        default="report",
        help="Directory containing report.json files (default: 'report')",
    )
    args = parser.parse_args()

    check_reports(args.dir)


if __name__ == "__main__":
    main()
