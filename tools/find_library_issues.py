import json
import glob
import argparse
from pathlib import Path


def check_reports(report_dir: str):
    base_path = Path(report_dir).resolve()
    if not base_path.exists() or not base_path.is_dir():
        print(f"Error: Directory '{report_dir}' not found.")
        return

    # Search for all report.json files recursively up to a reasonable depth
    patterns = [str(base_path / "*/report.json"), str(base_path / "*/*/report.json")]

    files = []
    for p in patterns:
        files.extend(glob.glob(p))

    # Remove duplicates
    files = list(set(files))

    print(f"Found {len(files)} report files in '{report_dir}'.")
    print("""
    ____  ____  __  __    _    ____  
   |  _ \|  _ \|  \/  |  / \  |  _ \ 
   | |_) | |_) | |\/| | / _ \ | |_) |
   |  __/|  __/| |  | |/ ___ \|  __/ 
   |_|   |_|   |_|  |_/_/   \_\_|    
                                     
   Prototype Pollution Multi-Purpose Assessment Platform
   v4.0.0 Enterprise (Scanner | Browser | 0-Day | OOB)
""")

    targets = {}

    for fpath in files:
        try:
            with open(fpath) as f:
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

        except FileNotFoundError:
            print(f"Warning: File not found {fpath}")
        except json.JSONDecodeError as e:
            print(f"Warning: Invalid JSON in {fpath}: {e}")
        except PermissionError:
            print(f"Warning: Permission denied reading {fpath}")
        except IOError as e:
            print(f"Warning: IO Error reading {fpath}: {e}")

    # Print results
    for target, items in targets.items():
        print(f"\nTarget: {target}")
        for item in items:
            print(f"  - Type: {item.get('type')}")
            print(f"    Severity: {item.get('severity')}")
            print(f"    Desc: {item.get('description')}")
            print(f"    CVE: {item.get('cve', 'N/A')}")


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
