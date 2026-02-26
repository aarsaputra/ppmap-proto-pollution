import json
import glob
import argparse
import hashlib
from pathlib import Path
from collections import defaultdict


def summarize_vulnerabilities(report_dir: str):
    base_path = Path(report_dir).resolve()
    if not base_path.exists() or not base_path.is_dir():
        print(f"Error: Directory '{report_dir}' not found.")
        return

    search_pattern = str(base_path / "*/report.json")
    report_files = glob.glob(search_pattern)
    vulnerable_targets = []

    total_scanned = len(report_files)

    print(f"Total Reports Found: {total_scanned}")
    print("-" * 80)
    print(r"""
    ____  ____  __  __    _    ____  
   |  _ \|  _ \|  \/  |  / \  |  _ \ 
   | |_) | |_) | |\/| | / _ \ | |_) |
   |  __/|  __/| |  | |/ ___ \|  __/ 
   |_|   |_|   |_|  |_/_/   \_\_|    
                                     
   Prototype Pollution Multi-Purpose Assessment Platform
   v4.0.0 Enterprise (Scanner | Browser | 0-Day | OOB)
""")
    print(f"{'Target':<40} | {'Type':<30} | {'Severity':<10}")
    print("-" * 80)

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
                    print(f"{target:<40} | {v_type:<30} | {severity:<10}")
                    vuln_counts[v_type] += 1

        except FileNotFoundError:
            print(f"Warning: File not found {report_path}")
        except json.JSONDecodeError as e:
            print(f"Warning: Invalid JSON in {report_path}: {e}")
        except PermissionError:
            print(f"Warning: Permission denied reading {report_path}")
        except IOError as e:
            print(f"Warning: IO Error reading {report_path}: {e}")
    print("-" * 80)
    print(f"Total Vulnerable Targets: {len(set(vulnerable_targets))}")
    print("\nVulnerability Summary:")
    for v_type, count in vuln_counts.items():
        print(f"  - {v_type}: {count}")


def diff_scan_results(file1_path: str, file2_path: str):
    """Compare two JSON scan result files and report differences."""
    print(f"Comparing {file1_path} vs {file2_path}")
    print("-" * 80)

    path1, path2 = Path(file1_path), Path(file2_path)
    if not path1.exists() or not path2.exists():
        print("Error: One or both input files do not exist.")
        return

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

        print(f"Base Findings (File 1): {len(set1)}")
        print(f"New Findings (File 2):  {len(set2)}")
        print("-" * 80)

        if new_findings:
            print("\n[+] NEW VULNERABILITIES FOUND:")
            for item in new_findings:
                print(f"  Target: {item[0]}")
                print(f"  Type:   {item[1]}")
                print(f"  Param:  {item[2]}")
                print(f"  Ref:    {item[3]}...")
                print("")
        else:
            print("\n[+] No new vulnerabilities found.")

        if fixed_findings:
            print("\n[-] VULNERABILITIES FIXED/GONE:")
            for item in fixed_findings:
                print(f"  Target: {item[0]}")
                print(f"  Type:   {item[1]}")
                print(f"  Param:  {item[2]}")
                print("")
        else:
            print("\n[-] No regressions or fixes detected.")

    except json.JSONDecodeError as e:
        print(f"Error parsing JSON files: {e}")
    except Exception as e:
        print(f"Unexpected error comparing files: {e}")


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
    args = parser.parse_args()

    if args.diff:
        diff_scan_results(args.diff[0], args.diff[1])
    else:
        summarize_vulnerabilities(args.dir)


if __name__ == "__main__":
    main()
