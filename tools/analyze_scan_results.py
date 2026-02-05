
import json
import glob
from collections import defaultdict

def analyze_reports():
    report_files = glob.glob("report/*/report.json")
    vulnerable_targets = []
    
    total_scanned = len(report_files)
    
    print(f"Total Reports Found: {total_scanned}")
    print("-" * 80)
    print("""
    ____  ____  __  __    _    ____  
   |  _ \|  _ \|  \/  |  / \  |  _ \ 
   | |_) | |_) | |\/| | / _ \ | |_) |
   |  __/|  __/| |  | |/ ___ \|  __/ 
   |_|   |_|   |_|  |_/_/   \_\_|    
                                     
   Prototype Pollution Multi-Purpose Assessment Platform
   v3.7.0 Enterprise (Scanner | Browser | 0-Day)
""")
    print(f"{'Target':<40} | {'Type':<30} | {'Severity':<10}")
    print("-" * 80)
    
    vuln_counts = defaultdict(int)
    
    for report_path in report_files:
        try:
            with open(report_path, 'r') as f:
                data = json.load(f)
                
            target = data.get('target', 'Unknown')
            findings = data.get('findings', [])
            
            real_vulns = []
            for finding in findings:
                f_type = finding.get('type')
                # Filter out informational findings
                if f_type not in ['discovered_endpoint', 'info']:
                    real_vulns.append(finding)
            
            if real_vulns:
                vulnerable_targets.append(target)
                for vuln in real_vulns:
                    v_type = vuln.get('type', 'unknown')
                    severity = vuln.get('severity', 'UNKNOWN')
                    print(f"{target:<40} | {v_type:<30} | {severity:<10}")
                    vuln_counts[v_type] += 1
                    
        except Exception as e:
            print(f"Error parsing {report_path}: {str(e)}")
            
    print("-" * 80)
    print(f"Total Vulnerable Targets: {len(set(vulnerable_targets))}")
    print("\nVulnerability Summary:")
    for v_type, count in vuln_counts.items():
        print(f"  - {v_type}: {count}")


def diff_scan_results(file1_path, file2_path):
    """Compare two JSON scan result files and report differences."""
    print(f"Comparing {file1_path} vs {file2_path}")
    print("-" * 80)
    
    try:
        with open(file1_path, 'r') as f1, open(file2_path, 'r') as f2:
            data1 = json.load(f1)
            data2 = json.load(f2)
            
        # Helper to extract unique finding identifiers
        def get_findings_set(data):
            findings = set()
            target = data.get('target', 'Unknown')
            for f in data.get('findings', []):
                # Create a unique tuple for each finding: (type, parameter, payload_signature)
                # Using payload signature (or partial payload) to identifying unique vulns
                ftype = f.get('type', 'unknown')
                param = f.get('parameter', 'global')
                payload = f.get('payload', '')[:20] # truncate payload for signature
                findings.add((target, ftype, param, payload))
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
            
    except Exception as e:
        print(f"Error comparing files: {e}")

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 2 and sys.argv[1] == '--diff':
        diff_scan_results(sys.argv[2], sys.argv[3])
    else:
        analyze_reports()
