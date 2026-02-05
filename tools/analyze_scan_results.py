
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

if __name__ == "__main__":
    analyze_reports()
