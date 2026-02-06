
import json
import glob
from collections import defaultdict

def analyze_reports():
    # Find all report.json files in subdirectories of report/
    report_files = glob.glob('report/*/report.json')
    
    summary = []
    
    for file_path in report_files:
        try:
            with open(file_path, 'r') as f:
                data = json.load(f)
                
            target = data.get('target', 'Unknown')
            findings = data.get('findings', [])
            
            if not findings:
                continue
                
            # Group findings by type
            vuln_counts = defaultdict(int)
            vuln_severities = {}
            
            for finding in findings:
                ftype = finding.get('type', 'Unknown')
                severity = finding.get('severity', 'Info')
                vuln_counts[ftype] += 1
                vuln_severities[ftype] = severity
            
            summary.append({
                'target': target,
                'counts': dict(vuln_counts),
                'severities': vuln_severities,
                'file': file_path
            })
            
        except Exception as e:
            print(f"Error reading {file_path}: {e}")

    # Sort by 'critical' or 'high' presence first
    # We'll just print them out nicely
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
   v4.0.0 Enterprise (Scanner | Browser | 0-Day | OOB)
""")
    print(f"{'Target':<40} | {'Type':<30} | {'Severity':<10}")
    print("-" * 125)
    
    for item in summary:
        first = True
        for vtype, count in item['counts'].items():
            severity = item['severities'][vtype]
            target_str = item['target'] if first else ""
            print(f"{target_str:<60} | {vtype:<40} | {count:<5} | {severity:<10}")
            first = False
        print("-" * 125)

if __name__ == "__main__":
    analyze_reports()
