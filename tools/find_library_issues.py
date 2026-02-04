
import json
import glob
import os


def check_reports():
    # Search in both 'report' and 'reports' directories
    patterns = [
        'report/*exabytes_co_id*/report.json',
        'reports/*exabytes_co_id*/report.json',
        'report/*/*exabytes_co_id*/report.json', # In case of nested structure
    ]
    
    files = []
    for p in patterns:
        files.extend(glob.glob(p))
    
    # Remove duplicates
    files = list(set(files))
    
    print(f"Found {len(files)} exabytes report files.")
    print("""
    ____  ____  __  __    _    ____  
   |  _ \|  _ \|  \/  |  / \  |  _ \ 
   | |_) | |_) | |\/| | / _ \ | |_) |
   |  __/|  __/| |  | |/ ___ \|  __/ 
   |_|   |_|   |_|  |_/_/   \_\_|    
                                     
   Prototype Pollution Multi-Purpose Assessment Platform
   v3.7.0 Enterprise (Scanner | Browser | 0-Day)
""")
    
    targets = {}
    
    for fpath in files:
        try:
            with open(fpath) as f:
                data = json.load(f)
            
            target = data.get('target', 'unknown')
            findings = data.get('findings', [])
            
            lib_findings = []
            for find in findings:
                ftype = find.get('type', '').lower()
                desc = find.get('description', '').lower()
                payload = find.get('payload', '').lower()
                
                # Check for jQuery or Vue or Older Libraries
                # Also checks for 'vulnerable' keyword in description just in case
                if (('jquery' in ftype or 'jquery' in desc) and 'vulnerable' in desc.lower()) or \
                   ('vue' in ftype or 'vue' in desc) or \
                   ('library' in ftype and 'vulnerable' in desc.lower()):
                    lib_findings.append(find)

            
            if lib_findings:
                targets[target] = lib_findings
                
        except Exception:
            pass
            
    # Print results
    for target, items in targets.items():
        print(f"\nTarget: {target}")
        for item in items:
            print(f"  - Type: {item.get('type')}")
            print(f"    Severity: {item.get('severity')}")
            print(f"    Desc: {item.get('description')}")
            print(f"    CVE: {item.get('cve', 'N/A')}")
            
if __name__ == "__main__":
    check_reports()
