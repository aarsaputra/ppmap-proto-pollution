import os
import shutil

SOURCE_DIR = "report"
DEST_BASE = "bug_bunty/reports"

if not os.path.exists(DEST_BASE):
    os.makedirs(DEST_BASE)

print("""
    ____  ____  __  __    _    ____  
   |  _ \|  _ \|  \/  |  / \  |  _ \ 
   | |_) | |_) | |\/| | / _ \ | |_) |
   |  __/|  __/| |  | |/ ___ \|  __/ 
   |_|   |_|   |_|  |_/_/   \_\_|    
                                     
   Prototype Pollution Multi-Purpose Assessment Platform
   v4.0.0 Enterprise (Scanner | Browser | 0-Day | OOB)
""")
print(f"Scanning {SOURCE_DIR}...")

count = 0
for item in os.listdir(SOURCE_DIR):
    src_path = os.path.join(SOURCE_DIR, item)
    if not os.path.isdir(src_path):
        continue
    
    # Pattern: {subdomain}_domainesia_com_{timestamp}
    if "domainesia_com" in item:
        try:
            parts = item.split("_domainesia_com_")
            if len(parts) != 2:
                continue
                
            subdomain_part = parts[0]
            timestamp = parts[1]
            
            # Fix subdomain: alessandria_id -> alessandria.id (heuristic)
            # What if it was sub-sub? sub_sub -> sub.sub
            # This is best effort.
            subdomain = subdomain_part.replace("_", ".")
            if subdomain == "":
                subdomain = "root"
                
            main_domain = "domainesia.com"
            
            # Create dest: bug_bunty/reports/domainesia.com/subdomain/timestamp/
            # Actually, let's make the folder name just the timestamp inside subdomain
            dest_dir = os.path.join(DEST_BASE, main_domain, subdomain, timestamp)
            
            if os.path.exists(dest_dir):
                print(f"Skipping {item}, dest exists")
                continue
                
            os.makedirs(os.path.dirname(dest_dir), exist_ok=True)
            
            print(f"Moving {item} -> {dest_dir}")
            shutil.move(src_path, dest_dir)
            count += 1
            
        except Exception as e:
            print(f"Error {item}: {e}")

print(f"Organized {count} reports.")
