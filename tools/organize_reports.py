import os
import shutil
import argparse


def organize_reports(source_dir: str, dest_base: str, match_string: str = None):
    if not os.path.exists(dest_base):
        try:
            os.makedirs(dest_base)
        except OSError as e:
            print(f"Error creating destination directory '{dest_base}': {e}")
            return

    print("""
    ____  ____  __  __    _    ____  
   |  _ \|  _ \|  \/  |  / \  |  _ \ 
   | |_) | |_) | |\/| | / _ \ | |_) |
   |  __/|  __/| |  | |/ ___ \|  __/ 
   |_|   |_|   |_|  |_/_/   \_\_|    
                                     
   Prototype Pollution Multi-Purpose Assessment Platform
   v4.0.0 Enterprise (Scanner | Browser | 0-Day | OOB)
""")
    print(f"Scanning {source_dir}...")

    count = 0
    try:
        items = os.listdir(source_dir)
    except OSError as e:
        print(f"Error reading source directory '{source_dir}': {e}")
        return

    for item in items:
        src_path = os.path.join(source_dir, item)
        if not os.path.isdir(src_path):
            continue

        if match_string and match_string not in item:
            continue

        try:
            # Fallback logic if the pattern isn't timestamped exactly like before
            if "_" in item:
                parts = item.split("_", 1)  # split at first underscore
                subdomain = parts[0].replace("_", ".")
                timestamp = parts[1]
            else:
                subdomain = "unknown"
                timestamp = item

            if subdomain == "":
                subdomain = "root"

            dest_dir = os.path.join(dest_base, subdomain, timestamp)

            if os.path.exists(dest_dir):
                print(f"Skipping {item}, dest exists")
                continue

            os.makedirs(os.path.dirname(dest_dir), exist_ok=True)

            print(f"Moving {item} -> {dest_dir}")
            shutil.move(src_path, dest_dir)
            count += 1

        except (OSError, shutil.Error) as e:
            print(f"Error processing {item}: {e}")

    print(f"Organized {count} reports.")


def main():
    parser = argparse.ArgumentParser(description="PPMAP Report Organizer")
    parser.add_argument(
        "--src", default="report", help="Source directory containing raw reports"
    )
    parser.add_argument(
        "--dest", default="bug_bounty_reports", help="Destination base directory"
    )
    parser.add_argument(
        "--match",
        help="Optional string that directory names must contain to be processed",
    )
    args = parser.parse_args()

    organize_reports(args.src, args.dest, args.match)


if __name__ == "__main__":
    main()
