import re
import sys

def main():
    try:
        # 1. Read ppmap/utils.py and add Colors
        with open("ppmap/utils.py", "r") as f:
            utils_code = f.read()

        colors_class = """
class Colors:
    HEADER = '\\033[95m'
    BLUE = '\\033[94m'
    CYAN = '\\033[96m'
    GREEN = '\\033[92m'
    YELLOW = '\\033[93m'
    WARNING = '\\033[93m'
    FAIL = '\\033[91m'
    ENDC = '\\033[0m'
    BOLD = '\\033[1m'
"""
        
        if "class Colors:" not in utils_code:
            with open("ppmap/utils.py", "w") as f:
                f.write(utils_code + "\n" + colors_class)
                
        # 2. Remove Colors from ppmap.py
        with open("ppmap.py", "r") as f:
            ppmap_code = f.read()
            
        color_pattern = re.compile(r'class Colors:.*?BOLD = \'\\033\[1m\'\n', re.DOTALL)
        ppmap_code = color_pattern.sub('', ppmap_code)
        
        with open("ppmap.py", "w") as f:
            f.write(ppmap_code)
            
        print("Successfully moved Colors to ppmap/utils.py.")
            
    except Exception as e:
        print(f"Failed to move Colors: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
