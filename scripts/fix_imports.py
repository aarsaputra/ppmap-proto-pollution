import re
import sys

def main():
    try:
        with open("ppmap.py", "r") as f:
            code = f.read()

        original_code = code

        # The issue is the old import:
        # from ppmap.scanner import (
        #     AsyncScanner, PrototypePollutionVerifier, 
        #     WAFBypassPayloads, EndpointDiscovery, ParameterDiscovery, QuickPoC
        # )
        
        # We need to remove this entirely because we moved the core scanner
        # into ppmap.scanner.core and other things might be referencing it improperly.
        
        pattern = re.compile(r'from ppmap\.scanner import \(\n.*?AsyncScanner.*?\n\)', re.DOTALL)
        code = pattern.sub('', code)
        
        # Also fix up the extra wrapper imports
        code = code.replace("from ppmap.scanner import AsyncScanner, PrototypePollutionVerifier", "")

        if code != original_code:
            with open("ppmap.py", "w") as f:
                f.write(code)
            print("Successfully removed broken scanner imports from ppmap.py.")
        else:
            print("Could not find the broken imports.")
            
    except Exception as e:
        print(f"Failed to fix imports: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
