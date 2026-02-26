#!/usr/bin/env python3
"""
PPMAP v4.0.0 - Manual Testing Interactive Guide
Memandu pengguna untuk testing manual hasil scan di browser console
"""

import sys
import os
import json

try:
    from colorama import Fore, Style, init

    init(autoreset=True)
except ImportError:

    class DummyColor:
        def __getattr__(self, name):
            return ""

    Fore = Style = DummyColor()


class ManualTestingGuide:
    def __init__(self):
        self.current_section = 0
        self.payloads = self._load_payloads()

    def _load_payloads(self):
        """Load payload examples from external config"""
        # Resolve path relative to this script: tools/../ppmap/config/payloads.json
        script_dir = os.path.dirname(os.path.abspath(__file__))
        payload_path = os.path.join(
            script_dir, "..", "ppmap", "config", "payloads.json"
        )

        try:
            with open(payload_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except FileNotFoundError:
            print(
                f"{Fore.RED}Error: Payload config not found at {payload_path}{Style.RESET_ALL}"
            )
        except json.JSONDecodeError as e:
            print(
                f"{Fore.RED}Error: Invalid JSON syntax in payload config: {e}{Style.RESET_ALL}"
            )
        except Exception as e:
            print(f"{Fore.RED}Error loading payloads: {e}{Style.RESET_ALL}")

        # Optional safe fallback if loading fails
        print(
            f"{Fore.YELLOW}Warning: Falling back to empty payloads. Fix payloads.json to continue.{Style.RESET_ALL}"
        )
        return {}

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
            print(
                f"     Severity: {Fore.RED if 'CRITICAL' in vuln['severity'] else Fore.YELLOW}{vuln['severity']}{Style.RESET_ALL}\n"
            )

        print("  0. Exit")
        while True:
            choice = input(
                f"{Fore.CYAN}Pilih nomor (0-{len(items)}): {Style.RESET_ALL}"
            ).strip()

            try:
                choice_int = int(choice)
                if choice_int == 0:
                    print(
                        f"{Fore.GREEN}Terima kasih! Selamat testing! 🚀{Style.RESET_ALL}"
                    )
                    sys.exit(0)
                elif 1 <= choice_int <= len(items):
                    return items[choice_int - 1]
                else:
                    print(
                        f"{Fore.RED}Please enter a number between 0 and {len(items)}.{Style.RESET_ALL}"
                    )
            except ValueError:
                print(
                    f"{Fore.RED}Invalid choice! Please enter a number.{Style.RESET_ALL}"
                )

    def show_vulnerability_details(self, vuln_key):
        """Show detailed payload for vulnerability"""
        vuln = self.payloads[vuln_key]

        while True:
            print(f"\n{Fore.CYAN}{'='*70}")
            print(f"{Fore.CYAN}{vuln['name']} ({vuln['severity']})")
            print(f"{Fore.CYAN}{'='*70}\n")

            print(f"{Fore.YELLOW}STEP-BY-STEP TESTING:\n")

            payloads = vuln["payloads"]
            for i, payload in enumerate(payloads, 1):
                print(f"{Fore.GREEN}[Test {i}] {payload['name']}")
                print(f"  {Fore.CYAN}Langkah:")

                if "code" in payload:
                    print("    1. Buka browser console (F12 → Console tab)")
                    print("    2. Copy & paste code ini:")
                    print(f"\n{Fore.MAGENTA}       {payload['code']}")
                    print(
                        f"\n{Fore.CYAN}    3. Jalankan, lalu jalankan verification code:"
                    )
                    print(f"\n{Fore.MAGENTA}       {payload['verify']}")
                    print(f"\n{Fore.CYAN}    4. Expected result:")
                    print(f"{Fore.GREEN}       {payload['expected']}\n")

                elif "url" in payload:
                    print("    1. Tambahkan payload ini ke URL:")
                    print(f"\n{Fore.MAGENTA}       {payload['url']}")
                    if "alternative" in payload:
                        print(f"\n{Fore.CYAN}    Alternative:")
                        print(f"{Fore.MAGENTA}       {payload['alternative']}")
                    if "note" in payload:
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

            while True:
                choice = input(f"{Fore.CYAN}Pilih (0-2): {Style.RESET_ALL}").strip()
                if choice in ["0", "1", "2"]:
                    break
                print(
                    f"{Fore.RED}Invalid choice. Please enter 0, 1, or 2.{Style.RESET_ALL}"
                )

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
            name = payload.get("name", "Untitled")
            print(f"  {i}. {name}")

        choice = input(
            f"\n{Fore.CYAN}Pilih (1-{len(payloads)}): {Style.RESET_ALL}"
        ).strip()

        try:
            choice = int(choice)
            if 1 <= choice <= len(payloads):
                payload = payloads[choice - 1]

                # Create copyable format
                if "code" in payload:
                    code = payload["code"]
                    verify = payload["verify"]
                    expected = payload["expected"]

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

                    # ensure safe print encoding by catching UnicodeEncodeError
                    try:
                        print(f"{Fore.MAGENTA}{content}")
                    except UnicodeEncodeError:
                        print(content.encode("utf-8", errors="replace").decode("utf-8"))

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
        "Check Function.proto": "constructor.constructor.prototype.test = 1; ({}).test",
        "Check React": 'typeof React !== "undefined" ? "React Found" : "Not Found"',
        "Check Charset": "document.charset || document.characterSet",
        "Check __proto__": r"({}).__proto__.constructor.name",
        "Cleanup": "delete Object.prototype.test",
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
