import argparse
import os
import sys
import time
import shlex
import recapture

def print_banner():
    print(r"""
  _____  ______  _____    _    _____  _______ _    _  _____  ______ 
 |  __ \|  ____|/ ____|  / \  |  __ \|__   __| |  | |/ ____||  ____|
 | |__) | |__  | |      / _ \ | |__) |  | |  | |  | | |  __ | |__   
 |  _  /|  __| | |     / /_\ \|  ___/   | |  | |  | | | |_ ||  __|  
 | | \ \| |____| |____/ ____ \| |       | |  | |__| | |__| || |____ 
 |_|  \_\______|\_____/_/   \_\_|       |_|   \____/ \_____||______|
                                              v1.0 | Gold Master CLI
    """) 

def print_legend():
    print("="*60)
    print("HTML REPORT LEGEND (How to read your results)")
    print("-" * 60)
    print(" [Strikethrough] : Deleted File (Recovered from MFT/FAT)")
    print(" [Red Text]      : Signature Mismatch (File extension is fake)")
    print(" [Purple Text]   : Keyword Hit (Contains suspect terms)")
    print(" [Bold/Red]      : Hash Alert (Matches known bad hash list)")
    print(" [Ghost Icon]    : Deleted/Unallocated Item")
    print("="*60 + "\n")

def main():
    print_banner()

    # --- INTERACTIVE MODE (For Double-Click Users) ---
    if len(sys.argv) == 1:
        print_legend()
        print("[*] Interactive Mode Detected (No arguments provided)")
        
        # 1. Ask for Target
        while True:
            target_input = input(">> Enter Target Path (Image/Drive/Folder): ").strip()
            # Remove quotes if user copied path as "C:\Path"
            if target_input.startswith('"') and target_input.endswith('"'):
                target_input = target_input[1:-1]
            
            if target_input and os.path.exists(target_input):
                break
            print("[!] Error: Path does not exist. Try again.")

        # 2. Ask for Output (Optional)
        out_input = input(f">> Enter Output Directory [Default: {os.getcwd()}]: ").strip()
        if out_input and out_input.startswith('"') and out_input.endswith('"'):
            out_input = out_input[1:-1]
        if not out_input:
            out_input = os.getcwd()

        # 3. Ask for Options
        skip_hash = input(">> Skip Hashing for speed? (y/N): ").lower().startswith('y')
        
        print("\n[*] Starting Scan...")
        run_scan_logic(target_input, out_input, None, skip_hash, "", "", "", "")
        
        # PAUSE AT THE END so window doesn't close
        print("\n" + "="*60)
        input("Press Enter to exit...")
        sys.exit(0)

    # --- STANDARD MODE (For CMD/Script Users) ---
    parser = argparse.ArgumentParser(description="Recapture Forensic Explorer - CLI Version")
    parser.add_argument("target", help="Path to Evidence File (E01/Raw) or Local Directory")
    parser.add_argument("-o", "--output", help="Output directory for the report", default=os.getcwd())
    parser.add_argument("-n", "--name", help="Custom filename for the report", default="")
    parser.add_argument("--hashlist", help="Path to text file containing bad hashes", default=None)
    parser.add_argument("--skip-hash", action="store_true", help="Skip file hashing (Faster Scan)")
    parser.add_argument("--legend", action="store_true", help="Show the Report Legend and exit")
    
    # Metadata
    parser.add_argument("--examiner", help="Name of the Examiner", default="")
    parser.add_argument("--ref", help="Case Reference Number", default="")
    parser.add_argument("--notes", help="Case Notes (surround with quotes)", default="")
    parser.add_argument("--keywords", help="Comma-separated list of keywords", default="")

    args = parser.parse_args()

    if args.legend:
        print_legend()
        sys.exit(0)

    # Determine Name
    final_name = args.name
    if not final_name:
        base = os.path.basename(args.target)
        final_name = f"Report_{base}.html"
    
    run_scan_logic(args.target, args.output, args.hashlist, args.skip_hash, args.examiner, args.ref, args.notes, args.keywords, final_name)

def run_scan_logic(target, out_dir, hashlist, skip, examiner, ref, notes, keywords, custom_name=""):
    # Output Filename Logic
    if not custom_name:
        base = os.path.basename(target)
        if not base: base = "Drive_Root"
        custom_name = f"Report_{base}.html"
    
    if not custom_name.lower().endswith(".html"):
        custom_name += ".html"
        
    final_path = os.path.join(out_dir, custom_name)

    # Convert keywords
    kw_formatted = keywords.replace(",", "\n") if keywords else ""

    print(f"[*] Target:   {target}")
    print(f"[*] Output:   {final_path}")
    print("-" * 60)

    start_time = time.time()

    # Console Progress Callback
    def console_callback(msg, pct=-1):
        if "|||" in msg:
            parts = msg.split("|||")
            text = parts[0]
            eta = parts[1] if len(parts) > 1 else ""
            sys.stdout.write(f"\r[{eta}] {text}".ljust(80))
            sys.stdout.flush()
        elif pct == -1:
            sys.stdout.write("\033[K") 
            print(f"\n[LOG] {msg}")
        else:
            bar_len = 40
            filled_len = int(bar_len * pct / 100)
            bar = '=' * filled_len + '-' * (bar_len - filled_len)
            sys.stdout.write(f"\r[{bar}] {pct}% - {msg}")
            sys.stdout.flush()

    try:
        recapture.run_recapture(
            target_path=target, 
            output_path=final_path, 
            hash_list=hashlist, 
            log_callback=console_callback, 
            skip_hash=skip, 
            examiner_name=examiner, 
            case_ref=ref, 
            notes=notes,
            keywords=kw_formatted
        )
        elapsed = time.time() - start_time
        print(f"\n\n[+] SUCCESS: Report generated in {elapsed:.2f} seconds.")
        print(f"[+] File saved: {final_path}")

    except KeyboardInterrupt:
        print("\n\n[!] Operation cancelled by user.")
    except Exception as e:
        print(f"\n\n[!] Critical Error: {e}")

if __name__ == "__main__":
    main()