import sys
import os

# --- BOOTLOADER FIX ---
if getattr(sys, 'frozen', False):
    sys.path.append(sys._MEIPASS)

import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext, ttk
import threading

# --- SPLASH SCREEN HANDLING ---
def safe_close_splash():
    try:
        import pyi_splash
        if pyi_splash.is_alive():
            pyi_splash.close()
    except ImportError:
        pass

try:
    import recapture
except ImportError as e:
    safe_close_splash()
    root = tk.Tk(); root.withdraw()
    messagebox.showerror("Startup Error", f"Could not find 'recapture.py'.\nError: {e}")
    sys.exit(1)
except Exception:
    pass 

class App:
    def __init__(self, root):
        self.window = root
        self.window.title("Recapture Forensic Explorer v1.0 | Gold Master") 
        self.window.geometry("700x980")
        self.window.resizable(False, False)
        self.window.configure(bg="#222") # Dark Theme
        self.window.protocol("WM_DELETE_WINDOW", self.on_closing)
        self.is_running = False

        # --- STYLE CONFIGURATION ---
        style = ttk.Style()
        style.theme_use('clam')
        style.configure(".", background="#222", foreground="white", font=("Segoe UI", 10))
        style.configure("TButton", background="#444", foreground="white", borderwidth=0)
        style.map("TButton", background=[("active", "#555")])
        style.configure("TCheckbutton", background="#222", foreground="white")
        style.map("TCheckbutton", background=[("active", "#222")], indicatorcolor=[("selected", "#007acc")])
        style.configure("TRadiobutton", background="#222", foreground="white")
        style.map("TRadiobutton", background=[("active", "#222")], indicatorcolor=[("selected", "#007acc")])

        self.build_ui()
        safe_close_splash()

    def build_ui(self):
        # BANNER
        tk.Label(self.window, text="RECAPTURE", bg="#222", fg="white", font=("Segoe UI", 20, "bold")).pack(pady=(15, 5))
        tk.Label(self.window, text="v1.0 | Gold Master", bg="#222", fg="#aaa").pack(pady=(0, 15))

        main_frame = tk.Frame(self.window, bg="#222", padx=20)
        main_frame.pack(fill="x")

        # 1. SOURCE SELECTION
        tk.Label(main_frame, text="Select Source Type:", bg="#222", fg="#aaa", font=("Segoe UI", 9)).pack(anchor="w")
        self.source_mode = tk.StringVar(value="file")
        rf = tk.Frame(main_frame, bg="#222")
        rf.pack(fill="x", pady=(5, 10))
        
        ttk.Radiobutton(rf, text="Forensic Image (E01/Raw)", variable=self.source_mode, value="file", command=self.upd_mode).pack(side="left", padx=(0, 20))
        ttk.Radiobutton(rf, text="Local Folder / Drive", variable=self.source_mode, value="folder", command=self.upd_mode).pack(side="left")

        # 2. EVIDENCE PATH
        self.lbl_ev = tk.Label(main_frame, text="Evidence File:", bg="#222", fg="white")
        self.lbl_ev.pack(anchor="w")
        
        f1 = tk.Frame(main_frame, bg="#222")
        f1.pack(fill="x")
        self.file_path = self.create_dark_entry(f1)
        self.file_path.pack(side="left", fill="x", expand=True, ipady=3)
        self.btn_browse = tk.Button(f1, text="Browse File", bg="#444", fg="white", relief="flat", command=self.sel_file)
        self.btn_browse.pack(side="right", padx=(5,0))

        # 3. OUTPUT DIR
        tk.Label(main_frame, text="Output Directory:", bg="#222", fg="white").pack(anchor="w", pady=(10,0))
        f2 = tk.Frame(main_frame, bg="#222")
        f2.pack(fill="x")
        self.out_dir = self.create_dark_entry(f2)
        self.out_dir.pack(side="left", fill="x", expand=True, ipady=3)
        tk.Button(f2, text="Browse", bg="#444", fg="white", relief="flat", command=self.sel_out).pack(side="right", padx=(5,0))
        
        # 4. HASH LIST
        tk.Label(main_frame, text="Hash List (.txt) [Optional]:", bg="#222", fg="white").pack(anchor="w", pady=(10,0))
        f_hash = tk.Frame(main_frame, bg="#222")
        f_hash.pack(fill="x")
        self.hash_path = self.create_dark_entry(f_hash)
        self.hash_path.pack(side="left", fill="x", expand=True, ipady=3)
        tk.Button(f_hash, text="Browse", bg="#444", fg="white", relief="flat", command=self.sel_hash).pack(side="right", padx=(5,0))

        # 5. METADATA
        row = tk.Frame(main_frame, bg="#222")
        row.pack(fill="x", pady=(10,0))
        
        lc = tk.Frame(row, bg="#222")
        lc.pack(side="left", fill="x", expand=True, padx=(0, 10))
        tk.Label(lc, text="Examiner Name:", bg="#222", fg="white").pack(anchor="w")
        self.ent_ex = self.create_dark_entry(lc)
        self.ent_ex.pack(fill="x", ipady=3)
        
        rc = tk.Frame(row, bg="#222")
        rc.pack(side="right", fill="x", expand=True)
        tk.Label(rc, text="Case Reference:", bg="#222", fg="white").pack(anchor="w")
        self.ent_ref = self.create_dark_entry(rc)
        self.ent_ref.pack(fill="x", ipady=3)

        # 6. KEYWORDS
        tk.Label(main_frame, text="Search Terms (One per line):", bg="#222", fg="#007acc", font=("Segoe UI", 9, "bold")).pack(anchor="w", pady=(10,0))
        self.txt_kws = tk.Text(main_frame, height=3, bg="#1e1e1e", fg="#00e676", relief="flat", insertbackground="white", font=("Consolas", 10))
        self.txt_kws.pack(fill="x", pady=2)

        # 7. NOTES
        tk.Label(main_frame, text="Case Notes:", bg="#222", fg="white").pack(anchor="w", pady=(10,0))
        self.txt_notes = tk.Text(main_frame, height=2, bg="#333", fg="white", relief="flat", insertbackground="white")
        self.txt_notes.pack(fill="x")

        # 8. FILENAME
        tk.Label(main_frame, text="Report Filename:", bg="#222", fg="white").pack(anchor="w", pady=(10,0))
        self.rep_name = self.create_dark_entry(main_frame)
        self.rep_name.pack(fill="x", ipady=3)

        # 9. OPTIONS
        self.do_skip = tk.BooleanVar()
        ttk.Checkbutton(main_frame, text="Fast Check (Skip Hashing)", variable=self.do_skip).pack(anchor="w", pady=15)

        # 10. ACTION BUTTONS
        btn_row = tk.Frame(self.window, bg="#222")
        btn_row.pack(fill="x", padx=20, pady=10)
        
        tk.Button(btn_row, text="Help / Legend", bg="#444", fg="white", font=("Segoe UI", 10), relief="flat", padx=15, pady=8, command=self.show_help).pack(side="left")

        self.start_btn = tk.Button(btn_row, text="START SCAN", bg="#007acc", fg="white", font=("Segoe UI", 12, "bold"), relief="flat", padx=20, pady=8, command=self.run)
        self.start_btn.pack(side="right", fill="x", expand=True, padx=(10,0))

        # 11. PROGRESS & STATUS
        self.pbar = ttk.Progressbar(self.window, orient="horizontal", length=100, mode="determinate")
        self.pbar.pack(fill="x", padx=20)
        
        stat_frame = tk.Frame(self.window, bg="#222")
        stat_frame.pack(fill="x", padx=20, pady=5)
        
        self.status = tk.Label(stat_frame, text="Ready", bg="#222", fg="#aaa", anchor="w")
        self.status.pack(side="left", fill="x", expand=True)
        
        # --- NEW PERCENTAGE LABEL ---
        self.status_pct = tk.Label(stat_frame, text="0%", bg="#222", fg="white", font=("Segoe UI", 9, "bold"))
        self.status_pct.pack(side="right", padx=10)

        self.status_eta = tk.Label(stat_frame, text="", bg="#222", fg="#007acc", font=("Segoe UI", 9, "bold"))
        self.status_eta.pack(side="right")

        self.console = scrolledtext.ScrolledText(self.window, height=6, bg="#111", fg="#0f0", font=("Consolas", 9))
        self.console.pack(fill="both", expand=True, padx=20, pady=(0, 10))
        self.console.config(state="disabled")

        # FOOTER CREDITS
        tk.Label(self.window, text="Created by Junaid Abid | Contact: Junaid@junaid.ltd", bg="#222", fg="#555", font=("Segoe UI", 8)).pack(pady=5)

    def create_dark_entry(self, parent):
        return tk.Entry(parent, bg="#333", fg="white", relief="flat", insertbackground="white")

    def show_help(self):
        hw = tk.Toplevel(self.window)
        hw.title("Report Legend")
        hw.geometry("450x450")
        hw.configure(bg="#222")
        p = tk.Frame(hw, bg="#222", padx=20, pady=20); p.pack(fill="both", expand=True)
        tk.Label(p, text="Report Icon Legend", bg="#222", fg="white", font=("Segoe UI", 14, "bold")).pack(pady=(0,20))
        items = [("Strikethrough", "Deleted File (Recovered)", "#aaa", True),
                 ("Red Text", "Signature Mismatch", "#ff5555", False),
                 ("Purple Text", "Keyword Hit", "#d186ff", False),
                 ("Bold / Alert", "Hash Match (Known Bad)", "#ff5555", False),
                 ("📁 Folder", "Standard Directory", "white", False),
                 ("👻 Ghost", "Deleted/Unallocated", "#aaa", False)]
        for t, d, c, s in items:
            f = tk.Frame(p, bg="#222"); f.pack(fill="x", pady=8)
            f_font = ("Segoe UI", 11, "overstrike") if s else ("Segoe UI", 11, "bold")
            tk.Label(f, text=t, bg="#222", fg=c, font=f_font).pack(anchor="w")
            tk.Label(f, text=d, bg="#222", fg="#ccc", font=("Segoe UI", 10)).pack(anchor="w", padx=10)
        tk.Button(p, text="Close", bg="#444", fg="white", command=hw.destroy).pack(side="bottom", pady=20)

    def on_closing(self):
        if self.is_running:
            if messagebox.askyesno("Confirm Exit", "Scan in progress. Exit now?"):
                self.window.destroy(); sys.exit(0)
        else: self.window.destroy()

    def upd_mode(self):
        if self.source_mode.get() == "file": 
            self.lbl_ev.config(text="Evidence File:")
            self.btn_browse.config(text="Browse File", command=self.sel_file)
        else: 
            self.lbl_ev.config(text="Target Folder:")
            self.btn_browse.config(text="Browse Folder", command=self.sel_folder)

    def sel_file(self):
        f = filedialog.askopenfilename(filetypes=[("Forensic Images", "*.E01;*.001;*.dd;*.img"), ("All Files", "*.*")])
        if f: self.set_path(self.file_path, f)
    def sel_folder(self):
        f = filedialog.askdirectory()
        if f: self.set_path(self.file_path, f)
    def sel_out(self):
        f = filedialog.askdirectory()
        if f: self.set_path(self.out_dir, f)
    def sel_hash(self):
        f = filedialog.askopenfilename(filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")])
        if f: self.set_path(self.hash_path, f)

    def set_path(self, entry, p):
        entry.delete(0, tk.END); entry.insert(0, p)
        # Auto-name report if evidence is selected
        if entry == self.file_path and not self.rep_name.get():
             self.rep_name.insert(0, f"Report_{os.path.basename(p) or 'Drive'}.html")

    def log(self, t, p=-1):
        if "|||" in t:
            parts = t.split("|||")
            self.status.config(text=parts[0])
            if len(parts) > 1: self.status_eta.config(text=parts[1])
            if p >= 0: 
                self.pbar["value"] = p
                self.status_pct.config(text=f"{p}%") # Update percentage
        elif "Indexing..." in t: self.status.config(text=t)
        else:
            self.console.config(state="normal")
            self.console.insert(tk.END, t + "\n")
            self.console.see(tk.END)
            self.console.config(state="disabled")
            if "Done!" in t: 
                self.status.config(text="Scan Complete")
                self.status_eta.config(text="")
                self.pbar["value"] = 100
                self.status_pct.config(text="100%")
        self.window.update_idletasks()

    def run(self):
        f_in = self.file_path.get(); f_out = self.out_dir.get()
        if not f_in or not f_out: messagebox.showerror("Error", "Select source/output"); return
        nm = self.rep_name.get().strip()
        if not nm: nm = f"Report_{os.path.basename(f_in)}.html"
        if not nm.lower().endswith(".html"): nm += ".html"
        
        self.pbar["value"]=0; 
        self.status_pct.config(text="0%")
        self.start_btn.config(text="SCANNING...", state="disabled", bg="#444")
        self.console.config(state="normal"); self.console.delete(1.0, tk.END); self.console.config(state="disabled")
        self.is_running = True
        
        scan_args = {
            "target_path": f_in, 
            "output_path": os.path.join(f_out, nm), 
            "hash_list": self.hash_path.get(), 
            "skip_hash": self.do_skip.get(), 
            "examiner_name": self.ent_ex.get(), 
            "case_ref": self.ent_ref.get(), 
            "notes": self.txt_notes.get("1.0", tk.END).strip(),
            "keywords": self.txt_kws.get("1.0", tk.END).strip()
        }
        t = threading.Thread(target=self.work, kwargs=scan_args); t.daemon = True; t.start()

    def work(self, **kwargs):
        def sl(m, p=-1): self.window.after(0, self.log, m, p)
        try:
            recapture.run_recapture(log_callback=sl, **kwargs)
            self.window.after(0, lambda: messagebox.showinfo("Success", "Report Generated!"))
        except Exception as e: sl(f"Error: {e}")
        finally:
            self.is_running = False
            self.window.after(0, lambda: self.start_btn.config(text="START SCAN", state="normal", bg="#007acc"))

if __name__ == "__main__":
    root = tk.Tk()
    app = App(root)
    root.mainloop()