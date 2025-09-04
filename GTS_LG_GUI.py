
# GTS_LG_GUI.py — GUI License Provisioning Tool (Ed25519) with XY scrollbars
# Requires: customtkinter, cryptography
# Purpose: Generate public_key.pem + license.json for the GTS app (admin use)
# This GUI mirrors the CLI logic in your provisioning script and adds a friendly UI.

import os, json, hashlib, secrets, base64, datetime, socket, re, sys, webbrowser, traceback
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
try:
    import customtkinter as ctk
except Exception:
    raise SystemExit("customtkinter is required. Install via: pip install customtkinter")

# --- Optional: cryptography ---
try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization
    CRYPTO_OK = True
except Exception:
    CRYPTO_OK = False

APP_NAME = "GTS License Provisioner (GUI)"

# Keep PIN policy compatible with your CLI tool (4-16, letters/digits/some symbols)
PIN_REGEX = re.compile(r"^[A-Za-z0-9@#$%^&+=!?.\-]{4,16}$")

def hash_pin(pin: str, salt_hex: str) -> str:
    h = hashlib.sha256()
    h.update(bytes.fromhex(salt_hex))
    h.update(pin.encode("utf-8"))
    return h.hexdigest()

def canonical_json_bytes(obj) -> bytes:
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")

def load_or_create_keypair(key_dir):
    """Load existing private/public key from key_dir or create them if missing."""
    priv_path = os.path.join(key_dir, "private_key.pem")
    pub_path = os.path.join(key_dir, "public_key.pem")
    if os.path.exists(priv_path) and os.path.exists(pub_path):
        with open(priv_path, "rb") as f:
            priv = serialization.load_pem_private_key(f.read(), password=None)
        with open(pub_path, "rb") as f:
            pub_pem = f.read()
        return priv, pub_pem

    if not CRYPTO_OK:
        raise RuntimeError("cryptography is not installed. Run: pip install cryptography")

    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key()
    priv_pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_pem = pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    with open(priv_path, "wb") as f: f.write(priv_pem)
    with open(pub_path, "wb") as f: f.write(pub_pem)
    return priv, pub_pem

# ------------- XY scroll container -------------
class XYScrollFrame(ctk.CTkFrame):
    """Frame with both vertical and horizontal scrollbars. Put content into .content."""
    def __init__(self, parent, **kwargs):
        super().__init__(parent, **kwargs)
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(0, weight=1)

        self.canvas = tk.Canvas(self, highlightthickness=0)
        self.canvas.grid(row=0, column=0, sticky="nsew")

        self.vbar = ttk.Scrollbar(self, orient="vertical", command=self.canvas.yview)
        self.vbar.grid(row=0, column=1, sticky="ns")
        self.hbar = ttk.Scrollbar(self, orient="horizontal", command=self.canvas.xview)
        self.hbar.grid(row=1, column=0, sticky="ew")

        self.canvas.configure(yscrollcommand=self.vbar.set, xscrollcommand=self.hbar.set)

        self.content = ctk.CTkFrame(self)
        self.win = self.canvas.create_window((0, 0), window=self.content, anchor="nw")

        self.content.bind("<Configure>", self._on_content_configure)
        self.canvas.bind("<Configure>", self._on_canvas_configure)

        # Mouse/trackpad scrolling
        self._bind_mouse(self.canvas)
        self._bind_mouse(self.content)

    def _on_content_configure(self, _e):
        self.canvas.configure(scrollregion=self.canvas.bbox("all"))

    def _on_canvas_configure(self, e):
        self.canvas.itemconfigure(self.win, width=max(self.content.winfo_reqwidth(), e.width))

    def _wheel(self, e):
        if e.state & 0x0001:  # Shift pressed -> horizontal
            self.canvas.xview_scroll(-1 if e.delta > 0 else 1, "units")
        else:
            self.canvas.yview_scroll(-1 if e.delta > 0 else 1, "units")

    def _wheel_linux(self, e):
        if e.num == 4:
            self.canvas.yview_scroll(-1, "units")
        elif e.num == 5:
            self.canvas.yview_scroll(1, "units")

    def _bind_mouse(self, widget):
        widget.bind_all("<MouseWheel>", self._wheel, add="+")
        widget.bind_all("<Shift-MouseWheel>", self._wheel, add="+")
        widget.bind_all("<Button-4>", self._wheel_linux, add="+")
        widget.bind_all("<Button-5>", self._wheel_linux, add="+")

# ------------- GUI -------------
class GTSLGApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title(APP_NAME)
        self.geometry("980x680")
        self.minsize(900, 600)
        self._safe_zoom()

        # Body: scrolled container
        wrap = XYScrollFrame(self)
        wrap.pack(fill="both", expand=True, padx=10, pady=10)
        f = wrap.content

        row = 0
        ctk.CTkLabel(f, text="License Provisioning", font=ctk.CTkFont(size=20, weight="bold")).grid(row=row, column=0, columnspan=6, sticky="w", pady=(4,10))

        row += 1
        ctk.CTkLabel(f, text="App Folder (write license.json & public_key.pem):").grid(row=row, column=0, sticky="w", padx=6, pady=6)
        self.app_dir = tk.StringVar(value=os.path.abspath("."))
        ctk.CTkEntry(f, textvariable=self.app_dir, width=480).grid(row=row, column=1, columnspan=3, sticky="w", padx=6)
        ctk.CTkButton(f, text="Browse", command=self._pick_app_dir).grid(row=row, column=4, padx=6)

        row += 1
        self.bind_var = tk.BooleanVar(value=False)
        ctk.CTkCheckBox(f, text="Bind license to hostname", variable=self.bind_var, command=self._toggle_host_input).grid(row=row, column=0, sticky="w", padx=6, pady=6)
        ctk.CTkLabel(f, text="Hostname:").grid(row=row, column=1, sticky="e", padx=6)
        self.host_name = tk.StringVar(value=socket.gethostname())
        self.host_entry = ctk.CTkEntry(f, textvariable=self.host_name, width=240, state="disabled")
        self.host_entry.grid(row=row, column=2, sticky="w", padx=6)

        ctk.CTkLabel(f, text="Expires (days, 0 = no expiry):").grid(row=row, column=3, sticky="e", padx=6)
        self.exp_days = tk.StringVar(value="0")
        ctk.CTkEntry(f, textvariable=self.exp_days, width=120).grid(row=row, column=4, sticky="w", padx=6)

        row += 1
        ctk.CTkLabel(f, text="Admin PIN:").grid(row=row, column=0, sticky="e", padx=6)
        self.pin1 = tk.StringVar()
        ctk.CTkEntry(f, textvariable=self.pin1, show="*", width=220).grid(row=row, column=1, sticky="w", padx=6)

        ctk.CTkLabel(f, text="Confirm PIN:").grid(row=row, column=2, sticky="e", padx=6)
        self.pin2 = tk.StringVar()
        ctk.CTkEntry(f, textvariable=self.pin2, show="*", width=220).grid(row=row, column=3, sticky="w", padx=6)

        row += 1
        btns = ctk.CTkFrame(f)
        btns.grid(row=row, column=0, columnspan=6, sticky="w", pady=(8, 4))
        ctk.CTkButton(btns, text="Generate License", command=self._generate, width=180).pack(side="left", padx=6)
        ctk.CTkButton(btns, text="Open App Folder", command=lambda: self._open_folder(self.app_dir.get())).pack(side="left", padx=6)
        ctk.CTkButton(btns, text="Open Key Folder", command=lambda: self._open_folder(os.path.abspath('.'))).pack(side="left", padx=6)

        row += 1
        # Log box with its own horizontal + vertical scrollbars
        ctk.CTkLabel(f, text="Output / Log:").grid(row=row, column=0, sticky="w", padx=6, pady=(8,2))
        log_wrap = ctk.CTkFrame(f)
        log_wrap.grid(row=row+1, column=0, columnspan=6, sticky="nsew", padx=6, pady=(0,8))
        f.grid_rowconfigure(row+1, weight=1)
        f.grid_columnconfigure(0, weight=1)
        self.log = tk.Text(log_wrap, height=12, wrap="none")
        self.log.grid(row=0, column=0, sticky="nsew")
        log_wrap.grid_rowconfigure(0, weight=1)
        log_wrap.grid_columnconfigure(0, weight=1)
        ysb = ttk.Scrollbar(log_wrap, orient="vertical", command=self.log.yview)
        ysb.grid(row=0, column=1, sticky="ns")
        xsb = ttk.Scrollbar(log_wrap, orient="horizontal", command=self.log.xview)
        xsb.grid(row=1, column=0, sticky="ew")
        self.log.configure(yscrollcommand=ysb.set, xscrollcommand=xsb.set)

        # footer note
        row += 2
        ctk.CTkLabel(f, text="Note: Distribute ONLY public_key.pem and license.json with the app. Keep private_key.pem safe.").grid(row=row, column=0, columnspan=6, sticky="w", padx=6, pady=(0,6))

    # --- helpers
    def _safe_zoom(self):
        try:
            self.after(120, lambda: self.state("zoomed"))
        except Exception:
            pass

    def _toggle_host_input(self):
        self.host_entry.configure(state="normal" if self.bind_var.get() else "disabled")

    def _pick_app_dir(self):
        d = filedialog.askdirectory(initialdir=self.app_dir.get() or os.path.abspath("."), title="Choose App Folder")
        if d:
            self.app_dir.set(d)

    def _log(self, line):
        self.log.insert("end", line + "\n")
        self.log.see("end")

    def _open_folder(self, path):
        try:
            if sys.platform.startswith("win"):
                os.startfile(path)
            elif sys.platform == "darwin":
                os.system(f'open "{path}"')
            else:
                os.system(f'xdg-open "{path}"')
        except Exception:
            self._log(f"[!] Could not open folder: {path}")

    def _validate_inputs(self):
        app_dir = self.app_dir.get().strip()
        if not app_dir:
            raise ValueError("App folder is required.")
        if not os.path.isdir(app_dir):
            raise ValueError("App folder does not exist.")
        p1 = self.pin1.get().strip()
        p2 = self.pin2.get().strip()
        if not PIN_REGEX.match(p1):
            raise ValueError("Invalid PIN. Allowed: 4–16 characters from A-Za-z0-9@#$%^&+=!?.-")
        if p1 != p2:
            raise ValueError("PINs do not match.")
        try:
            days = int(self.exp_days.get().strip() or "0")
            if days < 0 or days > 36500:
                raise ValueError
        except Exception:
            raise ValueError("Expires days must be a non-negative integer.")
        hostname = self.host_name.get().strip() if self.bind_var.get() else None
        return app_dir, p1, days, hostname

    def _generate(self):
        self.log.delete("1.0","end")
        if not CRYPTO_OK:
            messagebox.showerror("Missing dependency", "The 'cryptography' package is required.\nInstall: pip install cryptography")
            self._log("[!] cryptography missing; cannot generate keys.")
            return
        try:
            app_dir, pin, days, hostname = self._validate_inputs()
            os.makedirs(app_dir, exist_ok=True)

            self._log(f"[*] Using app folder: {app_dir}")
            priv, pub_pem = load_or_create_keypair(os.path.abspath("."))
            self._log("[*] Loaded/generated keypair in current folder.")

            salt = secrets.token_hex(16)
            pin_hash = hash_pin(pin, salt)
            payload = {
                "admin_pin_salt": salt,
                "admin_pin_hash": pin_hash,
                "issued_at": datetime.datetime.utcnow().isoformat(timespec="seconds") + "Z",
            }
            if hostname:
                payload["bind_hostname"] = True
                payload["hostname"] = hostname
            if days and days > 0:
                payload["expires_at"] = (datetime.datetime.utcnow() + datetime.timedelta(days=days)).isoformat(timespec="seconds") + "Z"

            # Sign
            sig = priv.sign(canonical_json_bytes(payload))
            lic = {"payload": payload, "signature": base64.b64encode(sig).decode("ascii")}

            # Write outputs
            with open(os.path.join(app_dir, "license.json"), "w", encoding="utf-8") as f:
                json.dump(lic, f, ensure_ascii=False, indent=2)
            with open(os.path.join(app_dir, "public_key.pem"), "wb") as f:
                f.write(pub_pem)

            self._log("[+] Wrote license.json and public_key.pem to app folder.")
            self._log("    Distribute ONLY public_key.pem and license.json with the app. Keep private_key.pem safe.")
            if hostname:
                self._log(f"    (License bound to hostname: {hostname})")
            messagebox.showinfo("Done", "License files written successfully.")
        except Exception as e:
            messagebox.showerror("Error", str(e))
            tb = traceback.format_exc()
            self._log("[!] Error during generation:\n" + tb)

if __name__ == "__main__":
    ctk.set_appearance_mode("System")
    ctk.set_default_color_theme("blue")
    app = GTSLGApp()
    app.mainloop()
