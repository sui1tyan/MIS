# GTS_LG_GUI.py
# GTS LG — License Generator (GUI)
# - Writes license.json + public_key.pem into the selected *app* folder (next to your main app .py/.exe).
# - Keeps private_key.pem beside this tool. Keep it secret.
# Deps: pip install customtkinter cryptography

import os
import json
import hashlib
import secrets
import base64
import datetime
import socket
import re
import sys
import argparse
import tkinter as tk
from tkinter import filedialog, messagebox

try:
    import customtkinter as ctk
except Exception as e:
    raise RuntimeError("customtkinter required. Install: pip install customtkinter") from e

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

PIN_REGEX = re.compile(r"^[A-Za-z0-9@#$%^&+=!?.\-]{4,16}$")

def _app_dir():
    # Directory where this tool resides (script or frozen EXE)
    if getattr(sys, "frozen", False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))

def hash_pin(pin: str, salt_hex: str) -> str:
    h = hashlib.sha256()
    h.update(bytes.fromhex(salt_hex))
    h.update(pin.encode("utf-8"))
    return h.hexdigest()

def canonical_json_bytes(obj) -> bytes:
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")

def load_or_create_keypair(key_dir: str):
    os.makedirs(key_dir, exist_ok=True)
    priv_path = os.path.join(key_dir, "private_key.pem")
    pub_path  = os.path.join(key_dir, "public_key.pem")
    if os.path.exists(priv_path) and os.path.exists(pub_path):
        with open(priv_path, "rb") as f:
            priv = serialization.load_pem_private_key(f.read(), password=None)
        with open(pub_path, "rb") as f:
            pub_pem = f.read()
        return priv, pub_pem
    priv = Ed25519PrivateKey.generate()
    pub  = priv.public_key()
    priv_pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_pem  = pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    with open(priv_path, "wb") as f: f.write(priv_pem)
    with open(pub_path,  "wb") as f: f.write(pub_pem)
    return priv, pub_pem

def write_license(app_dir: str, pin: str, bind_hostname: bool, custom_hostname: str, expires_days: int):
    key_dir = _app_dir()  # keep the private key beside this tool
    priv, pub_pem = load_or_create_keypair(key_dir)

    if not PIN_REGEX.match(pin or ""):
        raise ValueError("PIN must be 4–16 chars: A-Za-z0-9@#$%^&+=!?.-")

    salt = secrets.token_hex(16)
    pin_hash = hash_pin(pin, salt)

    payload = {
         "admin_pin_salt": salt,
         "admin_pin_hash": pin_hash,
         "issued_at": datetime.datetime.utcnow().isoformat(timespec="seconds") + "Z",
    }
    if bind_hostname:
        payload["bind_hostname"] = True
        payload["hostname"] = (custom_hostname or socket.gethostname())

    if expires_days and int(expires_days) > 0:
        payload["expires_at"] = (
            datetime.datetime.utcnow() + datetime.timedelta(days=int(expires_days))
        ).isoformat(timespec="seconds") + "Z"

    sig = priv.sign(canonical_json_bytes(payload))
    lic = {"payload": payload, "signature": base64.b64encode(sig).decode("ascii")}

    os.makedirs(app_dir, exist_ok=True)
    with open(os.path.join(app_dir, "license.json"), "w", encoding="utf-8") as f:
        json.dump(lic, f, ensure_ascii=False, indent=2)
    with open(os.path.join(app_dir, "public_key.pem"), "wb") as f:
        f.write(pub_pem)

class LGApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("GTS LG — License Generator")
        self.geometry("560x400")
        ctk.set_appearance_mode("Light")
        ctk.set_default_color_theme("blue")

        self.app_dir = tk.StringVar(value=os.path.abspath("."))
        self.pin1    = tk.StringVar()
        self.pin2    = tk.StringVar()
        self.expdays = tk.StringVar(value="0")
        self.bindhost = tk.BooleanVar(value=False)
        self.hostname = tk.StringVar(value=socket.gethostname())

        pad = {"padx":10, "pady":6}
        row = 0

        ctk.CTkLabel(self, text="App directory (next to your main app .py/.exe):").grid(row=row, column=0, columnspan=2, sticky="w", **pad); row+=1
        ctk.CTkEntry(self, textvariable=self.app_dir, width=380).grid(row=row, column=0, sticky="we", **pad)
        ctk.CTkButton(self, text="Browse", command=self.pick_dir).grid(row=row, column=1, sticky="e", **pad); row+=1

        ctk.CTkLabel(self, text="Admin PIN (4–16 chars)").grid(row=row, column=0, columnspan=2, sticky="w", **pad); row+=1
        ctk.CTkEntry(self, textvariable=self.pin1, show="*").grid(row=row, column=0, columnspan=2, sticky="we", **pad); row+=1
        ctk.CTkLabel(self, text="Confirm PIN").grid(row=row, column=0, columnspan=2, sticky="w", **pad); row+=1
        ctk.CTkEntry(self, textvariable=self.pin2, show="*").grid(row=row, column=0, columnspan=2, sticky="we", **pad); row+=1

        ctk.CTkCheckBox(self, text="Bind to hostname", variable=self.bindhost).grid(row=row, column=0, sticky="w", **pad)
        ctk.CTkEntry(self, textvariable=self.hostname, width=260).grid(row=row, column=1, sticky="e", **pad); row+=1

        ctk.CTkLabel(self, text="Expires in days (0 = no expiry)").grid(row=row, column=0, sticky="w", **pad)
        ctk.CTkEntry(self, textvariable=self.expdays, width=140).grid(row=row, column=1, sticky="e", **pad); row+=1

        ctk.CTkButton(self, text="Generate", command=self.generate).grid(row=row, column=0, columnspan=2, **pad)

        for c in (0,1):
            self.grid_columnconfigure(c, weight=1)

    def pick_dir(self):
        d = filedialog.askdirectory(initialdir=self.app_dir.get() or os.path.abspath("."))
        if d:
            self.app_dir.set(d)

    def generate(self):
        try:
            if (self.pin1.get() or "").strip() != (self.pin2.get() or "").strip():
                raise ValueError("PINs do not match.")
            pin = (self.pin1.get() or "").strip()
            app_dir = (self.app_dir.get() or "").strip()
            if not app_dir:
                raise ValueError("Please choose an app directory.")
            write_license(
                app_dir=app_dir,
                pin=pin,
                bind_hostname=self.bindhost.get(),
                custom_hostname=(self.hostname.get() or "").strip(),
                expires_days=int(self.expdays.get() or 0),
            )
            messagebox.showinfo("Done", f"license.json & public_key.pem written to:\n{app_dir}\n\nKeep private_key.pem (in {_app_dir()}) SECRET.")
        except Exception as e:
            messagebox.showerror("Error", str(e))

# Optional CLI (non-GUI)
def main_cli():
    ap = argparse.ArgumentParser(description="GTS LG — License Generator (CLI)")
    ap.add_argument("--app-dir", required=True, help="Folder of your main app (.py/.exe) to place license.json and public_key.pem")
    ap.add_argument("--pin", required=True, help="Admin PIN (4–16 chars; A-Za-z0-9@#$%^&+=!?.-)")
    ap.add_argument("--bind-hostname", action="store_true", help="Bind license to this machine's hostname (or --hostname)")
    ap.add_argument("--hostname", default=None, help="Custom hostname to bind to")
    ap.add_argument("--expires-days", type=int, default=0, help="Days until license expiry (0=no expiry)")
    args = ap.parse_args()

    write_license(
        app_dir=args.app_dir,
        pin=args.pin,
        bind_hostname=args.bind_hostname,
        custom_hostname=args.hostname,
        expires_days=args.expires_days,
    )
    print(f"Wrote license.json and public_key.pem to: {args.app_dir}")
    print(f"Private key kept at: {_app_dir()} (KEEP SECRET)")

if __name__ == "__main__":
    if len(sys.argv) > 1 and any(a.startswith("--app-dir") for a in sys.argv):
        main_cli()
    else:
        app = LGApp()
        app.mainloop()
