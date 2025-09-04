# GTS_Summary_regen.py
"""
GTS SED Desktop App — Regenerated (PDF layout + image limits + car plate + UI tweaks)
2025-08-28 update:
- PDF export redesigned:
  * Layout inspired by the physical template: each record rendered as a complete block
    with header (Date, Trip=PLACE/TRIP/CARPLATE, APDN, E12, K3, Status), marks grid for
    Estate (E2–E6, E12–E16) and Kilang (K1, K3–K7), and a Remarks section.
  * Renders multiple records per page when space allows, but NEVER splits a record across pages.
    If the next record block does not fit, it starts on a new page.
  * Each label row can display up to TWO image thumbnails (no overlap). If PIL is unavailable
    or an image cannot be opened, the filename is shown instead.
- Attachments limit:
  * Each label (e.g., "E2", "K4") can attach at most **2 images**. Attempts to add more are prevented.
  * A **Remove** button is added below each Attach button to clear all images for that label in the form.
- Car Plate No.:
  * Added a text box beside APDN (E2). New DB column: `car_plate` (migrated if missing).
  * Trip string displayed as PLACE/TRIP_NO/CAR_PLATE in the table and in PDF.
  * Right-side details include Car Plate.
- View table columns:
  * Now shows only ID, Date, Trip, Status (Area/Place omitted because Trip encodes them).
- Excel/CSV export removed:
  * All Excel/CSV-related buttons & functions removed.
  * "Export Selected" now exports selected records to **PDF**.
  * "Export All (PDF)" exports all records using the same layout.

Requires:
  pip install customtkinter Pillow reportlab
- DB sits next to this script: gts_records.db
"""

import os
import json
import sqlite3
import datetime
import logging
import traceback
import shutil
import textwrap
import hashlib
import secrets
import tkinter as tk
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from tkinter import ttk, filedialog, messagebox, simpledialog
from tkinter import font as tkfont

# Optional external libs (UI + images + PDFs)
try:
    import customtkinter as ctk
except Exception as e:
    raise RuntimeError("customtkinter required. Install: pip install customtkinter") from e

try:
    from PIL import Image
    PIL_AVAILABLE = True
except Exception:
    PIL_AVAILABLE = False

try:
    from reportlab.lib.pagesizes import A4, landscape
    from reportlab.pdfgen import canvas
    from reportlab.lib.units import mm
    REPORTLAB_AVAILABLE = True
except Exception:
    REPORTLAB_AVAILABLE = False

# ---------------- config & logging ----------------
APP_DIR = os.path.dirname(os.path.abspath(__file__))  # use the script folder
os.makedirs(APP_DIR, exist_ok=True)
IMG_STORE = os.path.join(APP_DIR, "images")
os.makedirs(IMG_STORE, exist_ok=True)
LOG_PATH = os.path.join(APP_DIR, "gts_app.log")
DB_PATH = os.path.join(APP_DIR, "gts_records.db")
SETTINGS_PATH = os.path.join(APP_DIR, "settings.json")  # app prefs (non-sensitive)
LICENSE_PATH = os.path.join(APP_DIR, "license.json")  # signed license (payload + signature)
PUBKEY_PATH = os.path.join(APP_DIR, "public_key.pem")  # Ed25519 public key

logging.basicConfig(filename=LOG_PATH, level=logging.INFO,
                    format="%(asctime)s %(levelname)s %(message)s")

def log_exc(msg=""):
    logging.error(msg)
    logging.error(traceback.format_exc())

# ---------------- labels & defaults ----------------
REQUIRED_E = ["E2","E3","E4","E5","E6","E12","E13","E14","E15","E16"]
REQUIRED_K = ["K1","K3","K4","K5","K6","K7"]

# Printable ASCII marks
MARK_SYMBOL = {"tick":"Y", "cross":"N", "zero":"0", "":""}

DEFAULT_AREAS = {
    "Sebatik Group": ["SB1", "SB2", "S3", "KF1", "KF2"],
    "Serudong Group": ["WM1", "WM2", "WM3", "BKS1", "BKS2", "BKS3"],
    "Sungai Mas": ["SGM", "SGK"],
    "Bergosong": ["BE"],
    "Kokorotus": ["KRT"]
}

# ---------------- database ----------------
def get_db_conn():
    return sqlite3.connect(DB_PATH, check_same_thread=False)

def _table_has_column(cur, table, col):
    cur.execute(f"PRAGMA table_info({table})")
    return any(r[1] == col for r in cur.fetchall())

def ensure_db_schema():
    try:
        conn = get_db_conn()
        cur = conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS areas (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE NOT NULL
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS places (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                area_id INTEGER NOT NULL,
                code TEXT,
                name TEXT,
                UNIQUE(area_id, code),
                FOREIGN KEY(area_id) REFERENCES areas(id) ON DELETE CASCADE
            )
        """)

        cur.execute("""
            CREATE TABLE IF NOT EXISTS gts_records (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                date TEXT,
                trip_no TEXT,
                area_id INTEGER,
                place_id INTEGER,
                estate_pics TEXT,
                kilang_pics TEXT,
                estate_marks TEXT,
                kilang_marks TEXT,
                remarks TEXT,
                status TEXT,
                created_at TEXT,
                updated_at TEXT,
                apdn_no TEXT,
                e12_seal TEXT,
                k3_seal TEXT,
                car_plate TEXT,
                FOREIGN KEY(area_id) REFERENCES areas(id),
                FOREIGN KEY(place_id) REFERENCES places(id)
            )
        """)
        # Migrate car_plate if missing (older DBs)
        if not _table_has_column(cur, "gts_records", "car_plate"):
            cur.execute("ALTER TABLE gts_records ADD COLUMN car_plate TEXT")

        conn.commit()

        # seed defaults
        for area_name, places in DEFAULT_AREAS.items():
            cur.execute("SELECT id FROM areas WHERE name = ?", (area_name,))
            row = cur.fetchone()
            aid = row[0] if row else None
            if not aid:
                cur.execute("INSERT INTO areas (name) VALUES (?)", (area_name,))
                aid = cur.lastrowid
            for pcode in places:
                cur.execute("SELECT 1 FROM places WHERE area_id=? AND code=?", (aid, pcode))
                if not cur.fetchone():
                    cur.execute("INSERT INTO places (area_id, code, name) VALUES (?,?,?)",
                                (aid, pcode, pcode))
        conn.commit()
        conn.close()
    except Exception:
        log_exc("ensure_db_schema failed")
        raise

ensure_db_schema()
DB_CONN = get_db_conn()
DB_CURSOR = DB_CONN.cursor()


# ---------------- settings & auth ----------------
def _load_settings():
    try:
        if os.path.exists(SETTINGS_PATH):
            with open(SETTINGS_PATH, "r", encoding="utf-8") as f:
                return json.load(f)
    except Exception:
        log_exc("load_settings")
    return {}

def _save_settings(d):
    try:
        with open(SETTINGS_PATH, "w", encoding="utf-8") as f:
            json.dump(d, f, ensure_ascii=False, indent=2)
    except Exception:
        log_exc("save_settings")


def _load_license():
    try:
        if os.path.exists(LICENSE_PATH):
            with open(LICENSE_PATH, "r", encoding="utf-8") as f:
                return json.load(f)
    except Exception:
        log_exc("load_license")
    return {}

def _save_license(d):
    try:
        with open(LICENSE_PATH, "w", encoding="utf-8") as f:
            json.dump(d, f, ensure_ascii=False, indent=2)
    except Exception:
        log_exc("save_license")

def _canonical_json_bytes(obj):
    try:
        # sort keys for deterministic signing/verification
        return json.dumps(obj, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")
    except Exception:
        return b""

def _verify_license_signature(lic_payload: dict, signature_b64: str) -> bool:
    try:
        if not os.path.exists(PUBKEY_PATH):
            return False
        with open(PUBKEY_PATH, "rb") as f:
            pub = serialization.load_pem_public_key(f.read())
        import base64
        sig = base64.b64decode(signature_b64)
        pub.verify(sig, _canonical_json_bytes(lic_payload))
        return True
    except Exception:
        return False


def _hash_pin(pin, salt_hex):
    h = hashlib.sha256()
    h.update(bytes.fromhex(salt_hex))
    h.update(pin.encode("utf-8"))
    return h.hexdigest()

def ensure_admin_pin_initialized():
    cfg = _load_license()
    if "admin_pin_hash" not in cfg or "admin_pin_salt" not in cfg:
        # not set yet
        return False
    return True
# ---------------- utilities ----------------
def dump_json(d):
    try:
        return json.dumps(d, ensure_ascii=False)
    except Exception:
        return "{}"

def load_json(s):
    try:
        return json.loads(s) if s else {}
    except Exception:
        return {}

def copy_images_to_store_if_needed(paths, label, date_str, trip_no, record_dir=None):
    """Copy images into IMG_STORE if they are outside; keep original if already in store."""
    saved = []
    target_dir = record_dir or IMG_STORE
    os.makedirs(target_dir, exist_ok=True)
    for idx, p in enumerate(paths):
        try:
            if (isinstance(p, str) and os.path.commonpath([os.path.abspath(p), os.path.abspath(target_dir)]) == os.path.abspath(target_dir)):
                saved.append(p)
                continue
        except Exception:
            pass
        try:
            base_ext = os.path.splitext(p)[1]
            safe_trip = (trip_no.replace(" ", "_") if trip_no else "trip")
            ts = datetime.datetime.now().strftime("%Y%m%d%H%M%S")
            fname = f"{date_str}_{safe_trip}_{label}_{idx}_{ts}{base_ext}"
            dest = os.path.join(target_dir, fname)
            shutil.copy2(p, dest)
            saved.append(dest)
        except Exception:
            log_exc(f"copy image failed for {p}")
    # de-dup
    seen = set()
    out = []
    for s in saved:
        if s not in seen:
            seen.add(s)
            out.append(s)
    return out

def compute_status_from_marks(e_marks, k_marks):
    for v in e_marks.values():
        if v == "" or v is None: return "Incomplete"
        if v == "cross": return "Incomplete"
    for v in k_marks.values():
        if v == "" or v is None: return "Incomplete"
        if v == "cross": return "Incomplete"
    return "Complete"


# --------- universal XY scroll container (no widget size changes) ---------
class _XYScrollFrame(ctk.CTkFrame):
    """A frame that provides both vertical and horizontal scrolling for its content.
    Use .content as the parent for your actual widgets.
    """
    def __init__(self, parent, **kwargs):
        super().__init__(parent, **kwargs)
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(0, weight=1)

        # Canvas hosts the content frame
        self._canvas = tk.Canvas(self, highlightthickness=0)
        self._canvas.grid(row=0, column=0, sticky="nsew")

        # Scrollbars
        self._vbar = ttk.Scrollbar(self, orient="vertical", command=self._canvas.yview)
        self._vbar.grid(row=0, column=1, sticky="ns")
        self._hbar = ttk.Scrollbar(self, orient="horizontal", command=self._canvas.xview)
        self._hbar.grid(row=1, column=0, sticky="ew")

        self._canvas.configure(yscrollcommand=self._vbar.set, xscrollcommand=self._hbar.set)

        # Inner content frame
        self.content = ctk.CTkFrame(self)
        self._win = self._canvas.create_window((0, 0), window=self.content, anchor="nw")

        # Resize/scroll bindings
        self.content.bind("<Configure>", self._on_content_configure)
        self._canvas.bind("<Configure>", self._on_canvas_configure)

        # Mouse-wheel (platform-friendly)
        self._bind_mousewheel(self._canvas)
        self._bind_mousewheel(self.content)

    def _on_content_configure(self, event):
        # Update scrollregion whenever content size changes
        self._canvas.configure(scrollregion=self._canvas.bbox("all"))

    def _on_canvas_configure(self, event):
        # Expand content width minimally so horizontal scroll is available when needed
        self._canvas.itemconfigure(self._win, width=max(self.content.winfo_reqwidth(), event.width))

    def _on_mousewheel(self, event):
        # Vertical scroll with wheel; shift-wheel scrolls horizontally
        if event.state & 0x0001:  # Shift pressed
            self._canvas.xview_scroll(-1 if event.delta > 0 else 1, "units")
        else:
            # Tk on Windows uses event.delta in steps of 120; on others use 1/-1
            delta = -1 if event.delta < 0 else 1
            self._canvas.yview_scroll(delta, "units")

    def _on_mousewheel_linux(self, event):
        # For Linux systems where <Button-4/5> are used
        if event.num == 4:
            self._canvas.yview_scroll(-1, "units")
        elif event.num == 5:
            self._canvas.yview_scroll(1, "units")

    def _bind_mousewheel(self, widget):
        widget.bind_all("<MouseWheel>", self._on_mousewheel, add="+")        # Windows / most
        widget.bind_all("<Shift-MouseWheel>", self._on_mousewheel, add="+")
        widget.bind_all("<Button-4>", self._on_mousewheel_linux, add="+")    # Linux
        widget.bind_all("<Button-5>", self._on_mousewheel_linux, add="+")
# ---------------- UI (Light + Roboto) ----------------
ctk.set_appearance_mode("Light")
ctk.set_default_color_theme("blue")

def roboto(size=12, weight="normal"):
    # If Roboto absent, Tk will fall back gracefully
    return ctk.CTkFont(family="Roboto", size=size, weight=weight)

class GTSApp(ctk.CTk):


    def _safe_zoom(self):
        try:
            self.state('zoomed')
        except Exception:
            pass
    def _guarded_manage_places_dialog(self):
        try:
            cfg = _load_license()
            payload = cfg.get("payload", {})
            sig = cfg.get("signature", "")
            if not payload or not sig or not _verify_license_signature(payload, sig) or "admin_pin_hash" not in payload or "admin_pin_salt" not in payload:
                messagebox.showinfo("Restricted", "This copy has no valid license. Areas/Places are read-only. Ask SED admin to provision a signed license.")
                return
            # Optional: enforce hostname and expiry
            if payload.get("bind_hostname"):
                import socket
                if payload.get("hostname") != socket.gethostname():
                    messagebox.showerror("License rejected", f"This license is bound to {payload.get('hostname')}.")
                    return
            if payload.get("expires_at"):
                import datetime
                try:
                    expires = datetime.datetime.fromisoformat(payload["expires_at"].replace("Z",""))
                    if datetime.datetime.utcnow() > expires:
                        messagebox.showerror("License expired", f"License expired on {payload['expires_at']}.")
                        return
                except Exception:
                    pass
            # Ask for PIN
            pin = simpledialog.askstring("Admin PIN", "Enter Admin PIN to proceed:", parent=self, show="*")
            if pin is None:
                return
            expected = payload.get("admin_pin_hash")
            salt = payload.get("admin_pin_salt")
            if _hash_pin(pin, salt) != expected:
                messagebox.showerror("Denied", "Incorrect PIN.")
                return
            # Passed -> open manage dialog
            self._manage_places_dialog()
        except Exception:
            log_exc("_guarded_manage_places_dialog")
    def __init__(self):
        super().__init__()
        self.title("SED — GTS Recording System")
        self.geometry("1320x880")
        # Resilient window defaults
        self.minsize(920, 600)  # keep min size; scrollbars handle overflow
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(0, weight=1)
        # Start maximized on Windows (safe no-op elsewhere)
        self.after(100, self._safe_zoom)

        self.editing_id = None

        # Global font prefs
        self.f_base = roboto(12)
        self.f_bold = roboto(12, "bold")
        self.f_h1 = roboto(16, "bold")

        # ttk styling
        style = ttk.Style(self)
        style.configure("Treeview", font=("Roboto", 11), rowheight=26)
        style.configure("Treeview.Heading", font=("Roboto", 12, "bold"))
        try:
            tkfont.nametofont("TkDefaultFont").configure(family="Roboto", size=11)
        except Exception:
            pass

        # Tabs
        self.tabview = ctk.CTkTabview(self, width=1200, height=820)
        self.tabview.pack(padx=12, pady=12, fill="both", expand=True)
        self.tabview.add("Create Record")
        self.tabview.add("View Records")
        self.create_tab = self.tabview.tab("Create Record")
        self.view_tab = self.tabview.tab("View Records")

        self._build_create_tab()
        self._build_view_tab()
        self.load_view_records()

    # ---------- Create Tab ----------
    def _build_create_tab(self):
        # Scrollable container so nothing is cut off on smaller windows
        scroll = _XYScrollFrame(self.create_tab)
        scroll.pack(fill="both", expand=True, padx=12, pady=8)
        f = scroll.content
        ctk.CTkLabel(f, text="Create / Edit Record", font=self.f_h1).pack(pady=(6, 8))

        top = ctk.CTkFrame(f)
        top.pack(fill="x", padx=12, pady=4)

        # Date / Trip / APDN (E2) / Car Plate / Seals
        ctk.CTkLabel(top, text="Date (YYYY-MM-DD):", font=self.f_base).grid(row=0, column=0, padx=6, pady=6, sticky="w")
        self.cr_date = ctk.StringVar(value=datetime.date.today().isoformat())
        ctk.CTkEntry(top, textvariable=self.cr_date, width=140, font=self.f_base).grid(row=0, column=1, padx=6)

        ctk.CTkLabel(top, text="Trip No:", font=self.f_base).grid(row=0, column=2, padx=6, pady=6, sticky="w")
        self.cr_trip = ctk.StringVar()
        ctk.CTkEntry(top, textvariable=self.cr_trip, width=120, font=self.f_base).grid(row=0, column=3, padx=6)

        ctk.CTkLabel(top, text="APDN (E2):", font=self.f_base).grid(row=0, column=4, padx=6, pady=6, sticky="w")
        self.cr_apdn_e2 = ctk.StringVar()
        ctk.CTkEntry(top, textvariable=self.cr_apdn_e2, width=140, font=self.f_base).grid(row=0, column=5, padx=6)

        ctk.CTkLabel(top, text="Car Plate:", font=self.f_base).grid(row=0, column=6, padx=6, pady=6, sticky="w")
        self.cr_car_plate = ctk.StringVar()
        ctk.CTkEntry(top, textvariable=self.cr_car_plate, width=140, font=self.f_base).grid(row=0, column=7, padx=6)

        # Area & Place
        ctk.CTkLabel(top, text="Area:", font=self.f_base).grid(row=1, column=0, padx=6, pady=6, sticky="w")
        self.cr_area_var = ctk.StringVar()
        self.cr_area_box = ctk.CTkComboBox(top, variable=self.cr_area_var,
                                           values=self._load_area_names(), width=220, font=self.f_base)
        self.cr_area_box.grid(row=1, column=1, padx=6)

        ctk.CTkLabel(top, text="Seal E12:", font=self.f_base).grid(row=2, column=0, padx=6, pady=6, sticky="w")
        self.cr_seal_e12 = ctk.StringVar()
        ctk.CTkEntry(top, textvariable=self.cr_seal_e12, width=140, font=self.f_base).grid(row=2, column=1, padx=6)

        ctk.CTkLabel(top, text="Seal K3:", font=self.f_base).grid(row=2, column=2, padx=6, pady=6, sticky="w")
        self.cr_seal_k3 = ctk.StringVar()
        ctk.CTkEntry(top, textvariable=self.cr_seal_k3, width=140, font=self.f_base).grid(row=2, column=3, padx=6)

        ctk.CTkLabel(top, text="Place:", font=self.f_base).grid(row=1, column=2, padx=6, pady=6, sticky="w")
        self.cr_place_var = ctk.StringVar()
        self.cr_place_box = ctk.CTkComboBox(top, variable=self.cr_place_var, values=self._load_places_for_current_area(), width=160, font=self.f_base)
        self.cr_place_box.grid(row=1, column=3, padx=6)

        ctk.CTkButton(top, text="Add Area", command=self._add_area_dialog, font=self.f_base).grid(row=1, column=4, padx=6)
        ctk.CTkButton(top, text="Add Place", command=self._add_place_dialog, font=self.f_base).grid(row=1, column=5, padx=6)
        ctk.CTkButton(top, text="Manage Areas/Places", command=self._guarded_manage_places_dialog, font=self.f_base).grid(row=1, column=6, padx=6)

        # When Area changes, reload places
        self.cr_area_var.trace_add("write", lambda *a: self._reload_places_box())
        # Section: Estate labels
        ctk.CTkLabel(f, text="Estate (E2–E6, E12–E16)", font=self.f_bold).pack(anchor="w", padx=12, pady=(8, 2))
        self.estate_files = {}
        self.estate_marks = {}
        self._build_mark_attach_grid(f, REQUIRED_E, self.estate_files, self.estate_marks)

        # Section: Kilang labels
        ctk.CTkLabel(f, text="Kilang (K1, K3–K7)", font=self.f_bold).pack(anchor="w", padx=12, pady=(8, 2))
        self.kilang_files = {}
        self.kilang_marks = {}
        self._build_mark_attach_grid(f, REQUIRED_K, self.kilang_files, self.kilang_marks)
        btn_row = ctk.CTkFrame(f)
        btn_row.pack(fill="x", padx=12, pady=10)
        ctk.CTkButton(
            btn_row,
            text="Save Record",
            command=self._save_record,
            font=self.f_base
        ).pack(side="left")

        ctk.CTkButton(
            btn_row,
            text="Switch to View",
            fg_color="transparent",
            command=lambda: self.tabview.set("View Records"),
            font=self.f_base
        ).pack(side="right")

        self.save_warning_label = ctk.CTkLabel(btn_row, text="", font=self.f_base)
        self.save_warning_label.pack(side="right", padx=12)
        ctk.CTkLabel(f, text="Remarks", font=self.f_bold).pack(anchor="w", padx=12, pady=(8, 2))
        self.cr_remarks = ctk.CTkTextbox(f, height=100, font=self.f_base, wrap="word")
        self.cr_remarks.pack(fill="x", padx=12)



        self._update_save_warning()

    def _build_mark_attach_grid(self, parent, labels, files_store, marks_store):
        wrap = ctk.CTkFrame(parent)
        wrap.pack(fill="both", expand=True, padx=6, pady=6)
        for i, lab in enumerate(labels):
            frame = ctk.CTkFrame(wrap)
            frame.grid(row=i, column=0, padx=6, pady=4, sticky="w")

            ctk.CTkLabel(frame, text=lab, width=44, font=self.f_base).pack(side="left", padx=(4, 6))

            # Button column (Attach + Remove stacked)
            btncol = ctk.CTkFrame(frame)
            btncol.pack(side="left")

            ctk.CTkButton(btncol, text="Attach", width=80,
                          command=lambda l=lab, fs=files_store: self._attach_files(l, fs), font=self.f_base).pack(side="top")

            ctk.CTkButton(btncol, text="Remove", width=80, fg_color="gray80",
                          command=lambda l=lab, fs=files_store: self._remove_files(l, fs), font=self.f_base).pack(side="top", pady=(4,0))

            count_lbl = ctk.CTkLabel(frame, text="0 files", width=90, font=self.f_base)
            count_lbl.pack(side="left", padx=(6, 0))

            var = tk.StringVar(value="")
            var.trace_add("write", lambda *a: self._update_save_warning())
            rb = ctk.CTkFrame(frame); rb.pack(side="left", padx=(8, 4))
            ctk.CTkRadioButton(rb, text="Y", variable=var, value="tick", font=self.f_base).pack(side="left", padx=2)
            ctk.CTkRadioButton(rb, text="N", variable=var, value="cross", font=self.f_base).pack(side="left", padx=2)
            ctk.CTkRadioButton(rb, text="0", variable=var, value="zero", font=self.f_base).pack(side="left", padx=2)

            files_store[lab] = {"paths": [], "count_widget": count_lbl}
            marks_store[lab] = var

    def _attach_files(self, label, storage):
        try:
            paths = filedialog.askopenfilenames(title=f"Select image(s) for {label}",
                                                filetypes=[("Images","*.jpg *.jpeg *.png *.bmp *.gif"), ("All files","*.*")])
            if not paths:
                return
            current = storage[label]["paths"]
            remaining = max(0, 2 - len(current))
            if remaining == 0:
                messagebox.showinfo("Limit reached", f"{label} already has 2 images attached.")
                return
            to_add = list(paths)[:remaining]
            if len(paths) > remaining:
                messagebox.showwarning("Limit", f"Only {remaining} more image(s) allowed for {label}. Extra files ignored.")
            current.extend(to_add)
            storage[label]["count_widget"].configure(text=f"{len(storage[label]['paths'])} files")
        except Exception:
            log_exc("_attach_files")
            messagebox.showerror("Error", "Failed to attach files. See log.")

    def _remove_files(self, label, storage):
        try:
            storage[label]["paths"] = []
            storage[label]["count_widget"].configure(text="0 files")
        except Exception:
            log_exc("_remove_files")

    def _clear_create_form(self):
        self.editing_id = None
        self.cr_date.set(datetime.date.today().isoformat())
        self.cr_trip.set("")
        self.cr_apdn_e2.set("")
        self.cr_car_plate.set("")
        self.cr_seal_e12.set("")
        self.cr_seal_k3.set("")
        self.cr_remarks.delete("0.0", "end")
        self.cr_area_box.configure(values=self._load_area_names())
        self.cr_place_box.configure(values=self._load_places_for_current_area())
        for d in (self.estate_files, self.kilang_files):
            for k in d:
                d[k]["paths"] = []
                d[k]["count_widget"].configure(text="0 files")
        for m in (self.estate_marks, self.kilang_marks):
            for k in m:
                m[k].set("")
        self._update_save_warning()

    # ---------- Area & Place management ----------
    def _load_area_names(self):
        try:
            DB_CURSOR.execute("SELECT name FROM areas ORDER BY name")
            return [r[0] for r in DB_CURSOR.fetchall()]
        except Exception:
            log_exc("_load_area_names")
            return []

    def _load_places_for_current_area(self):
        try:
            area = self.cr_area_var.get()
            if not area:
                return []
            DB_CURSOR.execute("SELECT id FROM areas WHERE name = ?", (area,))
            r = DB_CURSOR.fetchone()
            if not r:
                return []
            aid = r[0]
            DB_CURSOR.execute("SELECT code FROM places WHERE area_id = ? ORDER BY code", (aid,))
            return [x[0] for x in DB_CURSOR.fetchall()]
        except Exception:
            log_exc("_load_places_for_current_area")
            return []

    def _reload_places_box(self):
        vals = self._load_places_for_current_area()
        self.cr_place_box.configure(values=vals)
        if vals:
            self.cr_place_var.set(vals[0])
        else:
            self.cr_place_var.set("")

    def _add_area_dialog(self):
        name = simpledialog.askstring("Add Area", "Enter new area name:", parent=self)
        if not name:
            return
        try:
            DB_CURSOR.execute("INSERT OR IGNORE INTO areas (name) VALUES (?)", (name.strip(),))
            DB_CONN.commit()
            self.cr_area_box.configure(values=self._load_area_names())
            self.cr_area_var.set(name.strip())
            self._reload_places_box()
        except Exception:
            log_exc("_add_area_dialog")
            messagebox.showerror("Error", "Failed to add area. See log.")

    def _add_place_dialog(self):
        area = self.cr_area_var.get()
        if not area:
            messagebox.showwarning("No area", "Select or create an area first.")
            return
        code = simpledialog.askstring("Add Place", "Enter place code (e.g. 'SB4'):", parent=self)
        if not code:
            return
        try:
            DB_CURSOR.execute("SELECT id FROM areas WHERE name = ?", (area,))
            r = DB_CURSOR.fetchone()
            if not r:
                messagebox.showerror("Error", "Area not found.")
                return
            aid = r[0]
            DB_CURSOR.execute("INSERT OR IGNORE INTO places (area_id, code, name) VALUES (?,?,?)",
                              (aid, code.strip(), code.strip()))
            DB_CONN.commit()
            self._reload_places_box()
            self.cr_place_var.set(code.strip())
        except Exception:
            log_exc("_add_place_dialog")
            messagebox.showerror("Error", "Failed to add place. See log.")

    def _manage_places_dialog(self):
        try:
            dlg = tk.Toplevel(self)
            dlg.title("Manage Areas & Places")
            dlg.geometry("680x460")
            dlg.transient(self)
            dlg.grab_set()  # modal
            lb_font = tkfont.Font(family="Roboto", size=11)

            container = tk.Frame(dlg)
            container.pack(fill="both", expand=True, padx=8, pady=8)

            left = tk.Frame(container)
            left.pack(side="left", fill="y", padx=(0, 8))
            tk.Label(left, text="Areas", font=lb_font).pack()
            area_list = tk.Listbox(left, width=30, height=18, exportselection=False, font=lb_font)
            area_list.pack(fill="y")
            for a in self._load_area_names():
                area_list.insert("end", a)

            mid = tk.Frame(container)
            mid.pack(side="left", fill="both", expand=True)
            tk.Label(mid, text="Places in selected area", font=lb_font).pack()
            place_list = tk.Listbox(mid, width=32, height=18, exportselection=False, font=lb_font)
            place_list.pack(fill="both", expand=True)

            def on_area_select(evt=None):
                sel = area_list.curselection()
                place_list.delete(0, "end")
                if not sel:
                    return
                area = area_list.get(sel[0])
                DB_CURSOR.execute("SELECT id FROM areas WHERE name = ?", (area,))
                r = DB_CURSOR.fetchone()
                if not r:
                    return
                aid = r[0]
                DB_CURSOR.execute("SELECT code FROM places WHERE area_id = ? ORDER BY code", (aid,))
                for p in DB_CURSOR.fetchall():
                    place_list.insert("end", p[0])

            def delete_place():
                sel = place_list.curselection()
                if not sel:
                    messagebox.showinfo("Select", "Select a place to delete.", parent=dlg)
                    return
                place_code = place_list.get(sel[0])
                sel_area = area_list.curselection()
                if not sel_area:
                    return
                area_name = area_list.get(sel_area[0])
                DB_CURSOR.execute("SELECT id FROM areas WHERE name = ?", (area_name,))
                r = DB_CURSOR.fetchone()
                aid = r[0]
                if not messagebox.askyesno("Confirm", f"Delete place {place_code}?", parent=dlg):
                    return
                DB_CURSOR.execute("DELETE FROM places WHERE area_id = ? AND code = ?", (aid, place_code))
                DB_CONN.commit()
                on_area_select()

            def delete_area():
                sel = area_list.curselection()
                if not sel:
                    messagebox.showinfo("Select", "Select an area to delete.", parent=dlg)
                    return
                area_name = area_list.get(sel[0])
                if not messagebox.askyesno("Confirm", f"Delete area '{area_name}' and all its places?", parent=dlg):
                    return
                DB_CURSOR.execute("SELECT id FROM areas WHERE name = ?", (area_name,))
                r = DB_CURSOR.fetchone()
                if r:
                    aid = r[0]
                    DB_CURSOR.execute("DELETE FROM places WHERE area_id = ?", (aid,))
                    DB_CURSOR.execute("DELETE FROM areas WHERE id = ?", (aid,))
                    DB_CONN.commit()
                area_list.delete(sel[0])
                place_list.delete(0, "end")
                self.cr_area_box.configure(values=self._load_area_names())
                self._reload_places_box()

            area_list.bind("<<ListboxSelect>>", on_area_select)

            btnf = tk.Frame(dlg)
            btnf.pack(fill="x", side="bottom", padx=8, pady=8)
            tk.Button(btnf, text="Delete Place", command=delete_place, font=lb_font).pack(side="left", padx=6)
            tk.Button(btnf, text="Delete Area", command=delete_area, font=lb_font).pack(side="left", padx=6)
            tk.Button(btnf, text="Close", command=dlg.destroy, font=lb_font).pack(side="right", padx=6)

        except Exception:
            log_exc("manage_places_dialog")

    # ---------- Save / Update record ----------
    def _save_record(self):
        try:
            date_s = self.cr_date.get().strip()
            trip = self.cr_trip.get().strip()
            area_name = self.cr_area_var.get().strip()
            place_code = self.cr_place_var.get().strip()

            apdn = (self.cr_apdn_e2.get() or "").strip()
            car_plate = (self.cr_car_plate.get() or "").strip()
            seal_e12 = (self.cr_seal_e12.get() or "").strip()
            seal_k3 = (self.cr_seal_k3.get() or "").strip()

            if not date_s:
                messagebox.showwarning("Missing", "Please enter date."); return
            try:
                datetime.date.fromisoformat(date_s)
            except Exception:
                messagebox.showwarning("Bad date", "Date must be YYYY-MM-DD"); return
            if not area_name:
                messagebox.showwarning("Missing", "Choose an area."); return
            if not place_code:
                messagebox.showwarning("Missing", "Choose a place."); return

            missing_marks = [k for k in REQUIRED_E if self.estate_marks[k].get() == ""]
            missing_marks += [k for k in REQUIRED_K if self.kilang_marks[k].get() == ""]

            DB_CURSOR.execute("SELECT id FROM areas WHERE name = ?", (area_name,))
            ar = DB_CURSOR.fetchone()
            if not ar: messagebox.showerror("Error", "Selected area not found"); return
            area_id = ar[0]
            DB_CURSOR.execute("SELECT id FROM places WHERE area_id = ? AND code = ?", (area_id, place_code))
            pr = DB_CURSOR.fetchone()
            if not pr: messagebox.showerror("Error", "Selected place not found"); return
            place_id = pr[0]

            # Build images per label (REPLACE semantics so Remove works)
            # Prepare per-record directory inside images/
            try:
                trip_name = f"{place_code}/{trip or ''}{('/' + car_plate) if car_plate else ''}".strip('/')
                record_dir = os.path.join(IMG_STORE, f"{trip_name} {date_s}")
                os.makedirs(record_dir, exist_ok=True)
            except Exception:
                record_dir = IMG_STORE
            estate_saved = {}
            kilang_saved = {}

            for k in REQUIRED_E:
                new_saved = copy_images_to_store_if_needed(self.estate_files[k]["paths"], k, date_s, trip, record_dir=record_dir)
                estate_saved[k] = list(dict.fromkeys(new_saved))[:2]  # safety
            for k in REQUIRED_K:
                new_saved = copy_images_to_store_if_needed(self.kilang_files[k]["paths"], k, date_s, trip, record_dir=record_dir)
                kilang_saved[k] = list(dict.fromkeys(new_saved))[:2]  # safety

            e_marks_map = {k: self.estate_marks[k].get() for k in REQUIRED_E}
            k_marks_map = {k: self.kilang_marks[k].get() for k in REQUIRED_K}
            status = compute_status_from_marks(e_marks_map, k_marks_map)
            remarks = self.cr_remarks.get("0.0", "end").strip()
            now = datetime.datetime.now().isoformat(timespec="seconds")

            if not self.editing_id:
                DB_CURSOR.execute("""
                    INSERT INTO gts_records
                    (date, trip_no, area_id, place_id, apdn_no, e12_seal, k3_seal, car_plate,
                     estate_pics, kilang_pics, estate_marks, kilang_marks, remarks, status, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (date_s, trip, area_id, place_id, apdn, seal_e12, seal_k3, car_plate,
                      dump_json(estate_saved), dump_json(kilang_saved),
                      dump_json(e_marks_map), dump_json(k_marks_map),
                      remarks, status, now, now))
            else:
                DB_CURSOR.execute("""
                    UPDATE gts_records
                    SET date=?, trip_no=?, area_id=?, place_id=?, apdn_no=?, e12_seal=?, k3_seal=?, car_plate=?,
                        estate_pics=?, kilang_pics=?, estate_marks=?, kilang_marks=?, remarks=?, status=?, updated_at=?
                    WHERE id = ?
                """, (date_s, trip, area_id, place_id, apdn, seal_e12, seal_k3, car_plate,
                      dump_json(estate_saved), dump_json(kilang_saved),
                      dump_json(e_marks_map), dump_json(k_marks_map),
                      remarks, status, now, self.editing_id))
                self.editing_id = None

            DB_CONN.commit()
            if missing_marks:
                self.save_warning_label.configure(text=f" Saved (Incomplete). Missing marks: {len(missing_marks)}")
            else:
                self.save_warning_label.configure(text=f"Saved. Status: {status}")
            messagebox.showinfo("Saved", f"Record saved. Status: {status}")

            self._clear_create_form()
            self.load_view_records()
        except Exception:
            log_exc("_save_record")
            messagebox.showerror("Error", "Failed to save record. See log.")

    # ---------- View Tab (table + details) ----------
    def _build_view_tab(self):
        # Scrollable container so the filters/body never get cut
        scroll = _XYScrollFrame(self.view_tab)
        scroll.pack(fill="both", expand=True, padx=12, pady=8)
        f = scroll.content
        ctk.CTkLabel(f, text="View / Search Records", font=self.f_h1).pack(pady=(6,8))

        filter_row = ctk.CTkFrame(f)
        filter_row.pack(fill="x", padx=12, pady=6)

        ctk.CTkLabel(filter_row, text="Date From:", font=self.f_base).grid(row=0, column=0, padx=6, pady=4, sticky="w")
        self.v_date_from = ctk.StringVar()
        ctk.CTkEntry(filter_row, textvariable=self.v_date_from, width=120, font=self.f_base).grid(row=0, column=1, padx=6)
        ctk.CTkLabel(filter_row, text="Date To:", font=self.f_base).grid(row=0, column=2, padx=6, pady=4, sticky="w")
        self.v_date_to = ctk.StringVar()
        ctk.CTkEntry(filter_row, textvariable=self.v_date_to, width=120, font=self.f_base).grid(row=0, column=3, padx=6)

        ctk.CTkLabel(filter_row, text="Area:", font=self.f_base).grid(row=1, column=0, padx=6, pady=4, sticky="w")
        self.v_area = ctk.StringVar()
        self.v_area_box = ctk.CTkComboBox(filter_row, variable=self.v_area, values=self._load_area_names(), width=180, font=self.f_base)
        self.v_area_box.grid(row=1, column=1, padx=6)
        self.v_area.trace_add("write", lambda *a: self._reload_view_places())

        ctk.CTkLabel(filter_row, text="Place:", font=self.f_base).grid(row=1, column=2, padx=6, pady=4, sticky="w")
        self.v_place = ctk.StringVar()
        self.v_place_box = ctk.CTkComboBox(filter_row, variable=self.v_place, values=[], width=180, font=self.f_base)
        self.v_place_box.grid(row=1, column=3, padx=6)

        ctk.CTkLabel(filter_row, text="Trip No:", font=self.f_base).grid(row=2, column=0, padx=6, pady=4, sticky="w")
        self.v_trip = ctk.StringVar()
        ctk.CTkEntry(filter_row, textvariable=self.v_trip, width=180, font=self.f_base).grid(row=2, column=1, padx=6)

        ctk.CTkLabel(filter_row, text="Status:", font=self.f_base).grid(row=2, column=2, padx=6, pady=4, sticky="w")
        self.v_status = ctk.StringVar()
        ctk.CTkComboBox(filter_row, values=["", "Complete", "Incomplete"], variable=self.v_status, width=180, font=self.f_base).grid(row=2, column=3, padx=6)

        ctk.CTkButton(filter_row, text="Search", command=self.load_view_records, font=self.f_base).grid(row=0, column=4, padx=10)
        ctk.CTkButton(filter_row, text="Reset", fg_color="gray80", command=self._reset_view_filters, font=self.f_base).grid(row=1, column=4)

        # BODY: 2-column grid (left table, right details)
        body = ctk.CTkFrame(f)
        body.pack(fill="both", expand=True, padx=12, pady=8)
        body.grid_columnconfigure(0, weight=3)
        body.grid_columnconfigure(1, weight=2)
        body.grid_rowconfigure(0, weight=1)

        # left / table
        left_wrap = ctk.CTkFrame(body)
        left_wrap.grid(row=0, column=0, sticky="nsew", padx=(0,8), pady=0)
        cols = ("id", "date", "trip", "status")
        self.tree = ttk.Treeview(left_wrap, columns=cols, show="headings")
        for c in cols:
            self.tree.heading(c, text=c.capitalize())
            width = 260 if c == "trip" else (100 if c == "id" else 140)
            anchor = "center"
            self.tree.column(c, width=width, anchor=anchor, stretch=True)
        self.tree.pack(side="left", fill="both", expand=True)
        self.tree.bind("<Double-1>", self._on_tree_double_click)
        self.tree.bind("<<TreeviewSelect>>", self._on_tree_select)
        self.tree.tag_configure('incomplete', background='#fff5d6')
        self.tree.tag_configure('complete', background='#eafff2')
        vsb = ttk.Scrollbar(left_wrap, orient="vertical", command=self.tree.yview)
        vsb.pack(side="right", fill="y")
        hsb = ttk.Scrollbar(left_wrap, orient="horizontal", command=self.tree.xview)
        hsb.pack(side="bottom", fill="x")
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)

        # right / details
        right = ctk.CTkFrame(body)
        right.grid(row=0, column=1, sticky="nsew", padx=(8,0), pady=0)
        right.grid_rowconfigure(1, weight=1)

        ctk.CTkLabel(right, text="Record Details", font=self.f_base).grid(row=0, column=0, sticky="w", pady=(0,6))
        self.detail_text = ctk.CTkTextbox(right, height=520, font=self.f_base, wrap="word")
        self.detail_text.grid(row=1, column=0, sticky="nsew")

        btns = ctk.CTkFrame(right)
        btns.grid(row=2, column=0, sticky="ew", pady=(6,0))
        ctk.CTkButton(btns, text="Edit Selected", command=self._edit_selected, font=self.f_base).pack(side="left", padx=6)
        ctk.CTkButton(btns, text="Delete Selected", fg_color="#c63", command=self._delete_selected, font=self.f_base).pack(side="left", padx=6)
        ctk.CTkButton(btns, text="Delete Selected (Multi)", fg_color="#a33", command=self._delete_selected_multi, font=self.f_base).pack(side="left", padx=6)

        self.v_area.set("")
        self._reload_view_places()

    def _reload_view_places(self):
        area = self.v_area.get()
        if not area:
            self.v_place_box.configure(values=[])
            self.v_place.set("")
            return
        DB_CURSOR.execute("SELECT id FROM areas WHERE name = ?", (area,))
        r = DB_CURSOR.fetchone()
        if not r:
            self.v_place_box.configure(values=[])
            self.v_place.set("")
            return
        aid = r[0]
        DB_CURSOR.execute("SELECT code FROM places WHERE area_id = ? ORDER BY code", (aid,))
        names = [x[0] for x in DB_CURSOR.fetchall()]
        self.v_place_box.configure(values=names)
        if names:
            self.v_place.set(names[0])

    def _reset_view_filters(self):
        self.v_date_from.set("")
        self.v_date_to.set("")
        self.v_area.set("")
        self.v_place.set("")
        self.v_trip.set("")
        self.v_status.set("")
        self.load_view_records()

    def load_view_records(self):
        try:
            query = ("SELECT r.id, r.date, r.trip_no, a.name, p.code, r.car_plate, r.status FROM gts_records r "
                     "LEFT JOIN areas a ON r.area_id=a.id LEFT JOIN places p ON r.place_id=p.id WHERE 1=1")
            params = []
            df = self.v_date_from.get().strip()
            dt = self.v_date_to.get().strip()
            if df and dt:
                query += " AND date BETWEEN ? AND ?"; params.extend([df, dt])
            elif df:
                query += " AND date >= ?"; params.append(df)
            elif dt:
                query += " AND date <= ?"; params.append(dt)
            if self.v_area.get().strip():
                query += " AND a.name = ?"; params.append(self.v_area.get().strip())
            if self.v_place.get().strip():
                query += " AND p.code = ?"; params.append(self.v_place.get().strip())
            if self.v_trip.get().strip():
                query += " AND r.trip_no LIKE ?"; params.append(f"%{self.v_trip.get().strip()}%")
            if self.v_status.get().strip():
                query += " AND r.status = ?"; params.append(self.v_status.get().strip())
            query += " ORDER BY r.date DESC, r.id DESC LIMIT 100"
            DB_CURSOR.execute(query, params)
            rows = DB_CURSOR.fetchall()
            for i in self.tree.get_children():
                self.tree.delete(i)
            for i, row in enumerate(rows):
                rid, date_s, trip_no, area_name, place_code, car_plate, status = row
                place_code = place_code or "-"
                trip_str = f"{place_code}/{trip_no or '-'}{('/' + car_plate) if car_plate else ''}"
                tag = 'complete' if status == 'Complete' else 'incomplete'
                self.tree.insert("", "end", iid=str(rid),
                                 values=(rid, date_s, trip_str, status), tags=(tag,))
            self.detail_text.delete("0.0", "end")
        except Exception:
            log_exc("load_view_records")
            messagebox.showerror("Error", "Failed to load records. See log.")

    def _on_tree_double_click(self, event):
        sel = self.tree.selection()
        if not sel:
            return
        rid = int(sel[0])
        self._open_for_edit(rid)

    def _on_tree_select(self, event):
        sel = self.tree.selection()
        if not sel:
            return
        rid = int(sel[0])
        try:
            DB_CURSOR.execute("""
                SELECT date, trip_no, area_id, place_id, apdn_no, e12_seal, k3_seal, car_plate,
                       estate_pics, kilang_pics, estate_marks, kilang_marks, remarks, status, created_at, updated_at
                FROM gts_records
                WHERE id = ?
            """, (rid,))
            r = DB_CURSOR.fetchone()
            if not r:
                return
            (date_s, trip, aid, pid, apdn, seal_e12, seal_k3, car_plate,
             estate_s, kilang_s, e_marks_s, k_marks_s,
             remarks, status, created, updated) = r

            DB_CURSOR.execute("SELECT name FROM areas WHERE id = ?", (aid,))
            area_name = (DB_CURSOR.fetchone() or ["-"])[0]
            DB_CURSOR.execute("SELECT code FROM places WHERE id = ?", (pid,))
            place_code = (DB_CURSOR.fetchone() or ["-"])[0]

            estate_data = load_json(estate_s); kilang_data = load_json(kilang_s)
            e_marks = load_json(e_marks_s);     k_marks = load_json(k_marks_s)

            lines = [
                f"Date: {date_s}",
                f"Trip: {place_code}/{trip or '-'}{('/' + car_plate) if car_plate else ''}",
                f"Area / Place: {area_name} / {place_code}",
                f"Car Plate: {car_plate or '-'}",
                f"APDN (E2): {apdn or '-'}",
                f"Seal E12: {seal_e12 or '-'}    Seal K3: {seal_k3 or '-'}",
                f"Status: {status}",
                f"Saved: {created}   Updated: {updated or '-'}",
                ""
            ]
            lines.append("Estate:")
            for k in REQUIRED_E:
                lines.append(f"  {k}: {MARK_SYMBOL.get(e_marks.get(k, ''), '')} ({len(estate_data.get(k, []))} files)")
            lines.append("")
            lines.append("Kilang:")
            for k in REQUIRED_K:
                lines.append(f"  {k}: {MARK_SYMBOL.get(k_marks.get(k, ''), '')} ({len(kilang_data.get(k, []))} files)")
            lines.append("")
            lines.append("Remarks:")
            lines.append(remarks or "-")

            self.detail_text.delete("0.0", "end")
            self.detail_text.insert("0.0", "\n".join(lines))
        except Exception:
            log_exc("_on_tree_select")
            messagebox.showerror("Error", "Failed to show details. See log.")

    def _edit_selected(self):
        sel = self.tree.selection()
        if not sel:
            messagebox.showinfo("Select", "Please select a record to edit.")
            return
        rid = int(sel[0])
        self._open_for_edit(rid)

    def _open_for_edit(self, rid):
        try:
            DB_CURSOR.execute("""
                SELECT id, date, trip_no, area_id, place_id, apdn_no, e12_seal, k3_seal, car_plate,
                       estate_pics, kilang_pics, estate_marks, kilang_marks, remarks
                FROM gts_records WHERE id = ?
            """, (rid,))
            row = DB_CURSOR.fetchone()
            if not row:
                messagebox.showerror("Not found", "Record not found.")
                return
            (_id, date_s, trip, aid, pid, apdn, seal_e12, seal_k3, car_plate,
             estate_s, kilang_s, e_marks_s, k_marks_s, remarks) = row

            self.editing_id = rid
            self.cr_date.set(date_s or datetime.date.today().isoformat())
            self.cr_trip.set(trip or "")
            self.cr_apdn_e2.set(apdn or "")
            self.cr_car_plate.set(car_plate or "")
            self.cr_seal_e12.set(seal_e12 or "")
            self.cr_seal_k3.set(seal_k3 or "")

            DB_CURSOR.execute("SELECT name FROM areas WHERE id = ?", (aid,))
            area_name = (DB_CURSOR.fetchone() or [""])[0]
            self.cr_area_box.configure(values=self._load_area_names())
            self.cr_area_var.set(area_name)
            self._reload_places_box()
            DB_CURSOR.execute("SELECT code FROM places WHERE id = ?", (pid,))
            self.cr_place_var.set((DB_CURSOR.fetchone() or [""])[0])

            self.cr_remarks.delete("0.0", "end")
            self.cr_remarks.insert("0.0", remarks or "")

            e_marks = load_json(e_marks_s); k_marks = load_json(k_marks_s)
            for k in REQUIRED_E: self.estate_marks[k].set(e_marks.get(k, ""))
            for k in REQUIRED_K: self.kilang_marks[k].set(k_marks.get(k, ""))

            estate_data = load_json(estate_s); kilang_data = load_json(kilang_s)
            for k in REQUIRED_E:
                self.estate_files[k]["paths"] = list(estate_data.get(k, []))[:2]
                self.estate_files[k]["count_widget"].configure(text=f"{len(self.estate_files[k]['paths'])} files")
            for k in REQUIRED_K:
                self.kilang_files[k]["paths"] = list(kilang_data.get(k, []))[:2]
                self.kilang_files[k]["count_widget"].configure(text=f"{len(self.kilang_files[k]['paths'])} files")

            self.tabview.set("Create Record")
            self._update_save_warning()
        except Exception:
            log_exc("_open_for_edit")
            messagebox.showerror("Error", "Failed to open record for edit. See log.")

    def _delete_selected(self):
        sel = self.tree.selection()
        if not sel:
            messagebox.showinfo("Select", "Please select a record to delete.")
            return
        rid = int(sel[0])
        if not messagebox.askyesno("Confirm", f"Delete record {rid}? This cannot be undone."):
            return
        try:
            DB_CURSOR.execute("DELETE FROM gts_records WHERE id = ?", (rid,))
            DB_CONN.commit()
            self.load_view_records()
            messagebox.showinfo("Deleted", "Record deleted.")
        except Exception:
            log_exc("_delete_selected")
            messagebox.showerror("Error", "Failed to delete record. See log.")

    def _fetch_records(self, where="", params=(), limit=None):
        cols = ["id", "date", "trip_no", "area_id", "place_id", "apdn_no", "e12_seal", "k3_seal", "car_plate",
                "estate_pics", "kilang_pics", "estate_marks", "kilang_marks",
                "remarks", "status", "created_at", "updated_at"]
        sql = f"SELECT {', '.join(cols)} FROM gts_records"
        if where: sql += " WHERE " + where
        sql += " ORDER BY date DESC, id DESC"
        if limit: sql += f" LIMIT {int(limit)}"
        DB_CURSOR.execute(sql, params)
        rows = [dict(zip(cols, r)) for r in DB_CURSOR.fetchall()]
        return rows

    # ---------- PDF Exports ----------


    def _estimate_block_height(self, rec, w, h, margin):
        """Rough height estimate in points to decide page breaks (avoid splitting a record)."""
        rows = max(len(REQUIRED_E), len(REQUIRED_K))  # 10
        header_h = 18 * mm
        subheader_h = 10 * mm
        row_h = 14 * mm  # includes space for two thumbnails (scaled)
        # remarks: wrap to ~120 chars -> limit to 6 lines est.
        remarks = (rec.get("remarks") or "").strip()
        lines = max(1, min(6, (len(remarks)//120)+1))
        remarks_h = (6 + lines*5) * mm
        total = header_h + subheader_h + rows*row_h + remarks_h + 6*mm  # +gap
        return total

    def _draw_record_block(self, c, rec, x, y_top, width):
        """Draw one full record block at position (x, y_top). Returns new y (lower)."""
        # Preload lookups
        DB_CURSOR.execute("SELECT name FROM areas WHERE id = ?", (rec["area_id"],))
        area_name = (DB_CURSOR.fetchone() or [""])[0]
        DB_CURSOR.execute("SELECT code FROM places WHERE id = ?", (rec["place_id"],))
        place_code = (DB_CURSOR.fetchone() or [""])[0]

        estate_data = load_json(rec["estate_pics"]); kilang_data = load_json(rec["kilang_pics"])
        e_marks = load_json(rec["estate_marks"]);     k_marks = load_json(rec["kilang_marks"])

        # Layout constants
        w = width
        h_header = 18 * mm
        h_sub = 10 * mm
        row_h = 14 * mm
        col_gap = 6 * mm
        inner_pad = 3 * mm
        # Columns for Estate/Kilang
        col_w = (w - col_gap) / 2.0
        y = y_top

        # Header line 1
        c.setFont("Helvetica-Bold", 13)
        trip_str = f"{place_code}/{rec.get('trip_no') or '-'}{('/' + rec.get('car_plate')) if rec.get('car_plate') else ''}"
        c.drawString(x, y,
                     f"Date: {rec['date']}    Trip: {trip_str}    Status: {rec['status']}")
        y -= 7 * mm

        # Header line 2
        c.setFont("Helvetica", 10)
        c.drawString(x, y,
                     f"Area: {area_name}/{place_code}    APDN (E2): {rec.get('apdn_no') or '-'}    "
                     f"Seal E12: {rec.get('e12_seal') or '-'}    Seal K3: {rec.get('k3_seal') or '-'}    Car Plate: {rec.get('car_plate') or '-'}")
        y -= (h_header - 7*mm)

        # Column titles
        c.setFont("Helvetica-Bold", 11); c.drawString(x, y, "ESTATE")
        c.setFont("Helvetica-Bold", 11); c.drawString(x + col_w + col_gap, y, "KILANG")
        y -= h_sub

        # Row rendering helper
        def draw_label_rows(base_x, keys, marks_map, pics_map):
            yy = y
            thumb_w = 26 * mm
            thumb_h = 18 * mm
            for k in keys:
                # Label + mark
                c.setFont("Helvetica", 10)
                c.drawString(base_x, yy, f"{k} : {MARK_SYMBOL.get(marks_map.get(k,''), '')}")
                # images (up to 2) laid out to the right within the column
                imgs = list(pics_map.get(k, []))[:2]
                ix = base_x + 28 * mm
                for i, fpath in enumerate(imgs):
                    try:
                        if PIL_AVAILABLE and os.path.exists(fpath):
                            img = Image.open(fpath); img.thumbnail((int(thumb_w), int(thumb_h)))
                            tmp = os.path.join(APP_DIR, f"tmp_{os.path.basename(fpath)}_{i}.jpg")
                            img.convert("RGB").save(tmp, format="JPEG")
                            c.drawImage(tmp, ix, yy - thumb_h + 2, width=thumb_w, height=thumb_h, preserveAspectRatio=True, anchor='sw')
                            try: os.remove(tmp)
                            except: pass
                        else:
                            c.setFont("Helvetica", 8)
                            c.drawString(ix, yy-4, os.path.basename(fpath))
                    except Exception:
                        # ignore single image failure
                        pass
                    ix += thumb_w + 2*mm
                yy -= row_h
            return yy

        # Draw Estate column
        y_after_estate = draw_label_rows(x + inner_pad, REQUIRED_E, e_marks, estate_data)
        # Draw Kilang column
        y_after_kilang = draw_label_rows(x + col_w + col_gap + inner_pad, REQUIRED_K, k_marks, kilang_data)

        y = min(y_after_estate, y_after_kilang) - 4*mm

        # Remarks
        c.setFont("Helvetica-Bold", 11); c.drawString(x, y, "Remarks:")
        y -= 4*mm
        c.setFont("Helvetica", 10)
        remarks = (rec.get("remarks") or "-").strip()
        for ln in textwrap.wrap(remarks, width=140)[:10]:
            c.drawString(x, y, ln)
            y -= 5 * mm

        # Footer timestamps (small)
        c.setFont("Helvetica", 8)
        c.drawRightString(x + w, y + 4*mm, f"Saved: {rec.get('created_at')}   Updated: {rec.get('updated_at') or '-'}")

        return y - 4*mm

    # ---------- Helpers ----------
    def _update_save_warning(self):
        missing = [k for k in REQUIRED_E if self.estate_marks[k].get() == ""]
        missing += [k for k in REQUIRED_K if self.kilang_marks[k].get() == ""]
        if missing:
            txt = f"Missing {len(missing)} marks — saved records will be Incomplete until filled."
            self.save_warning_label.configure(text=txt)
        else:
            self.save_warning_label.configure(text="All labels filled. Saving will compute status accordingly.")


    
    def _guarded_set_admin_pin(self):
        messagebox.showinfo("Info", "PIN is now part of the signed license. Ask SED admin to issue a new license to change it.")
        return

# ---------- Admin PIN (protect manage areas/places) ----------
    def _set_admin_pin_dialog(self):
        try:
            dlg = tk.Toplevel(self)
            dlg.title("Set/Change Admin PIN")
            dlg.geometry("360x180")
            dlg.transient(self); dlg.grab_set()
            tk.Label(dlg, text="Enter new 4–12 character PIN (letters or numbers):").pack(pady=8)
            e1 = tk.Entry(dlg, show="*")
            e1.pack(pady=4)
            tk.Label(dlg, text="Confirm PIN:").pack(pady=4)
            e2 = tk.Entry(dlg, show="*")
            e2.pack(pady=4)

            def do_set():
                p1 = e1.get().strip()
                p2 = e2.get().strip()
                if not p1 or len(p1) < 4 or len(p1) > 12 or not p1.isalnum():
                    messagebox.showwarning("Invalid", "PIN must be 4–12 characters (letters or numbers).")
                    return
                if p1 != p2:
                    messagebox.showwarning("Mismatch", "PINs do not match.")
                    return
                salt = secrets.token_hex(16)
                h = _hash_pin(p1, salt)
                lic = _load_license()
                lic["admin_pin_salt"] = salt
                lic["admin_pin_hash"] = h
                _save_license(lic)
                messagebox.showinfo("Saved", "Admin PIN updated.")
                dlg.destroy()

            tk.Button(dlg, text="Save PIN", command=do_set).pack(pady=10)
            tk.Button(dlg, text="Cancel", command=dlg.destroy).pack()
        except Exception:
            log_exc("_set_admin_pin_dialog")

    


# ---------------- startup login (PIN before showing UI) ----------------
def _startup_login_guard(max_attempts: int = 5) -> bool:
    """
    Verify signed license and prompt for PIN before showing the main UI.
    Returns True if unlocked, False otherwise.
    """
    try:
        import tkinter as _tk
        from tkinter import simpledialog as _simpledialog, messagebox as _messagebox

        cfg = _load_license()
        if not cfg:
            _messagebox.showerror("License missing", "license.json not found. Contact SED admin.")
            return False
        payload = cfg.get("payload", {})
        sig = cfg.get("signature", "")
        if not os.path.exists(PUBKEY_PATH):
            _messagebox.showerror("Public key missing", "public_key.pem not found. Contact SED admin.")
            return False
        if not _verify_license_signature(payload, sig):
            _messagebox.showerror("Invalid license", "Signature verification failed.")
            return False

        import datetime as _dt
        if payload.get("bind_hostname"):
            import socket as _socket
            current_host = _socket.gethostname()
            if payload.get("hostname") != current_host:
                _messagebox.showerror("License rejected", f"This license is bound to {payload.get('hostname')}, not {current_host}.")
                return False
        if payload.get("expires_at"):
            try:
                expires = _dt.datetime.fromisoformat(payload["expires_at"].replace("Z",""))
                if _dt.datetime.utcnow() > expires:
                    _messagebox.showerror("License expired", f"License expired on {payload['expires_at']}.")
                    return False
            except Exception:
                pass

        root = _tk.Tk()
        root.withdraw()
        def _destroy_root():
            try:
                root.destroy()
            except Exception:
                pass
        tries = 0
        while tries < max_attempts:
            pin = _simpledialog.askstring("GTS Login", f"Enter Admin PIN ({max_attempts-tries} tries left):", show="*", parent=root)
            if pin is None:
                _destroy_root()
                return False
            expected = payload.get("admin_pin_hash")
            salt = payload.get("admin_pin_salt")
            if expected and salt and _hash_pin(pin, salt) == expected:
                _destroy_root()
                return True
            tries += 1
            _messagebox.showerror("Incorrect PIN", "PIN is incorrect.")
        _messagebox.showerror("Locked", "Too many failed attempts. Exiting.")
        _destroy_root()
        return False
    except Exception:
        log_exc("_startup_login_guard")
        _destroy_root()
        return False

# ---------------- run ----------------
if __name__ == "__main__":
    try:
        if not _startup_login_guard(max_attempts=5):
            raise SystemExit(1)
        app = GTSApp()
        app.mainloop()
    except SystemExit:
        pass
    except Exception:
        log_exc("Fatal error running app")
        raise
