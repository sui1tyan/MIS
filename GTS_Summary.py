import os
import sys
import json
import sqlite3
import datetime
import logging
import traceback
import shutil
import hashlib
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, simpledialog
from tkinter import font as tkfont

# ---- Ed25519 verification ----
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

# ---- CustomTkinter ----
try:
    import customtkinter as ctk
except Exception as e:
    raise RuntimeError("customtkinter required. Install: pip install customtkinter") from e

# ---------------- paths (keep everything beside the app) ----------------
if getattr(sys, "frozen", False):
    APP_DIR = os.path.dirname(sys.executable)
else:
    APP_DIR = os.path.dirname(os.path.abspath(__file__))

os.makedirs(APP_DIR, exist_ok=True)
IMG_STORE = os.path.join(APP_DIR, "images"); os.makedirs(IMG_STORE, exist_ok=True)
LOG_PATH = os.path.join(APP_DIR, "gts_app.log")
DB_PATH = os.path.join(APP_DIR, "gts_records.db")
SETTINGS_PATH  = os.path.join(APP_DIR, "settings.json")
LICENSE_PATH   = os.path.join(APP_DIR, "license.json")
PUBKEY_PATH    = os.path.join(APP_DIR, "public_key.pem")

# ---------------- logging ----------------
logging.basicConfig(filename=LOG_PATH, level=logging.INFO,
                    format="%(asctime)s %(levelname)s %(message)s")
def log_exc(msg=""):
    logging.error(msg)
    logging.error(traceback.format_exc())

# ---------------- labels & defaults ----------------
REQUIRED_E = ["E2","E3","E4","E5","E6","E12","E13","E14","E15","E16"]
REQUIRED_K = ["K1","K3","K4","K5","K6","K7"]
MARK_SYMBOL = {"tick":"Y", "cross":"N", "zero":"0", "":""}

DEFAULT_AREAS = {
    "Sebatik Group": ["SB1", "SB2", "S3", "KF1", "KF2"],
    "Serudong Group": ["WM1", "WM2", "WM3", "BKS1", "BKS2", "BKS3"],
    "Sungai Mas": ["SGM", "SGK"],
    "Bergosong": ["BE"],
    "Kokorotus": ["KRT"],
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

# ---------------- settings & license ----------------
def _load_settings():
    try:
        if os.path.exists(SETTINGS_PATH):
            with open(SETTINGS_PATH, "r", encoding="utf-8") as f:
                return json.load(f)
    except Exception:
        log_exc("load_settings")
    return {}

def _load_license():
    try:
        if os.path.exists(LICENSE_PATH):
            with open(LICENSE_PATH, "r", encoding="utf-8") as f:
                return json.load(f)
    except Exception:
        log_exc("load_license")
    return {}

def _canonical_json_bytes(obj):
    try:
        return json.dumps(obj, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")
    except Exception:
        return b""

def _verify_license_signature(lic_payload: dict, signature_b64: str) -> bool:
    try:
        if not os.path.exists(PUBKEY_PATH):
            return False
        with open(PUBKEY_PATH, "rb") as f:
            pub = Ed25519PublicKey.from_public_bytes(
                serialization.load_pem_public_key(f.read()).public_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PublicFormat.Raw
                )
            )
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

def copy_images_to_store(paths, label, dest_dir):
    os.makedirs(dest_dir, exist_ok=True)
    saved = []
    for idx, p in enumerate(paths or []):
        try:
            if isinstance(p, str) and os.path.commonpath([os.path.abspath(p), os.path.abspath(dest_dir)]) == os.path.abspath(dest_dir):
                saved.append(p)
                continue
        except Exception:
            pass
        try:
            base_ext = os.path.splitext(p)[1] or ".jpg"
            ts = datetime.datetime.now().strftime("%Y%m%d%H%M%S")
            fname = f"{label}_{idx}_{ts}{base_ext}"
            dest = os.path.join(dest_dir, fname)
            shutil.copy2(p, dest)
            saved.append(dest)
        except Exception:
            log_exc(f"copy image failed for {p}")
    # de-dup
    out, seen = [], set()
    for s in saved:
        if s not in seen:
            seen.add(s); out.append(s)
    return out

def compute_status_from_marks(e_marks, k_marks):
    for v in e_marks.values():
        if v == "" or v is None: return "Incomplete"
        if v == "cross": return "Incomplete"
    for v in k_marks.values():
        if v == "" or v is None: return "Incomplete"
        if v == "cross": return "Incomplete"
    return "Complete"

# ---------------- UI base ----------------
ctk.set_appearance_mode("Light")
ctk.set_default_color_theme("blue")

def roboto(size=12, weight="normal"):
    return ctk.CTkFont(family="Roboto", size=size, weight=weight)

# -------- DoubleScrollableFrame --------
class DoubleScrollableFrame(ctk.CTkFrame):
    def __init__(self, master, **kwargs):
        super().__init__(master, **kwargs)
        self.canvas = tk.Canvas(self, highlightthickness=0)
        self.inner  = ctk.CTkFrame(self.canvas)

        vsb = ttk.Scrollbar(self, orient="vertical",   command=self.canvas.yview)
        hsb = ttk.Scrollbar(self, orient="horizontal", command=self.canvas.xview)
        self.canvas.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)

        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(0, weight=1)
        self.canvas.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")

        self._win = self.canvas.create_window((0, 0), window=self.inner, anchor="nw")
        self.inner.bind("<Configure>", lambda e: self.canvas.configure(scrollregion=self.canvas.bbox("all")))
        self.canvas.bind("<Configure>", lambda e: self.canvas.itemconfigure(self._win, width=max(e.width, self.inner.winfo_reqwidth())))

        self.canvas.bind_all("<MouseWheel>", self._on_wheel)
        self.canvas.bind_all("<Shift-MouseWheel>", self._on_shift_wheel)

    def _on_wheel(self, e):
        self.canvas.yview_scroll(-1 if e.delta>0 else 1, "units")

    def _on_shift_wheel(self, e):
        self.canvas.xview_scroll(-1 if e.delta>0 else 1, "units")

# ---------------- Main App ----------------
class GTSApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("SED — GTS Recording System")
        self.geometry("1320x880")
        self.minsize(920, 600)
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(0, weight=1)
        self.after(100, lambda: self.state('zoomed'))

        self.editing_id = None

        self.f_base = roboto(12)
        self.f_bold = roboto(12, "bold")
        self.f_h1   = roboto(16, "bold")

        style = ttk.Style(self)
        style.configure("Treeview", font=("Roboto", 11), rowheight=26)
        style.configure("Treeview.Heading", font=("Roboto", 12, "bold"), anchor="w")

        try:
            tkfont.nametofont("TkDefaultFont").configure(family="Roboto", size=11)
        except Exception:
            pass

        self.tabview = ctk.CTkTabview(self, width=1200, height=820)
        self.tabview.pack(padx=12, pady=12, fill="both", expand=True)
        self.tabview.add("Create Record")
        self.tabview.add("View Records")
        self.create_tab = self.tabview.tab("Create Record")
        self.view_tab   = self.tabview.tab("View Records")

        self._build_create_tab()
        self._build_view_tab()
        self.load_view_records()

    # ---------- Create Tab ----------
    def _build_create_tab(self):
        ds = DoubleScrollableFrame(self.create_tab)
        ds.pack(fill="both", expand=True, padx=12, pady=8)
        f = ds.inner

        ctk.CTkLabel(f, text="Create / Edit Record", font=self.f_h1).pack(pady=(6, 8))

        top = ctk.CTkFrame(f)
        top.pack(fill="x", padx=12, pady=4)

        # Date
        ctk.CTkLabel(top, text="Date (YYYY-MM-DD):", font=self.f_base).grid(row=0, column=0, padx=6, pady=6, sticky="w")
        self.cr_date = tk.StringVar()
        self.cr_date.set(datetime.date.today().isoformat())
        self.date_entry = ctk.CTkEntry(top, textvariable=self.cr_date, width=140, font=self.f_base)
        self.date_entry.grid(row=0, column=1, padx=6)
        self.date_entry.bind("<FocusIn>",  lambda e: self._ensure_date_default())
        self.date_entry.bind("<FocusOut>", lambda e: self._validate_or_default_date())
        # ensure default is present but let StringVar drive content
        self.after(0, self._ensure_date_default)

        # Trip
        ctk.CTkLabel(top, text="Trip No:", font=self.f_base).grid(row=0, column=2, padx=6, pady=6, sticky="w")
        self.cr_trip = tk.StringVar()
        ctk.CTkEntry(top, textvariable=self.cr_trip, width=120, font=self.f_base).grid(row=0, column=3, padx=6)

        # APDN
        ctk.CTkLabel(top, text="APDN (E2):", font=self.f_base).grid(row=0, column=4, padx=6, pady=6, sticky="w")
        self.cr_apdn_e2 = tk.StringVar()
        ctk.CTkEntry(top, textvariable=self.cr_apdn_e2, width=140, font=self.f_base).grid(row=0, column=5, padx=6)

        # Car plate
        ctk.CTkLabel(top, text="Car Plate:", font=self.f_base).grid(row=0, column=6, padx=6, pady=6, sticky="w")
        self.cr_car_plate = tk.StringVar()
        ctk.CTkEntry(top, textvariable=self.cr_car_plate, width=140, font=self.f_base).grid(row=0, column=7, padx=6)

        # Area
        ctk.CTkLabel(top, text="Area:", font=self.f_base).grid(row=1, column=0, padx=6, pady=6, sticky="w")
        self.cr_area_var = tk.StringVar()
        area_values = self._load_area_names()
        self.cr_area_box = ctk.CTkComboBox(
            top,
            variable=self.cr_area_var,
            values=area_values,
            width=220,
            font=self.f_base,
            command=lambda _val: self._on_area_changed()
        )
        self.cr_area_box.grid(row=1, column=1, padx=6)
        if area_values:
            self.cr_area_var.set(area_values[0])
            self.cr_area_box.set(area_values[0])

        # Place
        ctk.CTkLabel(top, text="Place:", font=self.f_base).grid(row=1, column=2, padx=6, pady=6, sticky="w")
        self.cr_place_var = tk.StringVar()
        self.cr_place_box = ctk.CTkComboBox(
            top,
            variable=self.cr_place_var,
            values=self._load_places_for_current_area(),
            width=160,
            font=self.f_base
        )
        self.cr_place_box.grid(row=1, column=3, padx=6)
        self._on_area_changed()  # populate places for initial area

        # Seals
        ctk.CTkLabel(top, text="Seal E12:", font=self.f_base).grid(row=2, column=0, padx=6, pady=6, sticky="w")
        self.cr_seal_e12 = tk.StringVar()
        ctk.CTkEntry(top, textvariable=self.cr_seal_e12, width=140, font=self.f_base).grid(row=2, column=1, padx=6)

        ctk.CTkLabel(top, text="Seal K3:", font=self.f_base).grid(row=2, column=2, padx=6, pady=6, sticky="w")
        self.cr_seal_k3 = tk.StringVar()
        ctk.CTkEntry(top, textvariable=self.cr_seal_k3, width=140, font=self.f_base).grid(row=2, column=3, padx=6)

        ctk.CTkButton(top, text="Add Area",  command=self._add_area_dialog,  font=self.f_base).grid(row=1, column=4, padx=6)
        ctk.CTkButton(top, text="Add Place", command=self._add_place_dialog, font=self.f_base).grid(row=1, column=5, padx=6)
        ctk.CTkButton(top, text="Manage Areas/Places", command=self._guarded_manage_places_dialog, font=self.f_base).grid(row=1, column=6, padx=6)

        # Two-column section
        two_col = ctk.CTkFrame(f)
        two_col.pack(fill="both", expand=True, padx=12, pady=6)
        two_col.grid_columnconfigure(0, weight=1)
        two_col.grid_columnconfigure(1, weight=1)

        left  = ctk.CTkFrame(two_col); left.grid(row=0, column=0, sticky="nsew", padx=(0,6))
        right = ctk.CTkFrame(two_col); right.grid(row=0, column=1, sticky="nsew", padx=(6,0))

        ctk.CTkLabel(left, text="Estate (E2–E6, E12–E16)", font=self.f_bold).pack(anchor="w", pady=(4,2))
        self.estate_files = {}; self.estate_marks = {}
        self._build_mark_attach_grid(left, REQUIRED_E, self.estate_files, self.estate_marks)

        ctk.CTkLabel(right, text="Kilang (K1, K3–K7)", font=self.f_bold).pack(anchor="w", pady=(4,2))
        self.kilang_files = {}; self.kilang_marks = {}
        self._build_mark_attach_grid(right, REQUIRED_K, self.kilang_files, self.kilang_marks)

        ctk.CTkLabel(right, text="Remarks", font=self.f_bold).pack(anchor="w", pady=(8, 2))
        self.cr_remarks = ctk.CTkTextbox(right, height=120, font=self.f_base, wrap="word")
        self.cr_remarks.pack(fill="x")

        # Save / Switch
        btn_row = ctk.CTkFrame(f); btn_row.pack(fill="x", padx=12, pady=10)
        ctk.CTkButton(btn_row, text="Save Record", command=self._save_record, font=self.f_base).pack(side="left")
        ctk.CTkButton(btn_row, text="Switch to View", fg_color="transparent",
                      command=lambda: self.tabview.set("View Records"), font=self.f_base).pack(side="right")
        self.save_warning_label = ctk.CTkLabel(btn_row, text="", font=self.f_base)
        self.save_warning_label.pack(side="right", padx=12)

        legend_text = (
            "E2 - Ramp Pass & APDN; E3 - Timbangan lori tanpa muatan; E4 - Pandangan belakang lori; "
            "E5 - Sisi kiri lori; E6 - Sisi kanan lori; E12 - Selfie dengan seal; E13 - Timbangan lori tanpa muatan; "
            "E14 - Pandangan atas lori; E15 - Selfie di hadapan lori; E16 - Senarai semak yang lengkap di Estate\n"
            "K1 - Selfie dengan tangki air kosong; K3 - Perbandingan seal; K4 - Pandangan belakang lori; "
            "K5 - Sisi kanan lori; K6 - Sisi kiri lori; K7 - Senarai semak yang lengkap di Kilang"
        )
        ctk.CTkLabel(f, text=legend_text, font=self.f_base, wraplength=1100, anchor="w", justify="left").pack(fill="x", padx=12, pady=(6,8))

        self._update_save_warning()

    def _build_mark_attach_grid(self, parent, labels, files_store, marks_store):
        wrap = ctk.CTkFrame(parent)
        wrap.pack(fill="both", expand=True, padx=6, pady=6)
        for i, lab in enumerate(labels):
            frame = ctk.CTkFrame(wrap)
            frame.grid(row=i, column=0, padx=6, pady=4, sticky="w")

            ctk.CTkLabel(frame, text=lab, width=44, font=self.f_base).pack(side="left", padx=(4, 6))

            btncol = ctk.CTkFrame(frame); btncol.pack(side="left")
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
            if not paths: return
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
            log_exc("_load_area_names"); return []

    def _load_places_for_current_area(self):
        try:
            area = getattr(self, "cr_area_var", tk.StringVar()).get()
            if not area: return []
            DB_CURSOR.execute("SELECT id FROM areas WHERE name = ?", (area,))
            r = DB_CURSOR.fetchone()
            if not r: return []
            aid = r[0]
            DB_CURSOR.execute("SELECT code FROM places WHERE area_id = ? ORDER BY code", (aid,))
            return [x[0] for x in DB_CURSOR.fetchall()]
        except Exception:
            log_exc("_load_places_for_current_area"); return []

    def _reload_places_box(self):
        vals = self._load_places_for_current_area()
        self.cr_place_box.configure(values=vals)
        self.cr_place_var.set(vals[0] if vals else "")

    def _on_area_changed(self):
        self._reload_places_box()

    def _add_area_dialog(self):
        name = simpledialog.askstring("Add Area", "Enter new area name:", parent=self)
        if not name: return
        try:
            DB_CURSOR.execute("INSERT OR IGNORE INTO areas (name) VALUES (?)", (name.strip(),))
            DB_CONN.commit()
            self.cr_area_box.configure(values=self._load_area_names())
            self.cr_area_var.set(name.strip())
            self.cr_area_box.set(name.strip())
            self._reload_places_box()
        except Exception:
            log_exc("_add_area_dialog"); messagebox.showerror("Error", "Failed to add area. See log.")

    def _add_place_dialog(self):
        area = self.cr_area_var.get()
        if not area:
            messagebox.showwarning("No area", "Select or create an area first."); return
        code = simpledialog.askstring("Add Place", "Enter place code (e.g. 'SB4'):", parent=self)
        if not code: return
        try:
            DB_CURSOR.execute("SELECT id FROM areas WHERE name = ?", (area,))
            r = DB_CURSOR.fetchone()
            if not r:
                messagebox.showerror("Error", "Area not found."); return
            aid = r[0]
            DB_CURSOR.execute("INSERT OR IGNORE INTO places (area_id, code, name) VALUES (?,?,?)",
                              (aid, code.strip(), code.strip()))
            DB_CONN.commit()
            self._reload_places_box()
            self.cr_place_var.set(code.strip())
            self.cr_place_box.set(code.strip())
        except Exception:
            log_exc("_add_place_dialog"); messagebox.showerror("Error", "Failed to add place. See log.")

    def _guarded_manage_places_dialog(self):
        try:
            cfg = _load_license()
            payload = cfg.get("payload", {})
            sig = cfg.get("signature", "")
            if not payload or not sig or not _verify_license_signature(payload, sig) or "admin_pin_hash" not in payload or "admin_pin_salt" not in payload:
                messagebox.showinfo("Restricted", "This copy has no valid license. Areas/Places are read-only.")
                return
            if payload.get("bind_hostname"):
                import socket
                if payload.get("hostname") != socket.gethostname():
                    messagebox.showerror("License rejected", f"This license is bound to {payload.get('hostname')}."); return
            if payload.get("expires_at"):
                try:
                    expires = datetime.datetime.fromisoformat(payload["expires_at"].replace("Z",""))
                    if datetime.datetime.utcnow() > expires:
                        messagebox.showerror("License expired", f"License expired on {payload['expires_at']}."); return
                except Exception:
                    pass
            pin = simpledialog.askstring("Admin PIN", "Enter Admin PIN to proceed:", parent=self, show="*")
            if pin is None: return
            expected = payload.get("admin_pin_hash"); salt = payload.get("admin_pin_salt")
            if _hash_pin(pin, salt) != expected:
                messagebox.showerror("Denied", "Incorrect PIN."); return
            self._manage_places_dialog()
        except Exception:
            log_exc("_guarded_manage_places_dialog")

    def _manage_places_dialog(self):
        try:
            dlg = tk.Toplevel(self)
            dlg.title("Manage Areas & Places")
            dlg.geometry("680x460")
            dlg.transient(self); dlg.grab_set()
            lb_font = tkfont.Font(family="Roboto", size=11)

            container = tk.Frame(dlg); container.pack(fill="both", expand=True, padx=8, pady=8)
            left = tk.Frame(container); left.pack(side="left", fill="y", padx=(0, 8))
            tk.Label(left, text="Areas", font=lb_font).pack()
            area_list = tk.Listbox(left, width=30, height=18, exportselection=False, font=lb_font)
            area_list.pack(fill="y")
            for a in self._load_area_names():
                area_list.insert("end", a)

            mid = tk.Frame(container); mid.pack(side="left", fill="both", expand=True)
            tk.Label(mid, text="Places in selected area", font=lb_font).pack()
            place_list = tk.Listbox(mid, width=32, height=18, exportselection=False, font=lb_font)
            place_list.pack(fill="both", expand=True)

            def on_area_select(evt=None):
                sel = area_list.curselection()
                place_list.delete(0, "end")
                if not sel: return
                area = area_list.get(sel[0])
                DB_CURSOR.execute("SELECT id FROM areas WHERE name = ?", (area,))
                r = DB_CURSOR.fetchone()
                if not r: return
                aid = r[0]
                DB_CURSOR.execute("SELECT code FROM places WHERE area_id = ? ORDER BY code", (aid,))
                for p in DB_CURSOR.fetchall():
                    place_list.insert("end", p[0])

            def delete_place():
                sel = place_list.curselection()
                if not sel:
                    messagebox.showinfo("Select", "Select a place to delete.", parent=dlg); return
                place_code = place_list.get(sel[0])
                sel_area = area_list.curselection()
                if not sel_area: return
                area_name = area_list.get(sel_area[0])
                DB_CURSOR.execute("SELECT id FROM areas WHERE name = ?", (area_name,))
                r = DB_CURSOR.fetchone(); aid = r[0]
                if not messagebox.askyesno("Confirm", f"Delete place {place_code}?", parent=dlg): return
                DB_CURSOR.execute("DELETE FROM places WHERE area_id = ? AND code = ?", (aid, place_code))
                DB_CONN.commit(); on_area_select()

            def delete_area():
                sel = area_list.curselection()
                if not sel:
                    messagebox.showinfo("Select", "Select an area to delete.", parent=dlg); return
                area_name = area_list.get(sel[0])
                if not messagebox.askyesno("Confirm", f"Delete area '{area_name}' and all its places?", parent=dlg): return
                DB_CURSOR.execute("SELECT id FROM areas WHERE name = ?", (area_name,))
                r = DB_CURSOR.fetchone()
                if r:
                    aid = r[0]
                    DB_CURSOR.execute("DELETE FROM places WHERE area_id = ?", (aid,))
                    DB_CURSOR.execute("DELETE FROM areas WHERE id = ?", (aid,))
                    DB_CONN.commit()
                area_list.delete(sel[0]); place_list.delete(0, "end")
                self.cr_area_box.configure(values=self._load_area_names()); self._reload_places_box()

            area_list.bind("<<ListboxSelect>>", on_area_select)

            btnf = tk.Frame(dlg); btnf.pack(fill="x", side="bottom", padx=8, pady=8)
            tk.Button(btnf, text="Delete Place", command=delete_place, font=lb_font).pack(side="left", padx=6)
            tk.Button(btnf, text="Delete Area",  command=delete_area,  font=lb_font).pack(side="left", padx=6)
            tk.Button(btnf, text="Close",        command=dlg.destroy,  font=lb_font).pack(side="right", padx=6)

        except Exception:
            log_exc("manage_places_dialog")

    # ---------- Save / Update record ----------
    def _save_record(self):
        try:
            date_s      = self.cr_date.get().strip()
            trip        = self.cr_trip.get().strip()
            area_name   = self.cr_area_var.get().strip()
            place_code  = self.cr_place_var.get().strip()
            apdn        = (self.cr_apdn_e2.get() or "").strip()
            car_plate   = (self.cr_car_plate.get() or "").strip()
            seal_e12    = (self.cr_seal_e12.get() or "").strip()
            seal_k3     = (self.cr_seal_k3.get() or "").strip()

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

            safe_place = (place_code or "PLACE").replace(os.sep, "_")
            safe_trip  = (trip or "TRIP").replace(os.sep, "_")
            safe_car   = (car_plate or "NA").replace(os.sep, "_")
            record_dir = os.path.join(IMG_STORE, safe_place, safe_trip, f"{safe_car} {date_s}")

            estate_saved = {}
            kilang_saved = {}
            for k in REQUIRED_E:
                new_saved = copy_images_to_store(self.estate_files[k]["paths"], k, record_dir)
                estate_saved[k] = list(dict.fromkeys(new_saved))[:2]
            for k in REQUIRED_K:
                new_saved = copy_images_to_store(self.kilang_files[k]["paths"], k, record_dir)
                kilang_saved[k] = list(dict.fromkeys(new_saved))[:2]

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
            log_exc("_save_record"); messagebox.showerror("Error", "Failed to save record. See log.")

    # ---------- View Tab ----------
    def _build_view_tab(self):
        ds = DoubleScrollableFrame(self.view_tab)
        ds.pack(fill="both", expand=True, padx=12, pady=8)
        f = ds.inner

        ctk.CTkLabel(f, text="View / Search Records", font=self.f_h1).pack(pady=(6,8))

        filter_row = ctk.CTkFrame(f); filter_row.pack(fill="x", padx=12, pady=6)

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
        ctk.CTkButton(filter_row, text="Reset",  fg_color="gray80", command=self._reset_view_filters, font=self.f_base).grid(row=1, column=4)

        body = ctk.CTkFrame(f); body.pack(fill="both", expand=True, padx=12, pady=8)
        body.grid_columnconfigure(0, weight=3); body.grid_columnconfigure(1, weight=2); body.grid_rowconfigure(0, weight=1)

        left_wrap = ctk.CTkFrame(body); left_wrap.grid(row=0, column=0, sticky="nsew", padx=(0,8), pady=0)
        cols = ("id", "date", "trip", "status")
        self.tree = ttk.Treeview(left_wrap, columns=cols, show="headings")
        for c in cols:
            self.tree.heading(c, text=c.capitalize(), anchor="w")
            width = 260 if c == "trip" else 140
            self.tree.column(c, width=width, anchor="w", stretch=True)
        self.tree.pack(side="left", fill="both", expand=True)
        self.tree.bind("<Double-1>", self._on_tree_double_click)
        self.tree.bind("<<TreeviewSelect>>", self._on_tree_select)
        self.tree.tag_configure('incomplete', background='#fff5d6')
        self.tree.tag_configure('complete',   background='#eafff2')
        vsb = ttk.Scrollbar(left_wrap, orient="vertical",   command=self.tree.yview); vsb.pack(side="right",  fill="y")
        hsb = ttk.Scrollbar(left_wrap, orient="horizontal", command=self.tree.xview); hsb.pack(side="bottom", fill="x")
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)

        right = ctk.CTkFrame(body); right.grid(row=0, column=1, sticky="nsew", padx=(8,0), pady=0)
        right.grid_rowconfigure(1, weight=1)
        ctk.CTkLabel(right, text="Record Details", font=self.f_base).grid(row=0, column=0, sticky="w", pady=(0,6))
        self.detail_text = ctk.CTkTextbox(right, height=520, font=self.f_base, wrap="word")
        self.detail_text.grid(row=1, column=0, sticky="nsew")

        btns = ctk.CTkFrame(right); btns.grid(row=2, column=0, sticky="ew", pady=(6,0))
        ctk.CTkButton(btns, text="Edit Selected",   command=self._edit_selected, font=self.f_base).pack(side="left", padx=6)
        ctk.CTkButton(btns, text="Delete Selected", fg_color="#c63", command=self._delete_selected, font=self.f_base).pack(side="left", padx=6)

        self.v_area.set(""); self._reload_view_places()

    def _reload_view_places(self):
        area = self.v_area.get()
        if not area:
            self.v_place_box.configure(values=[]); self.v_place.set(""); return
        DB_CURSOR.execute("SELECT id FROM areas WHERE name = ?", (area,))
        r = DB_CURSOR.fetchone()
        if not r:
            self.v_place_box.configure(values=[]); self.v_place.set(""); return
        aid = r[0]
        DB_CURSOR.execute("SELECT code FROM places WHERE area_id = ? ORDER BY code", (aid,))
        names = [x[0] for x in DB_CURSOR.fetchall()]
        self.v_place_box.configure(values=names)
        self.v_place.set(names[0] if names else "")

    def _reset_view_filters(self):
        self.v_date_from.set(""); self.v_date_to.set(""); self.v_area.set(""); self.v_place.set("")
        self.v_trip.set(""); self.v_status.set("")
        self.load_view_records()

    def load_view_records(self):
        try:
            query = ("SELECT r.id, r.date, r.trip_no, a.name, p.code, r.car_plate, r.status FROM gts_records r "
                     "LEFT JOIN areas a ON r.area_id=a.id LEFT JOIN places p ON r.place_id=p.id WHERE 1=1")
            params = []
            df = self.v_date_from.get().strip(); dt = self.v_date_to.get().strip()
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
                trip_no_txt   = (trip_no or "").strip()
                car_plate_txt = (car_plate or "").strip()
                trip_str = place_code or "-"
                trip_str += f"/{trip_no_txt if trip_no_txt else '-'}"
                if car_plate_txt:
                    trip_str += f"/{car_plate_txt}"
                tag = 'complete' if status == 'Complete' else 'incomplete'
                self.tree.insert("", "end", iid=str(rid),
                                 values=(rid, date_s, trip_str, status), tags=(tag,))
            self.detail_text.delete("0.0", "end")
        except Exception:
            log_exc("load_view_records")
            messagebox.showerror("Error", "Failed to load records. See log.")

    def _on_tree_double_click(self, event):
        sel = self.tree.selection()
        if not sel: return
        rid = int(sel[0])
        self._open_for_edit(rid)

    def _on_tree_select(self, event):
        sel = self.tree.selection()
        if not sel: return
        rid = int(sel[0])
        try:
            DB_CURSOR.execute("""
                SELECT date, trip_no, area_id, place_id, apdn_no, e12_seal, k3_seal, car_plate,
                       estate_pics, kilang_pics, estate_marks, kilang_marks, remarks, status, created_at, updated_at
                FROM gts_records WHERE id = ?
            """, (rid,))
            r = DB_CURSOR.fetchone()
            if not r: return
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
            lines.append("Remarks:"); lines.append(remarks or "-")

            self.detail_text.delete("0.0", "end")
            self.detail_text.insert("0.0", "\n".join(lines))
        except Exception:
            log_exc("_on_tree_select"); messagebox.showerror("Error", "Failed to show details. See log.")

    def _edit_selected(self):
        sel = self.tree.selection()
        if not sel:
            messagebox.showinfo("Select", "Please select a record to edit."); return
        rid = int(sel[0]); self._open_for_edit(rid)

    def _open_for_edit(self, rid):
        try:
            DB_CURSOR.execute("""
                SELECT id, date, trip_no, area_id, place_id, apdn_no, e12_seal, k3_seal, car_plate,
                       estate_pics, kilang_pics, estate_marks, kilang_marks, remarks
                FROM gts_records WHERE id = ?
            """, (rid,))
            row = DB_CURSOR.fetchone()
            if not row:
                messagebox.showerror("Not found", "Record not found."); return
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
            self.cr_area_box.set(area_name)
            self._reload_places_box()
            DB_CURSOR.execute("SELECT code FROM places WHERE id = ?", (pid,))
            pc = (DB_CURSOR.fetchone() or [""])[0]
            self.cr_place_var.set(pc)
            self.cr_place_box.set(pc)

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
            log_exc("_open_for_edit"); messagebox.showerror("Error", "Failed to open record for edit. See log.")

    def _delete_selected(self):
        sel = self.tree.selection()
        if not sel:
            messagebox.showinfo("Select", "Please select a record to delete."); return
        rid = int(sel[0])
        if not messagebox.askyesno("Confirm", f"Delete record {rid}? This cannot be undone."):
            return
        try:
            DB_CURSOR.execute("DELETE FROM gts_records WHERE id = ?", (rid,))
            DB_CONN.commit()
            self.load_view_records()
            messagebox.showinfo("Deleted", "Record deleted.")
        except Exception:
            log_exc("_delete_selected"); messagebox.showerror("Error", "Failed to delete record. See log.")

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

    # ---------- helpers ----------
    def _update_save_warning(self):
        missing = [k for k in REQUIRED_E if self.estate_marks[k].get() == ""]
        missing += [k for k in REQUIRED_K if self.kilang_marks[k].get() == ""]
        if missing:
            self.save_warning_label.configure(text=f"Missing {len(missing)} marks — saved records will be Incomplete until filled.")
        else:
            self.save_warning_label.configure(text="All labels filled. Saving will compute status accordingly.")

    def _ensure_date_default(self):
        if not (self.cr_date.get() or "").strip():
            self.cr_date.set(datetime.date.today().isoformat())

    def _validate_or_default_date(self):
        s = (self.cr_date.get() or "").strip()
        try:
            if not s:
                raise ValueError("empty")
            datetime.date.fromisoformat(s)
        except Exception:
            self.cr_date.set(datetime.date.today().isoformat())

# ---------------- startup login (License + PIN) ----------------
def _startup_login_guard(max_attempts: int = 5) -> bool:
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

        root = _tk.Tk(); root.withdraw()
        tries = 0
        while tries < max_attempts:
            pin = _simpledialog.askstring("GTS Login", f"Enter Admin PIN ({max_attempts-tries} tries left):", show="*", parent=root)
            if pin is None:
                return False
            expected = payload.get("admin_pin_hash"); salt = payload.get("admin_pin_salt")
            if expected and salt and _hash_pin(pin, salt) == expected:
                return True
            tries += 1
            _messagebox.showerror("Incorrect PIN", "PIN is incorrect.")
        _messagebox.showerror("Locked", "Too many failed attempts. Exiting.")
        return False
    except Exception:
        log_exc("_startup_login_guard")
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
