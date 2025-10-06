# (Full updated GTS_Summary.py contents)
# -- BEGIN updated file -----------------------------------------------------
import os, sys, tempfile, atexit
import json, sqlite3
import datetime, time
import logging, traceback
import shutil
import hashlib
import tkinter as tk
import tempfile
import atexit
from tkinter import ttk, filedialog, messagebox, simpledialog
from tkinter import font as tkfont
from contextlib import contextmanager

# ---------- Helper: Resolve file paths ----------
def _resolve_path(self, p):
    """
    Convert a path to absolute path.
    - If p is already absolute, return normalized absolute path.
    - If p is relative, assume relative to IMG_STORE.
    - Returns None for invalid input.
    """
    if not p or not isinstance(p, str):
        return None
    # ensure IMG_STORE is absolute
    store = IMG_STORE if os.path.isabs(IMG_STORE) else os.path.abspath(IMG_STORE)
    abs_p = p if os.path.isabs(p) else os.path.join(store, p)
    return os.path.normpath(os.path.abspath(abs_p))

# ---------------- cleanup stale _MEI folders ----------------
try:
    import shutil

    temp_dir = tempfile.gettempdir()
    for name in os.listdir(temp_dir):
        if name.startswith("_MEI") and len(name) > 8:
            path = os.path.join(temp_dir, name)
            try:
                # check if directory looks like a PyInstaller unpack dir
                if os.path.isdir(path):
                    # skip current running _MEIPASS (used by this exe)
                    if hasattr(sys, "_MEIPASS") and os.path.samefile(sys._MEIPASS, path):
                        continue
                    # try remove quietly
                    shutil.rmtree(path, ignore_errors=True)
            except Exception:
                pass
except Exception as e:
    print("Cleanup of stale _MEI folders failed:", e)

# ---------------- prevent multiple instances ----------------
try:
    LOCK_PATH = os.path.join(tempfile.gettempdir(), "GTS_summary.lock")

    # If file exists and the process inside it is still running, block
    if os.path.exists(LOCK_PATH):
        try:
            with open(LOCK_PATH, "r") as f:
                pid = int(f.read().strip() or 0)
            import psutil
            if psutil.pid_exists(pid):
                import tkinter.messagebox as mbox
                mbox.showwarning("Already running", "GTS is already running.\nPlease close the existing window first.")
                sys.exit(0)
        except Exception:
            # file corrupted or unreadable — just remove it
            try:
                os.remove(LOCK_PATH)
            except Exception:
                pass

    # Write current process ID
    with open(LOCK_PATH, "w") as f:
        f.write(str(os.getpid()))

    # Auto-remove lock file on exit
    def _cleanup_lock():
        try:
            if os.path.exists(LOCK_PATH):
                os.remove(LOCK_PATH)
        except Exception:
            pass
    atexit.register(_cleanup_lock)

except Exception as e:
    print("Single-instance guard failed:", e)

# ---- Ed25519 verification ----
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

# ---- CustomTkinter ----
try:
    import customtkinter as ctk
except Exception as e:
    raise RuntimeError("customtkinter required. Install: pip install customtkinter") from e

# try to import PIL for images (optional)
try:
    from PIL import Image, ImageTk
except Exception:
    Image = None

# ---------------- icon / logo names ----------------
ICON_ICO_NAME = "SED_ICON.ico"
ICON_IMG_NAME = "SED_ICON.jpg"  # your uploaded image name

# ---------------- paths (keep everything beside the app) ----------------
if getattr(sys, "frozen", False):
    APP_DIR = os.path.dirname(sys.executable)
else:
    APP_DIR = os.path.dirname(os.path.abspath(__file__))

os.makedirs(APP_DIR, exist_ok=True)
IMG_STORE     = os.path.join(APP_DIR, "images"); os.makedirs(IMG_STORE, exist_ok=True)
LOG_PATH      = os.path.join(APP_DIR, "gts_app.log")
DB_PATH       = os.path.join(APP_DIR, "gts_records.db")
SETTINGS_PATH = os.path.join(APP_DIR, "settings.json")
LICENSE_PATH  = os.path.join(APP_DIR, "license.json")
PUBKEY_PATH   = os.path.join(APP_DIR, "public_key.pem")

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
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.execute("PRAGMA foreign_keys = ON")
    return conn

@contextmanager
def db_cursor():
    """Context manager to handle DB cursor safely."""
    conn = get_db_conn()
    cur = conn.cursor()
    try:
        yield cur
        conn.commit()
    except Exception:
        conn.rollback()
        log_exc("DB error")
        raise
    finally:
        conn.close()

def _table_has_column(cur, table, col):
    cur.execute(f"PRAGMA table_info({table})")
    return any(r[1] == col for r in cur.fetchall())

def ensure_db_schema():
    try:
        with db_cursor() as cur:
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
    except Exception:
        log_exc("ensure_db_schema failed")
        raise

ensure_db_schema()

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
            log_exc("Public key missing")
            return False
        with open(PUBKEY_PATH, "rb") as f:
            data = f.read()
        pub = serialization.load_pem_public_key(data)
        import base64
        sig = base64.b64decode(signature_b64)
        pub.verify(sig, _canonical_json_bytes(lic_payload))
        return True
    except Exception:
        log_exc("_verify_license_signature")
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
        
def _resolve_store_path(p):
    """Return absolute filesystem path for a stored image path.
    If p is already absolute return it unchanged; else join with IMG_STORE.
    Returns None for falsy p."""
    if not p:
        return None
    return p if os.path.isabs(p) else os.path.join(IMG_STORE, p)

def copy_images_to_store(paths, label, dest_dir):
    os.makedirs(dest_dir, exist_ok=True)
    saved = []
    for idx, p in enumerate(paths or []):
        try:
            # canonical source path (handle relative stored paths that are relative to IMG_STORE)
            src_candidate = p if os.path.isabs(p) else os.path.join(IMG_STORE, p)

            # if source exists and is already under dest_dir, store relative path
            if os.path.exists(src_candidate):
                try_src_abs = os.path.abspath(src_candidate)
                if os.path.commonpath([try_src_abs, os.path.abspath(dest_dir)]) == os.path.abspath(dest_dir):
                    saved.append(os.path.relpath(try_src_abs, IMG_STORE))
                    continue
        except Exception:
            pass

        try:
            # copy from the best available source (prefers src_candidate if exists, else p)
            src_to_copy = src_candidate if os.path.exists(src_candidate) else p
            base_ext = os.path.splitext(src_to_copy)[1] or ".jpg"
            ts = datetime.datetime.now().strftime("%Y%m%d%H%M%S")
            fname = f"{label}_{idx}_{ts}{base_ext}"
            dest = os.path.join(dest_dir, fname)
            shutil.copy2(src_to_copy, dest)
            saved.append(os.path.relpath(dest, IMG_STORE))
        except Exception:
            log_exc(f"copy image failed for {p}")
    # de-dup while preserving order
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

# --- Force CTk Buttons default to white box + black text + Roboto font ---
# Store original
_OrigCTkButton = ctk.CTkButton
class _CTkButtonAppDefault(_OrigCTkButton):
    def __init__(self, master=None, **kwargs):
        kwargs.setdefault("fg_color", "white")
        kwargs.setdefault("text_color", "black")
        kwargs.setdefault("hover_color", "#f0f0f0")
        kwargs.setdefault("font", roboto(12))
        super().__init__(master, **kwargs)
# replace global CTkButton with our default-style subclass
ctk.CTkButton = _CTkButtonAppDefault

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
        self.inner.bind(
            "<Configure>",
            lambda e: self.canvas.configure(scrollregion=self.canvas.bbox("all"))
        )
        self.canvas.bind(
            "<Configure>",
            lambda e: self.canvas.itemconfigure(self._win, width=max(e.width, self.inner.winfo_reqwidth()))
        )

        # mouse wheel scrolling: only while cursor is inside the frame
        # bind on Enter/Leave to enable/disable global wheel listeners
        def _enable_scroll(event=None):
            self.canvas.bind_all("<MouseWheel>", self._on_wheel)
            self.canvas.bind_all("<Shift-MouseWheel>", self._on_shift_wheel)
            # linux systems alternative events (optional)
            try:
                self.canvas.bind_all("<Button-4>", lambda e: self.canvas.yview_scroll(-1, "units"))
                self.canvas.bind_all("<Button-5>", lambda e: self.canvas.yview_scroll(1, "units"))
            except Exception:
                pass

        def _disable_scroll(event=None):
            try:
                self.canvas.unbind_all("<MouseWheel>")
                self.canvas.unbind_all("<Shift-MouseWheel>")
                self.canvas.unbind_all("<Button-4>")
                self.canvas.unbind_all("<Button-5>")
            except Exception:
                pass

        # enable when pointer enters the canvas area, disable on leave
        self.canvas.bind("<Enter>", _enable_scroll)
        self.canvas.bind("<Leave>", _disable_scroll)
        self.inner.bind("<Enter>", _enable_scroll)
        self.inner.bind("<Leave>", _disable_scroll)

    def _on_wheel(self, e):
        # Windows/Mac have e.delta, Linux may use Button-4/5 events handled separately.
        try:
            self.canvas.yview_scroll(-1 if e.delta > 0 else 1, "units")
        except Exception:
            # fallback
            try:
                self.canvas.yview_scroll(-1 if getattr(e, "delta", 0) > 0 else 1, "units")
            except Exception:
                pass

    def _on_shift_wheel(self, e):
        try:
            self.canvas.xview_scroll(-1 if e.delta > 0 else 1, "units")
        except Exception:
            try:
                self.canvas.xview_scroll(-1 if getattr(e, "delta", 0) > 0 else 1, "units")
            except Exception:
                pass

# ---------- small helpers for animation & assets ----------
def _fade_in_window(win, ms=300, steps=10):
    """Fade in window from alpha 0 -> 1 over ms milliseconds (best-effort)."""
    try:
        win.attributes("-alpha", 0.0)
    except Exception:
        return
    delay = ms / max(1, steps) / 1000.0
    for i in range(steps + 1):
        try:
            win.attributes("-alpha", i / steps)
            win.update()
            time.sleep(delay)
        except Exception:
            pass

def _fade_out_window(win, ms=300, steps=10):
    """Fade out window from alpha 1 -> 0."""
    try:
        for i in range(steps, -1, -1):
            try:
                win.attributes("-alpha", i / steps)
                win.update()
                time.sleep(ms / max(1, steps) / 1000.0)
            except Exception:
                pass
    except Exception:
        pass

def _find_logo_image():
    candidates = [
        os.path.join(APP_DIR, ICON_IMG_NAME),
        os.path.join(APP_DIR, "SED_ICON.png"),
        os.path.join(APP_DIR, "sed_icon.jpg"),
        os.path.join(APP_DIR, "logo.png"),
        "/mnt/data/SED_ICON.jpg",  # fallback for the environment where you uploaded
    ]
    for p in candidates:
        if p and os.path.exists(p):
            return p
    return None

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

        # set window icon if present (Windows .ico)
        try:
            ico_path = os.path.join(APP_DIR, ICON_ICO_NAME)
            if os.path.exists(ico_path):
                # iconbitmap works on Windows
                self.iconbitmap(ico_path)
        except Exception:
            # ignore if icon setting fails on other platforms
            pass

        # on-close confirm
        self.protocol("WM_DELETE_WINDOW", self._on_close_request)

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

        # Build tabs (store DoubleScrollableFrame references to control scrolling)
        self._build_create_tab()
        self._build_view_tab()
        self.load_view_records()

    # ... (rest of the class remains unchanged until the end) ...
    # For brevity I kept the rest of the original GTSApp implementation intact.
    # Below, the class methods are the same as before in your file, unchanged,
    # except I added the _on_close_request method and the places where the code
    # required minor integration (these are already included in the block below).

    # ---------- Create Tab ----------
    def _build_create_tab(self):
        self.create_ds = DoubleScrollableFrame(self.create_tab)
        self.create_ds.pack(fill="both", expand=True, padx=12, pady=8)
        f = self.create_ds.inner

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
        self.after(0, self._ensure_date_default)

        # Trip
        ctk.CTkLabel(top, text="Trip No:", font=self.f_base).grid(row=0, column=2, padx=6, pady=6, sticky="w")
        self.cr_trip = tk.StringVar()
        # make width same as other entries for consistent spacing
        ctk.CTkEntry(top, textvariable=self.cr_trip, width=140, font=self.f_base).grid(row=0, column=3, padx=6)

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
        self._on_area_changed()
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
        # increase height to reduce empty space after trimming the kilang grid
        self.cr_remarks = ctk.CTkTextbox(right, height=200, font=self.f_base, wrap="word")
        self.cr_remarks.pack(fill="x")

        # Save / Reset / Switch
        btn_row = ctk.CTkFrame(f); btn_row.pack(fill="x", padx=12, pady=10)
        ctk.CTkButton(btn_row, text="Save Record", command=self._save_record, font=self.f_base).pack(side="left", padx=(0,6))
        ctk.CTkButton(btn_row, text="Reset", command=self._reset_lower_section, font=self.f_base).pack(side="left", padx=(0,6))
        # use our show_view helper so it scrolls properly
        ctk.CTkButton(btn_row, text="Switch to View", command=self._show_view_tab, font=self.f_base).pack(side="right")
        self.save_warning_label = ctk.CTkLabel(btn_row, text="", font=self.f_base)
        self.save_warning_label.pack(side="right", padx=12)

        legend_text = (
            "E2 - Ramp Pass & APDN; E3 - Timbangan lori tanpa muatan; E4 - Pandangan belakang onto; "
            "E5 - Sisi kiri lori; E6 - Sisi kanan lori; E12 - Selfie dengan seal; E13 - Timbangan lori tanpa muatan; "
            "E14 - Pandangan atas lori; E15 - Selfie di hadapan lori; E16 - Senarai semak yang lengkap di Estate\n"
            "K1 - Selfie dengan tangki air kosong; K3 - Perbandingan seal; K4 - Pandangan belakang lori; "
            "K5 - Sisi kanan lori; K6 - Sisi kiri lori; K7 - Senarai semak yang lengkap di Kilang"
        )
        ctk.CTkLabel(f, text=legend_text, font=self.f_base, wraplength=1100, anchor="w", justify="left").pack(fill="x", padx=12, pady=(6,8))

        self._update_save_warning()

    def _build_mark_attach_grid(self, parent, labels, files_store, marks_store):
        # Use a compact grid layout — do not expand vertically so there's no blank space after last row.
        wrap = ctk.CTkFrame(parent)
        wrap.pack(fill="x", padx=6, pady=6)
        wrap.grid_columnconfigure(0, weight=1)

        for i, lab in enumerate(labels):
            frame = ctk.CTkFrame(wrap)
            frame.grid(row=i, column=0, sticky="ew", pady=4)
            # Columns: 0=label, 1=buttons, 2=count (stretch), 3=radios
            frame.grid_columnconfigure(0, weight=0)
            frame.grid_columnconfigure(1, weight=0)
            frame.grid_columnconfigure(2, weight=1)
            frame.grid_columnconfigure(3, weight=0)

            lbl = ctk.CTkLabel(frame, text=lab, width=44, font=self.f_base)
            lbl.grid(row=0, column=0, padx=(4, 6), sticky="w")

            btncol = ctk.CTkFrame(frame)
            btncol.grid(row=0, column=1, sticky="w")
            ctk.CTkButton(btncol, text="Attach", width=80,
                          command=lambda l=lab, fs=files_store: self._attach_files(l, fs), font=self.f_base).pack(side="left")
            ctk.CTkButton(btncol, text="Remove", width=80,
                          command=lambda l=lab, fs=files_store: self._remove_files(l, fs), font=self.f_base).pack(side="left", padx=(4,0))

            count_lbl = ctk.CTkLabel(frame, text="0 files", font=self.f_base)
            count_lbl.grid(row=0, column=2, sticky="w", padx=(6,0))

            var = tk.StringVar(value="")
            var.trace_add("write", lambda *a: self._update_save_warning())
            rb = ctk.CTkFrame(frame)
            rb.grid(row=0, column=3, padx=(8, 4), sticky="w")
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
            # delete existing files if they live in IMG_STORE (edit mode case)
            for p in list(storage[label].get("paths", [])):
                self._delete_if_under_store(p)
            storage[label]["paths"] = []
            storage[label]["count_widget"].configure(text="0 files")
        except Exception:
            log_exc("_remove_files")

    def _delete_if_under_store(self, p: str):
        try:
            if not p:
                return
            rp = p if os.path.isabs(p) else os.path.join(IMG_STORE, p)
            ap = os.path.abspath(rp)
            img_root = os.path.abspath(IMG_STORE)
            # only delete files inside the app's images folder
            if os.path.exists(ap) and os.path.commonpath([ap, img_root]) == img_root:
                os.remove(ap)
        except Exception:
            log_exc(f"_delete_if_under_store failed for {p}")

    
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
        self._on_area_changed()
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
            with db_cursor() as cur:
                cur.execute("SELECT name FROM areas ORDER BY name")
                return [r[0] for r in cur.fetchall()]
        except Exception:
            log_exc("_load_area_names")
            return []

    def _load_places_for_current_area(self):
        try:
            area = getattr(self, "cr_area_var", tk.StringVar()).get()
            if not area:
                return []
            with db_cursor() as cur:
                cur.execute("SELECT id FROM areas WHERE name = ?", (area,))
                r = cur.fetchone()
                if not r:
                    return []
                aid = r[0]
                cur.execute("SELECT code FROM places WHERE area_id = ? ORDER BY code", (aid,))
                return [x[0] for x in cur.fetchall()]
        except Exception:
            log_exc("_load_places_for_current_area")
            return []

    def _reload_places_box(self):
        vals = self._load_places_for_current_area()
        self.cr_place_box.configure(values=vals)
        self.cr_place_var.set(vals[0] if vals else "")

    def _on_area_changed(self):
        self._reload_places_box()

    def _add_area_dialog(self):
        name = simpledialog.askstring("Add Area", "Enter new area name:", parent=self)
        if not name:
            return
        try:
            with db_cursor() as cur:
                cur.execute("INSERT OR IGNORE INTO areas (name) VALUES (?)", (name.strip(),))
            self.cr_area_box.configure(values=self._load_area_names())
            self.cr_area_var.set(name.strip())
            self.cr_area_box.set(name.strip())
            self._reload_places_box()

            # refresh Manage dialog if open
            if hasattr(self, "manage_area_list"):
                self._reload_manage_areas()
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
            with db_cursor() as cur:
                cur.execute("SELECT id FROM areas WHERE name = ?", (area,))
                r = cur.fetchone()
                if not r:
                    messagebox.showerror("Error", "Area not found.")
                    return
                aid = r[0]
                cur.execute(
                    "INSERT OR IGNORE INTO places (area_id, code, name) VALUES (?,?,?)",
                    (aid, code.strip(), code.strip())
                )
            self._reload_places_box()
            self.cr_place_var.set(code.strip())
            self.cr_place_box.set(code.strip())

            # refresh Manage dialog if open
            if hasattr(self, "manage_place_list"):
                self._reload_manage_places()
        except Exception:
            log_exc("_add_place_dialog")
            messagebox.showerror("Error", "Failed to add place. See log.")

    def _guarded_manage_places_dialog(self):
        """Open a management window to view/add/delete Areas and Places."""
        try:
            # prevent multiple dialogs
            if hasattr(self, "manage_win") and self.manage_win.winfo_exists():
                try:
                    self.manage_win.deiconify()
                    self.manage_win.lift()
                    self.manage_win.focus_force()
                except Exception:
                    pass
                return    

            self.manage_win = ctk.CTkToplevel(self)
            win = self.manage_win
            win.title("Manage Areas and Places")
            win.geometry("600x400")
            win.transient(self)      # keep on top of main window
            win.focus_force()        # focus it

            # ---- Left: Areas ----
            left_frame = ctk.CTkFrame(win)
            left_frame.pack(side="left", fill="both", expand=True, padx=10, pady=10)

            ctk.CTkLabel(left_frame, text="Areas", font=self.f_bold).pack(anchor="w")

            self.manage_area_list = tk.Listbox(left_frame, height=15, exportselection=False)
            self.manage_area_list.pack(fill="both", expand=True, padx=5, pady=5)
            # reload places when area changes
            self.manage_area_list.bind("<<ListboxSelect>>", lambda e: self._reload_manage_places())

            btn_area_row = ctk.CTkFrame(left_frame)
            btn_area_row.pack(fill="x", pady=5)
            ctk.CTkButton(btn_area_row, text="Add Area", command=self._add_area_dialog, font=self.f_base).pack(side="left", padx=5)
            # keep 'Delete Area' but default white style
            ctk.CTkButton(btn_area_row, text="Delete Area", command=self._delete_selected_area, font=self.f_base).pack(side="left", padx=5)

            # ---- Right: Places ----
            right_frame = ctk.CTkFrame(win)
            right_frame.pack(side="left", fill="both", expand=True, padx=10, pady=10)

            ctk.CTkLabel(right_frame, text="Places in selected Area", font=self.f_bold).pack(anchor="w")

            self.manage_place_list = tk.Listbox(right_frame, height=15, exportselection=False)
            self.manage_place_list.pack(fill="both", expand=True, padx=5, pady=5)

            btn_place_row = ctk.CTkFrame(right_frame)
            btn_place_row.pack(fill="x", pady=5)
            ctk.CTkButton(btn_place_row, text="Add Place", command=self._add_place_dialog, font=self.f_base).pack(side="left", padx=5)
            ctk.CTkButton(btn_place_row, text="Delete Place", command=self._delete_selected_place, font=self.f_base).pack(side="left", padx=5)

            # preload lists
            self._reload_manage_areas()
            self._reload_manage_places()

        except Exception:
            log_exc("_guarded_manage_places_dialog")
            messagebox.showerror("Error", "Failed to open Manage Areas/Places. See log.")

    def _reload_manage_places(self):
        """Refresh the Places list based on selected Area in Manage dialog."""
        try:
            sel = self.manage_area_list.curselection()
            if not sel:
                return  # nothing selected; leave current places alone
            area = self.manage_area_list.get(sel[0])

            self.manage_place_list.delete(0, "end")
            with db_cursor() as cur:
                cur.execute("SELECT id FROM areas WHERE name = ?", (area,))
                r = cur.fetchone()
                if not r:
                    return
                aid = r[0]
                cur.execute("SELECT code FROM places WHERE area_id=? ORDER BY code", (aid,))
                for (code,) in cur.fetchall():
                    self.manage_place_list.insert("end", code)
        except Exception:
            log_exc("_reload_manage_places")

            
    def _reload_manage_areas(self):
        """Refresh the Areas list in Manage dialog."""
        try:
            self.manage_area_list.delete(0, "end")
            with db_cursor() as cur:
                cur.execute("SELECT name FROM areas ORDER BY name")
                for (name,) in cur.fetchall():
                    self.manage_area_list.insert("end", name)
        except Exception:
            log_exc("_reload_manage_areas")


    def _delete_selected_area(self):
        try:
            sel = self.manage_area_list.curselection()
            if not sel:
                messagebox.showinfo("Select", "Please select an Area to delete.")
                return
            name = self.manage_area_list.get(sel[0])

            # check linked records
            with db_cursor() as cur:
                cur.execute("SELECT COUNT(*) FROM gts_records r JOIN areas a ON r.area_id=a.id WHERE a.name=?", (name,))
                count = cur.fetchone()[0]
            if count > 0:
                messagebox.showwarning("Blocked", f"Cannot delete Area '{name}'. {count} records are linked.")
                return

            if not messagebox.askyesno("Confirm", f"Delete Area '{name}' and all its Places?"):
                return
            with db_cursor() as cur:
                cur.execute("DELETE FROM areas WHERE name = ?", (name,))
            self._reload_manage_areas()
            self._reload_manage_places()
            self.cr_area_box.configure(values=self._load_area_names())
        except Exception:
            log_exc("_delete_selected_area")
            messagebox.showerror("Error", "Failed to delete Area. See log.")

    def _delete_selected_place(self):
        try:
            sel_a = self.manage_area_list.curselection()
            sel_p = self.manage_place_list.curselection()
            if not sel_a or not sel_p:
                messagebox.showinfo("Select", "Please select a Place to delete.")
                return
            area = self.manage_area_list.get(sel_a[0])
            place = self.manage_place_list.get(sel_p[0])

            # check linked records
            with db_cursor() as cur:
                cur.execute("""
                    SELECT COUNT(*) FROM gts_records r
                    JOIN areas a ON r.area_id=a.id
                    JOIN places p ON r.place_id=p.id
                    WHERE a.name=? AND p.code=?
                """, (area, place))
                count = cur.fetchone()[0]
            if count > 0:
                messagebox.showwarning("Blocked", f"Cannot delete Place '{place}' in Area '{area}'. {count} records are linked.")
                return

            if not messagebox.askyesno("Confirm", f"Delete Place '{place}' in Area '{area}'?"):
                return
            with db_cursor() as cur:
                cur.execute("SELECT id FROM areas WHERE name = ?", (area,))
                r = cur.fetchone()
                if not r:
                    return
                aid = r[0]
                cur.execute("DELETE FROM places WHERE area_id=? AND code=?", (aid, place))
            self._reload_manage_places()
            self.cr_place_box.configure(values=self._load_places_for_current_area())
        except Exception:
            log_exc("_delete_selected_place")
            messagebox.showerror("Error", "Failed to delete Place. See log.")

    # ---------- Save / Update record ----------
    def _save_record(self):
        try:
            date_s      = self.cr_date.get().strip()
            trip_no_raw = self.cr_trip.get().strip()
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

            trip_num_only = trip_no_raw
            car_only = car_plate

            if self.editing_id and "/" in trip_no_raw:
                parts = trip_no_raw.split("/")
                if len(parts) == 3:
                    _, trip_num_only, car_only = parts
                elif len(parts) == 2:
                    _, trip_num_only = parts

            composite_trip = f"{place_code}/{trip_num_only or '-'}"
            if car_only:
                composite_trip += f"/{car_only}"
            
            missing_marks = [k for k in REQUIRED_E if self.estate_marks[k].get() == ""]
            missing_marks += [k for k in REQUIRED_K if self.kilang_marks[k].get() == ""]

            with db_cursor() as cur:
                cur.execute("SELECT id FROM areas WHERE name = ?", (area_name,))
                ar = cur.fetchone()
                if not ar: messagebox.showerror("Error", "Selected area not found"); return
                area_id = ar[0]

                cur.execute("SELECT id FROM places WHERE area_id = ? AND code = ?", (area_id, place_code))
                pr = cur.fetchone()
                if not pr: messagebox.showerror("Error", "Selected place not found"); return
                place_id = pr[0]

                safe_place = (place_code or "PLACE").replace(os.sep, "_")
                safe_trip  = (trip_no_raw or "TRIP").replace(os.sep, "_")
                safe_car   = (car_plate or "NA").replace(os.sep, "_")
                record_dir = os.path.join(IMG_STORE, safe_place, safe_trip, f"{safe_car} {date_s}")

                prev_estate = {}
                prev_kilang = {}
                if self.editing_id:
                    cur.execute("SELECT estate_pics, kilang_pics FROM gts_records WHERE id=?", (self.editing_id,))
                    _row_prev = cur.fetchone()
                    if _row_prev:
                        prev_estate = load_json(_row_prev[0]) or {}
                        prev_kilang = load_json(_row_prev[1]) or {}
                
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

                # delete files that are no longer referenced (edit mode)
                if self.editing_id:
                    self._cleanup_removed(prev_estate, estate_saved)
                    self._cleanup_removed(prev_kilang, kilang_saved)

                
                if not self.editing_id:
                    cur.execute("""
                        INSERT INTO gts_records
                        (date, trip_no, area_id, place_id, apdn_no, e12_seal, k3_seal, car_plate,
                         estate_pics, kilang_pics, estate_marks, kilang_marks, remarks, status, created_at, updated_at)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (date_s, composite_trip, area_id, place_id, apdn, seal_e12, seal_k3, car_plate,
                          dump_json(estate_saved), dump_json(kilang_saved),
                          dump_json(e_marks_map), dump_json(k_marks_map),
                          remarks, status, now, now))
                else:
                    cur.execute("""
                        UPDATE gts_records
                        SET date=?, trip_no=?, area_id=?, place_id=?, apdn_no=?, e12_seal=?, k3_seal=?, car_plate=?,
                            estate_pics=?, kilang_pics=?, estate_marks=?, kilang_marks=?, remarks=?, status=?, updated_at=?
                        WHERE id = ?
                    """, (date_s, composite_trip, area_id, place_id, apdn, seal_e12, seal_k3, car_plate,
                          dump_json(estate_saved), dump_json(kilang_saved),
                          dump_json(e_marks_map), dump_json(k_marks_map),
                          remarks, status, now, self.editing_id))
                    self.editing_id = None

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

   def _cleanup_removed(self, prev_map, new_map):
        """
        Remove any files that were previously in prev_map but no longer exist in new_map.
        Only deletes files under IMG_STORE.
        """
        try:
            prev_map = prev_map or {}
            new_map = new_map or {}

            for key, prev_list in prev_map.items():
                # Build set of absolute paths that should be kept
                keep_set = set()
                for np in new_map.get(key, []):
                    if not np or not isinstance(np, str):
                        continue
                    abs_np = self._resolve_path(np)
                    keep_set.add(abs_np)

                # Iterate previous paths and delete if not in keep_set
                for p in prev_list or []:
                    if not p or not isinstance(p, str):
                        continue
                    abs_prev = self._resolve_path(p)
                    if abs_prev not in keep_set:
                        # Only delete if it is under IMG_STORE
                        self._delete_if_under_store(abs_prev)

        except Exception:
            log_exc("_cleanup_removed")

    # ---------- Create reset lower section ----------
    def _reset_lower_section(self):
        """Clear estate/kilang attachments, marks, and remarks, and remove files safely."""
        try:
            # Helper to normalize paths before deletion
            def norm(p):
                if not p:
                    return None
                return os.path.normpath(os.path.abspath(p if os.path.isabs(p) else os.path.join(IMG_STORE, p)))

            # Reset estate files
            for k, data in self.estate_files.items():
                for p in list(data.get("paths", [])):
                    abs_p = self._resolve_path(p)
                    if abs_p and os.path.exists(abs_p):
                        self._delete_if_under_store(abs_p)
                data["paths"] = []
                data["count_widget"].configure(text="0 files")

            # Reset kilang files
            for k, data in self.kilang_files.items():
                for p in list(data.get("paths", [])):
                    abs_p = self._resolve_path(p)
                    if abs_p and os.path.exists(abs_p):
                        self._delete_if_under_store(abs_p)
                data["paths"] = []
                data["count_widget"].configure(text="0 files")

            # Reset marks
            for k in self.estate_marks: self.estate_marks[k].set("")
            for k in self.kilang_marks: self.kilang_marks[k].set("")

            # Reset remarks
            self.cr_remarks.delete("0.0", "end")

            # Update save warning
            self._update_save_warning()

        except Exception:
            log_exc("_reset_lower_section")
            messagebox.showerror("Error", "Failed to reset lower section. See log.")

    # ---------- View Tab ----------
    def _build_view_tab(self):
        self.view_ds = DoubleScrollableFrame(self.view_tab)
        self.view_ds.pack(fill="both", expand=True, padx=12, pady=8)
        f = self.view_ds.inner

        ctk.CTkLabel(f, text="View / Search Records", font=self.f_h1).pack(pady=(6,8))

        filter_row = ctk.CTkFrame(f); filter_row.pack(fill="x", padx=12, pady=6)

        ctk.CTkLabel(filter_row, text="Date From:", font=self.f_base).grid(row=0, column=0, padx=6, pady=4, sticky="w")
        self.v_date_from = tk.StringVar()
        ctk.CTkEntry(filter_row, textvariable=self.v_date_from, width=120, font=self.f_base).grid(row=0, column=1, padx=6)

        ctk.CTkLabel(filter_row, text="Date To:", font=self.f_base).grid(row=0, column=2, padx=6, pady=4, sticky="w")
        self.v_date_to = tk.StringVar()
        ctk.CTkEntry(filter_row, textvariable=self.v_date_to, width=120, font=self.f_base).grid(row=0, column=3, padx=6)

        ctk.CTkLabel(filter_row, text="Area:", font=self.f_base).grid(row=1, column=0, padx=6, pady=4, sticky="w")
        self.v_area = tk.StringVar()
        self.v_area_box = ctk.CTkComboBox(filter_row, variable=self.v_area, values=self._load_area_names(), width=180, font=self.f_base)
        self.v_area_box.grid(row=1, column=1, padx=6)
        self.v_area.trace_add("write", lambda *a: self._reload_view_places())

        ctk.CTkLabel(filter_row, text="Place:", font=self.f_base).grid(row=1, column=2, padx=6, pady=4, sticky="w")
        self.v_place = tk.StringVar()
        self.v_place_box = ctk.CTkComboBox(filter_row, variable=self.v_place, values=[], width=180, font=self.f_base)
        self.v_place_box.grid(row=1, column=3, padx=6)

        ctk.CTkLabel(filter_row, text="Trip No:", font=self.f_base).grid(row=2, column=0, padx=6, pady=4, sticky="w")
        self.v_trip = tk.StringVar()
        ctk.CTkEntry(filter_row, textvariable=self.v_trip, width=180, font=self.f_base).grid(row=2, column=1, padx=6)

        ctk.CTkLabel(filter_row, text="Status:", font=self.f_base).grid(row=2, column=2, padx=6, pady=4, sticky="w")
        self.v_status = tk.StringVar()
        ctk.CTkComboBox(filter_row, values=["", "Complete", "Incomplete"], variable=self.v_status, width=180, font=self.f_base).grid(row=2, column=3, padx=6)

        ctk.CTkButton(filter_row, text="Search", command=self.load_view_records, font=self.f_base).grid(row=0, column=4, padx=10)
        ctk.CTkButton(filter_row, text="Reset",  command=self._reset_view_filters, font=self.f_base).grid(row=1, column=4)

        body = ctk.CTkFrame(f); body.pack(fill="both", expand=True, padx=12, pady=8)
        body.grid_columnconfigure(0, weight=3); body.grid_columnconfigure(1, weight=2); body.grid_rowconfigure(0, weight=1)

        left_wrap = ctk.CTkFrame(body); left_wrap.grid(row=0, column=0, sticky="nsew", padx=(0,8), pady=0)
        cols = ("id", "date", "trip", "area", "place", "car_plate", "status")
        self.tree = ttk.Treeview(left_wrap, columns=cols, show="headings")
        for c in cols:
            self.tree.heading(c, text=c.capitalize(), anchor="w")
            if c == "trip":
                width = 300
            elif c == "id":
                width = 60
            elif c == "date":
                width = 120
            elif c in ("area", "place", "car_plate"):
                width = 140
            else:
                width = 120
            # FIXED size for columns (don't stretch)
            self.tree.column(c, width=width, anchor="w", stretch=False)
        self.tree.pack(side="left", fill="both", expand=True)
        self.tree.bind("<Double-1>", self._on_tree_double_click)
        self.tree.bind("<<TreeviewSelect>>", self._on_tree_select)
        self.tree.tag_configure('incomplete', background='#ffd6d6')  # red-ish for incomplete
        self.tree.tag_configure('complete',   background='#eafff2')
        vsb = ttk.Scrollbar(left_wrap, orient="vertical",   command=self.tree.yview); vsb.pack(side="right",  fill="y")
        hsb = ttk.Scrollbar(left_wrap, orient="horizontal", command=self.tree.xview); hsb.pack(side="bottom", fill="x")
        self.tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)

        right = ctk.CTkFrame(body); right.grid(row=0, column=1, sticky="nsew", padx=(8,0), pady=0)
        right.grid_rowconfigure(1, weight=1)
        right.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(right, text="Record Details", font=self.f_base).grid(row=0, column=0, sticky="w", pady=(0,6))
        # detail text + vertical scrollbar
        self.detail_text = ctk.CTkTextbox(right, height=520, font=self.f_base, wrap="word")
        self.detail_text.grid(row=1, column=0, sticky="nsew")

        # scrollbar for detail_text
        detail_vsb = ttk.Scrollbar(right, orient="vertical", command=self.detail_text.yview)
        detail_vsb.grid(row=1, column=1, sticky="ns")
        try:
            # CTkTextbox supports configuring yscrollcommand
            self.detail_text.configure(yscrollcommand=detail_vsb.set)
        except Exception:
            pass

        btns = ctk.CTkFrame(right); btns.grid(row=2, column=0, columnspan=2, sticky="ew", pady=(6,0))
        ctk.CTkButton(btns, text="Edit Selected",   command=self._edit_selected, font=self.f_base).pack(side="left", padx=6)
        ctk.CTkButton(btns, text="Delete Selected", command=self._delete_selected, font=self.f_base).pack(side="left", padx=6)

        self.v_area.set(""); self._reload_view_places()

    def _reload_view_places(self):
        area = self.v_area.get()
        if not area:
            self.v_place_box.configure(values=[]); self.v_place.set(""); return
        with db_cursor() as cur:
            cur.execute("SELECT id FROM areas WHERE name = ?", (area,))
            r = cur.fetchone()
            if not r:
                self.v_place_box.configure(values=[]); self.v_place.set(""); return
            aid = r[0]
            cur.execute("SELECT code FROM places WHERE area_id = ? ORDER BY code", (aid,))
            names = [x[0] for x in cur.fetchall()]
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

            with db_cursor() as cur:
                cur.execute(query, params)
                rows = cur.fetchall()

                for i in self.tree.get_children():
                    self.tree.delete(i)
            
                for i, row in enumerate(rows):
                    rid, date_s, trip_no, area_name, place_code, car_plate, status = row
                    trip_str = (trip_no or "-").strip()
                    tag = 'complete' if status == 'Complete' else 'incomplete'
                    self.tree.insert(
                        "", "end", iid=str(rid),
                        values=(rid, date_s, trip_str, area_name, place_code, car_plate, status),
                        tags=(tag,)
                    )
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
            with db_cursor() as cur:
                cur.execute("""
                    SELECT date, trip_no, area_id, place_id, apdn_no, e12_seal, k3_seal, car_plate,
                           estate_pics, kilang_pics, estate_marks, kilang_marks, remarks, status, created_at, updated_at
                    FROM gts_records WHERE id = ?
                """, (rid,))
                r = cur.fetchone()
            if not r: 
                return

            (date_s, trip, aid, pid, apdn, seal_e12, seal_k3, car_plate,
             estate_s, kilang_s, e_marks_s, k_marks_s,
             remarks, status, created, updated) = r

            with db_cursor() as cur:
                cur.execute("SELECT name FROM areas WHERE id = ?", (aid,))
                area_name = (cur.fetchone() or ["-"])[0]
                cur.execute("SELECT code FROM places WHERE id = ?", (pid,))
                place_code = (cur.fetchone() or ["-"])[0]

            estate_data = load_json(estate_s)
            for k in REQUIRED_E:
                resolved = []
                for p in (estate_data.get(k, []) or []):
                    abs_p = self._resolve_path(p)
                    if abs_p and os.path.exists(abs_p):
                        resolved.append(abs_p)
                resolved = resolved[:2]  # keep max 2 files per UI slot
                self.estate_files[k]["paths"] = resolved
                self.estate_files[k]["count_widget"].configure(text=f"{len(resolved)} files")
            
            kilang_data = load_json(kilang_s)
            for k in REQUIRED_K:
                resolved = []
                for p in (kilang_data.get(k, []) or []):
                    abs_p = self._resolve_path(p)
                    if abs_p and os.path.exists(abs_p):
                        resolved.append(abs_p)
                resolved = resolved[:2]
                self.kilang_files[k]["paths"] = resolved
                self.kilang_files[k]["count_widget"].configure(text=f"{len(resolved)} files")

            estate_data = {
                k: [
                    p for p in (estate_data.get(k, []) or [])
                    if os.path.exists(self._resolve_path(p))
                ]
                for k in REQUIRED_E
            }
            kilang_data = {
                k: [
                    p for p in (kilang_data.get(k, []) or [])
                    if os.path.exists(self._resolve_path(p))
                ]
                for k in REQUIRED_K
            }
            
            e_marks = load_json(e_marks_s)
            k_marks = load_json(k_marks_s)

            lines = [
                f"Date: {date_s}",
                f"Trip: {trip or '-'}",
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
            # ensure detail_text is scrolled to top when record selected
            try:
                self.detail_text.yview_moveto(0.0)
            except Exception:
                pass
        except Exception:
            log_exc("_on_tree_select")
            messagebox.showerror("Error", "Failed to show details. See log.")

    def _edit_selected(self):
        """Open selected record for editing."""
        sel = self.tree.selection()
        if not sel:
            messagebox.showinfo("Select", "Please select a record to edit.")
            return
        rid = int(sel[0])
        # Open for edit with normalized paths
        self._open_for_edit(rid)

    def _open_for_edit(self, rid):
        try:
            with db_cursor() as cur:
                cur.execute("""
                    SELECT id, date, trip_no, area_id, place_id, apdn_no, e12_seal, k3_seal, car_plate,
                           estate_pics, kilang_pics, estate_marks, kilang_marks, remarks
                    FROM gts_records WHERE id = ?
                """, (rid,))
                row = cur.fetchone()
            if not row:
                messagebox.showerror("Not found", "Record not found."); return

            (_id, date_s, trip, aid, pid, apdn, seal_e12, seal_k3, car_plate,
             estate_s, kilang_s, e_marks_s, k_marks_s, remarks) = row

            self.editing_id = rid
            self.cr_date.set(date_s or datetime.date.today().isoformat())
            self.cr_apdn_e2.set(apdn or "")
            self.cr_seal_e12.set(seal_e12 or "")
            self.cr_seal_k3.set(seal_k3 or "")

            if trip:
                parts = trip.split("/")
                if len(parts) == 3:
                    _, trip_num, car_plate_str = parts
                    self.cr_trip.set(trip_num)
                    self.cr_car_plate.set(car_plate_str)
                elif len(parts) == 2:
                    _, trip_num = parts
                    self.cr_trip.set(trip_num)
                    self.cr_car_plate.set(car_plate or "")
                else:
                    self.cr_trip.set(trip)
                    self.cr_car_plate.set(car_plate or "")
            else:
                self.cr_trip.set("")
                self.cr_car_plate.set(car_plate or "")

            with db_cursor() as cur:
                cur.execute("SELECT name FROM areas WHERE id = ?", (aid,))
                area_name = (cur.fetchone() or [""])[0]
                self.cr_area_box.configure(values=self._load_area_names())
                self.cr_area_var.set(area_name)
                self.cr_area_box.set(area_name)
                self._reload_places_box()
                cur.execute("SELECT code FROM places WHERE id = ?", (pid,))
                pc = (cur.fetchone() or [""])[0]
            self.cr_place_var.set(pc)
            self.cr_place_box.set(pc)

            self.cr_remarks.delete("0.0", "end")
            self.cr_remarks.insert("0.0", remarks or "")

            e_marks = load_json(e_marks_s); k_marks = load_json(k_marks_s)
            for k in REQUIRED_E: self.estate_marks[k].set(e_marks.get(k, ""))
            for k in REQUIRED_K: self.kilang_marks[k].set(k_marks.get(k, ""))

            estate_data = load_json(estate_s); kilang_data = load_json(kilang_s)
    
            for k in REQUIRED_E:
                resolved = []
                for p in (estate_data.get(k, []) or []):
                    if not isinstance(p, str): 
                        continue
                    rp = self._resolve_path(p)
                    if rp and os.path.exists(rp):
                        resolved.append(rp)
                resolved = resolved[:2]
                self.estate_files[k]["paths"] = resolved
                self.estate_files[k]["count_widget"].configure(text=f"{len(resolved)} files")

            for k in REQUIRED_K:
                resolved = []
                for p in (kilang_data.get(k, []) or []):
                    if not isinstance(p, str):
                        continue
                    rp = p if os.path.isabs(p) else os.path.join(IMG_STORE, p)
                    if os.path.exists(rp):
                        resolved.append(rp)
                resolved = resolved[:2]
                self.kilang_files[k]["paths"] = resolved
                self.kilang_files[k]["count_widget"].configure(text=f"{len(resolved)} files")

            # show create tab and ensure top
            self._show_create_tab()
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
            with db_cursor() as cur:
                cur.execute("DELETE FROM gts_records WHERE id = ?", (rid,))
            self.load_view_records()
            messagebox.showinfo("Deleted", "Record deleted.")
        except Exception:
            log_exc("_delete_selected"); messagebox.showerror("Error", "Failed to delete record. See log.")

    def _fetch_records(self, where="", params=(), limit=None):
        cols = [
            "id", "date", "trip_no", "area_id", "place_id", "apdn_no",
            "e12_seal", "k3_seal", "car_plate",
            "estate_pics", "kilang_pics",
            "estate_marks", "kilang_marks",
            "remarks", "status", "created_at", "updated_at"
        ]
        sql = f"SELECT {', '.join(cols)} FROM gts_records"
        if where:
            sql += " WHERE " + where
        sql += " ORDER BY date DESC, id DESC"
        if limit:
            sql += f" LIMIT {int(limit)}"

        with db_cursor() as cur:
            cur.execute(sql, params)
            rows = [dict(zip(cols, r)) for r in cur.fetchall()]
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
            messagebox.showwarning("Bad date", "Invalid date format. Resetting to today.")
            self.cr_date.set(datetime.date.today().isoformat())

    # ---------- tab navigation helpers ----------
    def _show_create_tab(self):
        """Switch to Create tab and ensure the UI is reset and paths are normalized."""
        try:
            self.tabview.set("Create Record")

            # Scroll to top-left
            try:
                self.create_ds.canvas.xview_moveto(0)
                self.create_ds.canvas.yview_moveto(0)
            except Exception:
                pass

            # Normalize current paths for all estate/kilang files
            def normalize_paths(files_dict):
                for k, data in files_dict.items():
                    paths = data.get("paths", [])
                    normalized = []
                    for p in paths:
                        if not p or not isinstance(p, str):
                            continue
                        abs_p = self._resolve_path(p)
                        if os.path.exists(abs_p):
                            normalized.append(abs_p)
                    data["paths"] = normalized
                    data["count_widget"].configure(text=f"{len(normalized)} files")

            normalize_paths(self.estate_files)
            normalize_paths(self.kilang_files)

            # Reset marks UI warning
            self._update_save_warning()

        except Exception:
            log_exc("_show_create_tab")

    def _show_view_tab(self):
        """Switch to View tab and ensure table & details are scrolled to top-left."""
        try:
            self.tabview.set("View Records")
            try:
                self.view_ds.canvas.xview_moveto(0)
                self.view_ds.canvas.yview_moveto(0)
            except Exception:
                pass
            try:
                self.tree.xview_moveto(0)
            except Exception:
                pass
            try:
                self.detail_text.yview_moveto(0)
            except Exception:
                pass
        except Exception:
            pass

    def _on_close_request(self):
        """Ask user for confirmation before quitting."""
        try:
            if messagebox.askyesno("Confirm", "Do you want to quit?"):
                self.destroy()
        except Exception:
            # if messagebox fails for some reason, still destroy
            try:
                self.destroy()
            except Exception:
                pass

# ---------------- startup login (License + PIN) ----------------
def _startup_login_guard(max_attempts: int = 5) -> bool:
    """Check license validity and prompt for Admin PIN with a branded login window."""
    try:
        # use tkinter messagebox for alerts
        from tkinter import messagebox as _messagebox

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

        # hostname binding
        if payload.get("bind_hostname"):
            import socket as _socket
            current_host = _socket.gethostname()
            if payload.get("hostname") != current_host:
                _messagebox.showerror("License rejected",
                                       f"This license is bound to {payload.get('hostname')}, not {current_host}.")
                return False

        # expiry check
        if payload.get("expires_at"):
            try:
                import datetime as _dt
                expires = _dt.datetime.fromisoformat(payload["expires_at"].replace("Z", ""))
                if _dt.datetime.utcnow() > expires:
                    _messagebox.showerror("License expired", f"License expired on {payload['expires_at']}.")
                    return False
            except Exception:
                pass

        # Build a custom CTk login window (modal)
        login = ctk.CTk()
        login.title("GTS Login")
        # set icon if exists
        try:
            ico_path = os.path.join(APP_DIR, ICON_ICO_NAME)
            if os.path.exists(ico_path):
                login.iconbitmap(ico_path)
        except Exception:
            pass

        # geometry (centered)
        w, h = 640, 340
        try:
            sw = login.winfo_screenwidth(); sh = login.winfo_screenheight()
            x = max(0, (sw - w) // 2); y = max(0, (sh - h) // 2)
            login.geometry(f"{w}x{h}+{x}+{y}")
        except Exception:
            login.geometry(f"{w}x{h}")

        login.resizable(False, False)

        main_frame = ctk.CTkFrame(login)
        main_frame.pack(fill="both", expand=True, padx=12, pady=12)

        # Left: image panel
        left = ctk.CTkFrame(main_frame, width=280)
        left.pack(side="left", fill="both", padx=(4,8), pady=4)
        left.pack_propagate(False)

        try:
            # Resolve correct image path (works for both script & bundled exe)
            if getattr(sys, "frozen", False):
                base_path = sys._MEIPASS
            else:
                base_path = APP_DIR
            logo_path = os.path.join(base_path, "SED_ICON.jpg")

            if os.path.exists(logo_path) and Image is not None:
                # --- load and prepare image safely ---
                img = Image.open(logo_path)
                max_size = 280
                img.thumbnail((max_size, max_size))
                # make a full in-memory copy (fixes PyInstaller blank image bug)
                img_copy = img.copy()

                # create CTkImage using memory-safe copy
                ctk_logo = ctk.CTkImage(
                    light_image=img_copy,
                    dark_image=img_copy,
                    size=img_copy.size
                )

                logo_widget = ctk.CTkLabel(left, image=ctk_logo, text="")
                logo_widget.image = ctk_logo  # prevent garbage collection
                logo_widget.pack(expand=True, fill="both", padx=10, pady=10)
            else:
                raise FileNotFoundError(logo_path)

        except Exception as e:
            print("Logo load failed:", e)
            ctk.CTkLabel(
                left,
                text="SECURITY &\nENFORCEMENT",
                font=roboto(18, "bold"),
                justify="center"
            ).pack(expand=True, fill="both")


        # Right side content
        right = ctk.CTkFrame(main_frame)
        right.pack(side="left", fill="both", expand=True, padx=(8,4), pady=4)
        ctk.CTkLabel(right, text="GTS — Admin Login", font=roboto(18, "bold")).pack(anchor="w", pady=(12,6), padx=6)
        ctk.CTkLabel(right, text="Enter Admin PIN to continue", font=roboto(11)).pack(anchor="w", padx=6)

        pin_var = tk.StringVar()
        pin_entry = ctk.CTkEntry(right, textvariable=pin_var, show="*", width=220, font=roboto(14))
        pin_entry.pack(pady=(14, 6), padx=6)
        pin_entry.focus_set()

        status_label = ctk.CTkLabel(right, text=f"{max_attempts} attempts remaining", font=roboto(10))
        status_label.pack(anchor="w", padx=6, pady=(0,6))

        btn_row = ctk.CTkFrame(right)
        btn_row.pack(padx=6, pady=8)
        result = {"ok": False, "tries": 0}

        def _fail_try():
            remaining = max_attempts - result["tries"]
            status_label.configure(text=f"{remaining} attempts remaining")
            if remaining <= 0:
                _messagebox.showerror("Locked", "Too many failed attempts. Exiting.")
                try:
                    _fade_out_window(login, ms=200)
                except Exception:
                    pass
                try:
                    login.destroy()
                except Exception:
                    pass

        def _on_cancel():
            try:
                login.destroy()
            except Exception:
                pass

        def _on_submit(event=None):
            pin = (pin_var.get() or "")
            expected = payload.get("admin_pin_hash")
            salt = payload.get("admin_pin_salt")
            if expected and salt and _hash_pin(pin, salt) == expected:
                result["ok"] = True
                # success animation then destroy
                try:
                    login.destroy()
                except Exception:
                    pass
            else:
                result["tries"] += 1
                _messagebox.showerror("Incorrect PIN", "PIN is incorrect.")
                _fail_try()

        ctk.CTkButton(btn_row, text="Login", command=_on_submit, width=100).pack(side="left", padx=(0,8))
        ctk.CTkButton(btn_row, text="Cancel", command=_on_cancel, width=100).pack(side="left")

        # allow Enter to submit
        login.bind("<Return>", _on_submit)

        # make modal
        try:
            login.grab_set()
        except Exception:
            pass

        # fade-in
        try:
            _fade_in_window(login, ms=300)
        except Exception:
            pass

        # run the modal window
        try:
            login.mainloop()
        except Exception:
            pass

        return result["ok"]

    except Exception:
        log_exc("_startup_login_guard")
        return False

# ---------------- run ----------------
if __name__ == "__main__":
    try:
        if not _startup_login_guard(max_attempts=5):
            raise SystemExit(1)
        app = GTSApp()
        # start invisible then fade-in
        try:
            app.attributes("-alpha", 0.0)
        except Exception:
            pass
        try:
            _fade_in_window(app, ms=400)
        except Exception:
            pass
        app.mainloop()
    except SystemExit:
        pass
    except Exception:
        log_exc("Fatal error running app")
        raise
# -- END updated file -------------------------------------------------------
