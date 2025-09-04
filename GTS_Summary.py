#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
GTS Summary — regenerated single-file app

Key changes vs previous build
- Robust startup guard: requires public_key.pem + license.json (PIN + signed payload)
- Window autosizing based on monitor resolution; min sizes set to avoid clipping
- View tab: ttk.Treeview with multi-select + working _delete_selected_multi()
- Record form: E12 (seal no.), K3 (seal no.), E2 (APDN) fields added to top section
- Attachments: max 2 images per label (enforced at UI + DB)
- Export to PDF: redesigned layout that packs multiple records per page when space allows,
  but never overlaps images; graceful overflow to next page
- Removed CSV/Excel exports
- Replaced emoji ticks with printable characters

Dependencies:
  pip install customtkinter Pillow reportlab cryptography

DB: SQLite (gts.db in working folder). Auto-creates tables on first run.
"""

import json
import os
import sys
import sqlite3
import datetime as dt
from pathlib import Path
from typing import List, Tuple, Optional, Dict

# --- third-party ---
try:
    import customtkinter as ctk
    from PIL import Image, ImageTk
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.units import mm
    from reportlab.pdfgen import canvas
    from reportlab.lib.utils import ImageReader
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding
    from cryptography.hazmat.primitives.serialization import load_pem_public_key
except Exception as e:
    print("Missing dependency:", e)
    print("Please install: pip install customtkinter Pillow reportlab cryptography")
    sys.exit(1)

import tkinter as tk
from tkinter import ttk, filedialog, messagebox

APP_NAME = "GTS Summary"
DB_PATH = Path("gts.db")
IMG_THUMB_SIZE = (140, 100)
MAX_IMAGES_PER_LABEL = 2
PRINT_TRUE = "✓"   # printable, not emoji
PRINT_FALSE = "✗"

# Labels (simplified). Extend as needed
ESTATE_LABELS = [
    ("E2", "Ramp ass & APDN"),
    ("E3", "Timbangan lori tanpa muatan"),
    ("E4", "E4 label"),
    ("E5", "E5 label"),
    ("E6", "E6 label"),
    ("E12", "Seal number"),
]
KILANG_LABELS = [
    ("K1", "K1 label"),
    ("K2", "K2 label"),
    ("K3", "Seal number"),
    ("K4", "K4 label"),
    ("K5", "K5 label"),
    ("K6", "K6 label"),
    ("K7", "K7 label"),
]

# --------- Licensing ---------
LICENSE_FILE = Path("license.json")
PUBLIC_KEY_FILE = Path("public_key.pem")


def verify_license_or_exit():
    """Verify license.json using public key. Exits app if missing/invalid.
    Expected license.json fields:
      {
        "pin": "1234",                  # numeric or string PIN
        "payload": { ... arbitrary ... },
        "signature": "base16/hex string of signature over canonical payload"
      }
    The canonical payload is the JSON-dumped payload with sorted keys and no spaces.
    """
    if not PUBLIC_KEY_FILE.exists() or not LICENSE_FILE.exists():
        messagebox.showerror(APP_NAME, "Missing public_key.pem or license.json. Contact admin.")
        sys.exit(2)
    try:
        data = json.loads(LICENSE_FILE.read_text(encoding="utf-8"))
        pin = str(data.get("pin", "")).strip()
        payload = data.get("payload", {})
        sig_hex = data.get("signature", "")
        if not (pin and payload and sig_hex):
            raise ValueError("Incomplete license.json")
        sig = bytes.fromhex(sig_hex)
        pub = load_pem_public_key(PUBLIC_KEY_FILE.read_bytes())
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        pub.verify(
            sig,
            canonical,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        # Optionally, prompt for PIN on startup
        root = tk.Tk(); root.withdraw()
        user_pin = tk.simpledialog.askstring("License PIN", "Enter PIN to unlock:", show='*')
        root.destroy()
        if user_pin is None or str(user_pin).strip() != pin:
            messagebox.showerror(APP_NAME, "Invalid PIN.")
            sys.exit(3)
    except Exception as e:
        messagebox.showerror(APP_NAME, f"License verification failed: {e}")
        sys.exit(4)


# --------- Database ---------
class DB:
    def __init__(self, path: Path):
        self.conn = sqlite3.connect(path)
        self.conn.row_factory = sqlite3.Row
        self.cur = self.conn.cursor()
        self._init_schema()

    def _init_schema(self):
        self.cur.executescript(
            """
            CREATE TABLE IF NOT EXISTS gts_records (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TEXT NOT NULL,
                apdn TEXT,
                e12_seal TEXT,
                k3_seal TEXT,
                estate_checks TEXT, -- JSON {label: bool}
                kilang_checks TEXT, -- JSON {label: bool}
                notes TEXT
            );

            CREATE TABLE IF NOT EXISTS gts_images (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                record_id INTEGER NOT NULL,
                label TEXT NOT NULL,
                path TEXT NOT NULL,
                FOREIGN KEY(record_id) REFERENCES gts_records(id) ON DELETE CASCADE
            );
            """
        )
        self.conn.commit()

    # --- CRUD ---
    def add_record(self, apdn: str, e12: str, k3: str,
                   estate: Dict[str, bool], kilang: Dict[str, bool],
                   notes: str) -> int:
        self.cur.execute(
            "INSERT INTO gts_records(created_at, apdn, e12_seal, k3_seal, estate_checks, kilang_checks, notes)\n"
            "VALUES(?, ?, ?, ?, ?, ?, ?)",
            (
                dt.datetime.now().isoformat(timespec="seconds"),
                apdn, e12, k3, json.dumps(estate), json.dumps(kilang), notes
            )
        )
        rid = self.cur.lastrowid
        self.conn.commit()
        return rid

    def update_record(self, rid: int, apdn: str, e12: str, k3: str,
                      estate: Dict[str, bool], kilang: Dict[str, bool], notes: str):
        self.cur.execute(
            "UPDATE gts_records SET apdn=?, e12_seal=?, k3_seal=?, estate_checks=?, kilang_checks=?, notes=? WHERE id=?",
            (apdn, e12, k3, json.dumps(estate), json.dumps(kilang), notes, rid)
        )
        self.conn.commit()

    def delete_records(self, ids: List[int]):
        if not ids:
            return
        q = f"DELETE FROM gts_records WHERE id IN ({','.join('?'*len(ids))})"
        self.cur.execute(q, ids)
        self.conn.commit()

    def list_records(self, limit: Optional[int] = None) -> List[sqlite3.Row]:
        q = "SELECT * FROM gts_records ORDER BY id DESC"
        if limit:
            q += " LIMIT ?"
            return self.cur.execute(q, (limit,)).fetchall()
        return self.cur.execute(q).fetchall()

    def get_record(self, rid: int) -> Optional[sqlite3.Row]:
        return self.cur.execute("SELECT * FROM gts_records WHERE id=?", (rid,)).fetchone()

    def list_images(self, rid: int, label: Optional[str] = None) -> List[sqlite3.Row]:
        if label:
            return self.cur.execute("SELECT * FROM gts_images WHERE record_id=? AND label=? ORDER BY id", (rid, label)).fetchall()
        return self.cur.execute("SELECT * FROM gts_images WHERE record_id=? ORDER BY id", (rid,)).fetchall()

    def add_image(self, rid: int, label: str, path: str):
        # enforce cap at DB level too
        cur_count = self.cur.execute("SELECT COUNT(*) FROM gts_images WHERE record_id=? AND label=?", (rid, label)).fetchone()[0]
        if cur_count >= MAX_IMAGES_PER_LABEL:
            raise ValueError(f"Max {MAX_IMAGES_PER_LABEL} images for {label}")
        self.cur.execute("INSERT INTO gts_images(record_id, label, path) VALUES(?,?,?)", (rid, label, path))
        self.conn.commit()

    def remove_image(self, img_id: int):
        self.cur.execute("DELETE FROM gts_images WHERE id=?", (img_id,))
        self.conn.commit()


# --------- UI ---------
ctk.set_appearance_mode("System")
ctk.set_default_color_theme("blue")


class GTSApp(ctk.CTk):
    def __init__(self, db: DB):
        super().__init__()
        self.db = db
        self.title(APP_NAME)
        # Autosize to monitor, with min size
        sw = self.winfo_screenwidth()
        sh = self.winfo_screenheight()
        w = int(sw * 0.9)
        h = int(sh * 0.9)
        w = max(w, 1100)
        h = max(h, 720)
        x = (sw - w) // 2
        y = (sh - h) // 2
        self.geometry(f"{w}x{h}+{x}+{y}")
        self.minsize(1000, 680)

        self._build_ui()

    # --- UI scaffolding ---
    def _build_ui(self):
        self.tabs = ctk.CTkTabview(self)
        self.tabs.pack(fill="both", expand=True, padx=10, pady=10)
        self.tab_create = self.tabs.add("Create Record")
        self.tab_view = self.tabs.add("View Records")
        self.tab_export = self.tabs.add("Export PDF")

        self._build_create_tab()
        self._build_view_tab()
        self._build_export_tab()

    # ---------- Create Record Tab ----------
    def _build_create_tab(self):
        wrap = ctk.CTkFrame(self.tab_create)
        wrap.pack(fill="both", expand=True, padx=10, pady=10)

        top = ctk.CTkFrame(wrap)
        top.pack(fill="x", padx=4, pady=4)

        # APDN, E12, K3
        ctk.CTkLabel(top, text="APDN (E2)").grid(row=0, column=0, padx=6, pady=6, sticky="e")
        self.ent_apdn = ctk.CTkEntry(top, width=180)
        self.ent_apdn.grid(row=0, column=1, padx=6, pady=6, sticky="w")

        ctk.CTkLabel(top, text="E12 Seal").grid(row=0, column=2, padx=6, pady=6, sticky="e")
        self.ent_e12 = ctk.CTkEntry(top, width=180)
        self.ent_e12.grid(row=0, column=3, padx=6, pady=6, sticky="w")

        ctk.CTkLabel(top, text="K3 Seal").grid(row=0, column=4, padx=6, pady=6, sticky="e")
        self.ent_k3 = ctk.CTkEntry(top, width=180)
        self.ent_k3.grid(row=0, column=5, padx=6, pady=6, sticky="w")

        # Estate / Kilang sections side-by-side, each vertical list
        mid = ctk.CTkFrame(wrap)
        mid.pack(fill="x", padx=4, pady=6)

        estate_fr = ctk.CTkFrame(mid)
        estate_fr.pack(side="left", fill="y", padx=8)
        ctk.CTkLabel(estate_fr, text="Estate labels").pack(anchor="w", pady=(4,2))
        self.estate_vars: Dict[str, tk.BooleanVar] = {}
        for code, title in ESTATE_LABELS:
            var = tk.BooleanVar(value=False)
            self.estate_vars[code] = var
            row = ctk.CTkFrame(estate_fr)
            row.pack(fill="x", pady=2)
            ctk.CTkCheckBox(row, text=f"{code} — {title}", variable=var).pack(side="left")
            ctk.CTkButton(row, text="Attach", width=70, command=lambda c=code: self._attach_images(c)).pack(side="right", padx=4)

        kilang_fr = ctk.CTkFrame(mid)
        kilang_fr.pack(side="left", fill="y", padx=16)
        ctk.CTkLabel(kilang_fr, text="Kilang labels").pack(anchor="w", pady=(4,2))
        self.kilang_vars: Dict[str, tk.BooleanVar] = {}
        for code, title in KILANG_LABELS:
            var = tk.BooleanVar(value=False)
            self.kilang_vars[code] = var
            row = ctk.CTkFrame(kilang_fr)
            row.pack(fill="x", pady=2)
            ctk.CTkCheckBox(row, text=f"{code} — {title}", variable=var).pack(side="left")
            ctk.CTkButton(row, text="Attach", width=70, command=lambda c=code: self._attach_images(c)).pack(side="right", padx=4)

        # Notes & Save
        bottom = ctk.CTkFrame(wrap)
        bottom.pack(fill="both", expand=True, padx=4, pady=6)
        ctk.CTkLabel(bottom, text="Notes").pack(anchor="w")
        self.txt_notes = tk.Text(bottom, height=5)
        self.txt_notes.pack(fill="x", pady=4)
        ctk.CTkButton(bottom, text="Save Record", command=self._save_record, height=36).pack(anchor="e", pady=6)

        # live attachments preview panel
        self.preview_panel = ctk.CTkScrollableFrame(bottom, height=160)
        self.preview_panel.pack(fill="x", pady=(8,4))
        ctk.CTkLabel(self.preview_panel, text="Attached images (per label max 2)").pack(anchor="w")
        self._preview_imgs: Dict[str, List[ImageTk.PhotoImage]] = {}

        # working area for pending attachments before save
        self._pending_attachments: Dict[str, List[str]] = {code: [] for code, _ in ESTATE_LABELS + KILANG_LABELS}

    def _attach_images(self, label_code: str):
        existing = self._pending_attachments[label_code]
        remain = MAX_IMAGES_PER_LABEL - len(existing)
        if remain <= 0:
            messagebox.showinfo(APP_NAME, f"{label_code}: already attached {MAX_IMAGES_PER_LABEL} images")
            return
        paths = filedialog.askopenfilenames(title=f"Attach images for {label_code}", filetypes=[("Image files", "*.png;*.jpg;*.jpeg;*.bmp;*.gif")])
        if not paths:
            return
        to_add = list(paths)[:remain]
        existing.extend(to_add)
        self._refresh_preview()

    def _refresh_preview(self):
        for w in list(self.preview_panel.winfo_children())[1:]:  # keep header label
            w.destroy()
        self._preview_imgs.clear()
        for code, files in self._pending_attachments.items():
            if not files:
                continue
            row = ctk.CTkFrame(self.preview_panel)
            row.pack(fill="x", pady=2)
            ctk.CTkLabel(row, text=f"{code}").pack(side="left", padx=6)
            holder: List[ImageTk.PhotoImage] = []
            for p in files:
                try:
                    img = Image.open(p).copy()
                    img.thumbnail(IMG_THUMB_SIZE)
                    tkimg = ImageTk.PhotoImage(img)
                    holder.append(tkimg)
                    lbl = ctk.CTkLabel(row, image=tkimg, text="")
                    lbl.pack(side="left", padx=3)
                except Exception:
                    pass
            self._preview_imgs[code] = holder

    def _save_record(self):
        apdn = self.ent_apdn.get().strip()
        e12 = self.ent_e12.get().strip()
        k3 = self.ent_k3.get().strip()
        est = {k: bool(v.get()) for k, v in self.estate_vars.items()}
        kil = {k: bool(v.get()) for k, v in self.kilang_vars.items()}
        notes = self.txt_notes.get("1.0", "end").strip()

        if not apdn:
            messagebox.showinfo(APP_NAME, "APDN is required")
            return
        try:
            rid = self.db.add_record(apdn, e12, k3, est, kil, notes)
            # persist attachments
            for code, files in self._pending_attachments.items():
                for p in files:
                    self.db.add_image(rid, code, p)
            # reset form
            self.ent_apdn.delete(0, 'end')
            self.ent_e12.delete(0, 'end')
            self.ent_k3.delete(0, 'end')
            for v in self.estate_vars.values(): v.set(False)
            for v in self.kilang_vars.values(): v.set(False)
            self.txt_notes.delete('1.0', 'end')
            self._pending_attachments = {code: [] for code, _ in ESTATE_LABELS + KILANG_LABELS}
            self._refresh_preview()
            messagebox.showinfo(APP_NAME, f"Record #{rid} saved")
            self.load_view_records()
            self.tabs.set("View Records")
        except Exception as e:
            messagebox.showerror(APP_NAME, f"Failed to save: {e}")

    # ---------- View Records Tab ----------
    def _build_view_tab(self):
        wrap = ctk.CTkFrame(self.tab_view)
        wrap.pack(fill="both", expand=True, padx=8, pady=8)

        left = ctk.CTkFrame(wrap)
        left.pack(side="left", fill="both", expand=True)

        cols = ("id", "created_at", "apdn", "e12_seal", "k3_seal")
        self.tree = ttk.Treeview(left, columns=cols, show="headings", selectmode="extended")
        for c in cols:
            self.tree.heading(c, text=c)
        self.tree.column("id", width=70, anchor="center")
        self.tree.column("created_at", width=160)
        self.tree.column("apdn", width=120)
        self.tree.column("e12_seal", width=110)
        self.tree.column("k3_seal", width=110)
        self.tree.pack(fill="both", expand=True)
        self.tree.bind("<<TreeviewSelect>>", lambda e: self._show_record_details())

        btns = ctk.CTkFrame(left)
        btns.pack(fill="x", pady=6)
        ctk.CTkButton(btns, text="Refresh", command=self.load_view_records).pack(side="left", padx=4)
        ctk.CTkButton(btns, text="Delete Selected (Multi)", command=self._delete_selected_multi).pack(side="left", padx=4)

        # right panel details
        right = ctk.CTkScrollableFrame(wrap, width=420)
        right.pack(side="left", fill="y", padx=8)
        self.detail_panel = right
        self.detail_widgets: List[tk.Widget] = []

        self.load_view_records()

    def load_view_records(self):
        for i in self.tree.get_children():
            self.tree.delete(i)
        for row in self.db.list_records():
            self.tree.insert('', 'end', iid=str(row["id"]), values=(row["id"], row["created_at"], row["apdn"], row["e12_seal"], row["k3_seal"]))
        self._clear_detail_panel()

    def _clear_detail_panel(self):
        for w in getattr(self, 'detail_widgets', []):
            try: w.destroy()
            except: pass
        self.detail_widgets = []

    def _show_record_details(self):
        sel = self.tree.selection()
        if not sel:
            return
        rid = int(sel[0])
        row = self.db.get_record(rid)
        if not row:
            return
        self._clear_detail_panel()
        add = self.detail_widgets.append
        mk = lambda t: ctk.CTkLabel(self.detail_panel, text=t)
        mk(f"Record #{row['id']}").pack(anchor='w', pady=(2,2)); add(_)
        ctk.CTkLabel(self.detail_panel, text=f"Created: {row['created_at']}").pack(anchor='w'); add(_)
        ctk.CTkLabel(self.detail_panel, text=f"APDN: {row['apdn']}").pack(anchor='w'); add(_)
        ctk.CTkLabel(self.detail_panel, text=f"E12 Seal: {row['e12_seal']}  |  K3 Seal: {row['k3_seal']}").pack(anchor='w'); add(_)

        def show_checks(title: str, data: Dict[str, bool]):
            ctk.CTkLabel(self.detail_panel, text=title).pack(anchor='w', pady=(6,2)); add(_)
            for k, v in data.items():
                ctk.CTkLabel(self.detail_panel, text=f"{k}: {PRINT_TRUE if v else PRINT_FALSE}").pack(anchor='w'); add(_)
        show_checks("Estate checks", json.loads(row['estate_checks'] or '{}'))
        show_checks("Kilang checks", json.loads(row['kilang_checks'] or '{}'))

        # images by label
        ctk.CTkLabel(self.detail_panel, text="Images:").pack(anchor='w', pady=(6,2)); add(_)
        imgs = self.db.list_images(rid)
        group: Dict[str, List[str]] = {}
        for imr in imgs:
            group.setdefault(imr['label'], []).append(imr['path'])
        for label, files in group.items():
            rowf = ctk.CTkFrame(self.detail_panel)
            rowf.pack(fill='x', pady=2); add(rowf)
            ctk.CTkLabel(rowf, text=label).pack(side='left', padx=6)
            holder: List[ImageTk.PhotoImage] = []
            for p in files:
                try:
                    img = Image.open(p).copy(); img.thumbnail(IMG_THUMB_SIZE)
                    tkimg = ImageTk.PhotoImage(img); holder.append(tkimg)
                    ctk.CTkLabel(rowf, image=tkimg, text="").pack(side='left', padx=3)
                except Exception:
                    ctk.CTkLabel(rowf, text=f"(missing {os.path.basename(p)})").pack(side='left', padx=3)

        if (row['notes'] or '').strip():
            ctk.CTkLabel(self.detail_panel, text="Notes:").pack(anchor='w', pady=(6,2)); add(_)
            t = tk.Text(self.detail_panel, height=6); t.insert('1.0', row['notes']); t.configure(state='disabled')
            t.pack(fill='x'); add(t)

    def _delete_selected_multi(self):
        sel = self.tree.selection()
        if not sel:
            messagebox.showinfo(APP_NAME, "Select one or more records to delete.")
            return
        ids = [int(i) for i in sel]
        if not messagebox.askyesno(APP_NAME, f"Delete {len(ids)} record(s)? This cannot be undone."):
            return
        try:
            self.db.delete_records(ids)
            self.load_view_records()
            messagebox.showinfo(APP_NAME, f"Deleted {len(ids)} record(s)")
        except Exception as e:
            messagebox.showerror(APP_NAME, f"Failed to delete: {e}")

    # ---------- Export Tab ----------
    def _build_export_tab(self):
        wrap = ctk.CTkFrame(self.tab_export)
        wrap.pack(fill="both", expand=True, padx=10, pady=10)
        ctk.CTkLabel(wrap, text="Export all records to PDF").pack(anchor='w')
        ctk.CTkButton(wrap, text="Export to PDF", command=self._export_pdf).pack(anchor='w', pady=8)
        self.lbl_export_status = ctk.CTkLabel(wrap, text="")
        self.lbl_export_status.pack(anchor='w', pady=4)

    def _export_pdf(self):
        out = filedialog.asksaveasfilename(title="Save PDF", defaultextension=".pdf", filetypes=[("PDF", "*.pdf")])
        if not out:
            return
        try:
            self._do_render_pdf(out)
            self.lbl_export_status.configure(text=f"Exported: {out}")
            messagebox.showinfo(APP_NAME, f"PDF exported to {out}")
        except Exception as e:
            messagebox.showerror(APP_NAME, f"Export failed: {e}")

    def _do_render_pdf(self, outpath: str):
        rows = self.db.list_records()
        c = canvas.Canvas(outpath, pagesize=A4)
        W, H = A4
        margin = 15*mm
        y = H - margin
        line_h = 6*mm
        img_max_w = W - 2*margin - 20
        img_row_h = 35*mm

        def new_page():
            nonlocal y
            c.showPage()
            y = H - margin

        def ensure_space(need: float):
            nonlocal y
            if y - need < margin:
                new_page()

        for row in rows:
            # Header block height estimate ~ 6 lines
            header_need = line_h * 6
            ensure_space(header_need)
            c.setFont("Helvetica-Bold", 12)
            c.drawString(margin, y, f"Record #{row['id']} — {row['created_at']}"); y -= line_h
            c.setFont("Helvetica", 10)
            c.drawString(margin, y, f"APDN: {row['apdn']}"); y -= line_h
            c.drawString(margin, y, f"E12 Seal: {row['e12_seal']}   K3 Seal: {row['k3_seal']}"); y -= line_h

            est = json.loads(row['estate_checks'] or '{}')
            kil = json.loads(row['kilang_checks'] or '{}')
            c.drawString(margin, y, "Estate checks:"); y -= line_h
            for k in est:
                c.drawString(margin+12, y, f"{k}: {PRINT_TRUE if est[k] else PRINT_FALSE}"); y -= line_h
            c.drawString(margin, y, "Kilang checks:"); y -= line_h
            for k in kil:
                c.drawString(margin+12, y, f"{k}: {PRINT_TRUE if kil[k] else PRINT_FALSE}"); y -= line_h

            # Notes
            notes = (row['notes'] or '').strip()
            if notes:
                ensure_space(line_h*2)
                c.setFont("Helvetica-Bold", 10)
                c.drawString(margin, y, "Notes:"); y -= line_h
                c.setFont("Helvetica", 10)
                # simple wrapping
                for line in wrap_text(notes, max_chars=95):
                    ensure_space(line_h)
                    c.drawString(margin+12, y, line); y -= line_h

            # Images grouped by label
            imgs = self.db.list_images(row['id'])
            groups: Dict[str, List[str]] = {}
            for imr in imgs:
                groups.setdefault(imr['label'], []).append(imr['path'])
            if groups:
                ensure_space(line_h)
                c.setFont("Helvetica-Bold", 10)
                c.drawString(margin, y, "Images:"); y -= line_h
                c.setFont("Helvetica", 10)
                for label, files in groups.items():
                    ensure_space(line_h)
                    c.drawString(margin+0, y, f"{label}:"); y -= line_h
                    # layout images for this label in a row if possible
                    if not files:
                        continue
                    # compute per-image width (max two per row since cap=2)
                    row_y = y
                    x = margin+12
                    for p in files:
                        try:
                            img = Image.open(p)
                            w, h = img.size
                            scale = min(img_max_w/2 / w, img_row_h / h)
                            tw, th = w*scale, h*scale
                            ensure_space(th + line_h)
                            c.drawImage(ImageReader(img), x, y - th, width=tw, height=th, preserveAspectRatio=True, anchor='sw')
                            x += tw + 10
                            row_y = min(row_y, y - th)
                        except Exception:
                            ensure_space(line_h)
                            c.drawString(margin+12, y, f"(missing {os.path.basename(p)})"); y -= line_h
                    y = row_y - 8

            # Spacer between records; try to keep 2 per page when possible
            ensure_space(line_h*2)
            y -= line_h

        c.save()


def wrap_text(text: str, max_chars: int = 90) -> List[str]:
    words = text.split()
    lines: List[str] = []
    cur = []
    n = 0
    for w in words:
        if n + len(w) + (1 if cur else 0) > max_chars:
            lines.append(" ".join(cur)); cur = [w]; n = len(w)
        else:
            cur.append(w); n += len(w) + (1 if cur[:-1] else 0)
    if cur:
        lines.append(" ".join(cur))
    return lines


def main():
    # Licensing check FIRST (UI safe because we may ask for PIN)
    verify_license_or_exit()

    # DB init
    db = DB(DB_PATH)

    # Launch UI
    app = GTSApp(db)
    app.mainloop()


if __name__ == "__main__":
    main()
