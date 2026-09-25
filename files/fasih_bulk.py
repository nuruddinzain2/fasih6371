#!/usr/bin/env python3
"""
fasih_bulk.py - Aksi massal Pengawas/PML di FASIH SM (pengganti ekstensi FASIH Action Center).

Memakai endpoint yang sama dengan ekstensi, dengan sesi login kamu sendiri.

Contoh:
  python fasih_bulk.py cek     ids.txt --period <SURVEY_PERIOD_ID>
  python fasih_bulk.py reject  ids.txt --period <SURVEY_PERIOD_ID> --dry-run
  python fasih_bulk.py reject  ids.txt --period <SURVEY_PERIOD_ID>
  python fasih_bulk.py reject  --failed-from log_reject_XXXX.csv --period <SURVEY_PERIOD_ID>

Cookie: simpan isi header "Cookie" dari browser ke cookie.txt. Jika kosong/kedaluwarsa,
skrip akan meminta cookie baru lewat terminal dan melanjutkan dari ID yang terhenti.
"""
import argparse
import csv
import os
import re
import sys
import time
import traceback
from datetime import datetime
from pathlib import Path
from urllib.parse import unquote, urlparse

import requests

BASE_URL = "https://fasih-sm.bps.go.id"
# Survey Period ID bawaan untuk mode klik-dua-kali (PENDATAAN, Sensus Ekonomi 2026)
DEFAULT_PERIOD = "fd68e454-ba45-4b85-8205-f3bf777ded24"
EP_APPROVAL = "/app/api/assignment-approval/api/v2/approval"
EP_REVOKE = "/app/api/assignment-approval/api/v2/revoke-approval"
EP_STATUS = "/app/api/assignment-general/api/assignment/get-by-assignment-id"
EP_MYINFO = "/app/api/survey/api/v1/users/myinfo"

# aksi -> (endpoint, statusApproval, label)
ACTIONS = {
    "reject": (EP_APPROVAL, "false", "Reject"),
    "approve": (EP_APPROVAL, "true", "Approve"),
    "revoke": (EP_REVOKE, "false", "Revoke"),
}
# Status yang dilewati otomatis (cocok jika alias status MENGANDUNG kata ini, tanpa peduli huruf besar/kecil)
DEFAULT_SKIP = {"reject": ["REJECT", "SUBMITTED"], "approve": [], "revoke": []}

MAX_RETRIES = 3


class AuthError(Exception):
    pass


# ---------------------------------------------------------------- sesi & cookie
def make_session(base_url: str) -> requests.Session:
    s = requests.Session()
    s.headers.update({
        "User-Agent": ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                       "(KHTML, like Gecko) Chrome/124.0 Safari/537.36"),
        "Accept": "application/json, text/plain, */*",
        "Referer": f"{base_url}/app/",
        "Origin": base_url,
    })
    return s


def load_cookies(session: requests.Session, cookie_str: str, base_url: str):
    """Ganti seluruh cookie di sesi dengan string cookie baru."""
    session.cookies.clear()
    host = urlparse(base_url).hostname
    cookie_str = re.sub(r"^\s*cookie:\s*", "", cookie_str, flags=re.I)
    for part in cookie_str.replace("\n", " ").split(";"):
        part = part.strip()
        if "=" not in part:
            continue
        k, v = part.split("=", 1)
        session.cookies.set(k.strip(), v.strip(), domain=host, path="/")


def get_xsrf(session: requests.Session):
    token = None
    for c in session.cookies:
        if c.name == "XSRF-TOKEN":
            token = unquote(c.value)  # ambil yang terakhir (paling baru)
    return token


def call(session, base_url, method, path, payload=None, params=None):
    token = get_xsrf(session)
    if not token:
        raise AuthError("XSRF-TOKEN tidak ada di cookie.")
    r = session.request(
        method, base_url + path,
        json=payload, params=params,
        headers={"X-XSRF-TOKEN": token, "Cache-Control": "no-cache"},
        timeout=30,
    )
    try:
        body = r.json()
    except ValueError:
        body = {}
    return r.status_code, body


def refresh_session(session, base_url):
    """Pengganti 'reload tab': buka halaman FASIH agar server memperbarui cookie XSRF."""
    try:
        session.get(f"{base_url}/app/surveys", timeout=30)
    except requests.RequestException:
        pass


def check_role(session, base_url, period_id):
    code, body = call(session, base_url, "GET", EP_MYINFO, params={"surveyPeriodId": period_id})
    if code != 200 or not body.get("success") or not body.get("data"):
        raise AuthError(f"HTTP {code}: {body.get('message', 'sesi tidak valid')}")
    u = body["data"]
    role = u.get("surveyRole") or {}
    desc = role.get("description") or role.get("name") or "?"
    name = u.get("fullname") or u.get("username") or "?"
    norm = f"{role.get('description', '')} {role.get('name', '')}".lower()
    allowed = any(k in norm for k in ("admin", "pengawas", "pml", "pemeriksa"))
    return name, desc, allowed


def session_alive(session, base_url, period_id) -> bool:
    try:
        check_role(session, base_url, period_id)
        return True
    except (AuthError, requests.RequestException):
        return False


def ask_new_cookie(session, base_url, period_id, cookie_file: Path, reason: str):
    """Dialog di terminal untuk memasukkan cookie baru. Return (name, role, allowed) atau None jika berhenti."""
    print(f"\n=== {reason} ===")
    print("Ambil cookie baru: browser yang sedang login FASIH > F12 > Network > klik request ke")
    print("fasih-sm.bps.go.id > Request Headers > salin nilai 'Cookie'.")
    print("Tempel di bawah lalu Enter. Atau isi cookie.txt lalu tekan Enter saja. Ketik 'stop' untuk berhenti.")
    while True:
        try:
            s = input("Cookie baru> ").strip()
        except (EOFError, KeyboardInterrupt):
            return None
        if s.lower() == "stop":
            return None
        if s:
            cookie_file.write_text(s, encoding="utf-8")
        elif cookie_file.exists():
            s = cookie_file.read_text(encoding="utf-8").strip()
        if not s:
            print("Cookie kosong.")
            continue
        load_cookies(session, s, base_url)
        try:
            info = check_role(session, base_url, period_id)
            print(f"Cookie diterima. Login sebagai: {info[0]} | Role: {info[1]}")
            return info
        except (AuthError, requests.RequestException) as e:
            print(f"Cookie belum valid ({e}). Coba lagi.")


# ---------------------------------------------------------------- input
UUID_RE = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
# nama header yang dikenali otomatis sebagai sumber Assignment ID (huruf besar/kecil tidak berpengaruh)
ID_HEADERS = ["link fasih", "assignment id", "id assignment", "id"]  # "_" dianggap spasi


def extract_id(value):
    """Ambil UUID dari teks/link (mis. .../assignment-detail/<UUID>); jika tidak ada UUID, pakai teks apa adanya."""
    v = str(value).strip()
    m = UUID_RE.search(v)
    return m.group(0) if m else v


def read_table(path: Path, sheet=None):
    """Baca xlsx/csv/tsv menjadi daftar baris (baris pertama = header)."""
    if path.suffix.lower() in (".xlsx", ".xlsm"):
        from openpyxl import load_workbook
        wb = load_workbook(path, read_only=True, data_only=True)
        ws = wb[sheet] if sheet else wb.active
        return [list(r) for r in ws.iter_rows(values_only=True)]
    text = path.read_text(encoding="utf-8-sig")
    first = text.splitlines()[0] if text.strip() else ""
    delim = max([",", ";", "\t"], key=first.count)
    return list(csv.reader(text.splitlines(), delimiter=delim))


def read_ids(path: Path, column=None, sheet=None):
    if path.suffix.lower() in (".xlsx", ".xlsm", ".csv", ".tsv"):
        rows = read_table(path, sheet)
        if not rows:
            return []
        header = [str(h).strip() if h is not None else "" for h in rows[0]]
        lower = [h.lower().replace("_", " ") for h in header]
        idx = None
        if column:
            column = column.lower().replace("_", " ")
            if column not in lower:
                sys.exit(f"Kolom '{column}' tidak ada. Kolom yang tersedia: {', '.join(h for h in header if h)}")
            idx = lower.index(column)
        else:
            for name in ID_HEADERS:
                if name in lower:
                    idx = lower.index(name)
                    break
        if idx is None:
            if len(header) == 1 and UUID_RE.search(header[0]):  # satu kolom tanpa judul: semua baris adalah ID
                idx, rows = 0, [[]] + rows
            else:
                sys.exit("Kolom ID tidak ditemukan otomatis. Tentukan dengan --column NAMA_KOLOM.\n"
                         f"Kolom yang tersedia: {', '.join(h for h in header if h)}")
        print(f"Sumber ID: kolom '{header[idx] if header else idx}' dari {path.name}")
        tokens = [extract_id(r[idx]) for r in rows[1:] if idx < len(r) and r[idx] not in (None, "")]
    else:
        tokens = [extract_id(t) for t in re.split(r"[\s,;]+", path.read_text(encoding="utf-8-sig"))]
    seen, ids = set(), []
    for t in tokens:
        if t and t not in seen:
            seen.add(t)
            ids.append(t)
    return ids


def read_failed_ids(log_path: Path):
    ids, seen = [], set()
    with open(log_path, newline="", encoding="utf-8-sig") as f:
        for row in csv.DictReader(f):
            if row.get("status") == "Gagal" and row.get("assignment_id") not in ("", "-"):
                if row["assignment_id"] not in seen:
                    seen.add(row["assignment_id"])
                    ids.append(row["assignment_id"])
    return ids


# ---------------------------------------------------------------- aksi
def process_one(session, base_url, action, assignment_id):
    """Return (ok, note, kind, data). kind: None | 'auth' | 'network' | 'server' | 'biz'."""
    last_note, kind = "", None
    for attempt in range(MAX_RETRIES + 1):
        try:
            if action == "cek":
                code, res = call(session, base_url, "GET", EP_STATUS,
                                 params={"assignmentId": assignment_id})
            else:
                ep, status_approval, _ = ACTIONS[action]
                payload = {
                    "assignmentId": assignment_id,
                    "statusApproval": status_approval,
                    "comment": '{"dataKey":"","notes":[]}',
                }
                code, res = call(session, base_url, "POST", ep, payload=payload)
        except AuthError as e:
            return False, str(e), "auth", None
        except requests.RequestException as e:
            last_note, kind = f"Jaringan: {e}", "network"
            if attempt < MAX_RETRIES:
                time.sleep(3)
                continue
            return False, last_note, kind, None

        msg = res.get("message") if isinstance(res, dict) else None
        if code == 200 and isinstance(res, dict) and res.get("success") and res.get("data"):
            d = res["data"]
            if action == "cek":
                return True, f"Status: [{d.get('assignment_status_alias', 'UNKNOWN')}] | Identitas: {d.get('code_identity', '-')}", None, d
            return True, f"Status: {d.get('assignmentStatusAlias', 'Success')}", None, d

        last_note = msg or f"HTTP {code}"
        if code == 429 or "rate limit" in last_note.lower():
            kind = "server"
            wait = 8 * (attempt + 1)
            print(f"    rate limit, tunggu {wait} dtk...")
            time.sleep(wait)
        elif code in (401, 403, 419) or re.search(r"token|session|sesi|login|unauthorized", last_note, re.I):
            kind = "auth"
            refresh_session(session, base_url)
            time.sleep(1.5)
        elif code in (502, 503, 504):
            kind = "server"
            time.sleep(3)
        else:
            return False, last_note, "biz", None  # ditolak server (tidak ditemukan, status tidak valid, dst.)
    return False, last_note, kind, None


def handle_id(session, base_url, action, aid, skip_kw, only_kw, precheck):
    """Return (state, note, kind). state: 'ok' | 'fail' | 'skip'."""
    prev = ""
    if action != "cek" and precheck:
        ok, note, kind, data = process_one(session, base_url, "cek", aid)
        if not ok:
            if kind == "biz":
                return "skip", f"Tidak ditemukan / tidak bisa diakses: {note}", None
            return "fail", f"Pra-cek gagal: {note}", kind
        alias = (data.get("assignment_status_alias") or "").upper()
        if any(k in alias for k in skip_kw):
            return "skip", f"Sudah berstatus [{alias}]", None
        if only_kw and not any(k in alias for k in only_kw):
            return "skip", f"Status [{alias}] tidak sesuai --only-status", None
        prev = f" (sebelumnya [{alias}])"
    ok, note, kind, _ = process_one(session, base_url, action, aid)
    return ("ok" if ok else "fail"), note + (prev if ok else ""), kind


def parse_kw(s):
    return [k.strip().upper() for k in s.split(",") if k.strip()] if s else []


# ---------------------------------------------------------------- main
def main(argv=None):
    ap = argparse.ArgumentParser(description="Aksi massal FASIH SM untuk Pengawas/PML")
    ap.add_argument("action", choices=["cek", "reject", "approve", "revoke"])
    ap.add_argument("ids_file", nargs="?", type=Path, help="File .xlsx/.csv/.txt berisi Assignment ID atau link FASIH")
    ap.add_argument("--column", help="Nama kolom berisi Assignment ID/link (default: otomatis, mis. link_fasih)")
    ap.add_argument("--sheet", help="Nama sheet Excel (default: sheet yang aktif)")
    ap.add_argument("--failed-from", type=Path, help="Ambil hanya ID berstatus Gagal dari file log CSV")
    ap.add_argument("--period", required=True, help="Survey Period ID")
    ap.add_argument("--cookie-file", type=Path, default=Path("cookie.txt"))
    ap.add_argument("--delay", type=float, default=0.6, help="Jeda antar ID (detik), default 0.6")
    ap.add_argument("--skip-status", help="Lewati jika status mengandung kata ini (pisah koma). "
                                          "Default reject: REJECT,SUBMITTED. Isi '-' untuk menonaktifkan.")
    ap.add_argument("--only-status", help="Proses hanya jika status mengandung salah satu kata ini (pisah koma)")
    ap.add_argument("--no-precheck", action="store_true", help="Jangan cek status dulu sebelum aksi")
    ap.add_argument("--dry-run", action="store_true", help="Hanya tampilkan rencana, tidak mengirim apa pun")
    ap.add_argument("--yes", action="store_true", help="Lewati konfirmasi ketik YA")
    ap.add_argument("--base-url", default=BASE_URL, help=argparse.SUPPRESS)
    args = ap.parse_args(argv)

    if args.failed_from:
        ids = read_failed_ids(args.failed_from)
    elif args.ids_file:
        ids = read_ids(args.ids_file, args.column, args.sheet)
    else:
        ap.error("Berikan ids_file atau --failed-from")
    if not ids:
        sys.exit("Tidak ada Assignment ID yang dibaca.")

    label = "Cek Status" if args.action == "cek" else ACTIONS[args.action][2]
    if args.skip_status is None:
        skip_kw = DEFAULT_SKIP.get(args.action, [])
    else:
        skip_kw = [] if args.skip_status.strip() == "-" else parse_kw(args.skip_status)
    only_kw = parse_kw(args.only_status)
    precheck = not args.no_precheck

    print(f"{len(ids)} Assignment ID unik | aksi: {label} | delay: {args.delay}s")
    print("Contoh ID:", ", ".join(ids[:3]), "..." if len(ids) > 3 else "")
    if args.action != "cek":
        print(f"Pra-cek status: {'ya' if precheck else 'tidak'} | lewati jika status: {skip_kw or '-'} | "
              f"hanya status: {only_kw or 'semua'}")

    if args.dry_run:
        print("DRY-RUN: tidak ada request yang dikirim.")
        return

    session = make_session(args.base_url)
    info = None
    if args.cookie_file.exists() and args.cookie_file.read_text(encoding="utf-8").strip():
        load_cookies(session, args.cookie_file.read_text(encoding="utf-8").strip(), args.base_url)
        try:
            info = check_role(session, args.base_url, args.period)
        except (AuthError, requests.RequestException) as e:
            info = ask_new_cookie(session, args.base_url, args.period, args.cookie_file,
                                  f"Cookie di {args.cookie_file} tidak valid ({e})")
    else:
        info = ask_new_cookie(session, args.base_url, args.period, args.cookie_file,
                              f"{args.cookie_file} belum ada / kosong")
    if not info:
        sys.exit("Dibatalkan: tidak ada sesi login yang valid.")
    name, role, allowed = info
    print(f"Login sebagai: {name} | Role: {role}")
    if not allowed and args.action != "cek":
        sys.exit("Role ini bukan Admin/Pengawas/PML. Dibatalkan.")

    if args.action != "cek" and not args.yes:
        ans = input(f"Ketik YA untuk {label} maksimal {len(ids)} assignment: ").strip()
        if ans != "YA":
            sys.exit("Dibatalkan.")

    log_path = Path(f"log_{args.action}_{datetime.now():%Y%m%d_%H%M%S}.csv")
    ok_n = fail_n = skip_n = 0
    stopped = False
    total = len(ids)
    with open(log_path, "w", newline="", encoding="utf-8-sig") as f:
        w = csv.writer(f)
        w.writerow(["waktu", "assignment_id", "aksi", "status", "keterangan"])

        def log(aid, status, note):
            w.writerow([datetime.now().strftime("%H:%M:%S"), aid, label, status, note])
            f.flush()

        i = 0
        try:
            while i < total:
                aid = ids[i]
                state, note, kind = handle_id(session, args.base_url, args.action, aid,
                                              skip_kw, only_kw, precheck)

                if state == "fail" and kind == "auth" and not session_alive(session, args.base_url, args.period):
                    log("-", "Info", f"Sesi kedaluwarsa saat memproses {aid}")
                    if not ask_new_cookie(session, args.base_url, args.period, args.cookie_file,
                                          "Sesi/cookie kedaluwarsa"):
                        stopped = True
                        break
                    log("-", "Info", "Cookie diperbarui, melanjutkan")
                    continue  # ulangi ID yang sama dengan cookie baru

                if state == "ok":
                    ok_n += 1
                    status, tag = "Berhasil", "OK"
                elif state == "skip":
                    skip_n += 1
                    status, tag = "Dilewati", "LEWAT"
                else:
                    fail_n += 1
                    status, tag = "Gagal", "GAGAL"
                log(aid, status, note)
                print(f"[{i + 1}/{total}] {aid} -> {tag} | {note}")

                i += 1
                if i < total:
                    time.sleep(args.delay)
        except KeyboardInterrupt:
            stopped = True
            print("\nDihentikan pengguna (Ctrl+C).")

    print(f"\n{'Dihentikan' if stopped else 'Selesai'}. Berhasil: {ok_n} | Dilewati: {skip_n} | "
          f"Gagal: {fail_n} | Belum diproses: {total - i} | Log: {log_path}")
    if fail_n:
        print(f"Ulangi yang gagal: python fasih_bulk.py {args.action} --failed-from {log_path} --period {args.period}")


def interactive_argv():
    """Mode klik-dua-kali: tanya langkah demi langkah, lalu kembalikan argumen untuk main()."""
    os.chdir(Path(__file__).resolve().parent)  # cookie.txt, data, dan log memakai folder skrip ini
    print("=== FASIH Bulk - Pengawas/PML ===\n")
    print("Aksi:  1) Cek status   2) Reject   3) Approve   4) Revoke")
    choice = input("Pilih aksi [Enter = 2 Reject]: ").strip() or "2"
    action = {"1": "cek", "2": "reject", "3": "approve", "4": "revoke"}.get(choice)
    if not action:
        sys.exit("Pilihan tidak valid.")

    found = next((n for n in ("data.xlsx", "data.csv", "data.txt") if Path(n).exists()), None)
    prompt = f"File daftar ID [Enter = {found}]: " if found else "File daftar ID (mis. data.xlsx): "
    fname = input(prompt).strip().strip('"') or found
    if not fname:
        sys.exit("File daftar ID belum ditentukan. Taruh data.xlsx di folder yang sama dengan skrip ini.")
    if not Path(fname).exists():
        sys.exit(f"File '{fname}' tidak ditemukan di folder {Path.cwd()}")

    period = input(f"Survey Period ID [Enter = {DEFAULT_PERIOD}]: ").strip() or DEFAULT_PERIOD
    argv = [action, fname, "--period", period]
    if action != "cek" and input("Mode uji coba tanpa mengirim apa pun (dry-run)? [y/N]: ").strip().lower() == "y":
        argv.append("--dry-run")
    print()
    return argv


if __name__ == "__main__":
    if len(sys.argv) == 1:  # diklik dua kali / dijalankan tanpa argumen
        try:
            main(interactive_argv())
        except SystemExit as e:
            if isinstance(e.code, str):
                print(e.code)
        except Exception:
            traceback.print_exc()
        input("\nTekan Enter untuk menutup jendela ini...")
    else:
        main()
