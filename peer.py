# peer_secure_final.py — Secure P2P  |  v5  (correct passphrase gate + UI)
#
# .enc file layout:
#   [0:16]   salt  (PBKDF2)
#   [16:28]  main_nonce (AES-GCM for the whole file)
#   [28:40]  probe_nonce (12 bytes, independent nonce for probe block)
#   [40:65]  probe_ct   (AESGCM.encrypt(probe_nonce, b"p2p_ok_v1", None) = 25 bytes)
#   [65:]    main_ct    (AESGCM.encrypt(main_nonce, plaintext, None))
#
# The probe block lets us verify the passphrase using ONLY the first 65 bytes
# without downloading the full file. AES-GCM authentication works on the
# complete probe unit, so wrong keys always raise an exception.
#
import socket
import ssl
import threading
import os
import json
import time
import hmac
import hashlib
import secrets
import struct
import shutil
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

# ─── NETWORK CONFIG ──────────────────────────────────────────────────────────
TRACKER_IP   = "192.168.198.161"       # ← change to your tracker's IP
TRACKER_PORT = 5000
CHUNK_SIZE   = 65536

# ─── SECURITY CONFIG ─────────────────────────────────────────────────────────
SHARED_SECRET = b"p2p_secret_key_change_me"   # Must match tracker_secure.py
PEER_ID       = secrets.token_hex(8)
TLS_CERT_FILE = "peer_cert.pem"
TLS_KEY_FILE  = "peer_key.pem"

PROBE_MAGIC        = b"p2p_ok_v1"   # 9 bytes; encrypted in probe block
PROBE_NONCE_OFFSET = 28             # [28:40] probe nonce (12 bytes)
PROBE_CT_OFFSET    = 40             # [40:65] probe ciphertext+tag (25 bytes)
PROBE_END          = 65             # total header bytes needed for validation
# ─────────────────────────────────────────────────────────────────────────────

progress_lock    = threading.Lock()
total_downloaded = 0
chunk_status     = {}
peer_speeds      = {}
upload_limit_bps = [0]
session_token    = [None]

os.makedirs("shared_files", exist_ok=True)
os.makedirs("downloads",    exist_ok=True)


# ═════════════════════════════════════════════════════════════════════════════
#  THEME PALETTES
# ═════════════════════════════════════════════════════════════════════════════
DARK = {
    "bg":        "#0f0f17",
    "bg2":       "#1a1a28",
    "bg3":       "#252538",
    "bg4":       "#32324a",
    "fg":        "#e2e8f4",
    "fg2":       "#9aa0b8",
    "accent":    "#7c6af7",
    "accent_d":  "#5a48d4",
    "green":     "#4ade80",
    "red":       "#f87171",
    "separator": "#2e2e46",
    "log_err":   "#f87171",
    "log_ok":    "#4ade80",
    "log_info":  "#60a5fa",
    "log_dim":   "#55576e",
}
LIGHT = {
    "bg":        "#f0f0f8",
    "bg2":       "#ffffff",
    "bg3":       "#eaeaf5",
    "bg4":       "#d8d8ec",
    "fg":        "#18181e",
    "fg2":       "#44445e",
    "accent":    "#5e35b1",
    "accent_d":  "#4527a0",
    "green":     "#15803d",
    "red":       "#b91c1c",
    "separator": "#d0d0e0",
    "log_err":   "#b91c1c",
    "log_ok":    "#15803d",
    "log_info":  "#1d4ed8",
    "log_dim":   "#888899",
}
current_theme = [DARK]
all_themeable = []


# ═════════════════════════════════════════════════════════════════════════════
#  PASSPHRASE POPUP
# ═════════════════════════════════════════════════════════════════════════════

def ask_decrypt_passphrase(filename, error_msg=""):
    """Modal dialog. Returns passphrase string or None if cancelled."""
    result = [None]
    T = current_theme[0]

    dialog = tk.Toplevel(root)
    dialog.title("AES-256 Decryption")
    dialog.resizable(False, False)
    dialog.configure(bg=T["bg2"])
    dialog.grab_set()
    dialog.focus_force()

    # Header
    hdr = tk.Frame(dialog, bg=T["accent"], pady=16)
    hdr.pack(fill=tk.X)
    tk.Label(hdr, text="🔐  AES-256 Decryption Required",
             bg=T["accent"], fg="#ffffff",
             font=("Helvetica", 13, "bold")).pack()

    # Body
    body = tk.Frame(dialog, bg=T["bg2"], padx=28, pady=16)
    body.pack(fill=tk.BOTH, expand=True)

    chip = tk.Frame(body, bg=T["bg3"], padx=10, pady=6)
    chip.pack(fill=tk.X, pady=(0, 14))
    tk.Label(chip, text="📄  " + filename,
             bg=T["bg3"], fg=T["fg2"],
             font=("Helvetica", 9), anchor="w").pack(fill=tk.X)

    tk.Label(body,
             text="Enter the passphrase used when this file was shared:",
             bg=T["bg2"], fg=T["fg"],
             font=("Helvetica", 10), justify="left", anchor="w"
             ).pack(fill=tk.X, pady=(0, 8))

    pp_var   = tk.StringVar()
    pp_entry = tk.Entry(body, textvariable=pp_var, show="*",
                        font=("Helvetica", 12),
                        bg=T["bg3"], fg=T["fg"],
                        insertbackground=T["fg"],
                        relief="flat",
                        highlightthickness=2,
                        highlightbackground=T["separator"],
                        highlightcolor=T["accent"],
                        width=36)
    pp_entry.pack(fill=tk.X, ipady=9, pady=(0, 6))
    pp_entry.focus_set()

    show_var = tk.BooleanVar(value=False)
    def toggle_show():
        pp_entry.config(show="" if show_var.get() else "*")
    tk.Checkbutton(body, text="Show passphrase",
                   variable=show_var, command=toggle_show,
                   bg=T["bg2"], fg=T["fg2"], selectcolor=T["bg3"],
                   activebackground=T["bg2"], activeforeground=T["fg"],
                   font=("Helvetica", 9), relief="flat", bd=0,
                   cursor="hand2").pack(anchor="w")

    warn_lbl = tk.Label(body, text=error_msg,
                        bg=T["bg2"], fg=T["red"],
                        font=("Helvetica", 9, "bold"), anchor="w")
    warn_lbl.pack(fill=tk.X, pady=(10, 0))

    # Separator
    tk.Frame(dialog, bg=T["separator"], height=1).pack(fill=tk.X, pady=(10, 0))

    # Button row — packed with side=BOTTOM so it is ALWAYS visible
    btn_row = tk.Frame(dialog, bg=T["bg3"], padx=20, pady=14)
    btn_row.pack(fill=tk.X, side=tk.BOTTOM)

    def on_confirm():
        pp = pp_var.get().strip()
        if not pp:
            warn_lbl.config(text="⚠  Passphrase cannot be empty.")
            pp_entry.focus_set()
            return
        result[0] = pp
        dialog.destroy()

    def on_cancel():
        dialog.destroy()

    tk.Button(btn_row, text="Cancel", command=on_cancel,
              bg=T["bg2"], fg=T["fg"], relief="flat",
              font=("Helvetica", 10), padx=16, pady=8,
              highlightthickness=1,
              highlightbackground=T["separator"],
              cursor="hand2").pack(side=tk.LEFT)

    tk.Button(btn_row, text="✓  Decrypt & Download",
              command=on_confirm,
              bg=T["accent"], fg="#ffffff", relief="flat",
              font=("Helvetica", 10, "bold"), padx=16, pady=8,
              activebackground=T["accent_d"],
              activeforeground="#ffffff",
              cursor="hand2").pack(side=tk.RIGHT)

    dialog.bind("<Return>", lambda e: on_confirm())
    dialog.bind("<Escape>", lambda e: on_cancel())

    # Measure and centre after all widgets are packed
    dialog.minsize(480, 360)
    dialog.update_idletasks()
    dw = max(480, dialog.winfo_reqwidth())
    dh = max(360, dialog.winfo_reqheight())
    root.update_idletasks()
    rx = root.winfo_rootx() + (root.winfo_width()  - dw) // 2
    ry = root.winfo_rooty() + (root.winfo_height() - dh) // 2
    dialog.geometry(f"{dw}x{dh}+{rx}+{ry}")

    root.wait_window(dialog)
    return result[0]


# ═════════════════════════════════════════════════════════════════════════════
#  TLS CERTIFICATE
# ═════════════════════════════════════════════════════════════════════════════

def ensure_tls_certs():
    if os.path.exists(TLS_CERT_FILE) and os.path.exists(TLS_KEY_FILE):
        return
    log("[TLS] Generating self-signed certificate...")
    try:
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        import datetime
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = issuer = x509.Name(
            [x509.NameAttribute(NameOID.COMMON_NAME, u"p2p-peer")])
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject).issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.utcnow())
            .not_valid_after(datetime.datetime.utcnow()
                             + datetime.timedelta(days=365))
            .sign(key, hashes.SHA256())
        )
        with open(TLS_KEY_FILE, "wb") as f:
            f.write(key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption()))
        with open(TLS_CERT_FILE, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        log("[TLS] Certificate generated successfully.")
    except Exception as e:
        log(f"[TLS][ERROR] {e}")


# ═════════════════════════════════════════════════════════════════════════════
#  AES-256-GCM  ENCRYPT / DECRYPT  (with embedded probe block)
# ═════════════════════════════════════════════════════════════════════════════

def derive_key(passphrase: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32,
                     salt=salt, iterations=200_000)
    return kdf.derive(passphrase.encode())


def encrypt_file(filepath: str, passphrase: str) -> str:
    salt        = os.urandom(16)
    main_nonce  = os.urandom(12)
    probe_nonce = os.urandom(12)
    key         = derive_key(passphrase, salt)
    aes         = AESGCM(key)

    # Probe block: a tiny self-contained AES-GCM unit (no partial ciphertext)
    probe_ct = aes.encrypt(probe_nonce, PROBE_MAGIC, None)  # 9 + 16 = 25 bytes

    with open(filepath, "rb") as f:
        plaintext = f.read()
    main_ct = aes.encrypt(main_nonce, plaintext, None)

    enc_path = filepath + ".enc"
    with open(enc_path, "wb") as f:
        # Layout: salt(16) + main_nonce(12) + probe_nonce(12) + probe_ct(25) + main_ct
        f.write(salt + main_nonce + probe_nonce + probe_ct + main_ct)

    log(f"[AES] Encrypted -> {os.path.basename(enc_path)}")
    return enc_path


def verify_passphrase_from_header(header_bytes: bytes, passphrase: str) -> bool:
    """
    Checks passphrase against the first PROBE_END bytes only.
    Returns True if and only if the probe block decrypts to PROBE_MAGIC.
    This is a complete AES-GCM unit — works reliably for both right and wrong keys.
    """
    if len(header_bytes) < PROBE_END:
        return False
    try:
        salt        = header_bytes[0:16]
        probe_nonce = header_bytes[PROBE_NONCE_OFFSET:PROBE_CT_OFFSET]   # [28:40]
        probe_ct    = header_bytes[PROBE_CT_OFFSET:PROBE_END]             # [40:65]
        key         = derive_key(passphrase, salt)
        decrypted   = AESGCM(key).decrypt(probe_nonce, probe_ct, None)
        return decrypted == PROBE_MAGIC
    except Exception:
        return False


def decrypt_file(enc_path: str, passphrase: str) -> tuple:
    """Returns (success: bool, out_path: str). Deletes .enc on success."""
    try:
        with open(enc_path, "rb") as f:
            raw = f.read()
        salt       = raw[0:16]
        main_nonce = raw[16:28]
        main_ct    = raw[PROBE_END:]      # skip the 65-byte header (probe included)
        key        = derive_key(passphrase, salt)
        plaintext  = AESGCM(key).decrypt(main_nonce, main_ct, None)
        out_path   = enc_path.replace(".enc", "")
        with open(out_path, "wb") as f:
            f.write(plaintext)
        os.remove(enc_path)
        log(f"[AES] Decrypted -> {os.path.basename(out_path)}")
        return True, out_path
    except Exception:
        return False, enc_path


# ═════════════════════════════════════════════════════════════════════════════
#  HMAC AUTH + SESSION TOKEN
# ═════════════════════════════════════════════════════════════════════════════

def generate_hmac_token(peer_id: str, timestamp: int) -> str:
    msg = f"{peer_id}:{timestamp}".encode()
    return hmac.new(SHARED_SECRET, msg, hashlib.sha256).hexdigest()


def authenticate_with_tracker():
    ts    = int(time.time())
    token = generate_hmac_token(PEER_ID, ts)
    msg   = json.dumps({"type": "auth", "peer_id": PEER_ID,
                        "token": token, "timestamp": ts})
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((TRACKER_IP, TRACKER_PORT))
        s.send(msg.encode())
        resp = json.loads(s.recv(4096).decode())
        s.close()
        if resp.get("status") == "ok":
            session_token[0] = resp["session_token"]
            log("[AUTH] Authenticated - session token obtained.")
            root.after(0, lambda: auth_indicator.config(
                text="● Authenticated", fg=current_theme[0]["green"]))
            return True
        log(f"[AUTH][ERROR] {resp.get('message')}")
        root.after(0, lambda: auth_indicator.config(
            text="● Auth failed", fg=current_theme[0]["red"]))
        return False
    except Exception as e:
        log(f"[AUTH][ERROR] {e}")
        root.after(0, lambda: auth_indicator.config(
            text="● Auth failed", fg=current_theme[0]["red"]))
        return False


def tracker_request(payload: dict) -> dict:
    if not session_token[0]:
        if not authenticate_with_tracker():
            return {"status": "error", "message": "Not authenticated"}
    payload["session_token"] = session_token[0]
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((TRACKER_IP, TRACKER_PORT))
        s.send(json.dumps(payload).encode())
        resp = json.loads(s.recv(8192).decode())
        s.close()
        if (resp.get("status") == "error"
                and "session" in resp.get("message", "")):
            session_token[0] = None
            if authenticate_with_tracker():
                payload["session_token"] = session_token[0]
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.connect((TRACKER_IP, TRACKER_PORT))
                s.send(json.dumps(payload).encode())
                resp = json.loads(s.recv(8192).decode())
                s.close()
        return resp
    except Exception as e:
        log(f"[TRACKER][ERROR] {e}")
        return {"status": "error", "message": str(e)}


# ═════════════════════════════════════════════════════════════════════════════
#  NETWORK HELPERS
# ═════════════════════════════════════════════════════════════════════════════

def get_my_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    ip = s.getsockname()[0]
    s.close()
    return ip


def chunk_hash(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# ═════════════════════════════════════════════════════════════════════════════
#  TRACKER ACTIONS
# ═════════════════════════════════════════════════════════════════════════════

def register_file(filename, peer_port):
    filepath = f"shared_files/{filename}"
    if not os.path.exists(filepath):
        log(f"[ERROR] File not found: {filepath}")
        return
    filesize = os.path.getsize(filepath)
    resp = tracker_request({
        "type": "register", "filename": filename,
        "ip": get_my_ip(), "port": peer_port,
        "filesize": filesize, "peer_id": PEER_ID
    })
    log(f"[REGISTER] {resp.get('message', resp)}")


def get_peers(filename):
    resp = tracker_request({"type": "get_peers", "filename": filename})
    if resp.get("status") == "ok":
        return resp.get("peers", [])
    log(f"[ERROR] get_peers: {resp.get('message')}")
    return []


def list_available_files():
    resp = tracker_request({"type": "list_files"})
    if resp.get("status") != "ok":
        log(f"[ERROR] list_files: {resp.get('message')}")
        return
    files = resp.get("files", [])
    file_list_box.delete(0, tk.END)
    log("=== Available Files ===")
    for f in files:
        size_mb = f["filesize"] / (1024 * 1024)
        entry   = f"{f['filename']}  |  {size_mb:.2f} MB  |  {f['peers']} peer(s)"
        log(entry)
        file_list_box.insert(tk.END, entry)


# ═════════════════════════════════════════════════════════════════════════════
#  TLS SSL CONTEXTS
# ═════════════════════════════════════════════════════════════════════════════

def get_server_ssl_ctx():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(TLS_CERT_FILE, TLS_KEY_FILE)
    return ctx


def get_client_ssl_ctx():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode    = ssl.CERT_NONE
    return ctx


# ═════════════════════════════════════════════════════════════════════════════
#  HEADER FETCH  (for passphrase pre-check — only first 65 bytes)
# ═════════════════════════════════════════════════════════════════════════════

def fetch_header_bytes(peer, filename) -> bytes:
    ip, port = peer[0], peer[1]
    try:
        raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw_sock.settimeout(10)
        conn = get_client_ssl_ctx().wrap_socket(raw_sock, server_hostname=ip)
        conn.connect((ip, port))
        req = json.dumps({"filename": filename, "start": 0,
                          "end": PROBE_END, "peer_id": PEER_ID}).encode()
        conn.send(struct.pack("!I", len(req)) + req)
        buf = b""
        while len(buf) < PROBE_END:
            chunk = conn.recv(PROBE_END - len(buf))
            if not chunk:
                break
            buf += chunk
        conn.close()
        return buf
    except Exception as e:
        log(f"[PRE-CHECK][ERROR] {e}")
        return b""


# ═════════════════════════════════════════════════════════════════════════════
#  DOWNLOAD — chunk worker
# ═════════════════════════════════════════════════════════════════════════════

def download_chunk(peer, filename, start, end, output_file,
                   filesize, chunk_index, max_retries=3):
    global total_downloaded
    ip, port = peer[0], peer[1]

    chunk_status[chunk_index] = {"peer": ip, "done": False}
    root.after(0, update_chunk_map)

    conn = None
    for attempt in range(1, max_retries + 1):
        try:
            raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            raw_sock.settimeout(15)
            conn = get_client_ssl_ctx().wrap_socket(raw_sock, server_hostname=ip)
            conn.connect((ip, port))
            break
        except Exception as e:
            log(f"[CHUNK] {ip}:{port} attempt {attempt} failed: {e}")
            if attempt == max_retries:
                root.after(0, lambda i=ip: update_peer_health(i, "dead"))
                return
            time.sleep(1)

    root.after(0, lambda i=ip: update_peer_health(i, "active"))
    log(f"[CHUNK] Bytes {start}-{end} from {ip}:{port} (TLS)")

    req = json.dumps({"filename": filename, "start": start,
                      "end": end, "peer_id": PEER_ID}).encode()
    conn.send(struct.pack("!I", len(req)) + req)

    t0          = time.time()
    chunk_bytes = bytearray()
    remaining   = end - start

    while remaining > 0:
        data = conn.recv(min(CHUNK_SIZE, remaining))
        if not data:
            break
        chunk_bytes += data
        remaining   -= len(data)
        with progress_lock:
            total_downloaded += len(data)
            pct = (total_downloaded / filesize) * 100
        root.after(0, lambda p=pct: (
            progress_bar.__setitem__("value", p),
            progress_label.config(text=f"{p:.1f}%")
        ))

    conn.close()
    log(f"[INTEGRITY] Chunk {chunk_index} SHA-256: "
        f"{chunk_hash(bytes(chunk_bytes))[:16]}...")

    with open(output_file, "r+b") as f:
        f.seek(start)
        f.write(chunk_bytes)

    elapsed = time.time() - t0
    if elapsed > 0:
        speed = (len(chunk_bytes) / (1024 * 1024)) / elapsed
        peer_speeds.setdefault(ip, []).append(speed)
        root.after(0, update_speed_graph)
        root.after(0, lambda i=ip: update_peer_health(i, "done"))

    chunk_status[chunk_index] = {"peer": ip, "done": True}
    root.after(0, update_chunk_map)


# ═════════════════════════════════════════════════════════════════════════════
#  DOWNLOAD ORCHESTRATOR
#
#  .enc flow:
#   1. Show passphrase popup (blocking, nothing downloaded yet)
#   2. Fetch only first 65 bytes from peer (no file written)
#   3. verify_passphrase_from_header()
#      WRONG  -> error shown in the SAME popup, user retries (max 3x)
#      RIGHT  -> proceed with full download + auto-decrypt
#      Cancel -> nothing happens at all
# ═════════════════════════════════════════════════════════════════════════════

def multi_source_download(filename):
    global total_downloaded

    peers_list = get_peers(filename)
    if not peers_list:
        log("[ERROR] No peers found.")
        return

    passphrase = None

    if filename.endswith(".enc"):
        error_msg = ""
        max_tries = 3

        for attempt in range(1, max_tries + 1):
            pp_holder  = [None]
            done_event = threading.Event()

            def show_dialog(err=error_msg):
                pp_holder[0] = ask_decrypt_passphrase(filename, error_msg=err)
                done_event.set()

            root.after(0, show_dialog)
            done_event.wait()

            pp = pp_holder[0]
            if pp is None:
                log("[DOWNLOAD] Cancelled - nothing downloaded.")
                return

            # Verify passphrase using only the first 65 bytes (no download yet)
            log(f"[AES] Verifying passphrase (attempt {attempt}/{max_tries})...")
            header = fetch_header_bytes(peers_list[0], filename)

            if len(header) < PROBE_END:
                error_msg = "Could not reach peer. Check connection."
                log(f"[AES][ERROR] {error_msg}")
                continue

            if verify_passphrase_from_header(header, pp):
                passphrase = pp
                log("[AES] Passphrase correct - starting download.")
                break
            else:
                remaining_tries = max_tries - attempt
                if remaining_tries > 0:
                    error_msg = (
                        f"Wrong passphrase - "
                        f"{remaining_tries} attempt"
                        f"{'s' if remaining_tries > 1 else ''} left."
                    )
                    log(f"[AES][ERROR] Wrong passphrase "
                        f"(attempt {attempt}/{max_tries}).")
                else:
                    log("[AES][ERROR] Wrong passphrase 3 times - download aborted. Nothing saved.")
                    root.after(0, lambda: messagebox.showerror(
                        "Wrong Passphrase",
                        "The passphrase was incorrect 3 times.\n\n"
                        "Download aborted — nothing was saved to disk."
                    ))
                    return

    # Only reaches here with a verified passphrase (or unencrypted file)
    total_downloaded = 0
    chunk_status.clear()
    peer_speeds.clear()
    root.after(0, lambda: progress_bar.__setitem__("value", 0))
    root.after(0, lambda: progress_label.config(text="0%"))
    root.after(0, lambda: integrity_label.config(
        text="", bg=current_theme[0]["bg2"]))

    filesize   = peers_list[0][2]
    num_peers  = len(peers_list)
    chunk_size = filesize // num_peers
    out_path   = f"downloads/{filename}"

    with open(out_path, "wb") as f:
        f.truncate(filesize)

    log(f"[DOWNLOAD] {filename} ({filesize/(1024*1024):.2f} MB) "
        f"from {num_peers} peer(s) via TLS")

    t0      = time.time()
    threads = []
    for i, peer in enumerate(peers_list):
        s = i * chunk_size
        e = filesize if i == num_peers - 1 else (i + 1) * chunk_size
        t = threading.Thread(target=download_chunk,
                             args=(peer, filename, s, e,
                                   out_path, filesize, i),
                             daemon=True)
        threads.append(t)
        t.start()
    for t in threads:
        t.join()

    elapsed = time.time() - t0
    speed   = (filesize / (1024 * 1024)) / (elapsed or 0.001)
    log(f"[DONE] {elapsed:.2f}s | {speed:.2f} MB/s avg")

    if filename.endswith(".enc") and passphrase:
        success, final_path = decrypt_file(out_path, passphrase)
        if success:
            verify_integrity(final_path)
        else:
            log("[AES][ERROR] Decryption failed after download - file kept as .enc")
            root.after(0, lambda: messagebox.showerror(
                "Decryption Error",
                "The file could not be decrypted after download.\n"
                "The .enc file is saved in downloads/ for retry."))
    else:
        verify_integrity(out_path)


def verify_integrity(filepath):
    sha = hashlib.sha256()
    with open(filepath, "rb") as f:
        for blk in iter(lambda: f.read(65536), b""):
            sha.update(blk)
    digest = sha.hexdigest()
    log(f"[INTEGRITY] File SHA-256: {digest}")
    root.after(0, lambda: integrity_label.config(
        text=f"SHA-256: {digest[:32]}...",
        bg="#14532d", fg="#86efac"
    ))


# ═════════════════════════════════════════════════════════════════════════════
#  PEER SERVER  (TLS)
# ═════════════════════════════════════════════════════════════════════════════

def serve_files(peer_port):
    ensure_tls_certs()
    raw_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    raw_server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    raw_server.bind(("0.0.0.0", peer_port))
    raw_server.listen()
    ssl_ctx = get_server_ssl_ctx()
    server  = ssl_ctx.wrap_socket(raw_server, server_side=True)
    log(f"[SERVER] TLS server listening on port {peer_port}")
    while True:
        try:
            conn, addr = server.accept()
            threading.Thread(target=handle_request,
                             args=(conn, addr), daemon=True).start()
        except Exception as e:
            log(f"[SERVER][ERROR] {e}")


def handle_request(conn, addr):
    try:
        raw_len = conn.recv(4)
        if not raw_len:
            return
        msg_len = struct.unpack("!I", raw_len)[0]
        data    = b""
        while len(data) < msg_len:
            data += conn.recv(msg_len - len(data))
        request  = json.loads(data.decode())
        filename = request["filename"]
        start    = request["start"]
        end      = request["end"]
        filepath = f"shared_files/{filename}"
        if not os.path.exists(filepath):
            conn.close()
            return
        log(f"[SERVE] Bytes {start}-{end} -> {addr[0]} (TLS)")
        with open(filepath, "rb") as f:
            f.seek(start)
            remaining = end - start
            while remaining > 0:
                chunk = f.read(min(CHUNK_SIZE, remaining))
                if not chunk:
                    break
                conn.send(chunk)
                remaining -= len(chunk)
                limit = upload_limit_bps[0]
                if limit > 0:
                    time.sleep(len(chunk) / limit)
    except Exception as e:
        log(f"[SERVE][ERROR] {e}")
    finally:
        conn.close()


# ═════════════════════════════════════════════════════════════════════════════
#  VISUAL HELPERS
# ═════════════════════════════════════════════════════════════════════════════

def update_peer_health(ip, status):
    color_map = {"active": "#22c55e", "done": "#16a34a",
                 "dead":   "#ef4444", "slow": "#f59e0b"}
    color = color_map.get(status, "#6b7280")
    short = ip.split(".")[-1]
    for w in peer_health_frame.winfo_children():
        if w.cget("text").startswith("." + short):
            w.config(bg=color)
            return
    tk.Label(peer_health_frame,
             text=f".{short}  {status}",
             bg=color, fg="white",
             font=("Helvetica", 8, "bold"),
             padx=8, pady=4, relief="flat").pack(side=tk.LEFT, padx=(0, 4))


def update_chunk_map():
    chunk_canvas.delete("all")
    total = len(chunk_status)
    if not total:
        return
    w     = chunk_canvas.winfo_width() or 700
    bar_w = max(3, w // total)
    for i, (_, info) in enumerate(sorted(chunk_status.items())):
        color = "#22c55e" if info["done"] else "#3b82f6"
        x0    = i * bar_w
        chunk_canvas.create_rectangle(x0, 0, x0 + bar_w - 1, 16,
                                      fill=color, outline="")


def update_speed_graph():
    T = current_theme[0]
    speed_canvas.delete("all")
    w       = speed_canvas.winfo_width() or 700
    h       = 50
    palette = ["#3b82f6", "#f97316", "#a855f7", "#14b8a6", "#ef4444"]
    all_s   = [s for samples in peer_speeds.values() for s in samples]
    if not all_s:
        return
    max_s = max(all_s) or 1
    for idx, (ip, samples) in enumerate(peer_speeds.items()):
        if len(samples) < 2:
            continue
        color = palette[idx % len(palette)]
        step  = w / max(len(samples) - 1, 1)
        pts   = [(j * step, h - (s / max_s) * (h - 4))
                 for j, s in enumerate(samples)]
        for j in range(len(pts) - 1):
            speed_canvas.create_line(*pts[j], *pts[j + 1],
                                     fill=color, width=2)
    speed_canvas.create_text(6, 4, anchor="nw",
                             text=f"max {max_s:.1f} MB/s",
                             font=("Helvetica", 8), fill=T["fg2"])


# ═════════════════════════════════════════════════════════════════════════════
#  LOG  (colour-coded)
# ═════════════════════════════════════════════════════════════════════════════

def log(message):
    T  = current_theme[0]
    ts = time.strftime("%H:%M:%S")
    activity_box.config(state=tk.NORMAL)
    line_start = activity_box.index("end-1c linestart")
    activity_box.insert(tk.END, f"[{ts}] {message}\n")
    line_end = activity_box.index("end-1c")
    msg_l = message.lower()
    if any(x in msg_l for x in ("[error]", "wrong pass", "failed",
                                 "abort", "incorrect", "3 times")):
        tag = "err"
    elif any(x in msg_l for x in ("[done]", "[integrity]", "decrypted",
                                   "correct", "verified", "generated",
                                   "registered", "sha-256")):
        tag = "ok"
    elif any(x in msg_l for x in ("[auth]", "[tls]", "[register]", "[aes]",
                                   "available", "[init]", "[note]",
                                   "[download]", "[server]")):
        tag = "info"
    else:
        tag = "dim"
    activity_box.tag_add(tag, line_start, line_end)
    activity_box.tag_config("err",  foreground=T["log_err"])
    activity_box.tag_config("ok",   foreground=T["log_ok"])
    activity_box.tag_config("info", foreground=T["log_info"])
    activity_box.tag_config("dim",  foreground=T["log_dim"])
    activity_box.see(tk.END)


# ═════════════════════════════════════════════════════════════════════════════
#  GUI ACTIONS
# ═════════════════════════════════════════════════════════════════════════════

def start_peer():
    try:
        port = int(port_entry.get())
        ensure_tls_certs()
        threading.Thread(target=serve_files, args=(port,), daemon=True).start()
        log(f"[SERVER] TLS server started on port {port}")
    except ValueError:
        messagebox.showerror("Error", "Enter a valid port number.")


def gui_authenticate():
    threading.Thread(target=authenticate_with_tracker, daemon=True).start()


def gui_register():
    filename   = file_entry.get().strip()
    port_str   = port_entry.get().strip()
    passphrase = passphrase_entry.get().strip()
    if not filename or not port_str:
        messagebox.showerror("Error", "Fill in both Filename and Port.")
        return
    try:
        port = int(port_str)
    except ValueError:
        messagebox.showerror("Error", "Invalid port number.")
        return

    def task():
        fp = f"shared_files/{filename}"
        if passphrase and not filename.endswith(".enc"):
            enc      = encrypt_file(fp, passphrase)
            enc_name = os.path.basename(enc)
            register_file(enc_name, port)
            root.after(0, lambda: (
                file_entry.delete(0, tk.END),
                file_entry.insert(0, enc_name)
            ))
        else:
            register_file(filename, port)

    threading.Thread(target=task, daemon=True).start()


def gui_download():
    filename = file_entry.get().strip()
    if not filename:
        messagebox.showerror("Error", "Enter or select a filename.")
        return
    threading.Thread(target=multi_source_download,
                     args=(filename,), daemon=True).start()


def browse_and_copy():
    filepath = filedialog.askopenfilename(title="Select file to share")
    if not filepath:
        return
    filename = os.path.basename(filepath)
    dest = f"shared_files/{filename}"
    if not os.path.exists(dest):
        shutil.copy(filepath, dest)
        log(f"[BROWSE] Copied {filename} -> shared_files/")
    file_entry.delete(0, tk.END)
    file_entry.insert(0, filename)


def on_file_select(event):
    sel = file_list_box.curselection()
    if sel:
        fname = file_list_box.get(sel[0]).split("|")[0].strip()
        file_entry.delete(0, tk.END)
        file_entry.insert(0, fname)


def on_throttle_change(val):
    mb = float(val)
    upload_limit_bps[0] = int(mb * 1024 * 1024) if mb > 0 else 0
    throttle_label.config(
        text=f"Upload: {'unlimited' if mb == 0 else f'{mb:.1f} MB/s'}")


# ═════════════════════════════════════════════════════════════════════════════
#  THEME ENGINE
# ═════════════════════════════════════════════════════════════════════════════

def apply_theme(T):
    root.configure(bg=T["bg"])
    style.configure("TProgressbar",
                    troughcolor=T["bg4"], background=T["accent"], thickness=14)
    style.configure("Vertical.TScrollbar",
                    background=T["bg4"], troughcolor=T["bg3"],
                    arrowcolor=T["fg2"])
    for (w, role) in all_themeable:
        try:
            if role == "bg":
                w.configure(bg=T["bg"])
            elif role in ("bg2", "card"):
                w.configure(bg=T["bg2"])
            elif role == "bg3":
                w.configure(bg=T["bg3"])
            elif role == "label":
                w.configure(bg=T["bg2"], fg=T["fg"])
            elif role == "label2":
                w.configure(bg=T["bg2"], fg=T["fg2"])
            elif role == "entry":
                w.configure(bg=T["bg3"], fg=T["fg"],
                            insertbackground=T["fg"],
                            highlightbackground=T["separator"],
                            highlightcolor=T["accent"])
            elif role == "listbox":
                w.configure(bg=T["bg3"], fg=T["fg"],
                            selectbackground=T["accent"])
            elif role == "text":
                w.configure(bg=T["bg3"], fg=T["fg"])
            elif role == "canvas":
                w.configure(bg=T["bg3"])
            elif role == "scale":
                w.configure(bg=T["bg2"], fg=T["fg"],
                            troughcolor=T["bg4"])
            elif role == "sep":
                w.configure(bg=T["separator"])
        except Exception:
            pass
    auth_indicator.configure(bg=T["bg2"])
    integrity_label.configure(bg=T["bg2"])
    peer_health_frame.configure(bg=T["bg2"])
    top_block.configure(bg=T["bg"])
    log_block.configure(bg=T["bg"])


def toggle_theme():
    if current_theme[0] is DARK:
        current_theme[0] = LIGHT
        theme_btn.config(text="Light", bg=LIGHT["bg4"], fg=LIGHT["fg"])
    else:
        current_theme[0] = DARK
        theme_btn.config(text="Dark", bg="#3a3a5c", fg=DARK["fg"])
    apply_theme(current_theme[0])


# ═════════════════════════════════════════════════════════════════════════════
#  WIDGET FACTORY HELPERS
# ═════════════════════════════════════════════════════════════════════════════

def mk_label(parent, text, role="label", font=("Helvetica", 10), **kw):
    T  = current_theme[0]
    fg = T["fg"] if role == "label" else T["fg2"]
    w  = tk.Label(parent, text=text, bg=T["bg2"], fg=fg, font=font, **kw)
    all_themeable.append((w, role))
    return w


def mk_entry(parent, width=20, show="", **kw):
    T = current_theme[0]
    w = tk.Entry(parent, bg=T["bg3"], fg=T["fg"],
                 insertbackground=T["fg"], relief="flat",
                 font=("Helvetica", 10), width=width, show=show,
                 highlightthickness=1,
                 highlightbackground=T["separator"],
                 highlightcolor=T["accent"], **kw)
    all_themeable.append((w, "entry"))
    return w


def mk_btn(parent, text, cmd, color=None, fgc="#ffffff", small=False):
    T    = current_theme[0]
    c    = color or T["accent"]
    size = 9 if small else 10
    w    = tk.Button(parent, text=text, command=cmd,
                     bg=c, fg=fgc, relief="flat",
                     padx=10, pady=4 if small else 7,
                     font=("Helvetica", size, "bold"),
                     activebackground=c, activeforeground=fgc,
                     cursor="hand2")
    return w


def mk_frame(parent, role="bg2", **kw):
    T  = current_theme[0]
    bg = {"bg": T["bg"], "bg2": T["bg2"], "bg3": T["bg3"],
          "card": T["bg2"]}.get(role, T["bg2"])
    w  = tk.Frame(parent, bg=bg, **kw)
    all_themeable.append((w, role))
    return w


def mk_sep(parent, vertical=False):
    T = current_theme[0]
    w = (tk.Frame(parent, bg=T["separator"], width=1)
         if vertical else
         tk.Frame(parent, bg=T["separator"], height=1))
    all_themeable.append((w, "sep"))
    return w


# ═════════════════════════════════════════════════════════════════════════════
#  MAIN WINDOW
#  root grid:
#    row 0 (weight=0) — all fixed-height controls
#    row 1 (weight=1) — activity log, always visible, fills remaining space
# ═════════════════════════════════════════════════════════════════════════════

root = tk.Tk()
root.title("P2P Secure File Sharing")
root.geometry("860x860")
root.configure(bg=DARK["bg"])
root.minsize(740, 680)

root.rowconfigure(0, weight=0)
root.rowconfigure(1, weight=1)
root.columnconfigure(0, weight=1)

style = ttk.Style()
style.theme_use("clam")
style.configure("TProgressbar",
                troughcolor=DARK["bg4"], background=DARK["accent"], thickness=14)
style.configure("Vertical.TScrollbar",
                background=DARK["bg4"], troughcolor=DARK["bg3"],
                arrowcolor=DARK["fg2"])

T = current_theme[0]


# ─── TOP BLOCK ───────────────────────────────────────────────────────────────
top_block = tk.Frame(root, bg=T["bg"])
top_block.grid(row=0, column=0, sticky="ew")
top_block.columnconfigure(0, weight=1)


def card(pady=(0, 5)):
    f = mk_frame(top_block, role="card")
    f.pack(fill=tk.X, padx=12, pady=pady)
    return f


def irow(parent):
    f = tk.Frame(parent, bg=T["bg2"])
    all_themeable.append((f, "bg2"))
    return f


# ── HEADER CARD ──────────────────────────────────────────────────────────────
hdr_card = card(pady=(10, 5))

# Left accent bar
accent_bar = tk.Frame(hdr_card, bg=T["accent"], width=5)
accent_bar.pack(side=tk.LEFT, fill=tk.Y)

tk.Label(hdr_card, text=" 🔒 P2P Secure File Sharing",
         bg=T["bg2"], fg=T["fg"],
         font=("Helvetica", 14, "bold")).pack(side=tk.LEFT, padx=12, pady=10)

# Right side: theme + badges
right = irow(hdr_card)
right.pack(side=tk.RIGHT, padx=8, pady=8)

theme_btn = tk.Button(right, text="Dark", command=toggle_theme,
                      bg="#3a3a5c", fg=DARK["fg"], relief="flat",
                      padx=10, pady=5, font=("Helvetica", 9, "bold"),
                      cursor="hand2")
theme_btn.pack(side=tk.RIGHT, padx=(8, 0))

for txt, col in [("TLS", "#1d4ed8"), ("AES-256", "#0f766e"),
                 ("HMAC", "#7c3aed"), ("Integrity", "#b45309"),
                 ("Rate Limit", "#991b1b")]:
    tk.Label(right, text=txt, bg=col, fg="#ffffff",
             font=("Helvetica", 7, "bold"),
             padx=6, pady=4).pack(side=tk.RIGHT, padx=(0, 3))

# ── AUTH CARD ────────────────────────────────────────────────────────────────
auth_card = card()
ar = irow(auth_card)
ar.pack(fill=tk.X, padx=12, pady=8)
mk_btn(ar, "Authenticate with Tracker",
       gui_authenticate, color="#0f766e").pack(side=tk.LEFT)
auth_indicator = tk.Label(ar, text="● Not authenticated",
                           bg=T["bg2"], fg=T["red"],
                           font=("Helvetica", 10, "bold"))
auth_indicator.pack(side=tk.LEFT, padx=12)

# ── CONFIG CARD ──────────────────────────────────────────────────────────────
cfg_card = card()

row_a = irow(cfg_card)
row_a.pack(fill=tk.X, padx=12, pady=(8, 4))
mk_label(row_a, "Port:", role="label").pack(side=tk.LEFT)
port_entry = mk_entry(row_a, width=7)
port_entry.insert(0, "6001")
port_entry.pack(side=tk.LEFT, padx=(4, 18), ipady=4)
mk_label(row_a, "Filename:", role="label").pack(side=tk.LEFT)
file_entry = mk_entry(row_a, width=38)
file_entry.pack(side=tk.LEFT, padx=(4, 8), ipady=4)
mk_btn(row_a, "Browse", browse_and_copy,
       color=T["bg4"], fgc=T["fg"], small=True).pack(side=tk.LEFT)

row_b = irow(cfg_card)
row_b.pack(fill=tk.X, padx=12, pady=(0, 8))
mk_label(row_b, "AES-256 Passphrase:", role="label").pack(side=tk.LEFT)
passphrase_entry = mk_entry(row_b, width=26, show="*")
passphrase_entry.pack(side=tk.LEFT, padx=(4, 10), ipady=4)
mk_label(row_b, "For sharing only  |  leave blank to skip encryption",
         role="label2", font=("Helvetica", 8)).pack(side=tk.LEFT)

# ── ACTION CARD ───────────────────────────────────────────────────────────────
act_card = card()
act_row  = irow(act_card)
act_row.pack(fill=tk.X, padx=12, pady=8)
mk_btn(act_row, "Start Peer Server", start_peer,
       "#1d4ed8").pack(side=tk.LEFT, padx=(0, 6))
mk_btn(act_row, "Register File",     gui_register,
       "#059669").pack(side=tk.LEFT, padx=(0, 6))
mk_btn(act_row, "Download File",     gui_download,
       T["accent"]).pack(side=tk.LEFT, padx=(0, 6))
mk_btn(act_row, "Refresh List",      list_available_files,
       "#b45309").pack(side=tk.LEFT)

# ── STATUS CARD ───────────────────────────────────────────────────────────────
status_card = card()
st_row = irow(status_card)
st_row.pack(fill=tk.X, padx=12, pady=(8, 4))

throttle_label = mk_label(st_row, "Upload: unlimited",
                           role="label2", font=("Helvetica", 9))
throttle_label.pack(side=tk.LEFT)
throttle_slider = tk.Scale(st_row, from_=0, to=10, resolution=0.5,
                            orient=tk.HORIZONTAL, command=on_throttle_change,
                            bg=T["bg2"], fg=T["fg"], troughcolor=T["bg4"],
                            highlightthickness=0, showvalue=0, length=120)
throttle_slider.pack(side=tk.LEFT, padx=(4, 12))
all_themeable.append((throttle_slider, "scale"))

mk_sep(st_row, vertical=True).pack(side=tk.LEFT, fill=tk.Y, pady=4, padx=6)
mk_label(st_row, "Progress:", role="label2",
         font=("Helvetica", 9)).pack(side=tk.LEFT, padx=(0, 6))
progress_bar = ttk.Progressbar(st_row, length=340, mode="determinate")
progress_bar.pack(side=tk.LEFT)
progress_label = mk_label(st_row, "0%",
                           font=("Helvetica", 10, "bold"), role="label")
progress_label.pack(side=tk.LEFT, padx=8)

integrity_label = tk.Label(status_card, text="",
                            bg=T["bg2"], fg="white",
                            font=("Helvetica", 9, "bold"),
                            padx=10, pady=3)
integrity_label.pack(pady=(0, 5))

# ── MONITORING CARD ───────────────────────────────────────────────────────────
mon_card = card()
mon      = irow(mon_card)
mon.pack(fill=tk.X, padx=12, pady=6)

# Peer status row
pr = tk.Frame(mon, bg=T["bg2"])
pr.pack(fill=tk.X, pady=(0, 4))
all_themeable.append((pr, "bg2"))
mk_label(pr, "Peer Status:", role="label2",
         font=("Helvetica", 9, "bold")).pack(side=tk.LEFT, padx=(0, 8))
peer_health_frame = tk.Frame(pr, bg=T["bg2"], height=30)
peer_health_frame.pack(side=tk.LEFT, fill=tk.X, expand=True)
all_themeable.append((peer_health_frame, "bg2"))

# Chunk map
mk_label(mon, "Chunk Map  (blue = downloading  |  green = done):",
         role="label2", font=("Helvetica", 8, "bold")).pack(anchor="w")
chunk_canvas = tk.Canvas(mon, height=16, bg=T["bg3"], highlightthickness=0)
chunk_canvas.pack(fill=tk.X, pady=(2, 5))
all_themeable.append((chunk_canvas, "canvas"))

# Speed graph
mk_label(mon, "Speed Graph  (MB/s per peer):",
         role="label2", font=("Helvetica", 8, "bold")).pack(anchor="w")
speed_canvas = tk.Canvas(mon, height=50, bg=T["bg3"], highlightthickness=0)
speed_canvas.pack(fill=tk.X, pady=(2, 5))
all_themeable.append((speed_canvas, "canvas"))

# File list
mk_label(mon, "Available Files  (click to select):",
         role="label2", font=("Helvetica", 9, "bold")).pack(anchor="w", pady=(4, 2))
file_list_box = tk.Listbox(mon, height=3,
                            bg=T["bg3"], fg=T["fg"],
                            font=("Helvetica", 9),
                            selectbackground=T["accent"],
                            relief="flat", highlightthickness=0,
                            activestyle="none")
file_list_box.pack(fill=tk.X)
file_list_box.bind("<<ListboxSelect>>", on_file_select)
all_themeable.append((file_list_box, "listbox"))


# ─── LOG BLOCK  (row 1 — expands to fill remaining window height) ─────────────
log_block = tk.Frame(root, bg=T["bg"])
log_block.grid(row=1, column=0, sticky="nsew", padx=12, pady=(0, 12))
log_block.rowconfigure(1, weight=1)
log_block.columnconfigure(0, weight=1)

# Log header bar
log_hdr = tk.Frame(log_block, bg=T["bg2"])
log_hdr.grid(row=0, column=0, columnspan=2, sticky="ew")
all_themeable.append((log_hdr, "bg2"))

mk_label(log_hdr, "  Activity Log",
         font=("Helvetica", 10, "bold"), role="label").pack(side=tk.LEFT, pady=6)

# Colour key legend
for txt, col in [("ERR", DARK["log_err"]), ("OK", DARK["log_ok"]),
                 ("INFO", DARK["log_info"]), ("DIM", DARK["log_dim"])]:
    kf = tk.Frame(log_hdr, bg=T["bg2"])
    kf.pack(side=tk.LEFT, padx=4)
    all_themeable.append((kf, "bg2"))
    tk.Label(kf, text="■", bg=T["bg2"], fg=col,
             font=("Helvetica", 9)).pack(side=tk.LEFT)
    tk.Label(kf, text=txt, bg=T["bg2"], fg=T["fg2"],
             font=("Helvetica", 8)).pack(side=tk.LEFT)


def clear_log():
    activity_box.config(state=tk.NORMAL)
    activity_box.delete("1.0", tk.END)


mk_btn(log_hdr, "Clear", clear_log,
       color=T["bg4"], fgc=T["fg2"], small=True).pack(
    side=tk.RIGHT, padx=8, pady=5)

# Text widget
activity_box = tk.Text(log_block, bg=T["bg3"], fg=T["fg"],
                        font=("Courier New", 9), relief="flat",
                        highlightthickness=1,
                        highlightbackground=T["separator"],
                        wrap=tk.WORD, state=tk.NORMAL,
                        padx=8, pady=6)
activity_box.grid(row=1, column=0, sticky="nsew")
all_themeable.append((activity_box, "text"))

# Scrollbar
log_sb = ttk.Scrollbar(log_block, orient=tk.VERTICAL,
                        command=activity_box.yview)
log_sb.grid(row=1, column=1, sticky="ns")
activity_box.configure(yscrollcommand=log_sb.set)


# ── Init messages ─────────────────────────────────────────────────────────────
log(f"[INIT] Peer ID  : {PEER_ID}")
log("[INIT] Step 1   : Click 'Authenticate with Tracker'")
log("[INIT] Step 2   : 'Start Peer Server' on your port  (e.g. 6001)")
log("[INIT] Step 3   : Browse -> set Passphrase -> 'Register File'  (to share)")
log("[INIT] Step 4   : Select from list -> 'Download File'  (to receive)")
log("[NOTE] .enc files: passphrase is verified BEFORE any download starts.")
log("[NOTE] Wrong passphrase = error in popup, nothing downloaded or saved.")

root.mainloop()
