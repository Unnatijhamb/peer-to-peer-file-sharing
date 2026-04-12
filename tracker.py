# tracker.py — Secure Enhanced Tracker
import socket
import threading
import json
import time
import hmac
import hashlib
import secrets
import os
from collections import defaultdict

HOST = "0.0.0.0"
PORT = 5000

# ─── SECURITY CONFIG ────────────────────────────────────────────────────────
SHARED_SECRET = b"p2p_secret_key_change_me"   # Must match peer.py
TOKEN_VALIDITY_WINDOW = 60                     # seconds; HMAC token expires after this
SESSION_TOKEN_TTL = 3600                       # session token valid for 1 hour
RATE_LIMIT_MAX = 20                            # max requests per window
RATE_LIMIT_WINDOW = 10                         # seconds
IP_WHITELIST_ENABLED = False                   # Set True and fill list to restrict
TRUSTED_IPS = ["127.0.0.1", "10.96.0.0/16"]   # used only if whitelist is enabled
# ────────────────────────────────────────────────────────────────────────────

peers = {}              # filename -> list of (ip, port, filesize, peer_id)
session_tokens = {}     # token -> {"ip": ..., "expires": timestamp}
rate_tracker = defaultdict(list)  # ip -> [timestamps of recent requests]
lock = threading.Lock()


# ════════════════════════════════════════════════════════════════════════════
#  SECURITY HELPERS
# ════════════════════════════════════════════════════════════════════════════

def generate_hmac_token(peer_id: str, timestamp: int) -> str:
    """Deterministic HMAC token from peer_id + timestamp + shared secret."""
    msg = f"{peer_id}:{timestamp}".encode()
    return hmac.new(SHARED_SECRET, msg, hashlib.sha256).hexdigest()


def verify_hmac_token(peer_id: str, token: str, timestamp: int) -> bool:
    """Accept token if within ±TOKEN_VALIDITY_WINDOW seconds of now."""
    now = int(time.time())
    for t in range(timestamp - TOKEN_VALIDITY_WINDOW, timestamp + TOKEN_VALIDITY_WINDOW + 1, 30):
        expected = generate_hmac_token(peer_id, t)
        if hmac.compare_digest(expected, token):
            return True
    return False


def issue_session_token(ip: str) -> str:
    token = secrets.token_hex(32)
    with lock:
        session_tokens[token] = {"ip": ip, "expires": time.time() + SESSION_TOKEN_TTL}
    return token


def validate_session_token(token: str, ip: str) -> bool:
    with lock:
        entry = session_tokens.get(token)
    if not entry:
        return False
    if entry["ip"] != ip:
        return False
    if time.time() > entry["expires"]:
        with lock:
            session_tokens.pop(token, None)
        return False
    return True


def is_rate_limited(ip: str) -> bool:
    now = time.time()
    with lock:
        timestamps = rate_tracker[ip]
        # Drop old entries
        rate_tracker[ip] = [t for t in timestamps if now - t < RATE_LIMIT_WINDOW]
        rate_tracker[ip].append(now)
        return len(rate_tracker[ip]) > RATE_LIMIT_MAX


def ip_allowed(ip: str) -> bool:
    if not IP_WHITELIST_ENABLED:
        return True
    if ip in TRUSTED_IPS:
        return True
    # Simple /16 subnet check
    for trusted in TRUSTED_IPS:
        if "/" in trusted:
            net, prefix = trusted.rsplit(".", 1)[0], int(trusted.split("/")[1])
            if prefix == 16 and ip.startswith(net.rsplit(".", 1)[0]):
                return True
    return False


def send_error(conn, msg: str):
    conn.send(json.dumps({"status": "error", "message": msg}).encode())


def send_ok(conn, payload=None):
    data = {"status": "ok"}
    if payload:
        data.update(payload)
    conn.send(json.dumps(data).encode())


# ════════════════════════════════════════════════════════════════════════════
#  REQUEST HANDLER
# ════════════════════════════════════════════════════════════════════════════

def handle_client(conn, addr):
    ip = addr[0]
    try:
        if not ip_allowed(ip):
            send_error(conn, "IP not whitelisted")
            return

        if is_rate_limited(ip):
            send_error(conn, "Rate limit exceeded")
            print(f"[TRACKER] Rate limited: {ip}")
            return

        data = conn.recv(4096).decode()
        request = json.loads(data)
        req_type = request.get("type")

        # ── AUTH: Peer joins with HMAC token, gets a session token back ──
        if req_type == "auth":
            peer_id  = request.get("peer_id", "")
            token    = request.get("token", "")
            ts       = request.get("timestamp", 0)

            if not verify_hmac_token(peer_id, token, ts):
                send_error(conn, "Authentication failed")
                print(f"[TRACKER] Auth failed from {ip} (peer_id={peer_id})")
                return

            session_tok = issue_session_token(ip)
            print(f"[TRACKER] Authenticated peer_id={peer_id} from {ip}")
            send_ok(conn, {"session_token": session_tok})
            return

        # ── All other requests require a valid session token ──
        session_tok = request.get("session_token", "")
        if not validate_session_token(session_tok, ip):
            send_error(conn, "Invalid or expired session token. Re-authenticate.")
            return

        # ── REGISTER ──────────────────────────────────────────────────────
        if req_type == "register":
            filename  = request["filename"]
            port      = request["port"]
            filesize  = request["filesize"]
            peer_id   = request.get("peer_id", ip)

            with lock:
                if filename not in peers:
                    peers[filename] = []
                already = any(p[0] == ip and p[1] == port for p in peers[filename])
                if not already:
                    peers[filename].append((ip, port, filesize, peer_id))

            print(f"[TRACKER] Registered '{filename}' from {ip}:{port}")
            send_ok(conn, {"message": "Registered successfully"})

        # ── DEREGISTER ────────────────────────────────────────────────────
        elif req_type == "deregister":
            filename = request["filename"]
            port     = request["port"]
            with lock:
                if filename in peers:
                    peers[filename] = [p for p in peers[filename]
                                       if not (p[0] == ip and p[1] == port)]
                    if not peers[filename]:
                        del peers[filename]
            print(f"[TRACKER] Deregistered '{filename}' from {ip}:{port}")
            send_ok(conn, {"message": "Deregistered"})

        # ── GET PEERS ─────────────────────────────────────────────────────
        elif req_type == "get_peers":
            filename = request["filename"]
            with lock:
                response = peers.get(filename, [])
            print(f"[TRACKER] Peers for '{filename}': {response}")
            send_ok(conn, {"peers": response})

        # ── LIST FILES ────────────────────────────────────────────────────
        elif req_type == "list_files":
            with lock:
                file_list = [
                    {"filename": fn, "filesize": pl[0][2], "peers": len(pl)}
                    for fn, pl in peers.items() if pl
                ]
            send_ok(conn, {"files": file_list})

        # ── PING ──────────────────────────────────────────────────────────
        elif req_type == "ping":
            send_ok(conn, {"message": "pong"})

        else:
            send_error(conn, f"Unknown request type: {req_type}")

    except json.JSONDecodeError:
        send_error(conn, "Malformed JSON")
    except Exception as e:
        print(f"[TRACKER][ERROR] {e}")
    finally:
        conn.close()


# ════════════════════════════════════════════════════════════════════════════
#  BACKGROUND: PURGE EXPIRED SESSION TOKENS
# ════════════════════════════════════════════════════════════════════════════

def purge_expired_tokens():
    while True:
        time.sleep(300)
        now = time.time()
        with lock:
            expired = [t for t, v in session_tokens.items() if now > v["expires"]]
            for t in expired:
                del session_tokens[t]
        if expired:
            print(f"[TRACKER] Purged {len(expired)} expired session token(s)")


# ════════════════════════════════════════════════════════════════════════════
#  MAIN
# ════════════════════════════════════════════════════════════════════════════

def start_tracker():
    threading.Thread(target=purge_expired_tokens, daemon=True).start()

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, PORT))
    server.listen()
    print(f"[TRACKER] Secure tracker running on port {PORT}")
    print(f"[TRACKER] HMAC window: ±{TOKEN_VALIDITY_WINDOW}s | Rate limit: {RATE_LIMIT_MAX} req/{RATE_LIMIT_WINDOW}s")

    while True:
        conn, addr = server.accept()
        threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()


if __name__ == "__main__":
    start_tracker()
