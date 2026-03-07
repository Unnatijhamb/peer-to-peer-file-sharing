import socket
import threading
import os
import json
import time
import tkinter as tk
from tkinter import ttk, messagebox

TRACKER_IP = "10.96.139.161"
TRACKER_PORT = 5000
CHUNK_SIZE = 65536

progress_lock = threading.Lock()
total_downloaded = 0


# ================= NETWORK FUNCTIONS =================

def get_my_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    ip = s.getsockname()[0]
    s.close()
    return ip


def register_file(filename, peer_port):
    filepath = f"shared_files/{filename}"

    if not os.path.exists(filepath):
        log("File not found in shared_files/")
        return

    filesize = os.path.getsize(filepath)
    ip = get_my_ip()

    message = {
        "type": "register",
        "filename": filename,
        "ip": ip,
        "port": peer_port,
        "filesize": filesize
    }

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((TRACKER_IP, TRACKER_PORT))
    s.send(json.dumps(message).encode())
    response = s.recv(1024).decode()
    s.close()

    log(response)


def get_peers(filename):
    message = {"type": "get_peers", "filename": filename}
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((TRACKER_IP, TRACKER_PORT))
    s.send(json.dumps(message).encode())
    data = s.recv(4096).decode()
    s.close()
    return json.loads(data)


def list_available_files():
    message = {"type": "list_files"}
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((TRACKER_IP, TRACKER_PORT))
    s.send(json.dumps(message).encode())
    data = s.recv(4096).decode()
    s.close()

    files = json.loads(data)

    log("Available Files:")
    for f in files:
        size_mb = f["filesize"] / (1024 * 1024)
        log(f"{f['filename']} | {size_mb:.2f} MB | {f['peers']} peer(s)")


# ================= DOWNLOAD LOGIC =================

def download_chunk(peer, filename, start, end, output_file, filesize):
    global total_downloaded
    ip, port, _ = peer

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((ip, port))
    except:
        log(f"Peer {ip}:{port} unreachable.")
        return

    log(f"Downloading chunk {start}-{end} from {ip}:{port}")

    request = {"filename": filename, "start": start, "end": end}
    s.send(json.dumps(request).encode())

    with open(output_file, "r+b") as f:
        f.seek(start)
        remaining = end - start

        while remaining > 0:
            data = s.recv(min(CHUNK_SIZE, remaining))
            if not data:
                break

            f.write(data)
            remaining -= len(data)

            with progress_lock:
                total_downloaded += len(data)
                percentage = (total_downloaded / filesize) * 100
                progress_bar["value"] = percentage

    s.close()


def multi_source_download(filename):
    global total_downloaded
    total_downloaded = 0

    peers = get_peers(filename)
    if not peers:
        log("No peers found.")
        return

    filesize = peers[0][2]
    num_peers = len(peers)
    chunk_size = filesize // num_peers

    output_path = f"downloads/{filename}"

    with open(output_path, "wb") as f:
        f.truncate(filesize)

    start_time = time.time()

    threads = []

    for i, peer in enumerate(peers):
        start = i * chunk_size
        end = filesize if i == num_peers - 1 else (i + 1) * chunk_size

        t = threading.Thread(
            target=download_chunk,
            args=(peer, filename, start, end, output_path, filesize)
        )
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    end_time = time.time()
    total_time = end_time - start_time
    speed = (filesize / (1024 * 1024)) / total_time

    log("Download completed.")
    log(f"Time: {total_time:.2f} seconds")
    log(f"Average Speed: {speed:.2f} MB/s")


# ================= SERVER =================

def serve_files(peer_port):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("0.0.0.0", peer_port))
    server.listen()

    log(f"Peer server running on port {peer_port}")

    while True:
        conn, addr = server.accept()
        threading.Thread(target=handle_request, args=(conn, addr)).start()


def handle_request(conn, addr):
    request = json.loads(conn.recv(1024).decode())
    filename = request["filename"]
    start = request["start"]
    end = request["end"]

    log(f"Serving chunk {start}-{end} to {addr[0]}")

    filepath = f"shared_files/{filename}"

    with open(filepath, "rb") as f:
        f.seek(start)
        remaining = end - start

        while remaining > 0:
            chunk = f.read(min(CHUNK_SIZE, remaining))
            if not chunk:
                break
            conn.send(chunk)
            remaining -= len(chunk)

    conn.close()


# ================= GUI =================

def log(message):
    activity_box.insert(tk.END, message + "\n")
    activity_box.see(tk.END)


def start_peer():
    port = int(port_entry.get())
    threading.Thread(target=serve_files, args=(port,), daemon=True).start()


def gui_register():
    register_file(file_entry.get(), int(port_entry.get()))


def gui_download():
    threading.Thread(
        target=multi_source_download,
        args=(file_entry.get(),),
        daemon=True
    ).start()


# ================= WINDOW =================

root = tk.Tk()
root.title("P2P File Sharing System")
root.geometry("600x500")

tk.Label(root, text="Peer Port").pack()
port_entry = tk.Entry(root)
port_entry.pack()

tk.Label(root, text="Filename").pack()
file_entry = tk.Entry(root)
file_entry.pack()

tk.Button(root, text="Start Peer", command=start_peer).pack(pady=5)
tk.Button(root, text="Register File", command=gui_register).pack(pady=5)
tk.Button(root, text="Download File", command=gui_download).pack(pady=5)
tk.Button(root, text="List Files", command=list_available_files).pack(pady=5)

progress_bar = ttk.Progressbar(root, length=400)
progress_bar.pack(pady=10)

activity_box = tk.Text(root, height=15)
activity_box.pack(pady=10)

root.mainloop()