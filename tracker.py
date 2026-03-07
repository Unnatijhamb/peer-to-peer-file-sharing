# tracker.py
import socket
import threading
import json

HOST = "0.0.0.0"
PORT = 5000

peers = {}
lock = threading.Lock()


def handle_client(conn):
    global peers
    try:
        data = conn.recv(4096).decode()
        request = json.loads(data)

        # ================= REGISTER =================
        if request["type"] == "register":
            filename = request["filename"]
            ip = request["ip"]
            port = request["port"]
            filesize = request["filesize"]

            with lock:
                if filename not in peers:
                    peers[filename] = []
                peers[filename].append((ip, port, filesize))

            print(f"[TRACKER] Registered {filename} from {ip}:{port}")
            conn.send("Registered Successfully".encode())

        # ================= GET PEERS =================
        elif request["type"] == "get_peers":
            filename = request["filename"]

            with lock:
                response = peers.get(filename, [])

            print(f"[TRACKER] Sending peers for {filename}: {response}")
            conn.send(json.dumps(response).encode())

        # ================= LIST FILES =================
        elif request["type"] == "list_files":

            with lock:
                file_list = []

                for filename, peer_list in peers.items():
                    if peer_list:
                        filesize = peer_list[0][2]
                        peer_count = len(peer_list)
                        file_list.append({
                            "filename": filename,
                            "filesize": filesize,
                            "peers": peer_count
                        })

            print("[TRACKER] Sending file list")
            conn.send(json.dumps(file_list).encode())

    except Exception as e:
        print("Error:", e)

    finally:
        conn.close()


def start_tracker():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((HOST, PORT))
    server.listen()

    print(f"[TRACKER] Running on port {PORT}")

    while True:
        conn, addr = server.accept()
        threading.Thread(target=handle_client, args=(conn,)).start()


if __name__ == "__main__":
    start_tracker()