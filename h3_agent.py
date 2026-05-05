import socket
import hashlib
import threading

# --- MTD VARIABLES ---
REAL_IP = "10.0.2.5"
SEED = "CS6045_Secret"
BEACON_PORT = 9999
IPC_PORT = 5050  # Local port for the client to query

# --- GLOBAL STATE ---
seq = 0
current_vip = None

def calculate_virtual_ip(seq_num):
    raw_string = f"{REAL_IP}:{SEED}:{seq_num}"
    hash_int = int(hashlib.sha256(raw_string.encode('utf-8')).hexdigest(), 16)
    return f"192.168.50.{(hash_int % 253) + 1}"

def listen_for_beacons():
    """Listens for SDN routing updates from the Controller"""
    global seq, current_vip
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", BEACON_PORT))

    while True:
        data, _ = sock.recvfrom(1024)
        message = data.decode('utf-8')
        if "SEQ_" in message:
            new_seq = int(message.split("SEQ_")[1])
            if new_seq > seq:
                seq = new_seq
                current_vip = calculate_virtual_ip(seq)
                print(f"[!] Routing Update Received! Network mutated to: {current_vip} (Seq {seq})")

def run_ipc_server():
    """Runs a local server for h3_client.py to query the active VIP"""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    # Bind strictly to localhost so it doesn't leak onto the Mininet network
    server.bind(("127.0.0.1", IPC_PORT))
    server.listen(5)

    print(f"[*] IPC Server listening for local app queries on 127.0.0.1:{IPC_PORT}...")

    while True:
        conn, _ = server.accept()
        if current_vip:
            conn.sendall(current_vip.encode('utf-8'))
        else:
            conn.sendall(b"WAIT")
        conn.close()

if __name__ == "__main__":
    # Initialize Patient Zero before starting servers
    current_vip = calculate_virtual_ip(seq)
    print(f"[*] Local Agent Booted. Initial target locked: {current_vip}")

    # Run the beacon listener in the background
    threading.Thread(target=listen_for_beacons, daemon=True).start()

    # Run the IPC server in the foreground
    try:
        run_ipc_server()
    except KeyboardInterrupt:
        print("\n[*] Agent shutting down.")
