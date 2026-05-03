import socket
import hashlib
import time
import threading

REAL_IP = "10.0.2.5"
SEED = "CS6045_Secret"
LISTEN_PORT = 9999
SERVER_PORT = 80

# Global state
seq = 0
current_vip = None
active_socket = None
socket_lock = threading.Lock()

def calculate_virtual_ip(seq_num):
    raw_string = f"{REAL_IP}:{SEED}:{seq_num}"
    hash_object = hashlib.sha256(raw_string.encode('utf-8'))
    hash_int = int(hash_object.hexdigest(), 16)
    v_host = (hash_int % 253) + 1
    return f"192.168.50.{v_host}"

def listen_for_beacon():
    """Background thread waiting for the Controller's UDP packet"""
    global current_vip, seq, active_socket

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", LISTEN_PORT))

    while True:
        data, addr = sock.recvfrom(1024)
        message = data.decode('utf-8')

        if "SEQ_" in message:
            new_seq = int(message.split("SEQ_")[1])
            if new_seq > seq:
                seq = new_seq
                current_vip = calculate_virtual_ip(seq)
                print(f"\n[!] BEACON RECEIVED: Controller signaled mutation!")
                print(f"[*] New Secure Target: {current_vip}")

                # Tear down the active connection to trigger a reconnect
                with socket_lock:
                    if active_socket:
                        active_socket.close()
                        active_socket = None

def run_tcp_client():
    """Foreground thread streaming data to the server"""
    global active_socket, current_vip

    while True:
        if current_vip is None:
            time.sleep(0.5)
            continue

        print(f"\n[*] Connecting to {current_vip}:{SERVER_PORT}...")

        with socket_lock:
            active_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            active_socket.settimeout(2.0)

        try:
            active_socket.connect((current_vip, SERVER_PORT))
            print(f"[+] Connected! Transmitting data...")

            counter = 1
            while True:
                message = f"Legitimate payload packet #{counter} (Targeting {current_vip})\n"
                with socket_lock:
                    if active_socket is None:
                        break # Socket was killed by the beacon thread
                    active_socket.sendall(message.encode('utf-8'))
                counter += 1
                time.sleep(1)

        except (socket.timeout, ConnectionRefusedError, BrokenPipeError, OSError):
            print(f"[-] Connection broken. Waiting for new routing instructions...")
            with socket_lock:
                if active_socket:
                    active_socket.close()
                    active_socket = None
            time.sleep(1)

if __name__ == "__main__":
    current_vip = calculate_virtual_ip(seq)
    print("[*] Legitimate Client Agent Started.")
    print(f"[*] Initial Virtual IP is {current_vip}")

    # Start the UDP listener in the background
    threading.Thread(target=listen_for_beacon, daemon=True).start()

    # Run the TCP client in the foreground
    try:
        run_tcp_client()
    except KeyboardInterrupt:
        print("\n[*] Client agent shutting down.")
