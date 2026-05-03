import socket
import hashlib

REAL_IP = "10.0.2.5"
SEED = "CS6045_Secret"
LISTEN_PORT = 9999

def calculate_virtual_ip(seq_num):
    """PRNG Math to calculate the new vIP"""
    raw_string = f"{REAL_IP}:{SEED}:{seq_num}"
    hash_object = hashlib.sha256(raw_string.encode('utf-8'))
    hash_int = int(hash_object.hexdigest(), 16)
    v_host = (hash_int % 253) + 1
    return f"192.168.50.{v_host}"

def start_agent():
    # Bind to 0.0.0.0 inside h3's namespace
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", LISTEN_PORT))

    print("[*] Client Agent active on h3.")
    print(f"[*] Listening for UDP beacons on port {LISTEN_PORT}...")

    while True:
        data, addr = sock.recvfrom(1024)
        message = data.decode('utf-8')

        if "SEQ_" in message:
            seq_num = int(message.split("SEQ_")[1])
            new_vip = calculate_virtual_ip(seq_num)

            print(f"\n[!] BEACON RECEIVED: Controller signaled mutation!")
            print(f"    -> Sequence Number: {seq_num}")
            print(f"    -> New Target vIP : {new_vip}")

if __name__ == "__main__":
    start_agent()
