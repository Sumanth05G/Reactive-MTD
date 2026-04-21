import socket
import hashlib

# --- MTD VARIABLES ---
REAL_IP = "10.0.2.5"     # The server's actual IP
SEED = "CS6045_Secret"   # The shared secret key
LISTEN_PORT = 9999       # Port for receiving the UDP beacon

def calculate_virtual_ip(seq_num):
    """PRNG Math to calculate the new vIP (Must match Controller exactly!)"""
    raw_string = f"{REAL_IP}:{SEED}:{seq_num}"
    hash_object = hashlib.sha256(raw_string.encode('utf-8'))
    hash_int = int(hash_object.hexdigest(), 16)
    
    v_host = (hash_int % 253) + 1
    return f"192.168.50.{v_host}"

def listen_for_beacon():
    print(f"[*] Legitimate Client Agent started.")
    print(f"[*] Listening for Controller beacons on UDP port {LISTEN_PORT}...")
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    # Bind to all interfaces on port 9999
    sock.bind(("0.0.0.0", LISTEN_PORT))

    while True:
        data, addr = sock.recvfrom(1024)
        message = data.decode('utf-8')
        
        # Parse the Sequence Number from the message (e.g., "SERVER_DB:SEQ_5")
        if "SEQ_" in message:
            seq_num = int(message.split("SEQ_")[1])
            print(f"\n[!] ALERT: Mutation triggered! Received Sequence: {seq_num}")
            
            # Run the math!
            new_vip = calculate_virtual_ip(seq_num)
            print(f"    -> Updating local routing...")
            print(f"    -> NEW SECURE TARGET: {new_vip} (translates to {REAL_IP} in P4 switch)")

if __name__ == "__main__":
    try:
        listen_for_beacon()
    except KeyboardInterrupt:
        print("\n[*] Agent stopped.")