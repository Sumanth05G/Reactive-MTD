import socket
import select
import hashlib

# --- CONFIG ---
REAL_IP = "10.0.2.5"
SEED = "CS6045_Secret"
UDP_LISTEN_PORT = 9999
IPC_PORT = 5050

current_vip = None
current_vport = None

def calculate_virtual_ip(seq_num):
    raw_string = f"{REAL_IP}:{SEED}:{seq_num}"
    hash_object = hashlib.sha256(raw_string.encode('utf-8'))
    hash_int = int(hash_object.hexdigest(), 16)
    v_host = (hash_int % 253) + 1
    return f"192.168.50.{v_host}"

def calculate_virtual_port(seq_num):
    raw_string = f"PORT:{REAL_IP}:{SEED}:{seq_num}"
    hash_object = hashlib.sha256(raw_string.encode('utf-8'))
    hash_int = int(hash_object.hexdigest(), 16)
    return 10000 + (hash_int % 50000)

if __name__ == "__main__":
    print("[*] Starting MTD Agent...")

    # Set up UDP Listener (Controller Beacons)
    udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    udp_sock.bind(("0.0.0.0", UDP_LISTEN_PORT))

    # Set up TCP Server (Client Queries)
    tcp_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp_server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    tcp_server.bind(("127.0.0.1", IPC_PORT))
    tcp_server.listen(5)

    print(f"[*] Listening for Controller Beacons on UDP {UDP_LISTEN_PORT}")
    print(f"[*] Serving Client App on TCP {IPC_PORT}")

    # Initialize Patient Zero
    current_vip = calculate_virtual_ip(0)
    current_vport = calculate_virtual_port(0)
    print(f"[*] Initial target locked: {current_vip}:{current_vport}")

    inputs = [udp_sock, tcp_server]

    while True:
        readable, _, _ = select.select(inputs, [], [])
        
        for s in readable:
            # --- HANDLE INCOMING UDP FROM CONTROLLER ---
            if s is udp_sock:
                data, _ = udp_sock.recvfrom(1024)
                try:
                    # Strip null bytes in case Scapy padded the raw payload
                    message = data.decode('utf-8', errors='ignore').strip('\x00')
                    
                    if "SEQ_" in message:
                        # USING YOUR PROVEN PARSING LOGIC
                        seq = int(message.split("SEQ_")[1])
                        
                        current_vip = calculate_virtual_ip(seq)
                        current_vport = calculate_virtual_port(seq)
                        
                        print(f"[!] Routing Update Received! Network mutated to: {current_vip}:{current_vport} (Seq {seq})")
                except Exception as e:
                    print(f"[!] Error parsing beacon: {e} | Raw data: {data}")
                    
            # --- HANDLE INCOMING TCP FROM CLIENT ---
            elif s is tcp_server:
                client_sock, _ = tcp_server.accept()
                try:
                    if current_vip and current_vport:
                        response = f"{current_vip}:{current_vport}"
                    else:
                        response = "WAIT"
                    client_sock.sendall(response.encode('utf-8'))
                except Exception as e:
                    print(f"[!] IPC Error: {e}")
                finally:
                    client_sock.close()
