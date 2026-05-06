import socket
import select
import hashlib
import builtins

# Force unbuffered output for background logging
def print(*args, **kwargs):
    kwargs['flush'] = True
    builtins.print(*args, **kwargs)

# --- CONFIG ---
SEED = "CS6045_Secret"
UDP_LISTEN_PORT = 9999
IPC_PORT = 5050

# Track the exact same state as the controller
HOSTS = {
    "10.0.2.5": {
        "active_vip": None,
        "port_offset": 0,
        "services": {
            80: {"active_vport": None},
            8080: {"active_vport": None}
        }
    }
}

def calculate_virtual_ip(real_ip, seq_num):
    raw_string = f"{real_ip}:{SEED}:{seq_num}"
    hash_object = hashlib.sha256(raw_string.encode('utf-8'))
    hash_int = int(hash_object.hexdigest(), 16)
    v_host = (hash_int % 253) + 1
    return f"192.168.50.{v_host}"

def calculate_port_offset(real_ip, seq_num):
    raw_string = f"PORT:{real_ip}:{SEED}:{seq_num}"
    hash_object = hashlib.sha256(raw_string.encode('utf-8'))
    hash_int = int(hash_object.hexdigest(), 16)
    return hash_int % 50000

def apply_route_update(real_ip, seq_num):
    if real_ip not in HOSTS:
        return
        
    host = HOSTS[real_ip]
    host["active_vip"] = calculate_virtual_ip(real_ip, seq_num)
    host["port_offset"] = calculate_port_offset(real_ip, seq_num)
    
    print(f"\n[!] Routing Update for {real_ip} (Seq {seq_num})")
    print(f"    -> New vIP: {host['active_vip']}")
    
    for real_port, service in host["services"].items():
        vPort = 10000 + ((real_port + host["port_offset"]) % 50000)
        service["active_vport"] = vPort
        print(f"    -> Service {real_port} mapped to vPort {vPort}")

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
    for host_ip in HOSTS:
        apply_route_update(host_ip, 0)

    inputs = [udp_sock, tcp_server]

    while True:
        readable, _, _ = select.select(inputs, [], [])
        
        for s in readable:
            if s is udp_sock:
                data, _ = udp_sock.recvfrom(1024)
                try:
                    message = data.decode('utf-8', errors='ignore').strip('\x00')
                    # Expecting: SERVER_DB:10.0.2.5:SEQ_X
                    if message.startswith("SERVER_DB:"):
                        parts = message.split(":")
                        if len(parts) >= 3 and parts[2].startswith("SEQ_"):
                            real_ip = parts[1]
                            seq = int(parts[2].replace("SEQ_", ""))
                            apply_route_update(real_ip, seq)
                except Exception as e:
                    print(f"[!] Error parsing beacon: {e} | Raw data: {data}")
                    
            elif s is tcp_server:
                client_sock, _ = tcp_server.accept()
                try:
                    # For now, to keep the existing h3_client.py working, we will always
                    # just serve the route for 10.0.2.5:80.
                    # Once we do the NFQUEUE transparent proxy, this TCP IPC server will be removed anyway.
                    host = HOSTS.get("10.0.2.5")
                    if host and host["active_vip"] and host["services"][80]["active_vport"]:
                        response = f"{host['active_vip']}:{host['services'][80]['active_vport']}"
                    else:
                        response = "WAIT"
                    client_sock.sendall(response.encode('utf-8'))
                except Exception as e:
                    print(f"[!] IPC Error: {e}")
                finally:
                    client_sock.close()
