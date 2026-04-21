import socket
import time
import hashlib
import subprocess

# --- MTD VARIABLES ---
REAL_IP = "10.0.2.5"
SEED = "CS6045_Secret"
# Right now we are running everything on a single machine
CLIENT_IP = "127.0.0.1"  # Legit client on h3
CLIENT_UDP_PORT = 9999

# --- SWITCH THRIFT PORTS ---
S1_PORT = 9090  # Edge 1 (Attacker)
S2_PORT = 9091  # Edge 2 (Server / MTD Target)
S3_PORT = 9092  # Edge 3 (Client)
S4_PORT = 10101 # Fabric

def push_p4_rules(thrift_port, rules_string):
    """Silently pushes commands to the P4 switch via the CLI"""
    try:
        subprocess.run(
            ["simple_switch_CLI", "--thrift-port", str(thrift_port)],
            input=rules_string,
            text=True,
            capture_output=True,
            check=True
        )
    except subprocess.CalledProcessError as e:
        print(f"[!] Error pushing rules to port {thrift_port}:\n{e.stderr}")

def initialize_static_network():
    """Sets up the non-moving parts of the network"""
    print("[*] Initializing Static Network Routes...")
    
    # S1: Route to h1, else Fabric
    push_p4_rules(S1_PORT, 
        "table_add ipv4_lpm to_port_action 10.0.1.66/32 => 1\n"
        "table_add ipv4_lpm to_port_action 10.0.0.0/16 => 2\n"
        "table_add ipv4_lpm to_port_action 192.168.50.0/24 => 2\n")
    
    # S3: Route to h3, else Fabric
    push_p4_rules(S3_PORT, 
        "table_add ipv4_lpm to_port_action 10.0.3.10/32 => 1\n"
        "table_add ipv4_lpm to_port_action 10.0.0.0/16 => 2\n"
        "table_add ipv4_lpm to_port_action 192.168.50.0/24 => 2\n")
    
    # S4 (Fabric): Route to edges based on subnet
    push_p4_rules(S4_PORT, 
        "table_add ipv4_lpm to_port_action 10.0.1.0/24 => 1\n"
        "table_add ipv4_lpm to_port_action 10.0.3.0/24 => 3\n"
        # We must route the Virtual Subnet (192.168.50.X) to S2!
        "table_add ipv4_lpm to_port_action 192.168.50.0/24 => 2\n")

def calculate_virtual_ip(seq_num):
    """PRNG Math to calculate the new vIP"""
    raw_string = f"{REAL_IP}:{SEED}:{seq_num}"
    hash_object = hashlib.sha256(raw_string.encode('utf-8'))
    hash_int = int(hash_object.hexdigest(), 16)
    
    v_host = (hash_int % 253) + 1
    return f"192.168.50.{v_host}"

def mutate_server(sequence_number):
    vIP = calculate_virtual_ip(sequence_number)
    print(f"\n==========================================")
    print(f"[*] MUTATION {sequence_number} | Target: {vIP}")
    
    # 1. Update S2 (The Server's Switch)
    # We clear the table first to wipe the old MTD rule, then re-add the static fabric route + new DNAT rule
    s2_rules = (
        "table_clear ipv4_lpm\n"
        f"table_add ipv4_lpm snat_and_route 10.0.0.0/16 => {vIP} 2\n"
        f"table_add ipv4_lpm dnat_action {vIP}/32 => {REAL_IP} 1\n"
    )
    push_p4_rules(S2_PORT, s2_rules)
    print(f"[*] P4 Switch S2 Updated: {vIP} translates to {REAL_IP}")
    
    # 2. Alert the Client via UDP
    message = f"SERVER_DB:SEQ_{sequence_number}"
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(message.encode('utf-8'), (CLIENT_IP, CLIENT_UDP_PORT))
    print(f"[*] Beacon sent to Legitimate Client.")

if __name__ == "__main__":
    initialize_static_network()
    
    seq = 1
    try:
        while True:
            mutate_server(seq)
            seq += 1
            time.sleep(30) # Wait 30 seconds before hopping again
    except KeyboardInterrupt:
        print("\n[*] Controller stopped.")