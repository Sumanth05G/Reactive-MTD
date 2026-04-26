import socket
import time
import hashlib
import subprocess
import struct
import nnpy

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

    push_p4_rules(S2_PORT, "mirroring_add 100 3\n")

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

def setup_ids_socket():
    """
    Initializes the persistent connection to the P4 switch.
    """
    print("[*] IDS Booting: Connecting to Server Edge (s2)...")
    sub = nnpy.Socket(nnpy.AF_SP, nnpy.SUB)
    sub.connect('ipc:///tmp/bmv2-1-notifications.ipc') 
    sub.setsockopt(nnpy.SUB, nnpy.SUB_SUBSCRIBE, '')
    return sub

def listen_for_attack(sub_socket):
    """
    Blocks and waits for the next P4 digest.
    """
    print("[*] IDS Active: Monitoring for alerts...")
    while True:
        # Blocking wait
        msg = sub_socket.recv()

        raw_ip_bytes = msg[56:60]
        if len(raw_ip_bytes) == 4:
            attacker_ip = socket.inet_ntoa(raw_ip_bytes)
            return attacker_ip

def flush_queue(sub_socket):
    """
    Drains any stale alerts from the socket buffer while the controller was asleep.
    """
    # We use DONTWAIT to grab messages instantly. If the queue is empty, it throws an error.
    flushed_count = 0
    while True:
        try:
            sub_socket.recv(flags=nnpy.DONTWAIT)
            flushed_count += 1
        except nnpy.NNError:
            # Queue is empty, break the loop
            break
            
    if flushed_count > 0:
        print(f"[*] Ignored {flushed_count} redundant alerts received during cooldown.")



if __name__ == "__main__":
    initialize_static_network()
    print("\n[*] Establishing initial Virtual IP (Patient Zero)...")
    seq = 0
    mutate_server(seq)
    seq += 1
    ids_socket = setup_ids_socket()
    try:
        while True:
            attacker_ip = listen_for_attack(ids_socket)
            
            print(f"\n[!] ALARM TRIGGERED! Port scan detected from {attacker_ip}!")
            print(f"[*] Executing Reactive IP Hopping (Sequence {seq})...")
            
            mutate_server(seq)
            seq += 1
            
            print("[*] Hopping complete. Network stabilized. Resuming IDS...\n")
            # Don't hop again too quickly
            time.sleep(5)
            flush_queue(ids_socket)
            
    except KeyboardInterrupt:
        print("\n[*] Controller stopped.")