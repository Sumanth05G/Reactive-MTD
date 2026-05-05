import socket
import time
import hashlib
import subprocess
from scapy.all import sniff, IP, TCP, Ether, UDP, sendp

# --- MTD VARIABLES ---
REAL_IP = "10.0.2.5"
SEED = "CS6045_Secret"
CLIENT_IP = "10.0.3.10"  # Target IP for h3
CLIENT_UDP_PORT = 9999
SNIFF_IFACE = "s2-eth3"  # The dedicated hardware mirror port

# --- SWITCH THRIFT PORTS ---
S1_PORT = 9090  # Edge 1 (Attacker)
S2_PORT = 9091  # Edge 2 (Server / MTD Target)
S3_PORT = 9092  # Edge 3 (Client)
S4_PORT = 10101 # Fabric

# --- STATE TRACKING ---
seq = 0
last_mutation_time = 0
active_vip = None  # Tracks the currently active target to prevent "Old IP" exploits

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

    # Set up the Hardware Port Mirror to out-of-band port 3
    push_p4_rules(S2_PORT, "mirroring_add 100 3\n")

def calculate_virtual_ip(seq_num):
    """PRNG Math to calculate the new vIP"""
    raw_string = f"{REAL_IP}:{SEED}:{seq_num}"
    hash_object = hashlib.sha256(raw_string.encode('utf-8'))
    hash_int = int(hash_object.hexdigest(), 16)

    v_host = (hash_int % 253) + 1
    return f"192.168.50.{v_host}"

def mutate_server(sequence_number):
    global active_vip

    vIP = calculate_virtual_ip(sequence_number)
    active_vip = vIP  # Update the active IP state

    print(f"\n==========================================")
    print(f"[*] MUTATION {sequence_number} | Target: {vIP}")

    # 1. Update S2 (The Server's Switch)
    s2_rules = (
        "table_clear ipv4_lpm\n"
        f"table_add ipv4_lpm snat_and_route 10.0.0.0/16 => {vIP} 2\n"
        f"table_add ipv4_lpm dnat_action {vIP}/32 => {REAL_IP} 1\n"
    )
    push_p4_rules(S2_PORT, s2_rules)
    print(f"[*] P4 Switch S2 Updated: {vIP} translates to {REAL_IP}")

    # 2. Alert the Client via Direct Packet Injection
    message = f"SERVER_DB:SEQ_{sequence_number}"

    # Craft a raw packet targeting h3's namespace
    beacon_pkt = Ether(dst="00:04:00:00:00:03") / IP(dst=CLIENT_IP) / UDP(dport=CLIENT_UDP_PORT) / message

    # Inject it directly into the switch port facing h3 (s3-eth1)
    sendp(beacon_pkt, iface="s3-eth1", verbose=False)
    print(f"[*] Beacon physically injected into s3-eth1 towards h3.")

def handle_alert(packet):
    """Callback triggered by Scapy when a cloned packet hits s2-eth3"""
    global seq, last_mutation_time, active_vip

    # Debounce to prevent rapid overlapping mutations
    current_time = time.time()
    if current_time - last_mutation_time < 5.0:
        return

    if IP in packet and TCP in packet:
        attacker_ip = packet[IP].src
        target_ip = packet[IP].dst

        # Verify the attacker is targeting the actual live Virtual IP
        if target_ip != active_vip:
            print(f"[*] Ignored attack on dead IP: {target_ip} from {attacker_ip}")
            return

        print(f"\n[!] ALARM TRIGGERED! Hardware clone caught from {attacker_ip}!")
        print(f"[*] Executing Reactive IP Hopping (Sequence {seq})...")

        mutate_server(seq)
        seq += 1
        last_mutation_time = time.time()
        print("[*] Hopping complete. Network stabilized. Resuming IDS...\n")

if __name__ == "__main__":
    initialize_static_network()
    print("\n[*] Establishing initial Virtual IP (Patient Zero)...")

    # Spin up the first Virtual IP before we start listening
    mutate_server(seq)
    seq += 1

    print(f"\n[*] Controller Active: Monitoring management port {SNIFF_IFACE}...")
    try:
        # Scapy sniff runs continuously until interrupted.
        sniff(iface=SNIFF_IFACE, prn=handle_alert, store=False, filter="tcp")
    except KeyboardInterrupt:
        print("\n[*] Controller stopped.")
