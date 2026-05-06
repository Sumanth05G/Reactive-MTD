import socket
import time
import hashlib
import subprocess
import re
from scapy.all import sniff, IP, TCP, Ether, UDP, sendp, Raw

# --- MTD VARIABLES ---
SEED = "CS6045_Secret"
CLIENT_UDP_PORT = 9999
SNIFF_IFACE = "s2-eth3"  # The dedicated hardware mirror port

LEGITIMATE_CLIENTS = [
    {"ip": "10.0.3.10", "iface": "s3-eth1"}
]

# --- SWITCH THRIFT PORTS ---
S1_PORT = 9090  # Edge 1 (Attacker)
S2_PORT = 9091  # Edge 2 (Server / MTD Target)
S3_PORT = 9092  # Edge 3 (Client)
S4_PORT = 10101 # Fabric

# --- STATE TRACKING ---
HOSTS = {
    "10.0.2.5": {
        "seq": 0,
        "last_mutation_time": 0,
        "active_vip": None,
        "port_offset": 0,
        "ip_p4_handles": {}, # {"inbound": handle, "outbound": handle}
        "services": {
            80: {"active_vport": None, "p4_handles": {}}, # {"inbound": handle, "outbound": handle}
            8080: {"active_vport": None, "p4_handles": {}}
        }
    }
}

def push_p4_rules(thrift_port, rules_string):
    """Pushes commands to the P4 switch and returns the handles of added entries"""
    try:
        result = subprocess.run(
            ["simple_switch_CLI", "--thrift-port", str(thrift_port)],
            input=rules_string,
            text=True,
            capture_output=True,
            check=True
        )
        # Extract all handles using regex from simple_switch_CLI stdout
        handles = re.findall(r"Entry has been added with handle (\d+)", result.stdout)
        return [int(h) for h in handles]
    except subprocess.CalledProcessError as e:
        print(f"[!] Error pushing rules to port {thrift_port}:\n{e.stderr}")
        return []

def initialize_static_network():
    """Sets up the non-moving parts of the network"""
    print("[*] Initializing Static Network Routes...")

    # S1: Route to h1, else Fabric
    push_p4_rules(S1_PORT,
        "table_add ipv4_lpm to_port_action 10.0.1.66/32 => 1\n"
        "table_add ipv4_lpm to_port_action 10.0.0.0/16 => 2\n"
        "table_add ipv4_lpm to_port_action 192.168.50.0/24 => 2\n")

    # S2 (Server Edge): Route to h2, else Fabric. + Hardware Mirroring
    push_p4_rules(S2_PORT,
        "table_add ipv4_lpm to_port_action 10.0.2.5/32 => 1\n"
        "table_add ipv4_lpm to_port_action 10.0.0.0/16 => 2\n"
        "mirroring_add 100 3\n")

    # S3: Route to h3, else Fabric
    push_p4_rules(S3_PORT,
        "table_add ipv4_lpm to_port_action 10.0.3.10/32 => 1\n"
        "table_add ipv4_lpm to_port_action 10.0.0.0/16 => 2\n"
        "table_add ipv4_lpm to_port_action 192.168.50.0/24 => 2\n")

    # S4 (Fabric): Route to edges based on subnet
    push_p4_rules(S4_PORT,
        "table_add ipv4_lpm to_port_action 10.0.1.0/24 => 1\n"
        "table_add ipv4_lpm to_port_action 10.0.3.0/24 => 3\n"
        "table_add ipv4_lpm to_port_action 192.168.50.0/24 => 2\n")

def calculate_virtual_ip(real_ip, seq_num):
    """PRNG Math to calculate the new vIP"""
    raw_string = f"{real_ip}:{SEED}:{seq_num}"
    hash_object = hashlib.sha256(raw_string.encode('utf-8'))
    hash_int = int(hash_object.hexdigest(), 16)
    v_host = (hash_int % 253) + 1
    return f"192.168.50.{v_host}"

def calculate_port_offset(real_ip, seq_num):
    """PRNG Math to calculate the port offset for this host sequence"""
    raw_string = f"PORT:{real_ip}:{SEED}:{seq_num}"
    hash_object = hashlib.sha256(raw_string.encode('utf-8'))
    hash_int = int(hash_object.hexdigest(), 16)
    return hash_int % 50000

def check_vip_collision(vip, exclude_host):
    for host_ip, host_data in HOSTS.items():
        if host_ip != exclude_host and host_data["active_vip"] == vip:
            return True
    return False

def mutate_server(host_ip):
    host = HOSTS[host_ip]
    
    # 1. Collision-Free vIP Generation
    while True:
        vIP = calculate_virtual_ip(host_ip, host["seq"])
        if not check_vip_collision(vIP, host_ip):
            break
        print(f"[*] Collision detected for {vIP}, incrementing sequence...")
        host["seq"] += 1
        
    port_offset = calculate_port_offset(host_ip, host["seq"])
    
    host["active_vip"] = vIP
    host["port_offset"] = port_offset

    print(f"\n==========================================")
    print(f"[*] MUTATION FOR HOST {host_ip} | Seq {host['seq']}")
    print(f"[*] New vIP: {vIP} | Port Offset: {port_offset}")

    # 2. Prepare Deletion Commands for Old Rules
    delete_cmds = ""
    if host["ip_p4_handles"]:
        delete_cmds += f"table_delete inbound_ip_nat {host['ip_p4_handles']['inbound']}\n"
        delete_cmds += f"table_delete outbound_ip_nat {host['ip_p4_handles']['outbound']}\n"
        
    for real_port, service in host["services"].items():
        if service["p4_handles"]:
            delete_cmds += f"table_delete inbound_tcp_nat {service['p4_handles']['inbound']}\n"
            delete_cmds += f"table_delete outbound_tcp_nat {service['p4_handles']['outbound']}\n"

    if delete_cmds:
        push_p4_rules(S2_PORT, delete_cmds)
        print(f"[*] Deleted old P4 NAT rules for host {host_ip}")

    # 3. Add New Rules
    # We must push them in a predictable order to capture the handles correctly.
    add_cmds = ""
    add_cmds += f"table_add inbound_ip_nat dnat_ip_action {vIP} => {host_ip}\n"
    add_cmds += f"table_add outbound_ip_nat snat_ip_action {host_ip} => {vIP}\n"
    
    services_list = list(host["services"].items())
    for real_port, service in services_list:
        vPort = 10000 + ((real_port + port_offset) % 50000)
        service["active_vport"] = vPort
        print(f"    -> Service Port {real_port} mapped to vPort {vPort}")
        
        add_cmds += f"table_add inbound_tcp_nat dnat_tcp_action {vIP} {vPort} => {host_ip} {real_port}\n"
        add_cmds += f"table_add outbound_tcp_nat snat_tcp_action {host_ip} {real_port} => {vIP} {vPort}\n"

    handles = push_p4_rules(S2_PORT, add_cmds)
    
    if len(handles) == 2 + (2 * len(services_list)):
        # Assign handles
        host["ip_p4_handles"] = {"inbound": handles[0], "outbound": handles[1]}
        idx = 2
        for real_port, service in services_list:
            service["p4_handles"] = {"inbound": handles[idx], "outbound": handles[idx+1]}
            idx += 2
        print(f"[*] Successfully installed new P4 NAT rules with handles.")
    else:
        print(f"[!] Warning: Expected {2 + (2 * len(services_list))} handles, got {len(handles)}")

    # 4. Alert the Clients via Direct Packet Injection
    message = f"SERVER_DB:{host_ip}:SEQ_{host['seq']}"

    for client in LEGITIMATE_CLIENTS:
        beacon_pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / IP(dst=client["ip"]) / UDP(dport=CLIENT_UDP_PORT) / Raw(load=message)
        sendp(beacon_pkt, iface=client["iface"], verbose=False)
        print(f"[*] Beacon ({message}) injected into {client['iface']} towards {client['ip']}.")

def handle_alert(packet):
    """Callback triggered by Scapy when a cloned packet hits s2-eth3"""
    if IP in packet and TCP in packet:
        attacker_ip = packet[IP].src
        target_ip = packet[IP].dst
        target_port = packet[TCP].dport

        # Find which host is being targeted
        matched_host_ip = None
        
        for host_ip, host_data in HOSTS.items():
            if host_data["active_vip"] == target_ip:
                matched_host_ip = host_ip
                break

        if not matched_host_ip:
            # Not targeting an active vIP/vPort that we track
            return

        host = HOSTS[matched_host_ip]

        # Debounce to prevent rapid overlapping mutations
        current_time = time.time()
        if current_time - host["last_mutation_time"] < 5.0:
            return

        print(f"\n[!] ALARM TRIGGERED! Hardware clone caught from {attacker_ip} targeting {target_ip}:{target_port}!")
        print(f"[*] Executing Reactive IP Hopping for Host {matched_host_ip}...")

        host["seq"] += 1
        mutate_server(matched_host_ip)
        host["last_mutation_time"] = time.time()
        print("[*] Hopping complete. Network stabilized. Resuming IDS...\n")

if __name__ == "__main__":
    initialize_static_network()
    print("\n[*] Establishing initial Virtual IPs (Patient Zero)...")

    for host_ip in HOSTS:
        mutate_server(host_ip)

    print(f"\n[*] Controller Active: Monitoring management port {SNIFF_IFACE}...")
    try:
        sniff(iface=SNIFF_IFACE, prn=handle_alert, store=False, filter="tcp")
    except KeyboardInterrupt:
        print("\n[*] Controller stopped.")
