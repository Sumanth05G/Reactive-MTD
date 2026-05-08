import socket
import time
import hashlib
import subprocess
import re
import base64
import json
import threading
from scapy.all import sniff, IP, TCP, Ether, UDP, sendp, Raw
from cryptography.fernet import Fernet

# --- MTD VARIABLES ---
SEED = "CS6045_Secret"
CLIENT_UDP_PORT = 9999

# --- CRYPTOGRAPHY SETUP ---
key_hash = hashlib.sha256(SEED.encode('utf-8')).digest()
FERNET_KEY = base64.urlsafe_b64encode(key_hash)
cipher_suite = Fernet(FERNET_KEY)

# --- DYNAMIC STATE ---
CONFIG = {}
HOSTS = {}
LEGITIMATE_CLIENTS = []
SNIFF_INTERFACES = []

def load_config():
    global CONFIG
    with open("config.json", "r") as f:
        CONFIG = json.load(f)
        
    for i, edge in enumerate(CONFIG.get("edge_switches", [])):
        for host in edge.get("hosts", []):
            if host.get("type") == "legitimate_client":
                # The interface name the switch uses to connect to this client is <switch_name>-eth<switch_port>
                client_iface = f"{edge['name']}-eth{host['switch_port']}"
                LEGITIMATE_CLIENTS.append({"ip": host["ip"], "iface": client_iface})
                
            elif host.get("type") == "server" and edge.get("is_mtd"):
                HOSTS[host["ip"]] = {
                    "switch_name": edge["name"],
                    "thrift_port": edge["thrift_port"],
                    "seq": 0,
                    "last_mutation_time": 0,
                    "active_vip": None,
                    "port_offset": 0,
                    "ip_p4_handles": {},
                    "services": {port: {"active_vport": None, "p4_handles": {}} for port in host.get("services", [])}
                }
                
        if edge.get("is_mtd") and "sniff_port" in edge:
            # The interface name for the dummy sniff host
            SNIFF_INTERFACES.append(f"{edge['name']}-eth{edge['sniff_port']}")

def push_p4_rules(thrift_port, rules_string):
    try:
        result = subprocess.run(
            ["simple_switch_CLI", "--thrift-port", str(thrift_port)],
            input=rules_string,
            text=True,
            capture_output=True,
            check=True
        )
        handles = re.findall(r"Entry has been added with handle (\d+)", result.stdout)
        return [int(h) for h in handles]
    except subprocess.CalledProcessError as e:
        print(f"[!] Error pushing rules to port {thrift_port}:\n{e.stderr}")
        return []

def initialize_static_network():
    print("[*] Initializing Static Network Routes dynamically from config...")
    
    fab_thrift = CONFIG["fabric_switch"]["thrift_port"]
    fab_cmds = ""

    all_vip_subnets = []

    for i, edge in enumerate(CONFIG.get("edge_switches", [])):
        fabric_egress_port = i + 1
        edge_cmds = ""
        edge_thrift = edge["thrift_port"]
        
        # Route 10.0.0.0/16 to Fabric
        edge_cmds += f"table_add ipv4_lpm to_port_action 10.0.0.0/16 => {edge['fabric_port']}\n"
        
        if edge.get("is_mtd"):
            vip_subnet = edge["vip_subnet"]
            all_vip_subnets.append(vip_subnet)
            # Fabric switch needs to know how to reach this vIP subnet
            fab_cmds += f"table_add ipv4_lpm to_port_action {vip_subnet} => {fabric_egress_port}\n"
            # Hardware Mirroring
            edge_cmds += f"mirroring_add 100 {edge['sniff_port']}\n"
            
        for host in edge.get("hosts", []):
            # Edge local routing
            edge_cmds += f"table_add ipv4_lpm to_port_action {host['ip']}/32 => {host['switch_port']}\n"
            
            # Fabric switch routing (assuming /24 subnets based on IP)
            subnet = host['ip'].rsplit('.', 1)[0] + ".0/24"
            if f"table_add ipv4_lpm to_port_action {subnet} =>" not in fab_cmds:
                fab_cmds += f"table_add ipv4_lpm to_port_action {subnet} => {fabric_egress_port}\n"
                
        # Push to Edge Switch
        push_p4_rules(edge_thrift, edge_cmds)

    # All edge switches must route to all known vIP subnets via the fabric
    for edge in CONFIG.get("edge_switches", []):
        edge_thrift = edge["thrift_port"]
        edge_cmds = ""
        for vip_sub in all_vip_subnets:
            if edge.get("vip_subnet") != vip_sub:
                edge_cmds += f"table_add ipv4_lpm to_port_action {vip_sub} => {edge['fabric_port']}\n"
        if edge_cmds:
            push_p4_rules(edge_thrift, edge_cmds)

    # Push to Fabric Switch
    push_p4_rules(fab_thrift, fab_cmds)

def calculate_virtual_ip(real_ip, seq_num):
    raw_string = f"{real_ip}:{SEED}:{seq_num}"
    hash_object = hashlib.sha256(raw_string.encode('utf-8'))
    hash_int = int(hash_object.hexdigest(), 16)
    v_host = (hash_int % 253) + 1
    # Need to infer the subnet from the config!
    host_switch = HOSTS[real_ip]["switch_name"]
    vip_subnet = None
    for edge in CONFIG["edge_switches"]:
        if edge["name"] == host_switch:
            vip_subnet = edge["vip_subnet"]
            break
    prefix = vip_subnet.rsplit('.', 1)[0]
    return f"{prefix}.{v_host}"

def calculate_port_offset(real_ip, seq_num):
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
    thrift_port = host["thrift_port"]
    
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

    delete_cmds = ""
    if host["ip_p4_handles"]:
        delete_cmds += f"table_delete inbound_ip_nat {host['ip_p4_handles']['inbound']}\n"
        delete_cmds += f"table_delete outbound_ip_nat {host['ip_p4_handles']['outbound']}\n"
        
    for real_port, service in host["services"].items():
        if service["p4_handles"]:
            delete_cmds += f"table_delete inbound_tcp_nat {service['p4_handles']['inbound']}\n"
            delete_cmds += f"table_delete outbound_tcp_nat {service['p4_handles']['outbound']}\n"

    if delete_cmds:
        push_p4_rules(thrift_port, delete_cmds)
        print(f"[*] Deleted old P4 NAT rules for host {host_ip}")

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

    handles = push_p4_rules(thrift_port, add_cmds)
    
    if len(handles) == 2 + (2 * len(services_list)):
        host["ip_p4_handles"] = {"inbound": handles[0], "outbound": handles[1]}
        idx = 2
        for real_port, service in services_list:
            service["p4_handles"] = {"inbound": handles[idx], "outbound": handles[idx+1]}
            idx += 2
        print(f"[*] Successfully installed new P4 NAT rules with handles.")
    else:
        print(f"[!] Warning: Expected {2 + (2 * len(services_list))} handles, got {len(handles)}")

    plaintext_message = f"SERVER_DB:{host_ip}:SEQ_{host['seq']}"
    encrypted_payload = cipher_suite.encrypt(plaintext_message.encode('utf-8'))

    for client in LEGITIMATE_CLIENTS:
        beacon_pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / IP(dst=client["ip"]) / UDP(dport=CLIENT_UDP_PORT) / Raw(load=encrypted_payload)
        for _ in range(3):
            sendp(beacon_pkt, iface=client["iface"], verbose=False)
            time.sleep(0.05)
        print(f"[*] Encrypted Beacon injected into {client['iface']} towards {client['ip']}.")

def handle_alert(packet):
    if IP in packet and TCP in packet:
        attacker_ip = packet[IP].src
        target_ip = packet[IP].dst
        target_port = packet[TCP].dport

        matched_host_ip = None
        for host_ip, host_data in HOSTS.items():
            if host_data["active_vip"] == target_ip:
                matched_host_ip = host_ip
                break

        if not matched_host_ip:
            return

        host = HOSTS[matched_host_ip]

        current_time = time.time()
        if current_time - host["last_mutation_time"] < 5.0:
            return

        print(f"\n[!] ALARM TRIGGERED! Hardware clone caught from {attacker_ip} targeting {target_ip}:{target_port}!")
        print(f"[*] Executing Reactive IP Hopping for Host {matched_host_ip}...")

        host["seq"] += 1
        mutate_server(matched_host_ip)
        host["last_mutation_time"] = time.time()
        print("[*] Hopping complete. Network stabilized. Resuming IDS...\n")

def sniff_thread_worker(iface):
    print(f"[*] Started Sniffing Thread on interface {iface}...")
    try:
        sniff(iface=iface, prn=handle_alert, store=False, filter="tcp")
    except Exception as e:
        print(f"[!] Sniffing failed on {iface}: {e}")

if __name__ == "__main__":
    load_config()
    initialize_static_network()
    
    print("\n[*] Establishing initial Virtual IPs (Patient Zero)...")
    for host_ip in HOSTS:
        mutate_server(host_ip)

    print(f"\n[*] Controller Active: Monitoring {len(SNIFF_INTERFACES)} management interfaces...")
    
    threads = []
    for iface in SNIFF_INTERFACES:
        t = threading.Thread(target=sniff_thread_worker, args=(iface,), daemon=True)
        t.start()
        threads.append(t)
        
    try:
        while True:
            time.sleep(1)
            # If all sniffing interfaces go down (e.g. Mininet exits), terminate the controller
            if threads and not any(t.is_alive() for t in threads):
                print("\n[*] All sniffing interfaces went down. Exiting controller.")
                break
    except KeyboardInterrupt:
        print("\n[*] Controller stopped.")
