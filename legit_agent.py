import socket
import select
import hashlib
import builtins
import os
import fcntl
import struct
import subprocess
import threading
import base64
import json
from scapy.all import IP, TCP, send, sniff, conf
from cryptography.fernet import Fernet, InvalidToken

# Force unbuffered output for background logging
def print(*args, **kwargs):
    kwargs['flush'] = True
    builtins.print(*args, **kwargs)

# --- CONFIG ---
SEED = "CS6045_Secret"
UDP_LISTEN_PORT = 9999
TUN_NAME = "mtd-tun0"

# --- CRYPTOGRAPHY SETUP ---
# Derive a valid 32-byte Fernet key from the plain text SEED
key_hash = hashlib.sha256(SEED.encode('utf-8')).digest()
FERNET_KEY = base64.urlsafe_b64encode(key_hash)
cipher_suite = Fernet(FERNET_KEY)

# Track highest seen sequence per host to block Replay Attacks
seen_seqs = {}

# Get the primary physical interface (usually h3-eth0)
PHYSICAL_IFACE = str(conf.route.route("0.0.0.0")[0])

# Track the exact same state as the controller (populated dynamically)
HOSTS = {}
VIP_SUBNETS = []

def load_config():
    with open("config.json", "r") as f:
        config = json.load(f)
        
    for edge in config.get("edge_switches", []):
        if edge.get("is_mtd"):
            VIP_SUBNETS.append(edge["vip_subnet"])
            for host in edge.get("hosts", []):
                if host.get("type") == "server":
                    HOSTS[host["ip"]] = {
                        "active_vip": None,
                        "port_offset": 0,
                        "services": {port: {"active_vport": None} for port in host.get("services", [])}
                    }
                    seen_seqs[host["ip"]] = 0

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

# --- TUN SETUP ---
def setup_tun():
    TUNSETIFF = 0x400454ca
    IFF_TUN = 0x0001
    IFF_NO_PI = 0x1000
    
    print(f"[*] Creating TUN interface: {TUN_NAME}")
    tun_fd = os.open('/dev/net/tun', os.O_RDWR)
    ifr = struct.pack('16sH', TUN_NAME.encode('utf-8'), IFF_TUN | IFF_NO_PI)
    fcntl.ioctl(tun_fd, TUNSETIFF, ifr)
    
    # Bring interface up
    subprocess.run(["ip", "link", "set", "dev", TUN_NAME, "up"], check=True)
    
    # Route traffic for our protected servers into the TUN
    for host_ip in HOSTS:
        print(f"[*] Hijacking route for {host_ip} into {TUN_NAME}")
        subprocess.run(["ip", "route", "add", f"{host_ip}/32", "dev", TUN_NAME], check=True)
        
    # Prevent the kernel from sending RSTs when it sees incoming vIP traffic
    for subnet in VIP_SUBNETS:
        print(f"[*] Adding iptables drop rules for vIP subnet {subnet} to prevent kernel RSTs")
        subprocess.run(["iptables", "-A", "INPUT", "-s", subnet, "-j", "DROP"], check=True)
        
    return tun_fd

# Create a global raw socket to bypass Scapy's ARP/Layer 2 issues
raw_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
# Tell the kernel we are providing the IP header
raw_sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

# --- EGRESS (Outbound to Wire) ---
def egress_loop(tun_fd):
    print(f"[*] Egress Thread Started: Reading from {TUN_NAME}")
    while True:
        try:
            packet_bytes = os.read(tun_fd, 2048)
            pkt = IP(packet_bytes)
            
            target_ip = pkt.dst
            if target_ip in HOSTS and HOSTS[target_ip]["active_vip"]:
                host = HOSTS[target_ip]
                
                if TCP in pkt and pkt[TCP].dport in host["services"]:
                    service = host["services"][pkt[TCP].dport]
                    
                    if service["active_vport"]:
                        # MANGLE!
                        pkt.dst = host["active_vip"]
                        pkt[TCP].dport = service["active_vport"]
                        
                        # Force Scapy to recalculate checksums
                        del pkt[IP].chksum
                        del pkt[TCP].chksum
                        
                        # Get the raw bytes with correct checksums
                        raw_bytes = bytes(pkt[IP])
                        
                        # Send out via native OS raw socket
                        raw_sock.sendto(raw_bytes, (pkt.dst, 0))
                        
        except Exception as e:
            print(f"[!] Egress Error: {e}")

# --- INGRESS (Inbound from Wire) ---
def handle_ingress(pkt):
    if IP in pkt and TCP in pkt:
        src_ip = pkt[IP].src
        src_port = pkt[TCP].sport
        
        # Reverse lookup: Is this packet coming from an active vIP:vPort?
        for real_ip, host in HOSTS.items():
            if host["active_vip"] == src_ip:
                for real_port, service in host["services"].items():
                    if service["active_vport"] == src_port:
                        
                        # MANGLE! (Revert back to Real IP:Port)
                        pkt[IP].src = real_ip
                        pkt[TCP].sport = real_port
                        
                        # Force Scapy to recalculate checksums
                        del pkt[IP].chksum
                        del pkt[TCP].chksum
                        
                        # Get raw bytes of Layer 3 (IP)
                        mangled_bytes = bytes(pkt[IP])
                        
                        # Inject into TUN
                        global tun_fd_global
                        os.write(tun_fd_global, mangled_bytes)
                        return

def ingress_loop():
    print(f"[*] Ingress Thread Started: Sniffing on {PHYSICAL_IFACE}")
    sniff(iface=PHYSICAL_IFACE, prn=handle_ingress, filter="tcp", store=False)

if __name__ == "__main__":
    print("[*] Starting Stateless NAT Agent...")

    # Load Dynamic Config
    load_config()

    # Set up TUN
    tun_fd_global = setup_tun()

    # Initialize Patient Zero
    for host_ip in HOSTS:
        apply_route_update(host_ip, 0)

    # Start Worker Threads
    egress_thread = threading.Thread(target=egress_loop, args=(tun_fd_global,), daemon=True)
    ingress_thread = threading.Thread(target=ingress_loop, daemon=True)
    
    egress_thread.start()
    ingress_thread.start()

    # Main Thread: Listen for UDP Beacons
    udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    udp_sock.bind(("0.0.0.0", UDP_LISTEN_PORT))

    print(f"[*] Listening for SECURE Controller Beacons on UDP {UDP_LISTEN_PORT}")

    while True:
        data, _ = udp_sock.recvfrom(2048) # Increased buffer for encrypted payload
        try:
            # 1. Decrypt and Verify Hash (Fernet handles this instantly)
            decrypted_bytes = cipher_suite.decrypt(data)
            message = decrypted_bytes.decode('utf-8')
            
            if message.startswith("SERVER_DB:"):
                parts = message.split(":")
                if len(parts) >= 3 and parts[2].startswith("SEQ_"):
                    real_ip = parts[1]
                    seq = int(parts[2].replace("SEQ_", ""))
                    
                    # 2. STRICT ANTI-REPLAY CHECK
                    if real_ip not in seen_seqs:
                        seen_seqs[real_ip] = -1
                        
                    if seq <= seen_seqs[real_ip]:
                        print(f"[!] REPLAY ATTACK BLOCKED! Received old sequence {seq} for {real_ip}. Dropping.")
                        continue
                        
                    # 3. Update network state
                    seen_seqs[real_ip] = seq
                    apply_route_update(real_ip, seq)
                    
        except InvalidToken:
            # Triggers if the attacker tries to guess the key or modify a single byte of the packet
            print("[!] SPOOFING DETECTED: Invalid cryptographic signature. Dropping packet.")
        except Exception as e:
            print(f"[!] General error parsing beacon: {e}")
