import socket
import time
import sys

IPC_PORT = 5050
TCP_USER_TIMEOUT = 18 # Used to aggressively drop dead Linux sockets

def get_active_route():
    """Queries the local h3_agent daemon for the current Virtual IP and Port"""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.connect(("127.0.0.1", IPC_PORT))
            response = sock.recv(1024).decode('utf-8')
            
            if response == "WAIT":
                return None, None
            
            # Split the string into IP and Port
            ip, port = response.split(':')
            return ip, int(port)
    except ConnectionRefusedError:
        return None, None

def run_tcp_client():
    counter = 1
    
    # 1. Wait for the agent to receive the "Patient Zero" beacon
    current_vip, current_vport = get_active_route()
    while not current_vip:
        print("[*] Waiting for background agent to provide initial route...")
        time.sleep(1)
        current_vip, current_vport = get_active_route()
        
    # 2. Main Application Loop
    while True:
        print(f"\n[*] Connecting to target: {current_vip}:{current_vport}...")
        
        try:
            active_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            active_socket.settimeout(3.0) 
            
            if sys.platform.startswith('linux'):
                active_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_USER_TIMEOUT, 3000)
                
            active_socket.connect((current_vip, current_vport))
            print("[+] Connected! Transmitting data...")
            
            while True:
                message = f"Legitimate payload packet #{counter} (Targeting {current_vip}:{current_vport})\n"
                active_socket.sendall(message.encode('utf-8'))
                counter += 1
                time.sleep(1) 
                
        except (socket.timeout, ConnectionRefusedError, BrokenPipeError, ConnectionResetError, OSError) as e:
            print(f"\n[!] Connection severed by L4 exception: {type(e).__name__}")
            active_socket.close()
            
            print("[*] Checking agent for MTD route mutation...")
            time.sleep(1) # Give the agent a moment to process the new UDP beacon
            
            latest_vip, latest_vport = get_active_route()
            
            # Check if EITHER the IP or the Port changed
            if latest_vip and (latest_vip != current_vip or latest_vport != current_vport):
                print(f"[+] Route mutation confirmed! Shifting to new target: {latest_vip}:{latest_vport}")
                current_vip = latest_vip
                current_vport = latest_vport
                continue 
            else:
                print("[-] Route is unchanged. This might be a genuine network failure.")
                print("[*] Retrying current route...")
                continue

if __name__ == "__main__":
    print("[*] Legitimate Client App Started.")
    try:
        run_tcp_client()
    except KeyboardInterrupt:
        print("\n[*] Client shutting down.")
