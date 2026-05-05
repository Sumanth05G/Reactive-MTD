import socket
import time
import sys

IPC_PORT = 5050
SERVER_PORT = 80

# Linux constant for TCP_USER_TIMEOUT (usually 18)
TCP_USER_TIMEOUT = 18

def get_active_vip():
    """Queries the local h3_agent daemon for the current Virtual IP"""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.connect(("127.0.0.1", IPC_PORT))
            vip = sock.recv(1024).decode('utf-8')
            return vip if vip != "WAIT" else None
    except ConnectionRefusedError:
        return None

def run_tcp_client():
    counter = 1

    current_vip = get_active_vip()
    while not current_vip:
        print("[*] Waiting for agent to provide initial route...")
        time.sleep(1)
        current_vip = get_active_vip()

    while True:
        print(f"\n[*] Connecting to target: {current_vip}:{SERVER_PORT}...")

        try:
            active_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

            # 1. Timeout for connection establishment
            active_socket.settimeout(3.0)

            # 2. THE FIX: Force Linux to kill the socket if ACKs stop arriving for 3000ms
            # This prevents the "TCP Blackhole" retransmission hang
            if sys.platform.startswith('linux'):
                active_socket.setsockopt(socket.IPPROTO_TCP, TCP_USER_TIMEOUT, 3000)

            active_socket.connect((current_vip, SERVER_PORT))
            print(f"[+] Connected! Transmitting data...")

            while True:
                message = f"Legitimate payload packet #{counter} (Targeting {current_vip})\n"
                active_socket.sendall(message.encode('utf-8'))
                counter += 1
                time.sleep(1)

        except (socket.timeout, ConnectionRefusedError, BrokenPipeError, OSError) as e:
            print(f"\n[!] Connection severed by L4 exception: {type(e).__name__}")
            active_socket.close()

            print("[*] Checking agent for SDN route mutation...")
            time.sleep(1) # Give the SDN controller a second to update the agent

            latest_vip = get_active_vip()

            if latest_vip and latest_vip != current_vip:
                print(f"[+] Route mutation confirmed! Shifting to new target: {latest_vip}")
                current_vip = latest_vip
                continue
            else:
                print("[-] Route is unchanged. This is a genuine network failure.")
                print("[-] Terminating application.")
                break

if __name__ == "__main__":
    print("[*] Legitimate Client App Started.")
    try:
        run_tcp_client()
    except KeyboardInterrupt:
        print("\n[*] Client shutting down.")
