import socket
import time
import argparse

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Vanilla TCP Ping-Pong Client")
    parser.add_argument("--ip", type=str, required=True, help="Server IP address to connect to")
    parser.add_argument("--port", type=int, default=80, help="Server port (default: 80)")
    args = parser.parse_args()

    SERVER_IP = args.ip
    SERVER_PORT = args.port

    print(f"[*] Starting Vanilla TCP Client connecting to {SERVER_IP}:{SERVER_PORT}...")
    
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        # Increase connection timeout just in case it attempts to connect right during a mutation
        s.settimeout(10.0) 
        
        print("[*] Connecting...")
        s.connect((SERVER_IP, SERVER_PORT))
        print("[+] Connected successfully! Beginning Ping-Pong...")
        
        # Disable timeout after connection so blocking recv works indefinitely
        s.settimeout(None)
        
        while True:
            try:
                # Client receives first
                data = s.recv(1024)
                if not data:
                    print("[-] Connection closed by server.")
                    break
                    
                received_val = int(data.decode('utf-8').strip())
                print(f"[Client] Received: {received_val}")
                
                # Increment and send back
                next_val = received_val + 1
                message = f"{next_val}"
                s.sendall(message.encode('utf-8'))
                print(f"[Client] Sent: {next_val}")
                
            except Exception as e:
                print(f"[!] Client Error: {e}")
                break
