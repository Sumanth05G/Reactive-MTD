import socket
import time

SERVER_IP = "10.0.2.5"
SERVER_PORT = 80

if __name__ == "__main__":
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
