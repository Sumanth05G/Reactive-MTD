import socket
import time
import argparse
def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('10.255.255.255', 1))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Vanilla TCP Ping-Pong Server")
    parser.add_argument("--port", type=int, default=80, help="Port to bind to (default: 80)")
    args = parser.parse_args()

    HOST = "0.0.0.0"
    PORT = args.port
    local_ip = get_local_ip()

    print(f"[*] Starting Vanilla TCP Server on {local_ip}:{PORT} (binding to {HOST})...")
    
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, PORT))
        s.listen()
        
        print("[*] Waiting for connection...")
        conn, addr = s.accept()
        
        with conn:
            print(f"[+] Connection accepted from {addr}")
            counter = 1
            
            while True:
                try:
                    # Server sends first
                    message = f"{counter}"
                    conn.sendall(message.encode('utf-8'))
                    print(f"[Server] Sent: {counter}")
                    
                    # Receive response
                    data = conn.recv(1024)
                    if not data:
                        print("[-] Connection closed by client.")
                        break
                        
                    received_val = int(data.decode('utf-8').strip())
                    print(f"[Server] Received: {received_val}")
                    
                    counter = received_val + 1
                    time.sleep(1) # Slow down so user can read it
                    
                except Exception as e:
                    print(f"[!] Server Error: {e}")
                    break
