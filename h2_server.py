import socket
import time

HOST = "10.0.2.5"
PORT = 80

if __name__ == "__main__":
    print(f"[*] Starting Vanilla TCP Server on {HOST}:{PORT}...")
    
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
