import socket

def run_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind(('0.0.0.0', 80))
    server_socket.listen(5)

    print("[*] Server active. Listening on TCP port 80...")

    while True:
        print("\n[*] Waiting for a client connection...")
        try:
            conn, addr = server_socket.accept()
            print(f"[+] Client connected from {addr}!")

            # THE FIX: The Ghost Connection killer.
            # If the server hears nothing for 3 seconds, it assumes the MTD hopped.
            conn.settimeout(3.0)

            while True:
                data = conn.recv(1024)
                if not data:
                    print("[-] Client disconnected gracefully.")
                    break
                print(f"[DATA] {data.decode('utf-8').strip()}")

        except socket.timeout:
            print("[!] Timeout: No heartbeat received. Assuming MTD hopped and dropped the connection.")
        except (ConnectionResetError, BrokenPipeError, OSError):
            print("[!] Connection abruptly broken by network.")
        finally:
            # Clean up the dead socket and loop back to accept the new connection
            if 'conn' in locals():
                conn.close()

if __name__ == "__main__":
    run_server()
