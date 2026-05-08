import urllib.request
import threading
import subprocess
import time
import hashlib
import sys

TARGET_IP = "10.0.2.5"
FILE_URL = f"http://{TARGET_IP}/test.bin"
PORT = "80"

def trigger_attack():
    print("\n[!] ATTACK THREAD: 50% mark reached! Firing SYN flood...")
    # Fire 60 packets to safely trip the P4 IDS
    subprocess.run(["hping3", "-S", "-p", PORT, "-c", "60", "-i", "u1000", TARGET_IP], 
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    print("[!] ATTACK THREAD: Mutation triggered!")

def get_file_md5(filepath):
    md5 = hashlib.md5()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            md5.update(chunk)
    return md5.hexdigest()

def run_benchmark():
    print("==================================================")
    print("      Absolute Precision Hitless File Transfer")
    print("==================================================")
    
    try:
        req = urllib.request.urlopen(FILE_URL)
    except Exception as e:
        print(f"[X] Failed to connect to server: {e}")
        return

    total_size = int(req.headers.get('content-length', 0))
    if total_size == 0:
        print("[X] Error: File not found or empty.")
        return
        
    print(f"[*] Starting download of {total_size / (1024*1024):.2f} MB file...")
    
    downloaded = 0
    attack_fired = False
    start_time = time.time()
    
    with open("downloaded.bin", "wb") as f:
        while True:
            chunk = req.read(65536)
            if not chunk:
                break
                
            f.write(chunk)
            downloaded += len(chunk)
            
            # Calculate progress
            progress = downloaded / total_size
            
            # Trigger exactly at the 50% mark
            if progress >= 0.5 and not attack_fired:
                threading.Thread(target=trigger_attack).start()
                attack_fired = True
                
            # CRITICAL: Artificial throttle. 
            # This ensures the transfer takes a few seconds so the network 
            # mutation actually overlaps with the active TCP stream.
            if attack_fired and progress < 0.70:
                time.sleep(0.001)

    end_time = time.time()
    
    print(f"\n[+] Transfer completed in {end_time - start_time:.2f} seconds.")
    print("[*] Verifying file integrity...")
    
    final_hash = get_file_md5("downloaded.bin")
    print("==================================================")
    print(f"FINAL MD5 HASH: {final_hash}")
    print("==================================================")

if __name__ == "__main__":
    run_benchmark()
