import subprocess
import json
import time
import socket
import os
import signal
import threading  # Added missing threading import

stop_cpu_monitor = False
cpu_samples = []

def manage_agent(action):
    """Handles stopping and starting the legit_agent.py to ensure pure baselines."""
    if action == "stop":
        print("[*] Terminating background legit_agent.py for pure baseline test...")
        os.system("pkill -f legit_agent.py")
        time.sleep(1) # Give OS time to clean up sockets/interfaces
    elif action == "start":
        print("[*] Booting legit_agent.py for MTD test...")
        # Start in background, discard output to keep terminal clean
        subprocess.Popen(["python3", "legit_agent.py"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        print("[*] Waiting 3 seconds for TUN interface and routing tables to initialize...")
        time.sleep(3)

def get_agent_pid():
    """Finds the PID of the legit_agent.py running in the background."""
    try:
        pid = subprocess.check_output(["pgrep", "-f", "legit_agent.py"]).decode().strip().split('\n')[0]
        return int(pid)
    except Exception:
        return None

def get_cpu_ticks(pid):
    """Reads raw CPU ticks from /proc/[pid]/stat to calculate instantaneous usage."""
    try:
        with open(f'/proc/{pid}/stat', 'r') as f:
            stats = f.read().split()
        return int(stats[13]) + int(stats[14])
    except Exception:
        return None

def monitor_cpu(pid):
    """Background thread to poll instantaneous CPU usage every 0.5 seconds."""
    global cpu_samples, stop_cpu_monitor
    cpu_samples = []
    ticks_per_sec = os.sysconf(os.sysconf_names['SC_CLK_TCK'])
    
    prev_ticks = get_cpu_ticks(pid)
    prev_time = time.time()
    
    while not stop_cpu_monitor:
        time.sleep(0.5)
        curr_ticks = get_cpu_ticks(pid)
        curr_time = time.time()
        
        if curr_ticks is not None and prev_ticks is not None:
            delta_ticks = curr_ticks - prev_ticks
            delta_sec = curr_time - prev_time
            # Calculate CPU percentage
            cpu_usage = 100.0 * (delta_ticks / ticks_per_sec) / delta_sec
            cpu_samples.append(cpu_usage)
            
        prev_ticks = curr_ticks
        prev_time = curr_time

def measure_tcp_latency(target_ip, port, label):
    print(f"[*] Measuring TCP Handshake Latency ({label}) to {target_ip}:{port}...")
    latencies = []
    
    for _ in range(5):
        try:
            start_time = time.time()
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2.0)
            sock.connect((target_ip, port))
            sock.close()
            end_time = time.time()
            latencies.append((end_time - start_time) * 1000) # Convert to ms
            time.sleep(0.1)
        except Exception as e:
            print(f"  [!] Connection failed: {e}")
            
    if latencies:
        avg_latency = sum(latencies) / len(latencies)
        print(f"  [+] {label} Latency: {avg_latency:.2f} ms")
        return avg_latency
    return None

def run_iperf(target_ip, port, label, duration=10, monitor_pid=None):
    print(f"\n[*] Running iperf3 Throughput Test ({label}) to {target_ip}:{port} for {duration}s...")
    
    global stop_cpu_monitor
    cpu_thread = None
    
    if monitor_pid:
        stop_cpu_monitor = False
        cpu_thread = threading.Thread(target=monitor_cpu, args=(monitor_pid,))
        cpu_thread.start()

    cmd = ["iperf3", "-c", target_ip, "-p", str(port), "-t", str(duration), "-J"]
    result = subprocess.run(cmd, capture_output=True, text=True)
    
    if monitor_pid:
        stop_cpu_monitor = True
        cpu_thread.join()

    try:
        data = json.loads(result.stdout)
        bps = data['end']['sum_received']['bits_per_second']
        mbps = bps / 1_000_000
        print(f"  [+] {label} Throughput: {mbps:.2f} Mbps")
        
        peak_cpu = max(cpu_samples) if cpu_samples else 0
        avg_cpu = sum(cpu_samples)/len(cpu_samples) if cpu_samples else 0
        
        if monitor_pid:
            print(f"  [+] Agent CPU Usage - Peak: {peak_cpu:.1f}%, Avg: {avg_cpu:.1f}%")
            
        return mbps, peak_cpu, avg_cpu
    except Exception as e:
        print(f"  [!] Error reading iperf3 output. Did the connection drop? Details: {e}")
        return 0, 0, 0

if __name__ == "__main__":
    print("==================================================")
    print("      MTD Comprehensive Evaluation Suite")
    print("==================================================\n")

    # 1. BASELINE TEST (Clean Environment)
    manage_agent("stop")
    base_rtt = measure_tcp_latency("10.0.4.20", 80, "BASELINE")
    base_mbps, _, _ = run_iperf("10.0.4.20", 80, "BASELINE", duration=10)

    # 2. MTD TEST (Agent Environment)
    print("\n--------------------------------------------------")
    manage_agent("start")
    agent_pid = get_agent_pid()
    
    if not agent_pid:
        print("[!] Error: Could not find legit_agent.py running. Aborting MTD test.")
        exit(1)
        
    print(f"[*] Confirmed legit_agent.py running on PID: {agent_pid}")

    mtd_rtt = measure_tcp_latency("10.0.2.5", 80, "MTD ENABLED")
    mtd_mbps, mtd_peak_cpu, mtd_avg_cpu = run_iperf("10.0.2.5", 80, "MTD ENABLED", duration=10, monitor_pid=agent_pid)
    
    # 3. RESULTS CALCULATION
    print("\n==================================================")
    print("                 FINAL RESULTS")
    print("==================================================")
    
    if base_mbps and mtd_mbps:
        print("--- THROUGHPUT ---")
        print(f"Baseline        : {base_mbps:.2f} Mbps")
        print(f"MTD             : {mtd_mbps:.2f} Mbps")
        print(f"Overhead Drop   : {((base_mbps - mtd_mbps) / base_mbps) * 100:.2f} %")
    
    if base_rtt and mtd_rtt:
        print("\n--- LATENCY (TCP Handshake) ---")
        print(f"Baseline RTT    : {base_rtt:.2f} ms")
        print(f"MTD RTT         : {mtd_rtt:.2f} ms")
        print(f"Added Latency   : {mtd_rtt - base_rtt:.2f} ms")
        
    print("\n--- CPU BOTTLENECK ---")
    if mtd_peak_cpu > 0:
        print(f"Agent Peak CPU  : {mtd_peak_cpu:.1f}% (Max spike in any 0.5s window)")
        print(f"Agent Avg CPU   : {mtd_avg_cpu:.1f}% (Average over 10s test)")
        print("Diagnosis       : Scapy packet crafting and TUN I/O in Python")
        print("                  is capping a CPU core, creating the bottleneck.")
    print("==================================================\n")
