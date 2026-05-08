import subprocess
import json
import time
import threading
import socket
import os

stop_cpu_monitor = False
cpu_samples = []

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
            if delta_sec > 0:
                cpu_usage = (delta_ticks / ticks_per_sec) / delta_sec * 100.0
                cpu_samples.append(cpu_usage)
                
        prev_ticks = curr_ticks
        prev_time = curr_time

def measure_tcp_latency(target_ip, port, description, count=15):
    """Measures the true Application-Layer TCP 3-way handshake latency."""
    print(f"\n[*] Measuring TCP Handshake Latency ({description}) to {target_ip}:{port}...")
    latencies = []
    
    for _ in range(count):
        try:
            start_time = time.time()
            # Establish a real TCP connection
            sock = socket.create_connection((target_ip, port), timeout=2.0)
            end_time = time.time()
            sock.close()
            
            rtt_ms = (end_time - start_time) * 1000.0
            latencies.append(rtt_ms)
            time.sleep(0.1) # Small buffer between connections
        except Exception as e:
            pass # Ignore dropped packets/timeouts in calculation
            
    if not latencies:
        print(f"[!] All connection attempts to {target_ip}:{port} timed out.")
        return None
        
    avg_rtt = sum(latencies) / len(latencies)
    print(f"[+] {description} Latency: {avg_rtt:.2f} ms")
    return avg_rtt

def run_iperf(target_ip, port, description, duration=10, monitor_pid=None):
    """Runs iperf3 throughput test, tracking instantaneous CPU usage."""
    global stop_cpu_monitor, cpu_samples
    print(f"[*] Starting {description} Throughput Test towards {target_ip}:{port} for {duration}s...")
    
    cpu_thread = None
    if monitor_pid:
        stop_cpu_monitor = False
        cpu_thread = threading.Thread(target=monitor_cpu, args=(monitor_pid,))
        cpu_thread.start()

    cmd = ["iperf3", "-c", target_ip, "-p", str(port), "-t", str(duration), "--json"]
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if monitor_pid and cpu_thread:
            stop_cpu_monitor = True
            cpu_thread.join()
            
        if result.returncode != 0:
            print(f"[!] iperf3 error:\n{result.stderr}")
            return None, 0.0
            
        data = json.loads(result.stdout)
        mbps = data['end']['sum_received']['bits_per_second'] / 1_000_000
        print(f"[+] {description} Throughput: {mbps:.2f} Mbps")
        
        avg_cpu = sum(cpu_samples) / len(cpu_samples) if cpu_samples else 0.0
        if monitor_pid:
            print(f"[+] legit_agent.py Peak CPU (any 0.5s window) : {max(cpu_samples):.1f}%")
            print(f"[+] legit_agent.py Avg CPU (over 10s test)    : {avg_cpu:.1f}%")
            
        return mbps, avg_cpu
        
    except Exception as e:
        print(f"[!] Failed to parse iperf3 output: {e}")
        if monitor_pid and cpu_thread:
            stop_cpu_monitor = True
            cpu_thread.join()
        return None, 0.0

if __name__ == "__main__":
    print("==================================================")
    print("      MTD Comprehensive Evaluation Suite")
    print("==================================================")
    
    # 1. BASELINE TESTS (No MTD - Target h_4_1)
    base_rtt = measure_tcp_latency("10.0.4.20", 80, "BASELINE")
    base_mbps, _ = run_iperf("10.0.4.20", 80, "BASELINE", duration=10)
    
    time.sleep(2)
    
    # 2. MTD TESTS (With Cryptography & TUN overhead - Target h_2_1)
    agent_pid = get_agent_pid()
    if not agent_pid:
        print("\n[!] WARNING: legit_agent.py not found running in background. CPU metric will be 0.")
    else:
        print(f"\n[*] Found legit_agent.py running on PID: {agent_pid}")

    mtd_rtt = measure_tcp_latency("10.0.2.5", 80, "MTD ENABLED")
    mtd_mbps, mtd_cpu = run_iperf("10.0.2.5", 80, "MTD ENABLED", duration=10, monitor_pid=agent_pid)
    
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
    if mtd_cpu > 0:
        print(f"Agent Peak CPU  : {max(cpu_samples):.1f}% (Max spike in any 0.5s window)")
        print(f"Agent Avg CPU   : {mtd_cpu:.1f}% (Average over 10s test)")
        if mtd_cpu > 70:
            print("Diagnosis       : Scapy packet crafting and TUN I/O in Python")
            print("                  is capping a CPU core, creating the bottleneck.")
    else:
        print("Agent CPU Usage : N/A (Agent not tracked)")
    print("==================================================")
