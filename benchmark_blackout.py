#!/usr/bin/env python3
import sys
import time
import socket
import argparse
import threading
import statistics
from scapy.all import ICMP

# --- CONFIGURATION ---
# The target is the REAL IP, hijacked by legit_agent.py into mtd-tun0
REAL_IP = "10.0.2.5"
TUN_INTERFACE = "mtd-tun0"
PROBE_INTERVAL = 0.001 # 1ms precision (1000 Hz)

class MTDBlackoutBenchmark:
    def __init__(self, target_ip, iterations):
        self.target_ip = target_ip
        self.iterations = iterations
        self.success_timestamps = []
        self.packets_sent = 0
        self.stop_event = threading.Event()

    def _setup_socket(self):
        """Configures a high-performance raw socket bound to the TUN interface."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        sock.settimeout(0.01) # 10ms read timeout
        
        # Strictly bind to the MTD TUN to prevent OS ICMP loopbacks/DUPs
        try:
            sock.setsockopt(socket.SOL_SOCKET, 25, TUN_INTERFACE.encode('utf-8')) # 25 is SO_BINDTODEVICE
        except OSError:
            print(f"[!] Warning: Could not bind strictly to {TUN_INTERFACE}. Run as root.")
            
        return sock

    def _prober_worker(self):
        """Tight loop utilizing pre-compiled packets and perf_counter for nanosecond precision."""
        sock = self._setup_socket()
        
        # Pre-compile the ICMP payload to completely eliminate loop overhead
        raw_payload = bytes(ICMP(id=1337, seq=1)) 
        
        while not self.stop_event.is_set():
            self.packets_sent += 1
            try:
                sock.sendto(raw_payload, (self.target_ip, 1))
                data, addr = sock.recvfrom(1024)
                
                # Filter noise: Must be from our target
                if addr[0] == self.target_ip:
                    # time.perf_counter() is monotonic and immune to system clock updates
                    self.success_timestamps.append(time.perf_counter())
            except socket.timeout:
                pass
            except Exception:
                pass # Ignore transient routing errors during the exact millisecond of blackout
            
            time.sleep(PROBE_INTERVAL)
            
        sock.close()

    def run(self):
        print("="*60)
        print(f"  [ PRO MTD BENCHMARK ] Target: {self.target_ip} | Freq: {1/PROBE_INTERVAL:.0f} Hz")
        print("="*60)
        
        prober_thread = threading.Thread(target=self._prober_worker, daemon=True)
        prober_thread.start()

        blackout_windows = []

        try:
            for i in range(self.iterations):
                print(f"\n[ Iteration {i+1}/{self.iterations} ]")
                
                # Controller enforces a 5-second cooldown. We wait 6s to ensure the system is armed.
                print("   [*] Enforcing 6s network stabilization (Controller Cooldown)...")
                time.sleep(6.0)
                
                print("   [!] SYSTEM ARMED. -> Launch attack on Virtual IP from h_1_1 NOW.")
                
                # Mark the starting index of timestamps for this specific mutation window
                start_marker = len(self.success_timestamps)
                
                # Give the user 4 seconds to launch the attack and the network to settle
                time.sleep(4.0) 
                end_marker = len(self.success_timestamps)

                window_samples = self.success_timestamps[start_marker:end_marker]
                
                if len(window_samples) > 1:
                    # Calculate discrete gaps between consecutive successful pings
                    gaps = [window_samples[j+1] - window_samples[j] for j in range(len(window_samples)-1)]
                    max_gap = max(gaps)
                    
                    # A blackout is a gap significantly larger than our 1ms probe interval
                    if max_gap > (PROBE_INTERVAL * 5):
                        effective_blackout_ms = (max_gap - PROBE_INTERVAL) * 1000
                        blackout_windows.append(effective_blackout_ms)
                        print(f"   [+] Mutation Detected! Blackout Window: {effective_blackout_ms:.2f} ms")
                    else:
                        print("   [-] No mutation gap detected. (Did you attack?)")
                else:
                    print("   [!] Error: No ICMP replies received in this window. Target unreachable.")

        except KeyboardInterrupt:
            print("\n[*] Benchmark interrupted by user.")
            
        finally:
            self.stop_event.set()
            prober_thread.join()
            self._report(blackout_windows)

    def _report(self, blackout_windows):
        packets_received = len(self.success_timestamps)
        loss_pct = 0.0
        if self.packets_sent > 0:
            loss_pct = ((self.packets_sent - packets_received) / self.packets_sent) * 100

        print("\n" + "="*60)
        print("                  TELEMETRY REPORT")
        print("="*60)
        print(f"  Packets Transmitted  : {self.packets_sent:,}")
        print(f"  Packets Received     : {packets_received:,}")
        print(f"  Background Loss Rate : {loss_pct:.3f}%")
        print("-" * 60)
        
        if blackout_windows:
            avg_b = statistics.mean(blackout_windows)
            max_b = max(blackout_windows)
            min_b = min(blackout_windows)
            
            print(f"  Captured Mutations   : {len(blackout_windows)}")
            print(f"  Average Blackout     : {avg_b:.2f} ms")
            print(f"  Minimum Blackout     : {min_b:.2f} ms")
            print(f"  Maximum Blackout     : {max_b:.2f} ms")
            
            if len(blackout_windows) >= 2:
                stdev_b = statistics.stdev(blackout_windows)
                print(f"  Jitter (StdDev)      : {stdev_b:.2f} ms")
        else:
            print("  [!] No valid mutations captured for statistical analysis.")
        print("="*60)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Pro-Grade MTD Blackout Benchmarker")
    parser.add_argument("--count", type=int, default=5, help="Number of mutations to track")
    args = parser.parse_args()
    
    benchmarker = MTDBlackoutBenchmark(target_ip=REAL_IP, iterations=args.count)
    benchmarker.run()
