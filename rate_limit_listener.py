#!/usr/bin/env python3
import nnpy
import socket
import time
import sys

def setup_ids_socket():
    """
    Initializes the persistent connection to the P4 switch.
    """
    print("[*] IDS Booting: Connecting to Server Edge (s2)...")
    sub = nnpy.Socket(nnpy.AF_SP, nnpy.SUB)
    sub.connect('ipc:///tmp/bmv2-1-notifications.ipc') 
    sub.setsockopt(nnpy.SUB, nnpy.SUB_SUBSCRIBE, '')
    return sub

def listen_for_attack(sub_socket):
    """
    Blocks and waits for the next P4 digest.
    """
    print("[*] IDS Active: Monitoring for alerts...")
    while True:
        # Blocking wait
        msg = sub_socket.recv()

        raw_ip_bytes = msg[56:60]
        if len(raw_ip_bytes) == 4:
            attacker_ip = socket.inet_ntoa(raw_ip_bytes)
            return attacker_ip

def flush_queue(sub_socket):
    """
    Drains any stale alerts from the socket buffer while the controller was asleep.
    """
    # We use DONTWAIT to grab messages instantly. If the queue is empty, it throws an error.
    flushed_count = 0
    while True:
        try:
            sub_socket.recv(flags=nnpy.DONTWAIT)
            flushed_count += 1
        except nnpy.NNError:
            # Queue is empty, break the loop
            break
            
    if flushed_count > 0:
        print(f"[*] Ignored {flushed_count} redundant alerts received during cooldown.")


if __name__ == "__main__":
    sub = setup_ids_socket()
    try:
        while True:
            # This blocks until a port scan is detected
            attacker_ip = listen_for_attack(sub)
            print(f"[!] ALARM! Port scan from {attacker_ip} detected. Normally mutation will be triggered but will be integrated later!")
            # Don't hop again too quickly
            time.sleep(5)
            flush_queue(sub)

    except KeyboardInterrupt:
        print("\n[*] Controller stopped.")
