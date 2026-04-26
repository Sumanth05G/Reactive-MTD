from scapy.all import sniff, IP

# Listening ONLY on the dedicated Management/Mirror Port!
SNIFF_IFACE = "s2-eth3"

def handle_alert(packet):
    # No complex filters needed. If it hits this cable, the hardware flagged it.
    if IP in packet:
        attacker_ip = packet[IP].src
        print(f"\n[!] IN-BAND HARDWARE CLONE CAUGHT!")
        print(f"[*] Port scan detected from {attacker_ip}!")
        print(f"[*] (Future: Trigger mutate_server(seq) here...)\n")

print(f"[*] Controller Out-of-Band Listener Booting...")
print(f"[*] Monitoring dedicated management port {SNIFF_IFACE}. CPU is idle...")

# We filter 'tcp' just so Mininet's IPv6 broadcast noise doesn't wake the script
sniff(iface=SNIFF_IFACE, prn=handle_alert, store=False, filter="tcp")