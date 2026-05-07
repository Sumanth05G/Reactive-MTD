# Reactive Moving Target Defense (MTD) in Mininet

## Overview
This project implements a **Reactive Moving Target Defense (MTD)** architecture using Mininet and P4 programmable switches. The network actively defends a backend server from reconnaissance attacks (e.g., port scans) by mutating the server's Virtual IP in real-time.

When a volumetric attack is detected by the P4 switch, the Python controller updates routing tables and injects an out-of-band UDP beacon to the legitimate client. The client agent intercepts this beacon, calculates the new cryptographic IP, and automatically reconnects to the new secure target, rendering the old IP obsolete for attackers.

## Prerequisites
- Mininet
- BMv2 (`simple_switch_CLI`)
- Python 3.x
- Scapy (requires `sudo` privileges)
- Python standard libraries: `socket`, `select`, `hashlib`, `fcntl`, `struct`, `os` (no external `pip` installations needed besides Scapy!)

## Dynamic Configuration
The entire network topology, routing, and MTD logic is dynamically driven by `config.json`.
- `s0` acts as the core fabric switch.
- `s1`, `s2`, `s3`, `s4` act as edge switches.
- `h_1_1` is the attacker, `h_2_1` is the MTD-protected server, `h_3_1` is the legitimate client, and `h_4_1` is a normal server (no MTD).

## Running and Testing

**Note:** The SDN controller requires root access to sniff and inject packets. Clients and servers run inside isolated Mininet namespaces.

### 1. Start the Mininet Data Plane
Open Terminal 1:
```bash
sudo python3 topo.py --edge_json edge.json --fabric_json fabric.json --config config.json
```
*(Note: The legitimate client agent `legit_agent.py` will automatically boot in the background for `h_3_1` during topology initialization!)*

### 2. Start the MTD Controller

Open Terminal 2 (host OS):

```bash
sudo python3 reactive_controller.py
```

> Wait for initialization. The initial "Patient Zero" Virtual IP will be printed and dynamic routing tables will be pushed to the fabric.

### 3. Start the Backend Server (h_2_1)

From the Mininet CLI:

```bash
mininet> xterm h_2_1
```

Inside the `h_2_1` terminal:

```bash
python3 SampleApp1/server.py --port 80
```

### 4. Start the Client App (h_3_1)

From the Mininet CLI:

```bash
mininet> xterm h_3_1
```

Inside the `h_3_1` terminal:

```bash
python3 SampleApp1/client.py --ip 10.0.2.5 --port 80
```

### 5. Launch the Attack (h_1_1)

From the main Mininet CLI:

```bash
mininet> h_1_1 hping3 -S -p 80 -c 4 -i u10000 <CURRENT_VIRTUAL_IP>
```

## Expected Behavior

During an attack, observe this sequence:

1. **Controller:** Detects attack on the dynamically created `sniff_port` interface (e.g., `s2-eth2`), updates NAT tables, and injects UDP notification beacon.
2. **Legitimate Agent (Background):** Intercepts the beacon, validates the Anti-Replay sequence, and updates the `mtd-tun0` TUN routes.
3. **Client App (h_3_1):** Application layer is unaware of the IP mutation; the TCP connection continues seamlessly.
4. **Server (h_2_1):** Traffic arrives correctly translated back to the Real IP.
