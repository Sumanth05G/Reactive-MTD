# Reactive Moving Target Defense (MTD) in Mininet

## Overview
This project implements a **Reactive Moving Target Defense (MTD)** architecture using Mininet and P4 programmable switches. The network actively defends a backend server from reconnaissance attacks (e.g., port scans) by mutating the server's Virtual IP in real-time.

When a volumetric attack is detected by the P4 switch, the Python controller updates routing tables and injects an out-of-band UDP beacon to the legitimate client. The client agent intercepts this beacon, calculates the new cryptographic IP, and automatically reconnects to the new secure target, rendering the old IP obsolete for attackers.

## Prerequisites
- Mininet
- BMv2 (`simple_switch_CLI`)
- Python 3.x
- Scapy (requires `sudo` privileges)

## Running and Testing

**Note:** The SDN controller requires root access to sniff and inject packets. Clients and servers run inside isolated Mininet namespaces.

### 1. Start the Mininet Data Plane
Open Terminal 1:
```bash
sudo python3 topo.py --edge_json edge.json --fabric_json fabric.json
````

### 2. Start the MTD Controller

Open Terminal 2 (host OS):

```bash
sudo python3 reactive_controller.py
```

> Wait for initialization. The initial "Patient Zero" Virtual IP will be printed.

### 3. Start the Backend Server (h2)

From the Mininet CLI:

```bash
mininet> xterm h2
```

Inside the `h2` terminal:

```bash
python3 h2_server.py
```

### 4. Start the Client Agents (h3)

Open two terminals for the client node:

```bash
mininet> xterm h3 h3
```

* **First `h3` terminal:** Run the background UDP listener:

  ```bash
  python3 h3_agent.py
  ```
* **Second `h3` terminal:** Run the active TCP client:

  ```bash
  python3 h3_client.py
  ```

### 5. Launch the Attack (h1)

From the main Mininet CLI:

```bash
mininet> h1 hping3 -S -p 80 -c 4 -i u10000 <CURRENT_VIRTUAL_IP>
```

## Expected Behavior

During an attack, observe this sequence:

1. **Controller:** Detects attack, updates NAT tables, and injects UDP notification beacon.
2. **Client Agent (h3):** Intercepts the beacon and computes the next Virtual IP.
3. **Client TCP (h3):** Reconnects to the new secure Virtual IP.
4. **Server (h2):** Drops the old connection and accepts the new one seamlessly.
