# Reactive Multi-Dimensional Moving Target Defense

This repository contains the implementation of a **Reactive Multi-Dimensional Moving Target Defense (MTD)** system using P4 programmable switches and SDN. The system embeds a lightweight Intrusion Detection System (IDS) directly into the switch data plane, keeping the network static during peacetime but reacting instantly to port-scanning behavior by mutating Virtual IPs and Ports. 

Legitimate TCP connections remain unaffected during mutation thanks to a transparent TUN-based endpoint agent.

## Environment Setup

It is highly recommended to use the official P4 development Virtual Machine, which ships with all P4 development tools pre-installed. It can be obtained from: [Official P4 Development VM](https://github.com/p4lang/tutorials?tab=readme-ov-file#download-a-virtual-machine-with-the-p4-development-tools-already-installed)

### Installing Dependencies

Inside the P4 VM, install the following additional packages:

```bash
sudo apt update && sudo apt install -y mininet hping3 nmap iperf3
sudo pip install scapy cryptography
```

## Configuration (`config.json`)

The entire network topology is defined in `config.json`, making the system fully data-driven. The current deployment uses four edge switches with the following topology:

| Node | Role | Real IP | Switch | MTD Enabled |
| :--- | :--- | :--- | :--- | :--- |
| `h_1_1` | Attacker | `10.0.1.66` | `s1` | No |
| `h_2_1` | Protected Server | `10.0.2.5` | `s2` | Yes (VIP: `192.168.50.0/24`) |
| `h_3_1` | Legitimate Client | `10.0.3.10` | `s3` | No |
| `h_4_1` | Unprotected Server| `10.0.4.20` | `s4` | No |

## Live Demonstration

The demonstration involves three actors: the protected server (`h_2_1`), the authorized client (`h_3_1`), and the attacker (`h_1_1`).

### Step 1: Compile the P4 Data Plane
Before launching the topology, compile the P4 source files using `p4c`:
```bash
p4c -b bmv2 edge.p4 -o edge.bmv2
p4c -b bmv2 fabric.p4 -o fabric.bmv2
```

### Step 2: Network Initialization
Launch the topology and controller in two separate terminals. The controller immediately installs the initial ("Patient Zero") NAT rules and VIPs.
```bash
# Terminal 1: Start the network
sudo python3 topo.py

# Terminal 2: Start the controller
sudo python3 reactive_controller.py
```

### Step 3: Connectivity Verification
The authorized client can reach the server transparently via the TUN agent. The attacker, lacking the agent, cannot reach the server.
```bash
mininet> h_3_1 ping -c 1 h_2_1   # Succeeds -- agent translates to current VIP
mininet> h_1_1 ping -c 1 h_2_1   # Fails -- no active NAT rule for attacker
```

### Step 4: Establishing a Live TCP Session
To prove mutation does not break active TCP sessions, establish a session before triggering the attack.
```bash
# In h_2_1 xterm: (launched by running xterm h_2_1 inside mininet>)
python3 SampleApp1/server.py

# In h_3_1 xterm: (launched by running xterm h_3_1 inside mininet>)
python3 SampleApp1/client.py --ip 10.0.2.5
```

### Step 5: Simulating the Reconnaissance Attack
The attacker launches a high-speed SYN flood targeting the VIP to enumerate open ports. (Read the current VIP from the controller's output).
```bash
mininet> h_1_1 hping3 -S -c 100 -p 80 --faster <CURRENT_VIP>
```

Upon executing the scan, you will observe:
1. **Detection:** The controller logs `[!] ALARM TRIGGERED`.
2. **Mutation:** A new VIP and Virtual Port are generated, NAT rules are updated via Thrift, and an encrypted beacon is dispatched.
3. **Continuity:** The TCP session on `h_3_1` continues uninterrupted.
4. **Attacker Isolation:** The old VIP is now inactive. Any further probe against it fails completely (`mininet> h_1_1 ping -c 5 <OLD_VIP>` will show 100% loss).


