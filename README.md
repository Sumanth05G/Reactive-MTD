# Reactive Moving Target Defense (MTD) using P4 & SDN

## Overview
This is a Minimum Viable Product (MVP) for an SDN-based Moving Target Defense system. It protects a backend server from reconnaissance by dynamically mutating its IP address. The control plane orchestrates the mutations, while the P4 data plane handles bidirectional Network Address Translation (NAT) transparently at line rate.

## Current System State (MVP)
* **Synchronized PRNG:** Both the SDN Controller and the Legitimate Client independently calculate the same Virtual IP (vIP) using a shared secret (`SEED`) and a sequence number.
* **Dynamic Data Plane:** The Python controller dynamically pushes rule updates to the BMv2 switches via Thrift to map the vIP to the Real IP.
* **Bidirectional NAT & ARP:** The BMv2 switches natively handle DNAT (Inbound) and SNAT (Outbound) for both IPv4 and ARP packets. No host-level ARP static routes (`arp -s`) are required.
* **End-to-End Reachability:** ICMP `ping` successfully routes from the client namespace to the mutated vIP.

## Topology
Standard Spine-Leaf setup using Mininet and `simple_switch` (BMv2):
* **h1 (Attacker):** `10.0.1.66` connected to Edge Switch `s1`
* **h2 (Server):** `10.0.2.5` connected to Edge Switch `s2` (NAT Target)
* **h3 (Client):** `10.0.3.10` connected to Edge Switch `s3`
* **s4 (Fabric):** Central backbone connecting `s1`, `s2`, and `s3`.
* **Virtual Subnet:** `192.168.50.0/24` (All vIPs are constrained to this block).

## Execution Guide

### 1. Boot the Data Plane
Compile the P4 program and launch the Mininet topology:
```bash
p4c-bm2-ss --p4v 16 basic_routing.p4 -o basic_routing.json
sudo python3 topo.py --behavioral-exe simple_switch --edge_json basic_routing.json --fabric_json basic_routing.json
```

### 2. Start the Client Agent (Host OS)
Open a new terminal (outside of Mininet) and run the client agent to listen for Controller beacons:
```bash
sudo python3 mtd_agent.py
```

### 3. Start the SDN Controller (Host OS)
Open a third terminal and execute the controller. It will push static routes, establish the first vIP NAT mapping on `s2`, and broadcast the UDP beacon:
```bash
sudo python3 controller.py
```

### 4. Verify End-to-End Reachability
1. Check the `mtd_agent.py` terminal to see the newly calculated Virtual IP (e.g., `192.168.50.144`).
2. Inside the Mininet CLI, initiate a ping from the client host to the Virtual IP:
```bash
mininet> h3 ping <Virtual_IP>
```
*Expected Result:* Successful ICMP echo replies, proving the P4 switch is successfully performing DNAT/SNAT on the traffic.