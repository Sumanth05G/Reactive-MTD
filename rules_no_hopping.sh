#!/bin/bash

echo "[*] Pushing static baseline rules (No MTD Hopping)..."

echo " -> Configuring Edge 1 (s1) [Thrift: 9090]"
simple_switch_CLI --thrift-port 9090 << EOF
table_add ipv4_lpm to_port_action 10.0.1.66/32 => 1
table_add ipv4_lpm to_port_action 10.0.0.0/16 => 2
EOF

echo " -> Configuring Edge 2 (s2 / Server) [Thrift: 9091]"
simple_switch_CLI --thrift-port 9091 << EOF
table_add ipv4_lpm to_port_action 10.0.2.5/32 => 1
table_add ipv4_lpm to_port_action 10.0.0.0/16 => 2
EOF

echo " -> Configuring Edge 3 (s3 / Client) [Thrift: 9092]"
simple_switch_CLI --thrift-port 9092 << EOF
table_add ipv4_lpm to_port_action 10.0.3.10/32 => 1
table_add ipv4_lpm to_port_action 10.0.0.0/16 => 2
EOF

echo " -> Configuring Fabric (s4) [Thrift: 10101]"
simple_switch_CLI --thrift-port 10101 << EOF
table_add ipv4_lpm to_port_action 10.0.1.0/24 => 1
table_add ipv4_lpm to_port_action 10.0.2.0/24 => 2
table_add ipv4_lpm to_port_action 10.0.3.0/24 => 3
EOF

echo "[*] All static rules pushed successfully! The network is physically wired."