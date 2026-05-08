#!/usr/bin/env python3

import json
from mininet.net import Mininet
from mininet.topo import Topo
from mininet.log import setLogLevel, info
from mininet.cli import CLI
from p4_mininet import P4Switch, P4Host
import argparse
from time import sleep

class MTDTopo(Topo):
    def __init__(self, sw_path, edge_json, fabric_json, config_json_path, **opts):
        Topo.__init__(self, **opts)

        with open(config_json_path, 'r') as f:
            self.config = json.load(f)

        self.host_names = []
        self.switch_names = []

        info('*** Adding Dynamic P4 Switches\n')
        # Fabric Switch
        fab = self.config["fabric_switch"]
        s_fabric = self.addSwitch(fab["name"], sw_path=sw_path, json_path=fabric_json, thrift_port=fab["thrift_port"])
        self.switch_names.append(fab["name"])

        # Edge Switches
        for i, edge in enumerate(self.config["edge_switches"]):
            s_edge = self.addSwitch(edge["name"], sw_path=sw_path, json_path=edge_json, thrift_port=edge["thrift_port"])
            self.switch_names.append(edge["name"])
            
            # Connect Edge to Fabric
            # We must enforce the port on the Edge switch side.
            # The fabric switch ports will just be 1, 2, 3... sequentially.
            self.addLink(s_edge, s_fabric, port1=edge["fabric_port"], port2=i+1)

            # Add Hosts for this Edge
            for host in edge.get("hosts", []):
                h = self.addHost(host["name"], ip=host["ip"]+'/24', mac=host["mac"])
                self.host_names.append(host["name"])
                # Connect Host to Edge with explicit port
                self.addLink(h, s_edge, port2=host["switch_port"])

            # Add Dummy Sniff Port if MTD is enabled
            if edge.get("is_mtd", False) and "sniff_port" in edge:
                sniff_host_name = f"{edge['name']}_ids"
                h_sniff = self.addHost(sniff_host_name, ip='10.0.99.1/24', mac='00:04:00:00:00:99')
                self.host_names.append(sniff_host_name)
                self.addLink(h_sniff, s_edge, port2=edge["sniff_port"])

def main():
    parser = argparse.ArgumentParser(description='MTD Custom Mininet Topology')
    parser.add_argument('--behavioral-exe', help='Path to behavioral executable', type=str, default="simple_switch")
    parser.add_argument('--edge_json', help='Path to Edge JSON config file', type=str, required=True)
    parser.add_argument('--fabric_json', help='Path to Fabric JSON config file', type=str, required=True)
    parser.add_argument('--config', help='Path to network configuration JSON', type=str, default="config.json")
    args = parser.parse_args()

    topo = MTDTopo(args.behavioral_exe, args.edge_json, args.fabric_json, args.config)

    # Initialize Mininet with the custom P4 classes
    net = Mininet(topo=topo, host=P4Host, switch=P4Switch, controller=None)
    net.start()

    # Configure default routes for hosts
    info('*** Configuring Host Routes\n')
    for host_name in topo.host_names:
        h = net.get(host_name)
        h.setDefaultRoute("dev eth0")
        h.describe()

    # Disable IPv6 on all switch interfaces to prevent background noise
    info('*** Disabling IPv6 on Switch Interfaces\n')
    for sw_name in topo.switch_names:
        s = net.get(sw_name)
        for intf in s.intfNames():
            if intf != 'lo':
                s.cmd(f"sysctl -w net.ipv6.conf.{intf}.disable_ipv6=1")

    sleep(1)
    info('*** Network Ready!\n')

    # --- START OF DAEMON INITIALIZATION ---
    info('*** Booting Legitimate Agents in the background...\n')
    for edge in topo.config["edge_switches"]:
        for host in edge.get("hosts", []):
            if host.get("type") == "legitimate_client" and "agent_script" in host:
                h_node = net.get(host["name"])
                script = host["agent_script"]
                log_file = f"/tmp/{host['name']}_agent.log"
                h_node.cmd(f'python3 {script} > {log_file} 2>&1 &')
                info(f'*** Agent running on {host["name"]}. View logs with: {host["name"]} cat {log_file}\n')

    CLI(net)
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    main()
