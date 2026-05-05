#!/usr/bin/env python3

from mininet.net import Mininet
from mininet.topo import Topo
from mininet.log import setLogLevel, info
from mininet.cli import CLI
from p4_mininet import P4Switch, P4Host
import argparse
from time import sleep

class MTDTopo(Topo):
    def __init__(self, sw_path, edge_json, fabric_json, **opts):
        Topo.__init__(self, **opts)

        info('*** Adding P4 Switches\n')
        # Edge Switches (Thrift ports: 9090, 9091, 9092)
        s1 = self.addSwitch('s1', sw_path=sw_path, json_path=edge_json, thrift_port=9090)
        s2 = self.addSwitch('s2', sw_path=sw_path, json_path=edge_json, thrift_port=9091)
        s3 = self.addSwitch('s3', sw_path=sw_path, json_path=edge_json, thrift_port=9092)

        # Fabric Switch (Thrift port: 10101)
        s4 = self.addSwitch('s4', sw_path=sw_path, json_path=fabric_json, thrift_port=10101)

        info('*** Adding Hosts\n')
        h1 = self.addHost('h1', ip='10.0.1.66/24', mac='00:04:00:00:00:01') # Attacker
        h2 = self.addHost('h2', ip='10.0.2.5/24', mac='00:04:00:00:00:02')  # Server
        h3 = self.addHost('h3', ip='10.0.3.10/24', mac='00:04:00:00:00:03') # Legit Client

        # The Dedicated IDS / Controller Tap
        h_ids = self.addHost('h_ids', ip='10.0.99.1/24', mac='00:04:00:00:00:99')

        info('*** Creating Links\n')
        # Connect Hosts to their respective Edge Switches
        self.addLink(h1, s1)
        self.addLink(h2, s2)
        self.addLink(h3, s3)

        # Connect all Edge Switches to the Fabric Switch
        self.addLink(s1, s4)
        self.addLink(s2, s4)
        self.addLink(s3, s4)

        # Connect IDS to s2
        self.addLink(h_ids, s2)

def main():
    parser = argparse.ArgumentParser(description='MTD Custom Mininet Topology')
    parser.add_argument('--behavioral-exe', help='Path to behavioral executable', type=str, default="simple_switch")
    parser.add_argument('--edge_json', help='Path to Edge JSON config file', type=str, required=True)
    parser.add_argument('--fabric_json', help='Path to Fabric JSON config file', type=str, required=True)
    args = parser.parse_args()

    topo = MTDTopo(args.behavioral_exe, args.edge_json, args.fabric_json)

    # Initialize Mininet with the custom P4 classes
    net = Mininet(topo=topo, host=P4Host, switch=P4Switch, controller=None)
    net.start()

    # Configure default routes for hosts
    info('*** Configuring Host Routes\n')
    for host_name in ['h1', 'h2', 'h3', 'h_ids']:
        h = net.get(host_name)
        h.setDefaultRoute("dev eth0")
        h.describe()

    # Disable IPv6 on all switch interfaces to prevent background noise
    info('*** Disabling IPv6 on Switch Interfaces\n')
    for sw_name in ['s1', 's2', 's3', 's4']:
        s = net.get(sw_name)
        for intf in s.intfNames():
            if intf != 'lo':
                s.cmd(f"sysctl -w net.ipv6.conf.{intf}.disable_ipv6=1")

    sleep(1)
    info('*** Network Ready!\n')

    # --- START OF DAEMON INITIALIZATION ---
    info('*** Booting h3_agent daemon in the background...\n')
    h3 = net.get('h3')

    # Execute the agent script in the background and pipe output to a log file
    h3.cmd('python3 h3_agent.py > /tmp/h3_agent_daemon.log 2>&1 &')

    info('*** Agent running. You can view its logs anytime from the Mininet CLI with: h3 cat /tmp/h3_agent_daemon.log\n')
    # --- END OF DAEMON INITIALIZATION ---

    CLI(net)
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    main()
