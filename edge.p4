#include <core.p4>
#include <v1model.p4>

typedef bit<48> EthernetAddress;
typedef bit<32> IPv4Address;

/* HEADER DEFINITIONS */

header ethernet_t {
    EthernetAddress dst_addr;
    EthernetAddress src_addr;
    bit<16>         ether_type;
}

header ipv4_t {
    bit<4>      version;
    bit<4>      ihl;
    bit<8>      diffserv;
    bit<16>     total_len;
    bit<16>     identification;
    bit<3>      flags;
    bit<13>     frag_offset;
    bit<8>      ttl;
    bit<8>      protocol;
    bit<16>     hdr_checksum;
    IPv4Address src_addr;
    IPv4Address dst_addr;
}

header tcp_t {
    bit<16> src_port;
    bit<16> dst_port;
    bit<32> seq_no;
    bit<32> ack_no;
    bit<4>  data_offset;
    bit<4>  res;
    bit<1>  cwr;
    bit<1>  ece;
    bit<1>  urg;
    bit<1>  ack;
    bit<1>  psh;
    bit<1>  rst;
    bit<1>  syn;
    bit<1>  fin;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgent_ptr;
}

header arp_t {
    bit<16> htype;
    bit<16> ptype;
    bit<8>  hlen;
    bit<8>  plen;
    bit<16> opcode;
    EthernetAddress hw_src_addr;
    IPv4Address proto_src_addr;
    EthernetAddress hw_dst_addr;
    IPv4Address proto_dst_addr;
}

struct headers_t {
    ethernet_t ethernet;
    ipv4_t     ipv4;
    tcp_t      tcp;
    arp_t      arp;
}

struct scan_alert_t {
    IPv4Address attacker_ip;
}

// We use this metadata to hold either the IPv4 Dest or the ARP Target IP
struct metadata_t {
    IPv4Address routing_dst_addr;
    IPv4Address translated_ip;    // Holds the new IP from the NAT action
    bit<2>      nat_type;         // 0 = None, 1 = DNAT, 2 = SNAT
}

error {
    IPv4IncorrectVersion,
    IPv4OptionsNotSupported
}

/* PARSER */

parser my_parser(packet_in packet,
                out headers_t hd,
                inout metadata_t meta,
                inout standard_metadata_t standard_meta)
{
    state start {
        packet.extract(hd.ethernet);
        transition select(hd.ethernet.ether_type) {
            0x0800:  parse_ipv4;
            0x0806:  parse_arp;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hd.ipv4);
        verify(hd.ipv4.version == 4w4, error.IPv4IncorrectVersion);
        verify(hd.ipv4.ihl == 4w5, error.IPv4OptionsNotSupported);
        transition select(hd.ipv4.protocol) {
            6: parse_tcp;
            default: accept;
        }
    }

    state parse_tcp {
        packet.extract(hd.tcp);
        transition accept;
    }

    state parse_arp {
        packet.extract(hd.arp);
        transition accept;
    }
}

/* DEPARSER */

control my_deparser(packet_out packet, in headers_t hdr)
{
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.arp);
        packet.emit(hdr.tcp);
    }
}

/* CHECKSUM CALCULATION AND VERIFICATION */

control my_verify_checksum(inout headers_t hdr, inout metadata_t meta) { apply { } }
control my_compute_checksum(inout headers_t hdr, inout metadata_t meta) {
    apply {
        update_checksum(
            hdr.ipv4.isValid(),
            { hdr.ipv4.version,
              hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.total_len,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.frag_offset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.src_addr,
              hdr.ipv4.dst_addr },
            hdr.ipv4.hdr_checksum,
            HashAlgorithm.csum16);
    }
}

/* INGRESS PIPELINE */

control my_ingress(inout headers_t hdr,
                  inout metadata_t meta,
                  inout standard_metadata_t standard_metadata)
{
    bool dropped = false;
    // 1024 slots for counts
    register<bit<32>>(1024) syn_counters;
    // 1024 slots for timestamps (v1model timestamps are 48-bit)
    register<bit<48>>(1024) last_syn_timestamps;

    action drop_action() {
        mark_to_drop(standard_metadata);
        dropped = true;
    }

    action to_port_action(bit<9> port) {
        standard_metadata.egress_spec = port;
    }

    action dnat_action(IPv4Address real_ip, bit<9> port) {
        meta.translated_ip = real_ip;
        meta.nat_type = 1; // Flag for DNAT
        standard_metadata.egress_spec = port;
    }

    action snat_and_route(IPv4Address virtual_ip, bit<9> port) {
        meta.translated_ip = virtual_ip;
        meta.nat_type = 2; // Flag for SNAT
        standard_metadata.egress_spec = port;
    }

    table ipv4_lpm {
        key = {
            meta.routing_dst_addr: lpm;
        }
        actions = {
            to_port_action;
            dnat_action;
            snat_and_route;
            drop_action;
        }
        size = 1024;
        default_action = drop_action;
    }

    apply {
        // --- INTRUSION DETECTION SYSTEM ---
        if (hdr.ipv4.isValid() && hdr.tcp.isValid() && hdr.tcp.syn == 1) {
            bit<32> syn_count;
            bit<48> last_time;
            bit<48> current_time = standard_metadata.ingress_global_timestamp;
            
            bit<32> index = (bit<32>) hdr.ipv4.src_addr & 1023;

            // Read the memory
            syn_counters.read(syn_count, index);
            last_syn_timestamps.read(last_time, index);

            // RATE MEASUREMENT: Did the last SYN happen more than 1 second ago?
            // (1,000,000 microseconds = 1 second)
            if (current_time - last_time > 1000000) {
                // Too much time passed. Reset the counter.
                syn_count = 1;
            } else {
                // It happened fast! Increment the counter.
                syn_count = syn_count + 1;
            }

            // Write the new data back to memory
            syn_counters.write(index, syn_count);
            last_syn_timestamps.write(index, current_time);

            // Check the threshold (e.g., 3 SYNs within 1 second)
            if (syn_count == 3) {
                // 100 is our arbitrary "Mirror Session ID"
                clone(CloneType.I2E, 100);
            }
        }
        // 1. Extract the target IP address depending on the packet type
        if (hdr.ipv4.isValid()) {
            meta.routing_dst_addr = hdr.ipv4.dst_addr;
        } else if (hdr.arp.isValid()) {
            meta.routing_dst_addr = hdr.arp.proto_dst_addr;
        } else {
            return; // Drop anything that isn't IPv4 or ARP
        }

        // 2. Apply the routing table using the extracted IP
        ipv4_lpm.apply();

        // 3. Apply the Translations to BOTH IPv4 and ARP!
        if (meta.nat_type == 1) {
            // It's DNAT (Inbound to Server)
            if (hdr.ipv4.isValid()) { hdr.ipv4.dst_addr = meta.translated_ip; }
            if (hdr.arp.isValid()) { hdr.arp.proto_dst_addr = meta.translated_ip; }
        } 
        else if (meta.nat_type == 2) {
            // It's SNAT (Outbound from Server)
            if (hdr.ipv4.isValid()) { hdr.ipv4.src_addr = meta.translated_ip; }
            if (hdr.arp.isValid()) { hdr.arp.proto_src_addr = meta.translated_ip; }
        }
    }
}

/* EGRESS PIPELINE */

control my_egress(inout headers_t hdr,
                 inout metadata_t meta,
                 inout standard_metadata_t standard_metadata)
{
    apply { }
}

/* SWITCH PACKAGE DEFINITION */

V1Switch(my_parser(),
         my_verify_checksum(),
         my_ingress(),
         my_egress(),
         my_compute_checksum(),
         my_deparser()) main;