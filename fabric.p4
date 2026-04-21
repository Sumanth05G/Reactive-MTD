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
    arp_t      arp;
}

// We use this metadata to hold either the IPv4 Dest or the ARP Target IP
struct metadata_t {
    IPv4Address routing_dst_addr;
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
    }
}

/* CHECKSUM CALCULATION AND VERIFICATION */

control my_verify_checksum(inout headers_t hdr, inout metadata_t meta) { apply { } }
control my_compute_checksum(inout headers_t hdr, inout metadata_t meta) { apply { } }

/* INGRESS PIPELINE */

control my_ingress(inout headers_t hdr,
                  inout metadata_t meta,
                  inout standard_metadata_t standard_metadata)
{
    bool dropped = false;

    action drop_action() {
        mark_to_drop(standard_metadata);
        dropped = true;
    }

    action to_port_action(bit<9> port) {
        standard_metadata.egress_spec = port;
    }

    table ipv4_lpm {
        key = {
            meta.routing_dst_addr: lpm;
        }
        actions = {
            to_port_action;
            drop_action;
        }
        size = 1024;
        default_action = drop_action;
    }

    apply {
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