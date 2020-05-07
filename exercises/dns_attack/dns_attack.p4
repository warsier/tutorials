/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

/* CONSTANTS */


#define IP_HASHTABLE_ENTRIES 16
// threshold should not exceed 2 ^ bit_width
#define IP_HASHTABLE_BIT_WIDTH 8
#define IP_HASHTABLE_THRESHOLD 256

// How many bits fit in the query name.
#define QNAME_LENGTH 56
// How many bits we can return as a reponse.
#define DNS_RESPONSE_SIZE 128

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

header ethernet_h {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType; 
}

header ipv4_h {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

header tcp_h {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
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
    bit<16> urgentPtr;
}

header udp_h {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> len;
    bit<16> chksum; 
}

header dns_question_record_h {
    bit<QNAME_LENGTH> dns_qname;
    bit<16> qtype;
    bit<16> qclass;
}

header dns_question_record_h_48 {
    bit<48> dns_qname;
    bit<16> qtype;
    bit<16> qclass;
}

header dns_h {
    bit<16> id;
    bit<1> is_response;
    bit<4> opcode;
    bit<1> auth_answer;
    bit<1> trunc;
    bit<1> recur_desired;
    bit<1> recur_avail;
    bit<1> reserved;
    bit<1> authentic_data;
    bit<1> checking_disabled;
    bit<4> resp_code;
    bit<16> q_count;
    bit<16> answer_count;
    bit<16> auth_rec;
    bit<16> addn_rec;
}

struct dns_query {
    dns_h dns_header;
    dns_question_record_h question;
}

header dns_response_h {
    bit<DNS_RESPONSE_SIZE> answer;
}

// user defined metadata
struct metadata {
    bit<1> do_dns;
    bit<1> recur_desired;
    bit<1> response_set;
    bit<1> is_dns;
    bit<1> is_ip;
    bit<3> unused;
}

// List of all recognized headers
struct headers { 
    ethernet_h               ethernet;
    ipv4_h                   ipv4;
    tcp_h                    tcp;
    udp_h                    udp;
    dns_query                dns;
    dns_response_h           dns_response_fields;
    dns_question_record_h_48 question_48;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in pkt,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            0x800: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            8: parse_tcp;
            17: parse_udp;
            default: accept;
        }
    }

    state parse_tcp {
       pkt.extract(hdr.tcp);
       transition accept;
    }

    state parse_udp {
        pkt.extract(hdr.udp);
        transition select(hdr.udp.dstPort == 53 || hdr.udp.srcPort == 53) {
            true: parse_dns_header;
            false: accept;
        }
    }

    state parse_dns_header {
        pkt.extract(hdr.dns.dns_header);
        meta.is_dns = 1;
        transition accept;
    }

}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {   
    apply {  }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    register<bit<IP_HASHTABLE_BIT_WIDTH>>(IP_HASHTABLE_ENTRIES) ip_hashtable;
    bit<32> total_request = 0;
    bit<32> reg_pos;
    bit<IP_HASHTABLE_BIT_WIDTH> reg_val;
    bit<1> direction;

    action drop() {
        mark_to_drop(standard_metadata);
    }

    action compute_hashes(ip4Addr_t ipAddr, bit<16> port) {
        //Get register position
        hash(
            reg_pos,
            HashAlgorithm.crc16,
            (bit<32>) 0,
            {ipAddr, port},
            (bit<32>) IP_HASHTABLE_ENTRIES
        );

    }

    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }
    
    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = drop();
    }

    action set_direction(bit<1> dir) {
        direction = dir;
    }

    action set_debug(bit<16> info) {
        hdr.udp.srcPort = info;
    }

    table check_ports {
        key = {
            standard_metadata.ingress_port: exact;
            standard_metadata.egress_spec: exact;
        }
        actions = {
            set_direction;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }

    apply {
        if (hdr.ipv4.isValid()){
            ipv4_lpm.apply();
            if (meta.is_dns == 1) {
                direction = 0; // default
                // if packet comes from outside
                check_ports.apply();
                // if (check_ports.apply().hit) {
                    total_request = total_request + 1;
                    compute_hashes(hdr.ipv4.srcAddr, hdr.udp.srcPort);
                    ip_hashtable.read(reg_val, reg_pos);
                    if (reg_val == IP_HASHTABLE_THRESHOLD - 1) {
                        drop();
                    }
                    else {
                        ip_hashtable.write(reg_pos, reg_val + 1);
                        // (bit<16>) reg_val + 1
                        set_debug(105);
                    }
                    // reset counter
                    if (total_request == IP_HASHTABLE_THRESHOLD * 2) {
                        total_request = 0;
                        // has to set it by hand since p4 does not support loop
                        ip_hashtable.write(0, 0);
                        ip_hashtable.write(1, 0);
                        ip_hashtable.write(2, 0);
                        ip_hashtable.write(3, 0);

                        ip_hashtable.write(4, 0);
                        ip_hashtable.write(5, 0);
                        ip_hashtable.write(6, 0);
                        ip_hashtable.write(7, 0);

                        ip_hashtable.write(8, 0);
                        ip_hashtable.write(9, 0);
                        ip_hashtable.write(10, 0);
                        ip_hashtable.write(11, 0);

                        ip_hashtable.write(12, 0);
                        ip_hashtable.write(13, 0);
                        ip_hashtable.write(14, 0);
                        ip_hashtable.write(15, 0);
                    }
                // }
            }
        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {  }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
     apply {
    update_checksum(
        hdr.ipv4.isValid(),
            { hdr.ipv4.version,
          hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out pkt, in headers hdr) {
    apply {
        pkt.emit(hdr.ethernet);
        pkt.emit(hdr.ipv4);
        pkt.emit(hdr.tcp);
        pkt.emit(hdr.udp);
        pkt.emit(hdr.dns.dns_header);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
