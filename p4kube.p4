/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ipv4_t {
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

header udp_t {
    bit<16>  srcPort;
    bit<16>  dstPort;
    bit<16>  length;
    bit<16>  checksum;
}

header tcp_t {
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


/*TCP timestamp implementation sources:
https://github.com/cheetahlib/cheetah-p4
https://github.com/jafingerhut/p4-guide/blob/master/tcp-options-parser/tcp-options-parser.p4 */
header Tcp_option_end_h {
    bit<8> kind;
}
header Tcp_option_nop_h {
    bit<8> kind;
}
header Tcp_option_sz_h {
    bit<8> length;
}
header Tcp_option_ss_h {
    bit<8>  kind;
    bit<8> length;
    bit<32> maxSegmentSize;
}
header Tcp_option_s_h {
    bit<8>  kind;
    bit<24> scale;
}
header Tcp_option_sack_h {
    bit<8>         kind;
    bit<8>         length;
    varbit<256>    sack;
}

header Tcp_option_timestamp_h {
    bit<8>         kind;
    bit<8>         length;
    bit<32> tsval;
    bit<32> tsecr;
}

//Versions without the kind for hop by hop
header Tcp_option_ss_e {
    bit<8> length;
    bit<16> maxSegmentSize;
}

header Tcp_option_sack_e {
    varbit<256>    sack;
}
header Tcp_option_timestamp_e {
    bit<8>         length;
    bit<32> tsval;
    bit<32> tsecr;
}

header_union Tcp_option_h {
    Tcp_option_end_h  end;
    Tcp_option_nop_h  nop;
    Tcp_option_ss_h   ss;
    Tcp_option_s_h    s;
    Tcp_option_sack_h sack;
    Tcp_option_timestamp_h timestamp;    
}

// Defines a stack of 10 tcp options
typedef Tcp_option_h[10] Tcp_option_stack;

header Tcp_option_padding_h {
    varbit<256> padding;
}

error {
    TcpDataOffsetTooSmall,
    TcpOptionTooLongForHeader,
    TcpBadSackOptionLength
}

struct Tcp_option_sack_top
{
    bit<8> kind;
    bit<8> length;
}


struct metadata {
    bit<14> ecmpHash;
    bit<14> ecmpGroupId;
    bit<16> tcpLength;
    bit<32> port_id;
}

header info_t {
    bit<32> virtualIP;  // Virtual IP for deployment identification
    bit<16> port;       // NodePort for routing
    bit<16> replicas;
}

#define MAX_IPV4_ADDRESSES  100

header ips_t {
    ip4Addr_t ipAddress;
}

struct headers {
    ethernet_t ethernet;
    ipv4_t     ipv4;
    udp_t      udp;
    tcp_t      tcp;
    //Tcp_option_stack tcp_options_vec;
    //Tcp_option_padding_h tcp_options_padding;
    Tcp_option_nop_h nop1;
    Tcp_option_nop_h nop2;
    //Linux MSS SACK TS
    Tcp_option_ss_e ss;
    Tcp_option_nop_h nop3;
    Tcp_option_sz_h sackw;
    Tcp_option_sack_e sack;
    Tcp_option_nop_h nop4;
    Tcp_option_timestamp_e timestamp;
    info_t     info;
    ips_t[MAX_IPV4_ADDRESSES] ips;
}

error {
    BadReplicaCount
}
/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

/*TCP timestamp implementation sources:                                         
https://github.com/cheetahlib/cheetah-p4                                        
https://github.com/jafingerhut/p4-guide/blob/master/tcp-options-parser/tcp-options-parser.p4 */

parser Tcp_option_parser(packet_in b,
                         in bit<4> tcp_hdr_data_offset,
                         out Tcp_option_stack vec,
                         out Tcp_option_padding_h padding)
{
    bit<7> tcp_hdr_bytes_left;
    
    state start {
        verify(tcp_hdr_data_offset >= 5, error.TcpDataOffsetTooSmall);
        tcp_hdr_bytes_left = 4 * (bit<7>) (tcp_hdr_data_offset - 5);
        transition next_option;
    }
    state next_option {
        transition select(tcp_hdr_bytes_left) {
            0 : accept;
            default : next_option_part2;
        }
    }
    
    state next_option_part2 {
        transition select(b.lookahead<bit<8>>()) {
            0: parse_tcp_option_end;
            1: parse_tcp_option_nop;
            2: parse_tcp_option_ss;
            3: parse_tcp_option_s;
            5: parse_tcp_option_sack;
	    8: parse_tcp_option_timestamp;
        }
    }

    state parse_tcp_option_timestamp {
        verify(tcp_hdr_bytes_left >= 10, error.TcpOptionTooLongForHeader);
        tcp_hdr_bytes_left = tcp_hdr_bytes_left - 10;
        b.extract(vec.next.timestamp);
        transition next_option;
    }
    
    state parse_tcp_option_end {
        b.extract(vec.next.end);
        tcp_hdr_bytes_left = tcp_hdr_bytes_left - 1;
        transition consume_remaining_tcp_hdr_and_accept;
    }
    state consume_remaining_tcp_hdr_and_accept {
        b.extract(padding, (bit<32>) (8 * (bit<9>) tcp_hdr_bytes_left));
        transition accept;
    }
    state parse_tcp_option_nop {
        b.extract(vec.next.nop);
        tcp_hdr_bytes_left = tcp_hdr_bytes_left - 1;
        transition next_option;
    }
    state parse_tcp_option_ss {
        verify(tcp_hdr_bytes_left >= 5, error.TcpOptionTooLongForHeader);
        tcp_hdr_bytes_left = tcp_hdr_bytes_left - 5;
        b.extract(vec.next.ss);
        transition next_option;
    }
    state parse_tcp_option_s {
        verify(tcp_hdr_bytes_left >= 4, error.TcpOptionTooLongForHeader);
        tcp_hdr_bytes_left = tcp_hdr_bytes_left - 4;
        b.extract(vec.next.s);
        transition next_option;
    }
    state parse_tcp_option_sack {
        bit<8> n_sack_bytes = b.lookahead<Tcp_option_sack_top>().length;
        verify(n_sack_bytes == 10 || n_sack_bytes == 18 ||
               n_sack_bytes == 26 || n_sack_bytes == 34,
               error.TcpBadSackOptionLength);
        verify(tcp_hdr_bytes_left >= (bit<7>) n_sack_bytes,
               error.TcpOptionTooLongForHeader);
        tcp_hdr_bytes_left = tcp_hdr_bytes_left - (bit<7>) n_sack_bytes;
        b.extract(vec.next.sack, (bit<32>) (8 * n_sack_bytes - 16));
        transition next_option;
    }
}

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    bit<16> number_replicas_remaining_to_parse;

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        meta.tcpLength = hdr.ipv4.totalLen - 20;
        transition select(hdr.ipv4.protocol) {
            6: parse_tcp;
            17: parse_udp;
            default: accept;
        }
    }

    state parse_tcp {
        packet.extract(hdr.tcp);
        packet.extract(hdr.nop1);
        transition select(hdr.nop1.kind){
	    1: parse_nop;
            2: parse_ss;
            4: parse_sack;
            8: parse_ts;
		default: accept;
	    }
    }	

    state parse_nop {
        packet.extract(hdr.nop2);
         transition select(hdr.nop2.kind){
            1: parse_nop2;
            8: parse_ts;
	    }
    }

    state parse_nop2 {
        packet.extract(hdr.nop3);
         transition select(hdr.nop3.kind){
            8: parse_ts;
		default: accept;
	    }
    }
    state parse_ss {
        //Finish parsing SS
        packet.extract(hdr.ss);
        packet.extract(hdr.nop3);
        transition select(hdr.nop3.kind){
            4: parse_sack;
            8: parse_ts;
		default: accept;
	    }
    }

    state parse_sack {
        packet.extract(hdr.sackw);
        packet.extract(hdr.sack, (bit<32>)hdr.sackw.length - 2);
        packet.extract(hdr.nop4);
        transition select(hdr.nop4.kind){
            8: parse_ts;
		default: accept;
	    }
    }

    state parse_ts {
        packet.extract(hdr.timestamp);
        transition accept;
    }

    state parse_udp {
        packet.extract(hdr.udp);
        transition select(hdr.udp.dstPort) {
            7777: parse_info;
            default: accept;
        }
    }

 // State to parse the incoming control packet and store the values
    state parse_info {
        packet.extract(hdr.info); // Extract virtual IP, NodePort, and replicas
        verify(hdr.info.replicas <= 10, error.BadReplicaCount);
        verify(hdr.info.replicas >= 0, error.BadReplicaCount);
        number_replicas_remaining_to_parse = hdr.info.replicas;
        transition select(hdr.info.replicas) {
            1: parse_ips;
            2: parse_ips;
            3: parse_ips;
            4: parse_ips;
            5: parse_ips;
            6: parse_ips;
            7: parse_ips;
            8: parse_ips;
            9: parse_ips;
            10: parse_ips;
            default: accept;
        }
    }
    // State to parse IP addresses for replicas
    state parse_ips {
        packet.extract(hdr.ips.next); // Extract IP of next replica
        number_replicas_remaining_to_parse = number_replicas_remaining_to_parse - 1;
        transition select(number_replicas_remaining_to_parse) {
            0: accept;
            default: parse_ips;
        }
    }
}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply { }
}

/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

register<bit<32>>(MAX_IPV4_ADDRESSES) ip_addresses;
register<bit<32>>(MAX_IPV4_ADDRESSES) port_to_ip;
register<bit<16>>(10) node_port; 
register<bit<16>>(10) replica_count; 
register<bit<32>>(10) virtual_ip; 
register<bit<32>>(100) replica_request_counter;  // 100 replicas (or adjust according to the number of replicas)
register<bit<32>>(1) debug_hash_value;
register<bit<32>>(1) debug_src_addr;
register<bit<16>>(1) debug_src_port;


control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {

    bit<16> num_groups;
    bit<16> priv_port;

/*TCP timestamp implementation sources:                                         
    https://github.com/cheetahlib/cheetah-p4                                        
    https://github.com/jafingerhut/p4-guide/blob/master/tcp-options-parser/tcp-options-parser.p4 */
    // Incremental checksum fix adapted from the pseudocode at https://p4.org/p4-spec/docs/PSA-v1.1.0.html#appendix-internetchecksum-implementation
    action ones_complement_sum(in bit<16> x, in bit<16> y, out bit<16> sum) {
	bit<17> ret = (bit<17>) x + (bit<17>) y;
	if (ret[16:16] == 1) {
            ret = ret + 1;
	}
	sum = ret[15:0];
    }

    // Restriction: data is a multiple of 16 bits long
    action subtract(inout bit<16> sum, bit<16> d) {
        ones_complement_sum(sum, ~d, sum);
    }

    action subtract32(inout bit<16> sum, bit<32> d) {
        ones_complement_sum(sum, ~(bit<16>)d[15:0], sum);
        ones_complement_sum(sum, ~(bit<16>)d[31:16], sum);
    }

    action add(inout bit<16> sum, bit<16> d) {
        ones_complement_sum(sum, d, sum);
    }

    action add32(inout bit<16> sum, bit<32> d) {
        ones_complement_sum(sum, (bit<16>)(d[15:0]), sum);
        ones_complement_sum(sum, (bit<16>)(d[31:16]), sum);
    }

    action encode_and_replace(in bit<32> server_id, in bit<32> target_ip){
        // Replace old srcIP with targetIP, old srcPort with 80. Incrementally update the tcp checksum.
	bit<16> sum = 0;
	subtract(sum, hdr.tcp.checksum);
	subtract(sum, hdr.tcp.srcPort);
        subtract32(sum, hdr.ipv4.srcAddr);
	subtract32(sum, hdr.timestamp.tsval);
	hdr.ipv4.srcAddr = target_ip;
        hdr.tcp.srcPort = 80;
	hdr.timestamp.tsval = (bit<32>)(hdr.timestamp.tsval & 4294967280) + server_id;
        add32(sum, hdr.ipv4.srcAddr);
	add32(sum, hdr.timestamp.tsval);
        add(sum, hdr.tcp.srcPort);
	hdr.tcp.checksum = ~sum;
    }

    action decode(){
	meta.port_id = (bit<32>)hdr.timestamp.tsecr & (bit<32>)15;
    }

    action drop() {
        mark_to_drop(standard_metadata);
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
 
    apply {
        bit<32> target_ip1 = 0x0A000002; // 10.0.0.2
        bit<32> target_ip2 = 0x0A000003; // 10.0.0.3
        bit<32> target_ip3 = 0x0A000004; // 10.0.0.4
        bit<32> target_ip4 = 0x0A000005; // 10.0.0.5
        bit<32> target_ip5 = 0x0A000006; // 10.0.0.6
        bit<32> target_ip6 = 0x0A000007; // 10.0.0.7
        bit<32> target_ip7 = 0x0A000008; // 10.0.0.8
        bit<32> target_ip8 = 0x0A000009; // 10.0.0.9
        bit<32> target_ip9 = 0x0A00000A; // 10.0.0.10
        bit<32> target_ip10 = 0x0A00000B; // 10.0.0.11 
        bit<16> node_port_0;
        bit<16> node_port_1;
        bit<16> node_port_2;
        bit<16> node_port_3;
        bit<16> node_port_4;
        bit<16> node_port_5;
        bit<16> node_port_6;
        bit<16> node_port_7;
        bit<16> node_port_8;
        bit<16> node_port_9;

        // Read both NodePorts from the registers for comparison
        node_port.read(node_port_0, 0);  // Read node_port[0] into node_port_0
        node_port.read(node_port_1, 1);  // Read node_port[1] into node_port_1
        node_port.read(node_port_2, 2);  // Read node_port[2] into node_port_2
        node_port.read(node_port_3, 3);  // Read node_port[3] into node_port_3
        node_port.read(node_port_4, 4);  // Read node_port[4] into node_port_4
        node_port.read(node_port_5, 5);  // Read node_port[5] into node_port_5
        node_port.read(node_port_6, 6);  // Read node_port[6] into node_port_6
        node_port.read(node_port_7, 7);  // Read node_port[7] into node_port_7
        node_port.read(node_port_8, 8);  // Read node_port[8] into node_port_8
        node_port.read(node_port_9, 9);  // Read node_port[9] into node_port_9
        bit<32> subnet_mask = 0xFFFFFF00;  // 255.255.255.0 mask to match 10.0.0.*
        bit<32> subnet_prefix = 0x0A000000;  // 10.0.0.0 in hexadecimal
        // Check if the request is a TCP request on port 80, and the destination IP is 10.0.0.2, 10.0.0.3 or 10.0.0.4 
        if (hdr.tcp.isValid() && hdr.tcp.dstPort == 80 && ((hdr.ipv4.dstAddr & subnet_mask) == subnet_prefix)) {  
            bit<32> replica_offset = 0; 
            bit<32> base_ip = 0;         
            bit<32> node_port_index = 0; 
            num_groups = 0;
            bit<32> replica_counter_value = 0;  // Variable to hold the current counter value


            // Determine which deployment this request is for based on IP
            if (hdr.ipv4.dstAddr == target_ip1) {
                base_ip = target_ip1;
                replica_count.read(num_groups, 0);  
                replica_offset = 0;  
                node_port_index = 0; 
            } else if (hdr.ipv4.dstAddr == target_ip2) {
                base_ip = target_ip2;
                replica_count.read(num_groups, 1);  
                replica_offset = 10;  
                node_port_index = 1; 
            } else if (hdr.ipv4.dstAddr == target_ip3){
                base_ip = target_ip3;
                replica_count.read(num_groups, 2);
                replica_offset = 20;
                node_port_index = 2;
            } else if (hdr.ipv4.dstAddr == target_ip4) {
                base_ip = target_ip4;
                replica_count.read(num_groups, 3);
                replica_offset = 30;
                node_port_index = 3;
            } else if (hdr.ipv4.dstAddr == target_ip5) {
                base_ip = target_ip5;
                replica_count.read(num_groups, 4);
                replica_offset = 40;
                node_port_index = 4;
            } else if (hdr.ipv4.dstAddr == target_ip6) {
                base_ip = target_ip6;
                replica_count.read(num_groups, 5);
                replica_offset = 50;
                node_port_index = 5;
            } else if (hdr.ipv4.dstAddr == target_ip7) {
                base_ip = target_ip7;
                replica_count.read(num_groups, 6);
                replica_offset = 60;
                node_port_index = 6;
            } else if (hdr.ipv4.dstAddr == target_ip8) {
                base_ip = target_ip8;
                replica_count.read(num_groups, 7);
                replica_offset = 70;
                node_port_index = 7;
            } else if (hdr.ipv4.dstAddr == target_ip9) {
                base_ip = target_ip9;
                replica_count.read(num_groups, 8);
                replica_offset = 80;
                node_port_index = 8;
            } else if (hdr.ipv4.dstAddr == target_ip10) {
                base_ip = target_ip10;
                replica_count.read(num_groups, 9);
                replica_offset = 90;
                node_port_index = 9;
            } else {
                drop();
            }

            // Check if there are any replicas, if not, drop the packet
            if (num_groups == 0) {
                drop();  // If no replicas, drop the packet
            }
	   else if (hdr.tcp.syn == 0 && hdr.timestamp.isValid()){
                // after handshake
		decode();
		bit<16> sum = 0;
	        subtract(sum, hdr.tcp.checksum);
	        subtract(sum, hdr.tcp.dstPort);
                subtract32(sum, hdr.ipv4.dstAddr);
		node_port.read(hdr.tcp.dstPort, node_port_index);
		port_to_ip.read(hdr.ipv4.dstAddr, meta.port_id);
                add32(sum, hdr.ipv4.dstAddr);
                add(sum, hdr.tcp.dstPort);
	        hdr.tcp.checksum = ~sum;
		ipv4_lpm.apply();
	   }

	   else {
                // Hash across [0, num_groups) to choose a replica
                hash(meta.ecmpHash,
                    HashAlgorithm.crc16,
                    (bit<1>)0,
                    { hdr.ipv4.srcAddr,
                    hdr.ipv4.dstAddr,
                    hdr.tcp.srcPort,
                    hdr.tcp.dstPort,
                    hdr.ipv4.protocol,
                    base_ip },  // base for the hash function
                    num_groups);

                bit<32> replica_index = replica_offset + (bit<32>)meta.ecmpHash;

                bit<16> sum = 0;
                subtract(sum, hdr.tcp.checksum);
                subtract(sum, hdr.tcp.dstPort);
                subtract32(sum, hdr.ipv4.dstAddr);

                // Select the correct replica based on the hash
                ip_addresses.read(hdr.ipv4.dstAddr, replica_index);

                // Set replica_counter_value to 0 before reading
                replica_counter_value = 0;
                replica_request_counter.read(replica_counter_value, replica_index);

                // Debug output to verify the initial value read

                // Explicitly add 1
                bit<32> increment = 1;
                replica_counter_value = replica_counter_value + increment;

                // Write the updated counter value back
                replica_request_counter.write(replica_index, replica_counter_value);

                // Debug output to confirm the final value


                // Now read the NodePort based on the earlier determined index
                node_port.read(hdr.tcp.dstPort, node_port_index);

                add32(sum, hdr.ipv4.dstAddr);
                add(sum, hdr.tcp.dstPort);
                hdr.tcp.checksum = ~sum;

                // Apply Longest Prefix Match to route to the next hop
                ipv4_lpm.apply();
            }   
        }

        else if (hdr.tcp.isValid()) {
            // Reverse NAT: Identify if the response is coming from a replica by checking srcPort
            debug_src_addr.write(0, hdr.ipv4.srcAddr);  // Log the current srcAddr
            debug_src_port.write(0, hdr.tcp.srcPort);  // Log the current srcPort

            // Use the stored node_port values to detect which deployment the response is for
	    bit<32> server_id = (bit<32>)standard_metadata.ingress_port;
	    port_to_ip.write(server_id, hdr.ipv4.srcAddr);

            bit<32> target_ip = 0;
            if (hdr.tcp.srcPort == node_port_0) {
		target_ip = target_ip1;
            } else if (hdr.tcp.srcPort == node_port_1) {
		target_ip = target_ip2;
            } else if (hdr.tcp.srcPort == node_port_2) {
		target_ip = target_ip3;
            } else if (hdr.tcp.srcPort == node_port_3) {
		target_ip = target_ip4;
            } else if (hdr.tcp.srcPort == node_port_4) {
		target_ip = target_ip5;
            } else if (hdr.tcp.srcPort == node_port_5) {
		target_ip = target_ip6;
            } else if (hdr.tcp.srcPort == node_port_6) {
		target_ip = target_ip7;
            } else if (hdr.tcp.srcPort == node_port_7) {
		target_ip = target_ip8;
            } else if (hdr.tcp.srcPort == node_port_8) {
		target_ip = target_ip9;
            } else if (hdr.tcp.srcPort == node_port_9) {
		target_ip = target_ip10;
            }
            if (target_ip != 0) {
                encode_and_replace(server_id, target_ip);
	    }
            // Apply LPM to route the traffic back to the client
            ipv4_lpm.apply();
        } else if (hdr.info.isValid()) { // Control Packet
            bit<32> offset = 0;  // Initialize offset to a default value

            // Determine the offset based on the virtual IP
            if (hdr.info.virtualIP == 0x0a000002) { // Control Packet for deployment 10.0.0.2 (nginx)
                offset = 0;  // No offset for deployment 1
            } else if (hdr.info.virtualIP == 0x0a000003) { // Control Packet for deployment 10.0.0.3 (nginx2)
                offset = 10;  // Offset for deployment 2 (nginx2 starts at index 10)
            } else if (hdr.info.virtualIP == 0x0a000004){ // Control Packet for deployment 10.0.0.4 (nginx3)
                offset = 20; // Offset for deployment 3 (nginx3 starts at index 20)
            } else if (hdr.info.virtualIP == 0x0a000005) { // Control Packet for deployment 10.0.0.5
                offset = 30;  // Offset for deployment 4 (starts at index 30)
            } else if (hdr.info.virtualIP == 0x0a000006) { // Control Packet for deployment 10.0.0.6
                offset = 40;  // Offset for deployment 5 (starts at index 40)
            } else if (hdr.info.virtualIP == 0x0a000007) { // Control Packet for deployment 10.0.0.7
                offset = 50;  // Offset for deployment 6 (starts at index 50)
            } else if (hdr.info.virtualIP == 0x0a000008) { // Control Packet for deployment 10.0.0.8
                offset = 60;  // Offset for deployment 7 (starts at index 60)
            } else if (hdr.info.virtualIP == 0x0a000009) { // Control Packet for deployment 10.0.0.9
                offset = 70;  // Offset for deployment 8 (starts at index 70)
            } else if (hdr.info.virtualIP == 0x0a00000A) { // Control Packet for deployment 10.0.0.10
                offset = 80;  // Offset for deployment 9 (starts at index 80)
            } else if (hdr.info.virtualIP == 0x0a00000B) { // Control Packet for deployment 10.0.0.11
                offset = 90;  // Offset for deployment 10 (starts at index 90)
            }
            else {
                drop();  // If the virtual IP is unknown, drop the packet
            }

            // Store Virtual IP in register based on deployment
            if (offset == 0) {
                virtual_ip.write(0, hdr.info.virtualIP);
                node_port.write(0, hdr.info.port);  // Write to index 0 for nginx
                replica_count.write(0, hdr.info.replicas);  // Write to index 0 for nginx
            } else if (offset == 10) {
                virtual_ip.write(1, hdr.info.virtualIP);
                node_port.write(1, hdr.info.port);  // Write to index 1 for nginx2
                replica_count.write(1, hdr.info.replicas);  // Write to index 1 for nginx2
            } else if (offset == 20){
                virtual_ip.write(2, hdr.info.virtualIP);
                node_port.write(2, hdr.info.port);  // Write to index 2 for nginx3
                replica_count.write(2, hdr.info.replicas);  // Write to index 2 for nginx3
            }else if (offset == 30) {
                virtual_ip.write(3, hdr.info.virtualIP);
                node_port.write(3, hdr.info.port);  // Write to index 3 for nginx4
                replica_count.write(3, hdr.info.replicas);  // Write to index 3 for nginx4
            } else if (offset == 40) {
                virtual_ip.write(4, hdr.info.virtualIP);
                node_port.write(4, hdr.info.port);  // Write to index 4 for nginx5
                replica_count.write(4, hdr.info.replicas);  // Write to index 4 for nginx5
            } else if (offset == 50) {
                virtual_ip.write(5, hdr.info.virtualIP);
                node_port.write(5, hdr.info.port);  // Write to index 5 for nginx6
                replica_count.write(5, hdr.info.replicas);  // Write to index 5 for nginx6
            } else if (offset == 60) {
                virtual_ip.write(6, hdr.info.virtualIP);
                node_port.write(6, hdr.info.port);  // Write to index 6 for nginx7
                replica_count.write(6, hdr.info.replicas);  // Write to index 6 for nginx7
            } else if (offset == 70) {
                virtual_ip.write(7, hdr.info.virtualIP);
                node_port.write(7, hdr.info.port);  // Write to index 7 for nginx8
                replica_count.write(7, hdr.info.replicas);  // Write to index 7 for nginx8
            } else if (offset == 80) {
                virtual_ip.write(8, hdr.info.virtualIP);
                node_port.write(8, hdr.info.port);  // Write to index 8 for nginx9
                replica_count.write(8, hdr.info.replicas);  // Write to index 8 for nginx9
            } else if (offset == 90) {
                virtual_ip.write(9, hdr.info.virtualIP);
                node_port.write(9, hdr.info.port);  // Write to index 9 for nginx10
                replica_count.write(9, hdr.info.replicas);  // Write to index 9 for nginx10
            }

            // Store IP addresses for replicas, based on the offset
            if (hdr.info.replicas >= 1) {
                ip_addresses.write(offset + 0, hdr.ips[0].ipAddress);  // First replica
            }
            if (hdr.info.replicas >= 2) {
                ip_addresses.write(offset + 1, hdr.ips[1].ipAddress);  // Second replica
            }
            if (hdr.info.replicas >= 3) {
                ip_addresses.write(offset + 2, hdr.ips[2].ipAddress);  // Third replica
            }
            if (hdr.info.replicas >= 4) {
                ip_addresses.write(offset + 3, hdr.ips[3].ipAddress);  // Fourth replica
            }
            if (hdr.info.replicas >= 5) {
                ip_addresses.write(offset + 4, hdr.ips[4].ipAddress);  // Fifth replica
            }
            if (hdr.info.replicas >= 6) {
                ip_addresses.write(offset + 5, hdr.ips[5].ipAddress);  // Sixth replica
            }
            if (hdr.info.replicas >= 7) {
                ip_addresses.write(offset + 6, hdr.ips[6].ipAddress);  // Seventh replica
            }
            if (hdr.info.replicas >= 8) {
                ip_addresses.write(offset + 7, hdr.ips[7].ipAddress);  // Eighth replica
            }
            if (hdr.info.replicas >= 9) {
                ip_addresses.write(offset + 8, hdr.ips[8].ipAddress);  // Ninth replica
            }
            if (hdr.info.replicas >= 10) {
                ip_addresses.write(offset + 9, hdr.ips[9].ipAddress);  // Tenth replica
            }
        }
    else if (hdr.ipv4.isValid()) {
            ipv4_lpm.apply(); // Normal IPv
        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply { }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
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

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
        packet.emit(hdr.udp);
        packet.emit(hdr.nop1);
        packet.emit(hdr.nop2);
        packet.emit(hdr.ss);
        packet.emit(hdr.nop3);
        packet.emit(hdr.sackw);
        packet.emit(hdr.sack);
        packet.emit(hdr.nop4);
        packet.emit(hdr.timestamp);
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
