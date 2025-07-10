/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/
#include "include/headers.p4"
#define BUCKET_SIZE 6
#define COUNTER_WIDTH 16
/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/
#include "include/parsers.p4"
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
register<bit<4>>(MAX_IPV4_ADDRESSES) quic_id_to_ip;
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
        if (hdr.quic.isValid() && ((hdr.ipv4.dstAddr & subnet_mask) == subnet_prefix)){
            // quic packet to server
             if ((hdr.quic.hdr_type == 1) && (hdr.quic.pkt_type == (bit<2>)0)){
                 // handshake
                 bit<32> replica_offset = 0; 
                 bit<32> base_ip = 0;         
                 bit<32> node_port_index = 0; 
                 num_groups = 0;
                 bit<32> replica_counter_value = 0;  // Variable to hold the current counter value

                 bit<32> dpl = hdr.ipv4.dstAddr & 15;
                 node_port_index = dpl-2;
                 replica_offset = (dpl-2)*10;
                 base_ip = hdr.ipv4.dstAddr;
                 replica_count.read(num_groups, dpl-2);

                 if (num_groups == 0) {
                     drop();  // If no replicas, drop the packet
                 }

                 // Hash across [0, num_groups) to choose a replica
                hash(meta.ecmpHash,
                    HashAlgorithm.crc16,
                    (bit<1>)0,
                    { hdr.ipv4.srcAddr,
                    hdr.ipv4.dstAddr,
                    hdr.udp.srcPort,
                    hdr.udp.dstPort,
                    hdr.ipv4.protocol,
                    base_ip },  // base for the hash function
                    num_groups);

                bit<32> replica_index = replica_offset + (bit<32>)meta.ecmpHash;

                bit<16> sum = 0;
                subtract(sum, hdr.udp.checksum);
                subtract(sum, hdr.udp.dstPort);
                subtract32(sum, hdr.ipv4.dstAddr);

                ip_addresses.read(hdr.ipv4.dstAddr, replica_index);

                node_port.read(hdr.udp.dstPort, node_port_index);

                add32(sum, hdr.ipv4.dstAddr);
                add(sum, hdr.udp.dstPort);
                hdr.udp.checksum = ~sum;

                // Apply Longest Prefix Match to route to the next hop
                ipv4_lpm.apply();
                 
	     }
            
        } 
        // Check if the request is a TCP request on port 80, and the destination IP is 10.0.0.2, 10.0.0.3 or 10.0.0.4 
        else if (hdr.tcp.isValid() && hdr.tcp.dstPort == 80 && ((hdr.ipv4.dstAddr & subnet_mask) == subnet_prefix)) {  
            bit<32> replica_offset = 0; 
            bit<32> base_ip = 0;         
            bit<32> node_port_index = 0; 
            num_groups = 0;
            bit<32> replica_counter_value = 0;  // Variable to hold the current counter value

            bit<32> dpl = hdr.ipv4.dstAddr & 15;
            node_port_index = dpl-2;
            replica_offset = (dpl-2)*10;
            base_ip = hdr.ipv4.dstAddr;
            replica_count.read(num_groups, dpl-2);


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
        packet.emit(hdr.quic);
        //packet.emit(hdr.quicShort);
        //packet.emit(hdr.quicLong1);
        //packet.emit(hdr.quicToken);
        //packet.emit(hdr.quicPayloadLen);
        //packet.emit(hdr.quicPayload);
        //packet.emit(hdr.quicLong2);
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
