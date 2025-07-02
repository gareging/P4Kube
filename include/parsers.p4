/*************************************************************************
*********************** P A R S E R  *******************************
*************************************************************************/
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
        transition accept;
    }

    state parse_udp {
        packet.extract(hdr.udp);
        transition select(hdr.udp.dstPort, hdr.udp.srcPort) {
            (7777, _): parse_info;
            (_, 4433): parse_quic;
            (4433, _): parse_quic;
            default: accept;
        }
    }

    state parse_quic {
        packet.extract(hdr.quic);
        transition accept;
        /*transition select(hdr.quic.hdr_type){
            0: parse_quicShort;
            1: parse_quicLong1;
            default: accept;
        }*/
    }
    /*
    state parse_quicShort {
        packet.extract(hdr.quicShort);
        transition accept;
    }

    state parse_quicLong1 {
        packet.extract(hdr.quicLong1);
        transition parse_quicToken;
    }

    state parse_quicToken{
        packet.extract(hdr.quicToken, (bit<32>)(8*hdr.quicLong1.token_len));
        packet.extract(hdr.quicPayloadLen);
        transition parse_quicPayload;
    }

   state parse_quicPayload{
       packet.extract(hdr.quicPayload, (bit<32>)(8*hdr.quicPayloadLen.payload_len));
       transition select(packet.lookahead<bit<1>>()) {
            1: parse_quicLong2; // another long header
            default: accept;
        } 
   }

    state parse_quicLong2{
       packet.extract(hdr.quicLong2);
       transition accept;
    }
    */

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

