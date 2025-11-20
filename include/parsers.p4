/*************************************************************************
*********************** P A R S E R  *******************************
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

    state parse_udp {
        packet.extract(hdr.udp);
        transition select(hdr.udp.dstPort, hdr.udp.srcPort) {
            (7777, _): parse_info;
            /*(_, 4433): parse_quic;
            (4433, _): parse_quic;*/
            default: parse_quic;
        }
    }

    state parse_quic {
       transition select(packet.lookahead<bit<1>>()) {
            1: parse_quicLong; // another long header
            default: accept;
        } 
     }


    state parse_quicLong {
        packet.extract(hdr.quicLong1);
        packet.extract(hdr.quicPayload, (bit<32>)(8*hdr.quicLong1.payload_len));
        transition select(packet.lookahead<bit<1>>()) {
            1: parse_quic_second; // another long header
            default: accept;
        } 
    }


    state parse_quic_second{
       packet.extract(hdr.quic_second);
       transition accept;
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

}

