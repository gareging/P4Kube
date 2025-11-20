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

header info_t {
    bit<32> virtualIP;
    bit<16> port;
    bit<16> replicas;
}

header quic_t {
    bit<1> hdr_type;
    bit<1> fixed;
    bit<2> pkt_type;
    bit<4> version;
}

header quicLong_t{
    bit<1> hdr_type;
    bit<1> fixed;
    bit<2> pkt_type;
    bit<4> reserved;
    bit<32> version;
    bit<8> dcid_length;
    bit<64> dst_cid;
    /*
    bit<8> dcid_first_byte;
    bit<16> cookie;
    bit<40> dcid_residue;
    */
    bit<8> scid_length;
    bit<64> src_cid;
    bit<8> token_len;
    bit<16> payload_len; 
}

header quicToken_t{
    varbit<2048> token;
}

/*header quicPayloadLen_t{
    bit<16> payload_len; 
}*/

header quicPayload_t{
    varbit<524280> payload; 
}

header quicShort_t{
    bit<8> dcid_first_byte;
    bit<16> cookie;
    bit<40> dcid_residue;
}

#define MAX_IPV4_ADDRESSES  100

header ips_t {
    ip4Addr_t ipAddress;
}

struct metadata {
    bit<14> ecmpHash;
    bit<14> ecmpGroupId;
    bit<16> tcpLength;
    bit<32> port_id; 
}

struct headers {
    ethernet_t ethernet;
    ipv4_t     ipv4;
    udp_t      udp;
    tcp_t      tcp;
    //   quic_t     quic;
    //quicShort_t quicShort;
    quicLong_t quicLong1;
    //quicToken_t quicToken;
    //quicPayloadLen_t quicPayloadLen;
    quicPayload_t quicPayload;
    quic_t quic_second;

    Tcp_option_nop_h nop1;
    Tcp_option_nop_h nop2;
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
