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

// TCP option headers
header Tcp_option_nop_h {
    bit<8> kind;
}
header Tcp_option_ss_e {
    bit<8> length;
    bit<16> maxSegmentSize;
}
header Tcp_option_sz_h {
    bit<8> length;
}
header Tcp_option_sack_e {
    varbit<256> sack;
}
header Tcp_option_timestamp_e {
    bit<8>  length;
    bit<32> tsval;
    bit<32> tsecr;
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
    bit<32> version;
    bit<8> dcid_length;
    bit<8> dcid_first_byte;
    bit<16> cookie;
    bit<40> dcid_residue;
    bit<8> scid_length;
    bit<64> src_cid;
    bit<8> token_len;
}

header quicToken_t{
    varbit<2048> token;
}

header quicPayloadLen_t{
    bit<16> payload_len; 
}

header quicPayload_t{
    varbit<2048> payload; 
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
    quic_t     quic;
    //quicShort_t quicShort;
    //quicLong_t quicLong1;
    //quicToken_t quicToken;
    //quicPayloadLen_t quicPayloadLen;
    //quicPayload_t quicPayload;
    //quicLong_t quicLong2;

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
