use crate::checksum::*;

pub enum Packet {
    IPv4(Ipv4Packet),
    IPv6(Ipv6Header),
    Unknown,
}

pub const SYN: u16 = 0b0000_0000_0000_0010;
pub const ACK: u16 = 0b0000_0000_0001_0000;
pub const FIN: u16 = 0b0000_0000_0000_0001;
pub const RST: u16 = 0b0000_0000_0000_0100;
pub const PSH: u16 = 0b0000_0000_0000_1000;
pub const URG: u16 = 0b0000_0000_0010_0000;

pub struct Ipv4HeaderFields {
    pub version: u8,
    pub ihl: u8,
    pub tos: u8,
    pub total_length: u16,
    pub identification: u16,
    pub flags: u8,
    pub fragment_offset: u16,
    pub ttl: u8,
    pub protocol: u8,
    pub source: [u8; 4],
    pub destination: [u8; 4],
}

pub struct Ipv4Header {
    pub fields: Ipv4HeaderFields,
    pub header_checksum: u16,
}
pub struct Ipv4Packet {
    pub header: Ipv4Header,
    pub payload: Vec<u8>,
}

pub struct TCPPacket {
    pub header: TCPHeader,
    pub payload: Vec<u8>,
}

pub struct Ipv6Header {
    pub version: u8,
    pub traffic_class: u8,
    pub flow_label: u32,
    pub payload_length: u16,
    pub next_header: u8,
    pub hop_limit: u8,
    pub source: [u8; 16],
    pub destination: [u8; 16],
    pub payload: Vec<u8>,
}

pub struct TCPHeader {
    pub src_port: u16,
    pub dst_port: u16,
    pub seq_num: u32,
    pub ack_num: u32,
    pub data_offset: u8,
    pub flags: u16,
    pub window: u16,
    pub checksum: u16,
    pub urgent_ptr: u16,
}

pub enum TCPState{
    Closed,
    SynSent,
    FinWait1,
    FinWait2,
    CloseWait,
    Closing,
    LastAck,
    TimeWait,
    SynReceived,
    Established,
}
pub struct TCB {
    pub state: TCPState,
    pub snd_una: u32,
    pub snd_nxt: u32,
    pub rcv_nxt: u32,
    pub irs: u32,
    pub iss: u32,
}
#[derive(Hash, Eq, PartialEq)]
pub struct ConnectionKey {
    pub src_ip: [u8; 4],
    pub src_port: u16,
    pub dst_ip: [u8; 4],
    pub dst_port: u16,
}
pub fn create_packet(x: &TCPPacket, y: &Ipv4Header) -> Vec<u8> {
    let mut buf: Vec<u8> = Vec::new();

    buf.push((y.fields.version << 4) | y.fields.ihl);
    buf.push(y.fields.tos);
    buf.extend_from_slice(&y.fields.total_length.to_be_bytes());
    buf.extend_from_slice(&y.fields.identification.to_be_bytes());

    let flags_frag = ((y.fields.flags as u16) << 13) | y.fields.fragment_offset;
    buf.extend_from_slice(&flags_frag.to_be_bytes());

    buf.push(y.fields.ttl);
    buf.push(y.fields.protocol);
    buf.extend_from_slice(&y.header_checksum.to_be_bytes());
    buf.extend_from_slice(&y.fields.source);
    buf.extend_from_slice(&y.fields.destination);

    buf.extend_from_slice(&x.header.src_port.to_be_bytes());
    buf.extend_from_slice(&x.header.dst_port.to_be_bytes());
    buf.extend_from_slice(&x.header.seq_num.to_be_bytes());
    buf.extend_from_slice(&x.header.ack_num.to_be_bytes());

    let data_offset_and_flags: u16 =
        ((x.header.data_offset as u16) << 12) | (x.header.flags & 0x1FF);
    buf.extend_from_slice(&data_offset_and_flags.to_be_bytes());
    buf.extend_from_slice(&x.header.window.to_be_bytes());
    buf.extend_from_slice(&x.header.checksum.to_be_bytes());
    buf.extend_from_slice(&x.header.urgent_ptr.to_be_bytes());

    buf.extend_from_slice(&x.payload);

    buf
}
pub fn check_flags(incoming_flags: &u16, tcp_flags: u16 ) -> bool {
    return (incoming_flags & tcp_flags != 0)
}

pub fn send_rst(dev: &tun_rs::SyncDevice, recv_ip: &Ipv4HeaderFields, recv_tcp: &TCPHeader) {
    let mut tcp_packet = TCPPacket {
        header: TCPHeader {
            src_port: recv_tcp.dst_port,
            dst_port: recv_tcp.src_port,
            seq_num: recv_tcp.ack_num,
            ack_num: recv_tcp.seq_num + 1,
            data_offset: 5,
            flags: 0x04,
            window: 0,
            checksum: 0,
            urgent_ptr: 0,
        },
        payload: vec![],
    };

    let ip_fields = Ipv4HeaderFields {
        version: 4,
        ihl: 5,
        tos: 0,
        total_length: 40,
        identification: 0,
        flags: 0,
        fragment_offset: 0,
        ttl: 64,
        protocol: 6,
        source: recv_ip.destination,
        destination: recv_ip.source,
    };

    let ip_chk = ip_checksum(&ip_fields);
    tcp_packet.header.checksum = tcp_checksum(recv_ip.destination, recv_ip.source, &tcp_packet);

    let ip_header = Ipv4Header { fields: ip_fields, header_checksum: ip_chk };
    dev.send(&create_packet(&tcp_packet, &ip_header));
    println!("RST sent");
}
pub fn send_fin(dev: &tun_rs::SyncDevice, recv_ip: &Ipv4HeaderFields, recv_tcp: &TCPHeader, seq: u32, ack: u32) {
    let mut tcp_packet = TCPPacket {
        header: TCPHeader {
            src_port: recv_tcp.dst_port,
            dst_port: recv_tcp.src_port,
            seq_num: seq,
            ack_num: ack,
            data_offset: 5,
            flags: 0x11,
            window: 64240,
            checksum: 0,
            urgent_ptr: 0,
        },
        payload: vec![],
    };
    let ip_fields = Ipv4HeaderFields {
        version: 4,
        ihl: 5,
        tos: 0,
        total_length: 40,
        identification: 0,
        flags: 0,
        fragment_offset: 0,
        ttl: 64,
        protocol: 6,
        source: recv_ip.destination,
        destination: recv_ip.source,
    };
    let ip_chk = ip_checksum(&ip_fields);
    tcp_packet.header.checksum = tcp_checksum(recv_ip.destination, recv_ip.source, &tcp_packet);
    let ip_header = Ipv4Header { fields: ip_fields, header_checksum: ip_chk };
    dev.send(&create_packet(&tcp_packet, &ip_header));
    println!("FIN sent");
}
pub fn send_ack(dev: &tun_rs::SyncDevice, recv_ip: &Ipv4HeaderFields, recv_tcp: &TCPHeader, seq: u32, ack: u32) {
    let mut tcp_packet = TCPPacket {
        header: TCPHeader {
            src_port: recv_tcp.dst_port,
            dst_port: recv_tcp.src_port,
            seq_num: seq,
            ack_num: ack,
            data_offset: 5,
            flags: 0x10,
            window: 64240,
            checksum: 0,
            urgent_ptr: 0,
        },
        payload: vec![],
    };
    let ip_fields = Ipv4HeaderFields {
        version: 4,
        ihl: 5,
        tos: 0,
        total_length: 40,
        identification: 0,
        flags: 0,
        fragment_offset: 0,
        ttl: 64,
        protocol: 6,
        source: recv_ip.destination,
        destination: recv_ip.source,
    };
    let ip_chk = ip_checksum(&ip_fields);
    tcp_packet.header.checksum = tcp_checksum(recv_ip.destination, recv_ip.source, &tcp_packet);
    let ip_header = Ipv4Header { fields: ip_fields, header_checksum: ip_chk };
    dev.send(&create_packet(&tcp_packet, &ip_header));
    println!("ACK sent");
}
