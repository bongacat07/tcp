pub enum Packet {
    IPv4(Ipv4Packet),
    IPv6(Ipv6Header),
    Unknown,
}

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
    SynRecieved,
    Established,
}

pub fn create_packet(x: &TCPPacket, y: &Ipv4Header) -> Vec<u8> {
    let mut buf: Vec<u8> = Vec::new();

    // ── IPv4 Header (20 bytes) ──────────────────────────
    buf.push((y.fields.version << 4) | y.fields.ihl);          // [0]  version + IHL
    buf.push(y.fields.tos);                                      // [1]  DSCP/ECN
    buf.extend_from_slice(&y.fields.total_length.to_be_bytes()); // [2-3]
    buf.extend_from_slice(&y.fields.identification.to_be_bytes()); // [4-5]

    let flags_frag = ((y.fields.flags as u16) << 13) | y.fields.fragment_offset;
    buf.extend_from_slice(&flags_frag.to_be_bytes());            // [6-7]

    buf.push(y.fields.ttl);                                      // [8]
    buf.push(y.fields.protocol);                                 // [9]
    buf.extend_from_slice(&y.header_checksum.to_be_bytes());     // [10-11]
    buf.extend_from_slice(&y.fields.source);                     // [12-15]
    buf.extend_from_slice(&y.fields.destination);                // [16-19]

    // ── TCP Header (20 bytes) ───────────────────────────
    buf.extend_from_slice(&x.header.src_port.to_be_bytes());     // [20-21]
    buf.extend_from_slice(&x.header.dst_port.to_be_bytes());     // [22-23]
    buf.extend_from_slice(&x.header.seq_num.to_be_bytes());      // [24-27]
    buf.extend_from_slice(&x.header.ack_num.to_be_bytes());      // [28-31]

    let data_offset_and_flags: u16 = ((x.header.data_offset as u16) << 12) | (x.header.flags & 0x1FF);
    buf.extend_from_slice(&data_offset_and_flags.to_be_bytes()); // correct 2 bytes      // [33-34] flags (u16)
    buf.extend_from_slice(&x.header.window.to_be_bytes());       // [35-36]
    buf.extend_from_slice(&x.header.checksum.to_be_bytes());     // [37-38]
    buf.extend_from_slice(&x.header.urgent_ptr.to_be_bytes());   // [39-40] (padded naturally)

    // ── Payload ─────────────────────────────────────────
    buf.extend_from_slice(&x.payload);

    buf
}
