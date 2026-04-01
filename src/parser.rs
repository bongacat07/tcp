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

pub enum Packet {
    IPv4(Ipv4Packet),
    IPv6(Ipv6Header),
    Unknown,
}

pub fn parser(buf: &[u8]) -> Packet {
    if buf.is_empty() {
        return Packet::Unknown;
    }

    match buf[0] >> 4 {
        4 => {
            if buf.len() < 20 {
                return Packet::Unknown;
            }

            let ihl = buf[0] & 0x0F;
            if ihl < 5 {
                return Packet::Unknown;
            }

            let total_length = ((buf[2] as u16) << 8) | buf[3] as u16;
            if total_length as usize > buf.len() {
                return Packet::Unknown;
            }

            let header_end = ihl as usize * 4;
            if header_end > total_length as usize {
                return Packet::Unknown;
            }

            let payload = buf[header_end..total_length as usize].to_vec();

            Packet::IPv4(Ipv4Packet {
                header: Ipv4Header {
                    fields: Ipv4HeaderFields {
                        version: 4,
                        ihl,
                        tos: buf[1],
                        total_length,
                        identification: ((buf[4] as u16) << 8) | buf[5] as u16,
                        flags: buf[6] >> 5,
                        fragment_offset: (((buf[6] as u16) & 0x1F) << 8) | buf[7] as u16,
                        ttl: buf[8],
                        protocol: buf[9],
                        source: [buf[12], buf[13], buf[14], buf[15]],
                        destination: [buf[16], buf[17], buf[18], buf[19]],
                    },
                    header_checksum: ((buf[10] as u16) << 8) | buf[11] as u16,
                },
                payload,
            })
        }

        6 => {
            if buf.len() < 40 {
                return Packet::Unknown;
            }

            let payload_length = ((buf[4] as u16) << 8) | buf[5] as u16;
            if 40 + payload_length as usize > buf.len() {
                return Packet::Unknown;
            }

            let payload = buf[40..40 + payload_length as usize].to_vec();

            Packet::IPv6(Ipv6Header {
                version: 6,
                traffic_class: ((buf[0] & 0x0F) << 4) | (buf[1] >> 4),
                flow_label: (((buf[1] as u32) & 0x0F) << 16)
                    | ((buf[2] as u32) << 8)
                    | buf[3] as u32,
                payload_length,
                next_header: buf[6],
                hop_limit: buf[7],
                source: buf[8..24].try_into().unwrap(),
                destination: buf[24..40].try_into().unwrap(),
                payload,
            })
        }

        _ => Packet::Unknown,
    }
}
pub fn tcp_parser(buf: &Vec<u8>) -> TCPHeader {
    TCPHeader {
        src_port: u16::from_be_bytes([buf[0], buf[1]]),
        dst_port: u16::from_be_bytes([buf[2], buf[3]]),
        seq_num: u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]),
        ack_num: u32::from_be_bytes([buf[8], buf[9], buf[10], buf[11]]),

        data_offset: (buf[12] >> 4) * 4, // in bytes
        flags: ((buf[12] as u16 & 0x01) << 8) | buf[13] as u16,

        window: u16::from_be_bytes([buf[14], buf[15]]),
        checksum: u16::from_be_bytes([buf[16], buf[17]]),
        urgent_ptr: u16::from_be_bytes([buf[18], buf[19]]),
    }
}
