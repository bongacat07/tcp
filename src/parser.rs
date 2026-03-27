
pub struct Ipv4Header {
    pub version: u8,
    pub ihl: u8,
    pub tos: u8,
    pub total_length: u16,
    pub identification: u16,
    pub flags: u8,
    pub fragment_offset: u16,
    pub ttl: u8,
    pub protocol: u8,
    pub header_checksum: u16,
    pub source: [u8; 4],
    pub destination: [u8; 4],
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
}

pub enum Packet {
    IPv4(Ipv4Header),
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
                return Packet::Unknown; // minimum IPv4 header size
            }

            let version = 4;
            let ihl = buf[0] & 0x0F;
            let tos = buf[1];

            let total_length =
                ((buf[2] as u16) << 8) | buf[3] as u16;

            let identification =
                ((buf[4] as u16) << 8) | buf[5] as u16;

            let flags = buf[6] >> 5;

            let fragment_offset =
                (((buf[6] as u16) & 0x1F) << 8) | buf[7] as u16;

            let ttl = buf[8];
            let protocol = buf[9];

            let header_checksum =
                ((buf[10] as u16) << 8) | buf[11] as u16;

            let source = [buf[12], buf[13], buf[14], buf[15]];
            let destination = [buf[16], buf[17], buf[18], buf[19]];

            Packet::IPv4(Ipv4Header {
                version,
                ihl,
                tos,
                total_length,
                identification,
                flags,
                fragment_offset,
                ttl,
                protocol,
                header_checksum,
                source,
                destination,
            })
        }

        6 => {
            if buf.len() < 40 {
                return Packet::Unknown; // minimum IPv6 header
            }

            let version = 6;

            let traffic_class =
                ((buf[0] & 0x0F) << 4) | (buf[1] >> 4);

            let flow_label =
                (((buf[1] as u32) & 0x0F) << 16)
                | ((buf[2] as u32) << 8)
                | buf[3] as u32;

            let payload_length =
                ((buf[4] as u16) << 8) | buf[5] as u16;

            let next_header = buf[6];
            let hop_limit = buf[7];

            let mut source = [0u8; 16];
            source.copy_from_slice(&buf[8..24]);

            let mut destination = [0u8; 16];
            destination.copy_from_slice(&buf[24..40]);

            Packet::IPv6(Ipv6Header {
                version,
                traffic_class,
                flow_label,
                payload_length,
                next_header,
                hop_limit,
                source,
                destination,
            })
        }

        _ => Packet::Unknown,
    }
}
