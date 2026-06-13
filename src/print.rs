use crate::protocol::*;

pub fn print_ipv4(h: &Ipv4Packet) {
    println!("--- IPv4 Packet ---");
    println!("Version: {}", h.header.fields.version);
    println!("IHL: {}", h.header.fields.ihl);
    println!("Protocol: {}", h.header.fields.protocol);
    println!("Source: {}.{}.{}.{}",
        h.header.fields.source[0],
        h.header.fields.source[1],
        h.header.fields.source[2],
        h.header.fields.source[3]);
    println!("Destination: {}.{}.{}.{}",
        h.header.fields.destination[0],
        h.header.fields.destination[1],
        h.header.fields.destination[2],
        h.header.fields.destination[3]);
    println!("-------------------");
}

pub fn print_tcp(tcp: &TCPPacket) {
    let h = &tcp.header;
    let f = h.flags & 0b00111111;

    let flag_str = match f {
        0b000010 => "SYN".to_string(),
        0b010010 => "SYN-ACK".to_string(),
        0b010000 => "ACK".to_string(),
        0b000001 => "FIN".to_string(),
        0b010001 => "FIN-ACK".to_string(),
        0b000100 => "RST".to_string(),
        0b011000 => "PSH-ACK".to_string(),
        _ => {
            let mut s = Vec::new();
            if f & 0b100000 != 0 { s.push("URG") }
            if f & 0b010000 != 0 { s.push("ACK") }
            if f & 0b001000 != 0 { s.push("PSH") }
            if f & 0b000100 != 0 { s.push("RST") }
            if f & 0b000010 != 0 { s.push("SYN") }
            if f & 0b000001 != 0 { s.push("FIN") }
            s.join("-")
        }
    };

    println!("--- TCP ---");
    println!("Src Port: {}", h.src_port);
    println!("Dst Port: {}", h.dst_port);
    println!("Seq:      {}", h.seq_num);
    println!("Ack:      {}", h.ack_num);
    println!("Flags:    {}", flag_str);
    println!("-----------");
}

pub fn print_ipv6(_: &Ipv6Header) {
    println!("IPv6 packet");
}
