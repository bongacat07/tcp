use tun_rs::DeviceBuilder;

use tcp::{
    parser, tcp_parser, ip_checksum, tcp_checksum, create_packet,
    Packet, Ipv4Packet, Ipv6Header, TCPPacket,
    TCPState, Ipv4Header, Ipv4HeaderFields, TCPHeader,
};

fn print_ipv4(h: &Ipv4Packet) {
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

fn print_tcp(tcp: &TCPPacket) {
    let h = &tcp.header;
    println!("--- TCP ---");
    println!("Src Port: {}", h.src_port);
    println!("Dst Port: {}", h.dst_port);
    println!("Seq: {}", h.seq_num);
    println!("Ack: {}", h.ack_num);
    let flags = h.flags;
    println!("Flags: SYN={} ACK={}",
        (flags & 0x02) != 0,
        (flags & 0x10) != 0);
}

fn print_ipv6(_: &Ipv6Header) {
    println!("IPv6 packet");
}

fn main() {
    let dev = DeviceBuilder::new()
        .name("tun0")
        .ipv4("10.0.0.12", 24, None)
        .mtu(1500)
        .build_sync()
        .unwrap();

    let mut state = TCPState::Closed;
    let mut buf = [0u8; 65535];

    loop {
        match dev.recv(&mut buf) {
            Ok(len) => {
                let packet = parser(&buf[..len]);

                match packet {
                    Packet::IPv4(h) => {
                        print_ipv4(&h);

                        if h.header.fields.protocol != 6 {
                            continue;
                        }

                        let packet = tcp_parser(&h.payload);

                        if let Some(tcp) = packet {
                            print_tcp(&tcp);

                            let flags = tcp.header.flags;

                            match state {
                                TCPState::Closed => {
                                    if (flags & 0x02) != 0 && (flags & 0x10) == 0 {
                                        let recv_ip = &h.header.fields;
                                        let recv_tcp = &tcp.header;

                                        let mut tcp_packet = TCPPacket {
                                            header: TCPHeader {
                                                src_port: recv_tcp.dst_port,
                                                dst_port: recv_tcp.src_port,
                                                seq_num: 0,
                                                ack_num: recv_tcp.seq_num + 1,
                                                data_offset: 5,
                                                flags: 0x12,
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
                                        let tcp_chk = tcp_checksum(
                                            recv_ip.destination,
                                            recv_ip.source,
                                            &tcp_packet,
                                        );
                                        tcp_packet.header.checksum = tcp_chk;

                                        let ip_header = Ipv4Header {
                                            fields: ip_fields,
                                            header_checksum: ip_chk,
                                        };

                                        let packet = create_packet(&tcp_packet, &ip_header);
                                        dev.send(&packet);

                                        state = TCPState::SynRecieved;
                                        println!("SYN received, SYN-ACK sent");
                                    }
                                }

                                TCPState::SynRecieved => {
                                    if (flags & 0x10) != 0 && (flags & 0x02) == 0 {
                                        state = TCPState::Established;
                                        println!("Handshake complete");
                                    }
                                }

                                TCPState::Established => {
                                }
                            }
                        }
                    }

                    Packet::IPv6(h) => {
                        print_ipv6(&h);
                    }

                    Packet::Unknown => {
                        println!("Unknown packet");
                    }
                }
            }

            Err(e) => {
                eprintln!("recv error: {}", e);
            }
        }
    }
}
