use tun_rs::DeviceBuilder;
pub mod lib;
use parser::{parser, Packet};

use crate::parser::tcp_parser;

fn main() {
    let dev = DeviceBuilder::new()
        .name("tun0")
        .ipv4("10.0.0.12", 24, None)
        .mtu(1500)
        .build_sync()
        .unwrap();

    let mut buf = [0u8; 65535];
    loop {
        match dev.recv(&mut buf) {
            Ok(len) => {
                println!("Received packet");
                let packet = parser(&buf[..len]);
                match packet {
                    Packet::IPv4(h) => {
                        println!("--- IPv4 Packet ---");
                        println!("Version: {}", h.header.fields.version);
                        println!("IHL: {}", h.header.fields.ihl);
                        println!("TOS: {}", h.header.fields.tos);
                        println!("Total Length: {}", h.header.fields.total_length);
                        println!("Identification: {}", h.header.fields.identification);
                        println!("Flags: {}", h.header.fields.flags);
                        println!("Fragment Offset: {}", h.header.fields.fragment_offset);
                        println!("TTL: {}", h.header.fields.ttl);
                        println!("Protocol: {}", h.header.fields.protocol);
                        println!("Header Checksum: {}", h.header.header_checksum);
                        println!("Source: {}.{}.{}.{}",
                            h.header.fields.source[0], h.header.fields.source[1], h.header.fields.source[2], h.header.fields.source[3]);
                        println!("Destination: {}.{}.{}.{}",
                            h.header.fields.destination[0], h.header.fields.destination[1], h.header.fields.destination[2], h.header.fields.destination[3]);
                        print!("Payload: ");
                        for byte in h.payload.iter() {
                            print!("{:02x}", byte);
                        }
                        println!("-------------------");
                        if h.header.fields.protocol != 6 {
                               return;
                           }

                           println!("TCP packet received");

                           let packet = tcp_parser(&h.payload);

                           match packet {
                               Some(tcp) => {
                                   let header = &tcp.header;

                                   println!("Source port: {}", header.src_port);
                                   println!("Destination port: {}", header.dst_port);
                                   println!("Sequence number: {}", header.seq_num);
                                   println!("Acknowledgment number: {}", header.ack_num);

                                   println!("Header length: {} bytes", header.data_offset);
                                   println!("Window size: {}", header.window);
                                   println!("Checksum: 0x{:04x}", header.checksum);
                                   println!("Urgent pointer: {}", header.urgent_ptr);

                                   println!("TCP payload size: {} bytes", tcp.payload.len());

                                   let flags = header.flags;

                                   println!("Flags:");
                                   println!("  FIN: {}", (flags & 0x01) != 0);
                                   println!("  SYN: {}", (flags & 0x02) != 0);
                                   println!("  RST: {}", (flags & 0x04) != 0);
                                   println!("  PSH: {}", (flags & 0x08) != 0);
                                   println!("  ACK: {}", (flags & 0x10) != 0);
                                   println!("  URG: {}", (flags & 0x20) != 0);
                                   println!("  ECE: {}", (flags & 0x40) != 0);
                                   println!("  CWR: {}", (flags & 0x80) != 0);
                               }

                               None => {
                                   println!("Invalid TCP packet");
                               }
                           }
                    }
                    Packet::IPv6(h) => {
                        println!("--- IPv6 Packet ---");
                        println!("Version: {}", h.version);
                        println!("Traffic Class: {}", h.traffic_class);
                        println!("Flow Label: {}", h.flow_label);
                        println!("Payload Length: {}", h.payload_length);
                        println!("Next Header: {}", h.next_header);
                        println!("Hop Limit: {}", h.hop_limit);
                        print!("Source: ");
                        for (i, byte) in h.source.iter().enumerate() {
                            print!("{:02x}", byte);
                            if i % 2 == 1 && i != 15 { print!(":"); }
                        }
                        println!();
                        print!("Destination: ");
                        for (i, byte) in h.destination.iter().enumerate() {
                            print!("{:02x}", byte);
                            if i % 2 == 1 && i != 15 { print!(":"); }
                        }
                        println!();
                        print!("Payload: ");
                        for byte in h.payload.iter() {
                            print!("{:02x}", byte);
                        }
                        println!();
                        println!("-------------------");
                    }
                    Packet::Unknown => {
                        println!("Unknown packet");
                    }
                }
            }
            Err(e) => {
                eprintln!("recv error: {}", e);
                continue;
            }
        }
    }
}
