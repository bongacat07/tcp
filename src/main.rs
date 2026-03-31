use tun_rs::DeviceBuilder;
pub mod parser;
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
                        println!("Version: {}", h.version);
                        println!("IHL: {}", h.ihl);
                        println!("TOS: {}", h.tos);
                        println!("Total Length: {}", h.total_length);
                        println!("Identification: {}", h.identification);
                        println!("Flags: {}", h.flags);
                        println!("Fragment Offset: {}", h.fragment_offset);
                        println!("TTL: {}", h.ttl);
                        println!("Protocol: {}", h.protocol);
                        println!("Header Checksum: {}", h.header_checksum);
                        println!("Source: {}.{}.{}.{}",
                            h.source[0], h.source[1], h.source[2], h.source[3]);
                        println!("Destination: {}.{}.{}.{}",
                            h.destination[0], h.destination[1], h.destination[2], h.destination[3]);
                        print!("Payload: ");
                        for byte in h.payload.iter() {
                            print!("{:02x}", byte);
                        }
                        println!("-------------------");
                        if h.protocol == 6 {
                            println!("TCP packet received");

                            let header = tcp_parser(&h.payload);
                            let header_len = header.data_offset as usize;
                            if h.payload.len() > header_len {
                                let tcp_payload = &h.payload[header_len..];
                                println!("TCP payload size: {} bytes", tcp_payload.len());
                            } else {
                                println!("No TCP payload");
                            }

                            println!("Source port: {}", header.src_port);
                            println!("Destination port: {}", header.dst_port);
                            println!("Sequence number: {}", header.seq_num);
                            println!("Acknowledgment number: {}", header.ack_num);

                            println!("Header length: {} bytes", header.data_offset);
                            println!("Window size: {}", header.window);
                            println!("Checksum: 0x{:04x}", header.checksum);
                            println!("Urgent pointer: {}", header.urgent_ptr);

                            // Decode flags (this is where it gets interesting)
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

                            // Optional: extract payload (after TCP header)

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
